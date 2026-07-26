package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func exec(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	err = run(args, &out, &errBuf)
	return out.String(), errBuf.String(), err
}

func TestVersionAndHelp(t *testing.T) {
	out, _, err := exec(t, "version")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(out), "v") {
		t.Errorf("version = %q, err = %v", out, err)
	}
	out, _, err = exec(t, "help")
	if err != nil || !strings.Contains(out, "rpc-lag-probe run") {
		t.Errorf("help = %q, err = %v", out, err)
	}
}

func TestUnknownCommandFails(t *testing.T) {
	if _, _, err := exec(t, "frobnicate"); err == nil {
		t.Error("unknown command accepted")
	}
	if _, _, err := exec(t); err == nil {
		t.Error("empty invocation accepted")
	}
}

// The example config in the repository must actually validate: an example
// that does not run is worse than no example.
func TestValidateShippedExample(t *testing.T) {
	t.Setenv("PROVIDER_A_KEY", "example-key-aaaaaaaaaaaaaaaaaaaaaa")
	t.Setenv("PROVIDER_B_KEY", "example-key-bbbb")
	t.Setenv("RPC_LAG_PROBE_WEBHOOK_URL", "https://hooks.example/probe")

	out, _, err := exec(t, "validate", "--config", filepath.Join("examples", "endpoints.yaml"))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	for _, want := range []string{"config OK", "endpoints          5 across 2 chain(s)", "provider-a-eth", "values redacted"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// Nothing secret-shaped may reach stdout.
	for _, secret := range []string{"example-key-aaaaaaaaaaaaaaaaaaaaaa", "example-key-bbbb"} {
		if strings.Contains(out, secret) {
			t.Errorf("validate leaked a credential into its output:\n%s", out)
		}
	}
}

func TestValidateRejectsUnsetVariables(t *testing.T) {
	// No environment variables are set here, so expansion must fail loudly
	// rather than probing a URL with a literal ${PLACEHOLDER} in it.
	_, _, err := exec(t, "validate", "--config", filepath.Join("examples", "endpoints.yaml"))
	if err == nil {
		t.Fatal("validate accepted a config with unset variables")
	}
	if !strings.Contains(err.Error(), "PROVIDER_A_KEY") {
		t.Errorf("error does not name the missing variable: %v", err)
	}
}

func TestValidateRequiresConfigFlag(t *testing.T) {
	if _, _, err := exec(t, "validate"); err == nil {
		t.Error("validate ran without --config")
	}
}

func TestReportMarkdownFromFixture(t *testing.T) {
	out, _, err := exec(t, "report", "--evidence", filepath.Join("testdata", "sample-evidence.jsonl"),
		"--lag-blocks", "2", "--customer", "Example Labs")
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	for _, want := range []string{
		"# RPC endpoint lag and divergence audit — Example Labs",
		"provider-c",
		"## Incidents",
		"## Hash divergence",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestReportJSONIsMachineReadable(t *testing.T) {
	out, _, err := exec(t, "report", "--evidence", filepath.Join("testdata", "sample-evidence.jsonl"), "--format", "json")
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	var got struct {
		Endpoints []struct {
			Endpoint     string  `json:"endpoint"`
			Availability float64 `json:"availability"`
		} `json:"endpoints"`
		Incidents   []map[string]any `json:"incidents"`
		Divergences []map[string]any `json:"divergences"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(got.Endpoints) != 3 || len(got.Divergences) != 1 {
		t.Errorf("unexpected shape: %d endpoints, %d divergences", len(got.Endpoints), len(got.Divergences))
	}
}

func TestReportWritesToFile(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "audit.md")
	_, stderr, err := exec(t, "report", "--evidence", filepath.Join("testdata", "sample-evidence.jsonl"), "--out", dst)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if !strings.Contains(stderr, "wrote "+dst) {
		t.Errorf("stderr = %q", stderr)
	}
	body, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 500 {
		t.Errorf("report file is suspiciously short (%d bytes)", len(body))
	}
}

func TestReportRejectsUnknownFormat(t *testing.T) {
	if _, _, err := exec(t, "report", "--evidence", filepath.Join("testdata", "sample-evidence.jsonl"), "--format", "powerpoint"); err == nil {
		t.Error("unknown format accepted")
	}
}

func TestReportMissingFileFails(t *testing.T) {
	if _, _, err := exec(t, "report", "--evidence", filepath.Join(t.TempDir(), "nope.jsonl")); err == nil {
		t.Error("missing evidence file accepted")
	}
}

// End to end: two local fake nodes, one measurement round, JSON on stdout and
// an evidence log on disk that the report command can then consume.
func TestRunOnceAgainstFakeNodes(t *testing.T) {
	node := func(height uint64) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Method string `json:"method"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":"0x%x"}`, height)
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}

	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "probe.jsonl")
	cfgPath := filepath.Join(dir, "probe.yaml")
	cfg := fmt.Sprintf(`
region: test-local
interval: 1s
timeout: 500ms
finality_depth: 64
evidence_log: %s
endpoints:
  - name: leader
    url: %s
    chain: ethereum
  - name: laggard
    url: %s
    chain: ethereum
`, evidencePath, node(20000000), node(19999995))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := exec(t, "run", "--config", cfgPath, "--once", "--log-level", "error")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var got struct {
		Lags []struct {
			Endpoint  string `json:"endpoint"`
			LagBlocks uint64 `json:"lag_blocks"`
			Leader    bool   `json:"leader"`
		} `json:"lags"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if len(got.Lags) != 2 {
		t.Fatalf("lags = %d, want 2", len(got.Lags))
	}
	for _, l := range got.Lags {
		switch l.Endpoint {
		case "leader":
			if !l.Leader || l.LagBlocks != 0 {
				t.Errorf("leader scored wrong: %+v", l)
			}
		case "laggard":
			if l.LagBlocks != 5 {
				t.Errorf("laggard lag = %d, want 5", l.LagBlocks)
			}
		}
	}

	if _, err := os.Stat(evidencePath); err != nil {
		t.Fatalf("no evidence log written: %v", err)
	}
	reportOut, _, err := exec(t, "report", "--evidence", evidencePath, "--lag-blocks", "3", "--min-samples", "1")
	if err != nil {
		t.Fatalf("report on freshly written evidence: %v", err)
	}
	if !strings.Contains(reportOut, "laggard") {
		t.Errorf("the report does not mention the laggard:\n%s", reportOut)
	}
}

func TestRunRequiresConfig(t *testing.T) {
	if _, _, err := exec(t, "run"); err == nil {
		t.Error("run started without --config")
	}
}
