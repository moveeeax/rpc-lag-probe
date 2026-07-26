package report

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/rpc-lag-probe/internal/analysis"
	"github.com/moveeeax/rpc-lag-probe/internal/evidence"

	"gopkg.in/yaml.v3"
)

const fixture = "../../testdata/sample-evidence.jsonl"

func loadFixture(t *testing.T) *evidence.Bundle {
	t.Helper()
	b, err := evidence.Load(filepath.Clean(fixture))
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	return b
}

func defaultOptions() Options {
	return Options{
		Rules: analysis.IncidentRules{LagBlocks: 2, MinSamples: 2},
		Now:   time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC),
	}
}

func TestAnalyseFixture(t *testing.T) {
	res := Analyse(loadFixture(t), defaultOptions())

	if len(res.Summaries) != 3 {
		t.Fatalf("summaries = %d, want 3", len(res.Summaries))
	}
	byName := map[string]analysis.EndpointSummary{}
	for _, s := range res.Summaries {
		byName[s.Endpoint] = s
	}

	a := byName["provider-a"]
	if a.Availability != 1 || a.LagBlocksMax != 0 || a.LeaderShare != 1 {
		t.Errorf("provider-a should be clean and always leading: %+v", a)
	}
	c := byName["provider-c"]
	if c.LagBlocksMax != 6 {
		t.Errorf("provider-c max lag = %d blocks, want 6", c.LagBlocksMax)
	}
	if c.LagSecondsMax != 62 {
		t.Errorf("provider-c max lag = %vs, want 62", c.LagSecondsMax)
	}
	if c.Errors["rate_limited"] != 3 {
		t.Errorf("provider-c rate limits = %d, want 3", c.Errors["rate_limited"])
	}
	if c.Availability >= 1 {
		t.Errorf("provider-c availability = %v, want below 1", c.Availability)
	}
	if c.Region != "ap-southeast-1" {
		t.Errorf("provider-c region = %q", c.Region)
	}

	kinds := map[string]int{}
	for _, in := range res.Incidents {
		kinds[in.Kind]++
	}
	if kinds[analysis.KindLag] != 1 {
		t.Errorf("lag incidents = %d, want 1", kinds[analysis.KindLag])
	}
	if kinds[analysis.KindUnavailable] != 1 {
		t.Errorf("unavailable incidents = %d, want 1", kinds[analysis.KindUnavailable])
	}
	if kinds[analysis.KindDivergence] != 1 {
		t.Errorf("divergence incidents = %d, want 1", kinds[analysis.KindDivergence])
	}
}

func TestMarkdownContainsTheDeliverable(t *testing.T) {
	out := Markdown(loadFixture(t), Options{
		Customer: "Example Labs",
		Rules:    analysis.IncidentRules{LagBlocks: 2, MinSamples: 2},
		Now:      time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC),
	})

	want := []string{
		"# RPC endpoint lag and divergence audit — Example Labs",
		"| Measurement window | 2026-07-20T09:00:00Z → 2026-07-20T09:01:58Z",
		"| Vantage points | ap-southeast-1, eu-central-1, us-east-1 |",
		"## Findings",
		"## Lag and availability by endpoint",
		"### Errors by class",
		"## Incidents",
		"## Hash divergence",
		"## Method",
		"provider-c",
		"19999942",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("report is missing %q", w)
		}
	}
	// Every divergence cluster hash must appear in full: a truncated hash is
	// not something a customer can take to their provider.
	if !strings.Contains(out, "0x9a17be44c2d0e5f68713b9c0a4d2e6f8091a2b3c4d5e6f708192a3b4c5d6e7f80") {
		t.Error("the minority hash is not printed in full")
	}
}

func TestMarkdownOnEmptyEvidence(t *testing.T) {
	out := Markdown(&evidence.Bundle{}, defaultOptions())
	for _, w := range []string{"no samples", "_No samples._", "_No incident crossed", "_No two endpoints reported"} {
		if !strings.Contains(out, w) {
			t.Errorf("empty report is missing %q:\n%s", w, out)
		}
	}
}

func TestMarkdownSaysSoWhenNothingWasFound(t *testing.T) {
	b := &evidence.Bundle{
		First: time.Now().Add(-time.Hour), Last: time.Now(),
		Lags: []analysis.Lag{
			{HeadSample: analysis.HeadSample{At: time.Now(), Endpoint: "a", Chain: "ethereum", Region: "eu", ErrClass: "ok", Height: 10, Latency: time.Millisecond}, Leader: true},
			{HeadSample: analysis.HeadSample{At: time.Now(), Endpoint: "b", Chain: "ethereum", Region: "eu", ErrClass: "ok", Height: 10, Latency: time.Millisecond}, Leader: true},
		},
	}
	out := Markdown(b, defaultOptions())
	if !strings.Contains(out, "No endpoint breached the lag threshold") {
		t.Errorf("a clean window should say so plainly:\n%s", out)
	}
}

func TestTopIncidentsCap(t *testing.T) {
	opts := defaultOptions()
	opts.TopIncidents = 1
	out := Markdown(loadFixture(t), opts)
	if !strings.Contains(out, "further incident(s) omitted") {
		t.Error("the incident table was not capped")
	}
}

func TestERPCConfigIsDerivedFromMeasurement(t *testing.T) {
	res := Analyse(loadFixture(t), defaultOptions())
	out := ERPC(res)

	want := []string{
		"projects:",
		"  - id: main",
		"    upstreams:",
		"- id: provider-a",
		"endpoint: ${PROVIDER_A_URL}",
		"chainId: 1",
		"failsafe:",
		"timeout:",
		"retry:",
		"# Suggested Prometheus alert thresholds",
		"rpc_probe_divergence_events_total",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("eRPC config is missing %q:\n%s", w, out)
		}
	}
	// The best-measured endpoint must be listed first.
	if strings.Index(out, "- id: provider-a") > strings.Index(out, "- id: provider-c") {
		t.Error("upstreams are not ranked by measured quality")
	}
	// The flakiest endpoint gets the extra retry.
	cSection := out[strings.Index(out, "- id: provider-c"):]
	if !strings.Contains(cSection, "maxAttempts: 3") {
		t.Errorf("the unreliable endpoint did not get extra attempts:\n%s", cSection)
	}
}

// A config that does not parse is worse than no config, so the generated eRPC
// file is round-tripped through a YAML parser and inspected structurally.
func TestERPCConfigParsesAsYAML(t *testing.T) {
	out := ERPC(Analyse(loadFixture(t), defaultOptions()))

	var parsed struct {
		Projects []struct {
			ID        string `yaml:"id"`
			Upstreams []struct {
				ID       string `yaml:"id"`
				Endpoint string `yaml:"endpoint"`
				Type     string `yaml:"type"`
				EVM      struct {
					ChainID int `yaml:"chainId"`
				} `yaml:"evm"`
				Failsafe struct {
					Timeout struct {
						Duration string `yaml:"duration"`
					} `yaml:"timeout"`
					Retry struct {
						MaxAttempts int `yaml:"maxAttempts"`
					} `yaml:"retry"`
				} `yaml:"failsafe"`
			} `yaml:"upstreams"`
		} `yaml:"projects"`
	}
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("generated config is not valid YAML: %v\n%s", err, out)
	}
	if len(parsed.Projects) != 1 || len(parsed.Projects[0].Upstreams) != 3 {
		t.Fatalf("unexpected structure: %+v", parsed)
	}
	for _, u := range parsed.Projects[0].Upstreams {
		if u.Type != "evm" || u.EVM.ChainID != 1 {
			t.Errorf("upstream %s: type/chain wrong: %+v", u.ID, u)
		}
		if !strings.HasPrefix(u.Endpoint, "${") || !strings.HasSuffix(u.Endpoint, "_URL}") {
			t.Errorf("upstream %s endpoint is not a placeholder: %q", u.ID, u.Endpoint)
		}
		if u.Failsafe.Timeout.Duration == "" || u.Failsafe.Retry.MaxAttempts < 1 {
			t.Errorf("upstream %s has no usable failsafe: %+v", u.ID, u.Failsafe)
		}
	}
}

// The evidence log has no URLs in it by construction; the generated config
// must not invent any either.
func TestERPCNeverEmitsARealURL(t *testing.T) {
	out := ERPC(Analyse(loadFixture(t), defaultOptions()))
	for _, forbidden := range []string{"https://", "http://", "apikey", "api_key"} {
		if strings.Contains(strings.ToLower(out), forbidden) {
			t.Errorf("generated config contains %q:\n%s", forbidden, out)
		}
	}
}

func TestERPCWithNoEndpoints(t *testing.T) {
	out := ERPC(Analyse(&evidence.Bundle{}, defaultOptions()))
	if !strings.Contains(out, "no endpoints in the evidence log") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

func TestTimeoutAndHedgeDerivation(t *testing.T) {
	tight := analysis.EndpointSummary{LatencyP50: 40 * time.Millisecond, LatencyP90: 60 * time.Millisecond, LatencyP99: 70 * time.Millisecond}
	if got := timeoutFor(tight); got != "1s" {
		t.Errorf("timeout = %s, want the 1s floor", got)
	}
	if _, ok := hedgeFor(tight); ok {
		t.Error("a tight latency distribution should not get a hedge")
	}

	tail := analysis.EndpointSummary{LatencyP50: 100 * time.Millisecond, LatencyP90: 480 * time.Millisecond, LatencyP99: 900 * time.Millisecond}
	if got := timeoutFor(tail); got != "1.8s" {
		t.Errorf("timeout = %s, want twice the p99", got)
	}
	d, ok := hedgeFor(tail)
	if !ok || d != 500*time.Millisecond {
		t.Errorf("hedge = %s (%v), want 500ms rounded up from p90", d, ok)
	}

	slow := analysis.EndpointSummary{LatencyP50: 20 * time.Second, LatencyP90: 25 * time.Second, LatencyP99: 40 * time.Second}
	if got := timeoutFor(slow); got != "30s" {
		t.Errorf("timeout = %s, want the 30s ceiling", got)
	}
}

func TestSlugAndEnvName(t *testing.T) {
	if got := slug("Provider A / eth-mainnet"); got != "provider-a-eth-mainnet" {
		t.Errorf("slug = %q", got)
	}
	if got := envName("provider-a eth"); got != "PROVIDER_A_ETH" {
		t.Errorf("envName = %q", got)
	}
}
