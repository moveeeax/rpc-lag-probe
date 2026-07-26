package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/rpc-lag-probe/internal/analysis"
)

func lag(endpoint string, height, blocks uint64, secs float64, latency time.Duration, class string) analysis.Lag {
	return analysis.Lag{
		HeadSample: analysis.HeadSample{
			At: time.Now(), Endpoint: endpoint, Provider: "prov", Region: "eu-central-1",
			Chain: "ethereum", Height: height, Latency: latency, ErrClass: class,
		},
		LagBlocks: blocks, LagSeconds: secs,
	}
}

func TestExpositionContainsEverySeries(t *testing.T) {
	r := New("v1.2.3")
	r.ObserveLag(lag("provider-a", 20000000, 0, 0, 45*time.Millisecond, "ok"))
	r.ObserveLag(lag("provider-b", 19999997, 3, 36, 320*time.Millisecond, "ok"))
	r.ObserveDivergence("ethereum")

	out := r.String()
	want := []string{
		`rpc_probe_build_info{version="v1.2.3"} 1`,
		`rpc_probe_up{endpoint="provider-a",provider="prov",region="eu-central-1",chain="ethereum"} 1`,
		`rpc_probe_head_block{endpoint="provider-b",provider="prov",region="eu-central-1",chain="ethereum"} 19999997`,
		`rpc_probe_lag_blocks{endpoint="provider-b",provider="prov",region="eu-central-1",chain="ethereum"} 3`,
		`rpc_probe_lag_seconds{endpoint="provider-b",provider="prov",region="eu-central-1",chain="ethereum"} 36`,
		`rpc_probe_divergence_events_total{chain="ethereum"} 1`,
		"# TYPE rpc_probe_request_duration_seconds histogram",
		"# TYPE rpc_probe_requests_total counter",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("exposition is missing:\n  %s\ngot:\n%s", w, out)
		}
	}
}

func TestHistogramBucketsAreCumulative(t *testing.T) {
	r := New("test")
	for _, d := range []time.Duration{5 * time.Millisecond, 30 * time.Millisecond, 300 * time.Millisecond, 4 * time.Second} {
		r.ObserveLag(lag("e", 1, 0, 0, d, "ok"))
	}
	out := r.String()

	checks := map[string]string{
		`le="0.01"`: " 1\n",
		`le="0.05"`: " 2\n",
		`le="0.5"`:  " 3\n",
		`le="5"`:    " 4\n",
		`le="+Inf"`: " 4\n",
	}
	for le, wantSuffix := range checks {
		line := findLine(out, le)
		if line == "" {
			t.Fatalf("no bucket line for %s in:\n%s", le, out)
		}
		if !strings.HasSuffix(line+"\n", wantSuffix) {
			t.Errorf("bucket %s = %q, want it to end with %q", le, line, strings.TrimSpace(wantSuffix))
		}
	}
	if !strings.Contains(out, "rpc_probe_request_duration_seconds_count{endpoint=\"e\",provider=\"prov\",region=\"eu-central-1\",chain=\"ethereum\"} 4") {
		t.Errorf("histogram count wrong:\n%s", out)
	}
}

func findLine(out, needle string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, needle) {
			return l
		}
	}
	return ""
}

func TestFailedPollMarksEndpointDown(t *testing.T) {
	r := New("test")
	r.ObserveLag(lag("e", 20000000, 0, 0, 40*time.Millisecond, "ok"))
	r.ObserveLag(lag("e", 0, 0, 0, 10*time.Millisecond, "rate_limited"))
	out := r.String()

	if !strings.Contains(out, `rpc_probe_up{endpoint="e",provider="prov",region="eu-central-1",chain="ethereum"} 0`) {
		t.Errorf("endpoint not marked down:\n%s", out)
	}
	if !strings.Contains(out, `rpc_probe_rate_limited_total{endpoint="e",provider="prov",region="eu-central-1",chain="ethereum"} 1`) {
		t.Errorf("429 not counted:\n%s", out)
	}
	if !strings.Contains(out, `class="rate_limited"} 1`) || !strings.Contains(out, `class="ok"} 1`) {
		t.Errorf("request classes not counted:\n%s", out)
	}
	// The last good height must survive a failed poll, otherwise a dashboard
	// shows head 0 every time an endpoint hiccups.
	if !strings.Contains(out, `rpc_probe_head_block{endpoint="e",provider="prov",region="eu-central-1",chain="ethereum"} 20000000`) {
		t.Errorf("last known head was clobbered by a failure:\n%s", out)
	}
}

func TestLabelValuesAreEscapedExactlyOnce(t *testing.T) {
	r := New("test")
	l := lag(`weird"name\`, 1, 0, 0, time.Millisecond, "ok")
	r.ObserveLag(l)
	out := r.String()
	if !strings.Contains(out, `endpoint="weird\"name\\"`) {
		t.Errorf("label escaping wrong:\n%s", out)
	}
}

func TestZeroStateIsStillValid(t *testing.T) {
	out := New("test").String()
	if !strings.Contains(out, `rpc_probe_divergence_events_total{chain="none"} 0`) {
		t.Errorf("empty registry should still expose a divergence counter:\n%s", out)
	}
}

func TestHandlerServesTextFormat(t *testing.T) {
	r := New("test")
	r.ObserveLag(lag("e", 1, 0, 0, time.Millisecond, "ok"))

	srv := httptest.NewServer(r.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type = %q", ct)
	}
}
