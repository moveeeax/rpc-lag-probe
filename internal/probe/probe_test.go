package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moveeeax/rpc-lag-probe/internal/alert"
	"github.com/moveeeax/rpc-lag-probe/internal/analysis"
	"github.com/moveeeax/rpc-lag-probe/internal/config"
	"github.com/moveeeax/rpc-lag-probe/internal/evidence"
	"github.com/moveeeax/rpc-lag-probe/internal/metrics"
	"github.com/moveeeax/rpc-lag-probe/internal/rpc"
)

// fakeNode is a stand-in RPC endpoint whose head height and block hashes the
// test controls. It is the only way to exercise divergence without a paid
// provider and a lucky day.
type fakeNode struct {
	mu     sync.Mutex
	height uint64
	// hashSuffix distinguishes this node's block hashes from its peers'.
	hashSuffix string
	status     int
	delay      time.Duration
	calls      int
}

func newNode(height uint64, hashSuffix string) *fakeNode {
	return &fakeNode{height: height, hashSuffix: hashSuffix, status: http.StatusOK}
}

func (n *fakeNode) setHeight(h uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.height = h
}

func (n *fakeNode) server(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		height, suffix, status, delay := n.height, n.hashSuffix, n.status, n.delay
		n.calls++
		n.mu.Unlock()

		if delay > 0 {
			time.Sleep(delay)
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":"nope"}`)
			return
		}
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		switch req.Method {
		case "eth_blockNumber":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":"0x%x"}`, height)
		case "eth_getBlockByNumber":
			want, _ := rpc.ParseHexUint(req.Params[0].(string))
			if want > height {
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":null}`)
				return
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"number":"0x%x","hash":"0x%064x%s","parentHash":"0x00","timestamp":"0x66000000"}}`,
				want, want, suffix)
		default:
			http.Error(w, "unsupported method", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

type capturingNotifier struct {
	mu     sync.Mutex
	alerts []alert.Alert
}

func (c *capturingNotifier) Notify(_ context.Context, a alert.Alert) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alerts = append(c.alerts, a)
	return nil
}

func (c *capturingNotifier) snapshot() []alert.Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]alert.Alert(nil), c.alerts...)
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func testConfig(urls map[string]string) *config.Config {
	cfg := &config.Config{
		Region:            "eu-central-1",
		Interval:          50 * time.Millisecond,
		Timeout:           50 * time.Millisecond,
		FinalityDepth:     10,
		HashCheckInterval: 50 * time.Millisecond,
		Alerts:            config.Alerts{LagBlocks: 3, Cooldown: time.Hour, OnDivergence: true},
	}
	names := []string{"node-a", "node-b", "node-c"}
	for _, n := range names {
		if u, ok := urls[n]; ok {
			cfg.Endpoints = append(cfg.Endpoints, config.Endpoint{
				Name: n, URL: u, Chain: config.ChainEthereum, Region: "eu-central-1", Provider: n,
			})
		}
	}
	return cfg
}

func mustProbe(t *testing.T, cfg *config.Config, opts ...Option) *Probe {
	t.Helper()
	p, err := New(cfg, opts...)
	if err != nil {
		t.Fatalf("new probe: %v", err)
	}
	return p
}

func lagsByName(lags []analysis.Lag) map[string]analysis.Lag {
	m := make(map[string]analysis.Lag, len(lags))
	for _, l := range lags {
		m[l.Endpoint] = l
	}
	return m
}

func TestTickScoresLagAgainstTheFastestPeer(t *testing.T) {
	a, b, c := newNode(20000000, "aa"), newNode(19999996, "aa"), newNode(19999999, "aa")
	cfg := testConfig(map[string]string{"node-a": a.server(t), "node-b": b.server(t), "node-c": c.server(t)})

	reg := metrics.New("test")
	p, err := New(cfg, WithMetrics(reg), WithLogger(quietLogger()))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	res := p.Tick(context.Background(), time.Now())
	got := lagsByName(res.Lags)

	if len(got) != 3 {
		t.Fatalf("samples = %d, want 3", len(got))
	}
	if !got["node-a"].Leader || got["node-a"].LagBlocks != 0 {
		t.Errorf("node-a should lead: %+v", got["node-a"])
	}
	if got["node-b"].LagBlocks != 4 {
		t.Errorf("node-b lag = %d, want 4", got["node-b"].LagBlocks)
	}
	if got["node-c"].LagBlocks != 1 {
		t.Errorf("node-c lag = %d, want 1", got["node-c"].LagBlocks)
	}
	for name, l := range got {
		if l.Latency <= 0 {
			t.Errorf("%s: latency not measured", name)
		}
		if l.Region != "eu-central-1" || l.Chain != "ethereum" {
			t.Errorf("%s: missing provenance: %+v", name, l)
		}
	}
	if !strings.Contains(reg.String(), `rpc_probe_lag_blocks{endpoint="node-b",provider="node-b",region="eu-central-1",chain="ethereum"} 4`) {
		t.Errorf("metrics did not record the lag:\n%s", reg.String())
	}
}

func TestTickDetectsHashDivergenceAtAFinalisedHeight(t *testing.T) {
	// node-c serves a different hash for every block. All three are at the
	// same head, so nothing but the hash comparison can catch it.
	a, b, c := newNode(20000000, "aa"), newNode(20000000, "aa"), newNode(20000000, "cc")
	cfg := testConfig(map[string]string{"node-a": a.server(t), "node-b": b.server(t), "node-c": c.server(t)})

	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	w, err := evidence.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	notifier := &capturingNotifier{}
	reg := metrics.New("test")
	p, err := New(cfg, WithEvidence(w), WithMetrics(reg), WithNotifier(notifier), WithLogger(quietLogger()))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	res := p.Tick(context.Background(), time.Now())
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if len(res.Divergences) != 1 {
		t.Fatalf("divergences = %d, want 1", len(res.Divergences))
	}
	ev := res.Divergences[0]
	if ev.Height != 20000000-10 {
		t.Errorf("compared at height %d, want head minus the finality depth", ev.Height)
	}
	if len(ev.Clusters) != 2 {
		t.Fatalf("clusters = %+v", ev.Clusters)
	}
	if len(ev.Clusters[0].Endpoints) != 2 || ev.MajorityHash == "" {
		t.Errorf("majority not identified: %+v", ev)
	}
	if len(ev.Minority) != 1 || ev.Minority[0] != "node-c" {
		t.Errorf("minority = %v, want [node-c]", ev.Minority)
	}
	if len(ev.Clusters[1].Raw) == 0 {
		t.Error("the divergent payload was not captured as evidence")
	}

	bundle, err := evidence.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Divergences) != 1 {
		t.Fatalf("evidence log has %d divergence records, want 1", len(bundle.Divergences))
	}
	if len(bundle.Lags) != 3 {
		t.Errorf("evidence log has %d lag records, want 3", len(bundle.Lags))
	}
	if !strings.Contains(reg.String(), `rpc_probe_divergence_events_total{chain="ethereum"} 1`) {
		t.Error("divergence counter not incremented")
	}

	var found bool
	for _, a := range notifier.snapshot() {
		if a.Kind == analysis.KindDivergence && a.Severity == alert.SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("no critical divergence alert was sent: %+v", notifier.snapshot())
	}
}

func TestTickDoesNotReportDivergenceWhenNodesAgree(t *testing.T) {
	a, b := newNode(20000000, "aa"), newNode(19999998, "aa")
	cfg := testConfig(map[string]string{"node-a": a.server(t), "node-b": b.server(t)})
	p := mustProbe(t, cfg, WithLogger(quietLogger()))

	res := p.Tick(context.Background(), time.Now())
	if len(res.Divergences) != 0 {
		t.Fatalf("agreeing nodes reported a divergence: %+v", res.Divergences)
	}
}

// A trailing endpoint that has not yet reached the finalised height answers
// null. That is a miss, not a disagreement.
func TestTickTreatsMissingBlockAsUnanswered(t *testing.T) {
	a, b := newNode(20000000, "aa"), newNode(19999985, "aa")
	cfg := testConfig(map[string]string{"node-a": a.server(t), "node-b": b.server(t)})
	p := mustProbe(t, cfg, WithLogger(quietLogger()))

	res := p.Tick(context.Background(), time.Now())
	if len(res.Divergences) != 0 {
		t.Fatalf("a node that has not reached the height was reported as divergent: %+v", res.Divergences)
	}
}

func TestHashCheckIsRateLimited(t *testing.T) {
	a, b := newNode(20000000, "aa"), newNode(20000000, "bb")
	cfg := testConfig(map[string]string{"node-a": a.server(t), "node-b": b.server(t)})
	cfg.HashCheckInterval = time.Hour
	p := mustProbe(t, cfg, WithLogger(quietLogger()))

	now := time.Now()
	if res := p.Tick(context.Background(), now); len(res.Divergences) != 1 {
		t.Fatalf("first tick should compare hashes: %+v", res.Divergences)
	}
	if res := p.Tick(context.Background(), now.Add(time.Second)); len(res.Divergences) != 0 {
		t.Fatalf("hashes compared again inside the interval, burning paid quota: %+v", res.Divergences)
	}
}

// Even once the interval has elapsed, the same finalised height must not be
// compared twice: that would double-count a single divergence.
func TestHashCheckSkipsAlreadyComparedHeight(t *testing.T) {
	a, b := newNode(20000000, "aa"), newNode(20000000, "bb")
	cfg := testConfig(map[string]string{"node-a": a.server(t), "node-b": b.server(t)})
	cfg.HashCheckInterval = cfg.Interval
	p := mustProbe(t, cfg, WithLogger(quietLogger()))

	now := time.Now()
	if res := p.Tick(context.Background(), now); len(res.Divergences) != 1 {
		t.Fatal("first tick should compare hashes")
	}
	if res := p.Tick(context.Background(), now.Add(time.Second)); len(res.Divergences) != 0 {
		t.Fatalf("the same height was compared twice: %+v", res.Divergences)
	}
	a.setHeight(20000001)
	b.setHeight(20000001)
	if res := p.Tick(context.Background(), now.Add(2*time.Second)); len(res.Divergences) != 1 {
		t.Fatal("a new finalised height should be compared")
	}
}

func TestFailedEndpointIsRecordedNotFatal(t *testing.T) {
	a := newNode(20000000, "aa")
	broken := newNode(20000000, "aa")
	broken.status = http.StatusTooManyRequests
	cfg := testConfig(map[string]string{"node-a": a.server(t), "node-b": broken.server(t)})

	notifier := &capturingNotifier{}
	p := mustProbe(t, cfg, WithNotifier(notifier), WithLogger(quietLogger()))
	got := lagsByName(p.Tick(context.Background(), time.Now()).Lags)

	if got["node-b"].ErrClass != "rate_limited" {
		t.Errorf("node-b class = %q, want rate_limited", got["node-b"].ErrClass)
	}
	if got["node-b"].Status != http.StatusTooManyRequests {
		t.Errorf("HTTP status not recorded: %d", got["node-b"].Status)
	}
	if !got["node-a"].Leader {
		t.Error("the healthy endpoint should still be scored")
	}
	var sawUnavailable bool
	for _, a := range notifier.snapshot() {
		if a.Kind == analysis.KindUnavailable && a.Endpoint == "node-b" {
			sawUnavailable = true
		}
	}
	if !sawUnavailable {
		t.Errorf("no unavailability alert: %+v", notifier.snapshot())
	}
}

func TestLagAlertRespectsCooldown(t *testing.T) {
	a, b := newNode(20000000, "aa"), newNode(19999990, "aa")
	cfg := testConfig(map[string]string{"node-a": a.server(t), "node-b": b.server(t)})
	notifier := &capturingNotifier{}
	p := mustProbe(t, cfg, WithNotifier(notifier), WithLogger(quietLogger()))

	now := time.Now()
	for i := 0; i < 4; i++ {
		p.Tick(context.Background(), now.Add(time.Duration(i)*time.Second))
	}
	lagAlerts := 0
	for _, al := range notifier.snapshot() {
		if al.Kind == analysis.KindLag {
			lagAlerts++
		}
	}
	if lagAlerts != 1 {
		t.Errorf("sent %d lag alerts across four ticks, want 1 (cooldown is an hour)", lagAlerts)
	}
}

func TestRunWritesEvidenceAndStops(t *testing.T) {
	a, b := newNode(20000000, "aa"), newNode(19999999, "aa")
	cfg := testConfig(map[string]string{"node-a": a.server(t), "node-b": b.server(t)})

	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	w, err := evidence.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p := mustProbe(t, cfg, WithEvidence(w), WithLogger(quietLogger()))

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	bundle, err := evidence.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Runs) != 2 {
		t.Errorf("run markers = %d, want a start and a finish", len(bundle.Runs))
	}
	if len(bundle.Lags) < 4 {
		t.Errorf("only %d lag records after ~3 ticks of two endpoints", len(bundle.Lags))
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("nil config accepted")
	}
	if _, err := New(&config.Config{}); err == nil {
		t.Error("empty config accepted")
	}
}
