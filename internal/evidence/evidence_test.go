package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/rpc-lag-probe/internal/analysis"
)

var t0 = time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)

func TestWriteAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "probe.jsonl")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	lag := analysis.Lag{
		HeadSample: analysis.HeadSample{
			At: t0, Endpoint: "provider-a", Provider: "a", Region: "eu-central-1",
			Chain: "ethereum", Height: 20000000, Latency: 120 * time.Millisecond, ErrClass: "ok",
		},
		LagBlocks: 2, LagSeconds: 24, BestHeight: 20000002,
	}
	ev := analysis.DivergenceEvent{
		DetectedAt: t0.Add(time.Minute), Chain: "ethereum", Height: 19999936,
		Clusters: []analysis.HashCluster{
			{Hash: "0xaaa", Endpoints: []string{"provider-a"}, Raw: []byte(`{"hash":"0xaaa"}`)},
			{Hash: "0xbbb", Endpoints: []string{"provider-b"}},
		},
		MajorityHash: "", Minority: []string{"provider-a", "provider-b"},
	}
	if err := w.Write(Record{Type: TypeRunStarted, Region: "eu-central-1", Message: "start"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Write(Record{TS: t0, Type: TypeLag, Region: "eu-central-1", Chain: "ethereum", Lag: &lag}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Write(Record{TS: t0.Add(time.Minute), Type: TypeDivergence, Chain: "ethereum", Divergence: &ev}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	b, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(b.Lags) != 1 {
		t.Fatalf("lags = %d, want 1", len(b.Lags))
	}
	got := b.Lags[0]
	if got.Endpoint != "provider-a" || got.LagBlocks != 2 || got.LagSeconds != 24 {
		t.Errorf("lag round trip lost data: %+v", got)
	}
	if got.Latency != 120*time.Millisecond {
		t.Errorf("latency = %s, want 120ms", got.Latency)
	}
	if len(b.Divergences) != 1 || len(b.Divergences[0].Clusters) != 2 {
		t.Fatalf("divergences = %+v", b.Divergences)
	}
	if string(b.Divergences[0].Clusters[0].Raw) != `{"hash":"0xaaa"}` {
		t.Errorf("raw payload lost: %s", b.Divergences[0].Clusters[0].Raw)
	}
	if len(b.Runs) != 1 {
		t.Errorf("run records = %d, want 1", len(b.Runs))
	}
	if b.First.IsZero() || !b.Last.After(b.First) {
		t.Errorf("window = %s .. %s", b.First, b.Last)
	}
	if len(b.Regions) != 1 || b.Regions[0] != "eu-central-1" {
		t.Errorf("regions = %v", b.Regions)
	}
	if len(b.Chains) != 1 || b.Chains[0] != "ethereum" {
		t.Errorf("chains = %v", b.Chains)
	}
}

// The log is evidence: reopening it must never truncate what is already there.
func TestOpenAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe.jsonl")
	for i := 0; i < 3; i++ {
		w, err := Open(path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if err := w.Write(Record{TS: t0.Add(time.Duration(i) * time.Second), Type: TypeRunStarted}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close %d: %v", i, err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.TrimSpace(string(raw)), "\n") + 1; n != 3 {
		t.Errorf("log has %d lines after three runs, want 3", n)
	}
}

func TestWriteStampsMissingTimestamps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe.jsonl")
	w, _ := Open(path)
	if err := w.Write(Record{Type: TypeAlert, Message: "hi"}); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Alerts) != 1 || b.Alerts[0].TS.IsZero() {
		t.Errorf("alert record has no timestamp: %+v", b.Alerts)
	}
}

func TestParseCountsMalformedLinesInsteadOfFailing(t *testing.T) {
	src := strings.Join([]string{
		`{"ts":"2026-07-20T09:00:00Z","type":"run_started"}`,
		``,
		`this is not json`,
		`{"ts":"2026-07-20T09:00:02Z","type":"lag","lag":{"endpoint":"a","height":10,"err_class":"ok"}}`,
		`{"ts":"2026-07-20T09:00:04Z","type":"something_new_from_a_newer_probe"}`,
	}, "\n")
	b, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if b.Malformed != 1 {
		t.Errorf("malformed = %d, want 1", b.Malformed)
	}
	if len(b.Lags) != 1 {
		t.Errorf("lags = %d, want 1", len(b.Lags))
	}
	if b.Lags[0].At.IsZero() {
		t.Error("lag timestamp should fall back to the record timestamp")
	}
}

func TestLoadSampleFixture(t *testing.T) {
	b, err := Load(filepath.Join("..", "..", "testdata", "sample-evidence.jsonl"))
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	if b.Malformed != 0 {
		t.Errorf("fixture has %d malformed lines", b.Malformed)
	}
	if len(b.Lags) != 180 {
		t.Errorf("fixture lags = %d, want 180", len(b.Lags))
	}
	if len(b.Divergences) != 1 {
		t.Errorf("fixture divergences = %d, want 1", len(b.Divergences))
	}
	if len(b.Regions) != 3 {
		t.Errorf("fixture regions = %v, want three vantage points", b.Regions)
	}
}
