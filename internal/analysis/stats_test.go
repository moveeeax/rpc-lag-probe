package analysis

import (
	"math"
	"testing"
	"time"
)

func TestPercentileNearestRank(t *testing.T) {
	values := []float64{5, 1, 4, 2, 3, 10, 9, 8, 7, 6}
	tests := map[float64]float64{
		0.5:  5,
		0.9:  9,
		0.99: 10,
		1.0:  10,
		0.1:  1,
	}
	for p, want := range tests {
		if got := Percentile(values, p); got != want {
			t.Errorf("Percentile(p=%.2f) = %v, want %v", p, got, want)
		}
	}
	if got := Percentile(nil, 0.99); got != 0 {
		t.Errorf("empty percentile = %v, want 0", got)
	}
	if got := Percentile([]float64{42}, 0.5); got != 42 {
		t.Errorf("single-value percentile = %v, want 42", got)
	}
}

func TestPercentileDoesNotMutateInput(t *testing.T) {
	values := []float64{3, 1, 2}
	Percentile(values, 0.5)
	if values[0] != 3 || values[1] != 1 || values[2] != 2 {
		t.Errorf("input was reordered: %v", values)
	}
}

func TestAggregatorSummary(t *testing.T) {
	agg := NewAggregator(2)
	for i := 0; i < 10; i++ {
		l := Lag{HeadSample: HeadSample{
			At: at(i), Endpoint: "slow", Provider: "p", Region: "eu-central-1", Chain: "ethereum",
			Height: 100, Latency: time.Duration(i+1) * 100 * time.Millisecond, ErrClass: "ok",
		}, LagBlocks: uint64(i), LagSeconds: float64(i) * 1.5, BestHeight: 100 + uint64(i), Leader: i == 0}
		agg.Add(l)
	}
	// Two failures, one of them rate limited.
	agg.Add(Lag{HeadSample: HeadSample{At: at(10), Endpoint: "slow", Region: "eu-central-1", Chain: "ethereum", ErrClass: "rate_limited", Latency: 50 * time.Millisecond}})
	agg.Add(Lag{HeadSample: HeadSample{At: at(11), Endpoint: "slow", Region: "eu-central-1", Chain: "ethereum", ErrClass: "timeout"}})

	sums := agg.Summaries()
	if len(sums) != 1 {
		t.Fatalf("summaries = %d, want 1", len(sums))
	}
	s := sums[0]
	if s.Samples != 12 || s.OK != 10 {
		t.Errorf("samples/ok = %d/%d, want 12/10", s.Samples, s.OK)
	}
	if math.Abs(s.Availability-10.0/12.0) > 1e-9 {
		t.Errorf("availability = %v", s.Availability)
	}
	if s.Errors["rate_limited"] != 1 || s.Errors["timeout"] != 1 {
		t.Errorf("errors = %v", s.Errors)
	}
	if s.LagBlocksMax != 9 {
		t.Errorf("max lag blocks = %d, want 9", s.LagBlocksMax)
	}
	if s.LagBlocksP50 != 4 {
		t.Errorf("lag blocks p50 = %v, want 4", s.LagBlocksP50)
	}
	// Lag >= 2 blocks happened on 8 of the 10 healthy polls.
	if math.Abs(s.StaleShare-0.8) > 1e-9 {
		t.Errorf("stale share = %v, want 0.8", s.StaleShare)
	}
	// It reported height 100 while the leader climbed away: never a leader
	// except on the very first tick.
	if math.Abs(s.LeaderShare-0.1) > 1e-9 {
		t.Errorf("leader share = %v, want 0.1", s.LeaderShare)
	}
	if s.LatencyMax != time.Second {
		t.Errorf("max latency = %s, want 1s", s.LatencyMax)
	}
	if !s.First.Equal(at(0)) || !s.Last.Equal(at(11)) {
		t.Errorf("window = %s .. %s", s.First, s.Last)
	}
}

func TestAggregatorSortsByChainThenEndpoint(t *testing.T) {
	agg := NewAggregator(1)
	for _, spec := range []struct{ endpoint, chain string }{
		{"z", "base"}, {"a", "ethereum"}, {"b", "base"},
	} {
		agg.Add(Lag{HeadSample: HeadSample{At: at(0), Endpoint: spec.endpoint, Chain: spec.chain, ErrClass: "ok"}})
	}
	got := agg.Summaries()
	want := []string{"b", "z", "a"}
	for i, w := range want {
		if got[i].Endpoint != w {
			t.Fatalf("order = %s..., want %v", got[i].Endpoint, want)
		}
	}
}
