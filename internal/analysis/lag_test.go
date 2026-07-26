package analysis

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)

func at(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

func sample(name string, height uint64, when time.Time) HeadSample {
	return HeadSample{At: when, Endpoint: name, Region: "eu-central-1", Chain: "ethereum", Height: height, ErrClass: "ok"}
}

func byName(lags []Lag) map[string]Lag {
	m := make(map[string]Lag, len(lags))
	for _, l := range lags {
		m[l.Endpoint] = l
	}
	return m
}

func TestComputeLagMeasuresAgainstFastestPeer(t *testing.T) {
	clock := NewHeightClock(100)
	samples := []HeadSample{
		sample("fast", 100, at(0)),
		sample("slow", 97, at(0)),
		sample("mid", 99, at(0)),
	}
	got := byName(ComputeLag(samples, at(0), clock))

	if !got["fast"].Leader || got["fast"].LagBlocks != 0 {
		t.Errorf("fast should be the leader with zero lag, got %+v", got["fast"])
	}
	if got["slow"].LagBlocks != 3 {
		t.Errorf("slow lag = %d blocks, want 3", got["slow"].LagBlocks)
	}
	if got["mid"].LagBlocks != 1 {
		t.Errorf("mid lag = %d blocks, want 1", got["mid"].LagBlocks)
	}
	for _, l := range got {
		if l.BestHeight != 100 {
			t.Errorf("%s: best height = %d, want 100", l.Endpoint, l.BestHeight)
		}
	}
}

// The seconds figure must come from what the probe itself saw, never from a
// provider-supplied block timestamp.
func TestComputeLagSecondsUsesObservedHeightTransitions(t *testing.T) {
	clock := NewHeightClock(100)
	// The network moves 100 -> 101 at t=0 and 101 -> 102 at t=12.
	ComputeLag([]HeadSample{sample("fast", 100, at(-12))}, at(-12), clock)
	ComputeLag([]HeadSample{sample("fast", 101, at(0))}, at(0), clock)
	ComputeLag([]HeadSample{sample("fast", 102, at(12))}, at(12), clock)

	// At t=30 an endpoint is still on 100: it went stale when 101 appeared, 30s ago.
	got := byName(ComputeLag([]HeadSample{
		sample("fast", 102, at(30)),
		sample("stuck", 100, at(30)),
	}, at(30), clock))

	if got["stuck"].LagBlocks != 2 {
		t.Fatalf("lag blocks = %d, want 2", got["stuck"].LagBlocks)
	}
	if got["stuck"].LagSeconds != 30 {
		t.Errorf("lag seconds = %v, want 30", got["stuck"].LagSeconds)
	}
	if got["stuck"].Estimated {
		t.Error("lag seconds should not be flagged as estimated when the transition was observed")
	}
	if got["fast"].LagSeconds != 0 {
		t.Errorf("the leader must have zero lag seconds, got %v", got["fast"].LagSeconds)
	}
}

func TestComputeLagSecondsFallsBackAndFlagsEstimate(t *testing.T) {
	clock := NewHeightClock(100)
	// The probe never saw height 96 or 97: it started mid-window.
	got := byName(ComputeLag([]HeadSample{
		sample("fast", 100, at(0)),
		sample("slow", 95, at(0)),
	}, at(0), clock))

	if got["slow"].LagBlocks != 5 {
		t.Fatalf("lag blocks = %d, want 5", got["slow"].LagBlocks)
	}
	if !got["slow"].Estimated {
		t.Error("lag seconds should be flagged as estimated when the transition was not observed")
	}
}

func TestComputeLagIgnoresUnhealthySamples(t *testing.T) {
	clock := NewHeightClock(100)
	broken := sample("broken", 9999999, at(0))
	broken.ErrClass = "timeout"
	broken.Err = "context deadline exceeded"

	got := byName(ComputeLag([]HeadSample{sample("ok", 100, at(0)), broken}, at(0), clock))
	if got["ok"].BestHeight != 100 {
		t.Errorf("a failed sample's height leaked into the reference head: %d", got["ok"].BestHeight)
	}
	if got["broken"].LagBlocks != 0 || got["broken"].Leader {
		t.Errorf("a failed sample must not be scored: %+v", got["broken"])
	}
}

func TestComputeLagWithNoHealthySamples(t *testing.T) {
	s := sample("down", 0, at(0))
	s.ErrClass = "http_error"
	got := ComputeLag([]HeadSample{s}, at(0), NewHeightClock(10))
	if len(got) != 1 || got[0].BestHeight != 0 {
		t.Errorf("unexpected result: %+v", got)
	}
}

func TestHeightClockKeepsEarliestObservation(t *testing.T) {
	clock := NewHeightClock(10)
	clock.Observe(100, at(5))
	clock.Observe(100, at(1))
	clock.Observe(100, at(9))
	seen, ok := clock.FirstSeen(100)
	if !ok {
		t.Fatal("height 100 not recorded")
	}
	if !seen.Equal(at(1)) {
		t.Errorf("first seen = %s, want %s", seen, at(1))
	}
}

func TestHeightClockPrunes(t *testing.T) {
	clock := NewHeightClock(4)
	for h := uint64(100); h <= 110; h++ {
		clock.Observe(h, at(int(h)))
	}
	if _, ok := clock.FirstSeen(100); ok {
		t.Error("old height should have been pruned")
	}
	if _, ok := clock.FirstSeen(110); !ok {
		t.Error("recent height should be retained")
	}
	if _, ok := clock.FirstSeen(107); !ok {
		t.Error("height inside the retention window should be retained")
	}
}

func TestFinalisedHeight(t *testing.T) {
	if h, ok := FinalisedHeight(20000000, 64); !ok || h != 19999936 {
		t.Errorf("FinalisedHeight = %d, %v", h, ok)
	}
	if _, ok := FinalisedHeight(10, 64); ok {
		t.Error("a chain shorter than the finality depth has no comparable height")
	}
	if _, ok := FinalisedHeight(0, 64); ok {
		t.Error("no head means no finalised height")
	}
}
