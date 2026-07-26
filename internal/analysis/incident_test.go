package analysis

import (
	"strings"
	"testing"
	"time"
)

func lagAt(sec int, endpoint string, blocks uint64, secs float64) Lag {
	return Lag{
		HeadSample: HeadSample{At: at(sec), Endpoint: endpoint, Region: "eu-central-1", Chain: "ethereum", ErrClass: "ok", Height: 100},
		LagBlocks:  blocks, LagSeconds: secs,
	}
}

func failedAt(sec int, endpoint, class string) Lag {
	return Lag{HeadSample: HeadSample{At: at(sec), Endpoint: endpoint, Region: "eu-central-1", Chain: "ethereum", ErrClass: class, Err: class}}
}

func TestDetectLagIncidentsGroupsContinuousBreaches(t *testing.T) {
	points := []Lag{
		lagAt(0, "a", 0, 0),
		lagAt(2, "a", 4, 12),
		lagAt(4, "a", 6, 24),
		lagAt(6, "a", 5, 20),
		lagAt(8, "a", 0, 0), // recovered
		lagAt(10, "a", 7, 30),
		lagAt(12, "a", 7, 30),
	}
	got := DetectLagIncidents(points, IncidentRules{LagBlocks: 3, MinSamples: 2})
	if len(got) != 2 {
		t.Fatalf("incidents = %d, want 2: %+v", len(got), got)
	}
	first := got[0]
	if !first.Start.Equal(at(2)) || !first.End.Equal(at(6)) {
		t.Errorf("first incident window = %s..%s", first.Start, first.End)
	}
	if first.Duration() != 4*time.Second {
		t.Errorf("duration = %s, want 4s", first.Duration())
	}
	if first.PeakLagBlocks != 6 || first.PeakLagSeconds != 24 {
		t.Errorf("peak = %d blocks / %vs", first.PeakLagBlocks, first.PeakLagSeconds)
	}
	if first.Samples != 3 {
		t.Errorf("samples = %d, want 3", first.Samples)
	}
	if !strings.Contains(first.Detail, "6 blocks") {
		t.Errorf("detail = %q", first.Detail)
	}
}

func TestDetectLagIncidentsSuppressesSingleTickBlips(t *testing.T) {
	points := []Lag{
		lagAt(0, "a", 0, 0),
		lagAt(2, "a", 9, 40), // one-tick spike
		lagAt(4, "a", 0, 0),
	}
	if got := DetectLagIncidents(points, IncidentRules{LagBlocks: 3, MinSamples: 2}); len(got) != 0 {
		t.Fatalf("single-tick blip became an incident: %+v", got)
	}
	if got := DetectLagIncidents(points, IncidentRules{LagBlocks: 3, MinSamples: 1}); len(got) != 1 {
		t.Fatalf("min-samples 1 should have kept the blip: %+v", got)
	}
}

func TestDetectLagIncidentsSecondsThreshold(t *testing.T) {
	points := []Lag{lagAt(0, "a", 1, 45), lagAt(2, "a", 1, 47)}
	got := DetectLagIncidents(points, IncidentRules{LagBlocks: 10, LagSeconds: 30, MinSamples: 2})
	if len(got) != 1 {
		t.Fatalf("seconds threshold did not fire: %+v", got)
	}
}

func TestDetectLagIncidentsSeparatesUnavailability(t *testing.T) {
	points := []Lag{
		lagAt(0, "a", 5, 20),
		lagAt(2, "a", 5, 20),
		failedAt(4, "a", "rate_limited"),
		failedAt(6, "a", "rate_limited"),
	}
	got := DetectLagIncidents(points, IncidentRules{LagBlocks: 3, MinSamples: 2})
	if len(got) != 2 {
		t.Fatalf("incidents = %d, want a lag one and an unavailable one: %+v", len(got), got)
	}
	if got[0].Kind != KindLag || got[1].Kind != KindUnavailable {
		t.Errorf("kinds = %s, %s", got[0].Kind, got[1].Kind)
	}
	if got[1].Detail != "rate_limited" {
		t.Errorf("unavailable detail = %q, want the error class once, not repeated", got[1].Detail)
	}
}

func TestDetectLagIncidentsPerEndpoint(t *testing.T) {
	points := []Lag{
		lagAt(0, "a", 5, 20), lagAt(0, "b", 0, 0),
		lagAt(2, "a", 5, 20), lagAt(2, "b", 5, 20),
		lagAt(4, "a", 0, 0), lagAt(4, "b", 5, 20),
	}
	got := DetectLagIncidents(points, IncidentRules{LagBlocks: 3, MinSamples: 2})
	if len(got) != 2 {
		t.Fatalf("incidents = %d, want one per endpoint: %+v", len(got), got)
	}
	if got[0].Endpoint == got[1].Endpoint {
		t.Errorf("both incidents belong to %s", got[0].Endpoint)
	}
}

func TestDetectLagIncidentsHandlesOutOfOrderInput(t *testing.T) {
	points := []Lag{lagAt(4, "a", 5, 20), lagAt(0, "a", 5, 20), lagAt(2, "a", 5, 20)}
	got := DetectLagIncidents(points, IncidentRules{LagBlocks: 3, MinSamples: 3})
	if len(got) != 1 {
		t.Fatalf("out-of-order samples were not merged: %+v", got)
	}
	if !got[0].Start.Equal(at(0)) || !got[0].End.Equal(at(4)) {
		t.Errorf("window = %s..%s", got[0].Start, got[0].End)
	}
}

func TestDivergenceIncidentsNameTheMinority(t *testing.T) {
	ev := DivergenceEvent{
		DetectedAt: at(10), Chain: "ethereum", Height: 19999936,
		Clusters: []HashCluster{
			{Hash: hashA, Endpoints: []string{"a", "b"}, Regions: []string{"eu-central-1", "us-east-1"}},
			{Hash: hashB, Endpoints: []string{"c"}, Regions: []string{"ap-southeast-1"}},
		},
		MajorityHash: hashA,
		Minority:     []string{"c"},
	}
	got := DivergenceIncidents([]DivergenceEvent{ev})
	if len(got) != 1 {
		t.Fatalf("incidents = %d, want 1: %+v", len(got), got)
	}
	in := got[0]
	if in.Endpoint != "c" || in.Kind != KindDivergence {
		t.Errorf("incident = %+v", in)
	}
	if in.Region != "ap-southeast-1" {
		t.Errorf("region = %q, want the minority endpoint's vantage point", in.Region)
	}
	if in.Height != 19999936 {
		t.Errorf("height = %d", in.Height)
	}
	if !strings.Contains(in.Detail, "majority") || !strings.Contains(in.Detail, "served") {
		t.Errorf("detail = %q", in.Detail)
	}
}

func TestDivergenceIncidentsWithoutMajorityCoverEveryEndpoint(t *testing.T) {
	ev := DivergenceEvent{
		DetectedAt: at(10), Chain: "ethereum", Height: 100,
		Clusters: []HashCluster{
			{Hash: hashA, Endpoints: []string{"a"}, Regions: []string{"eu-central-1"}},
			{Hash: hashB, Endpoints: []string{"b"}, Regions: []string{"us-east-1"}},
		},
		Minority: []string{"a", "b"},
	}
	got := DivergenceIncidents([]DivergenceEvent{ev})
	if len(got) != 2 {
		t.Fatalf("incidents = %d, want one per endpoint: %+v", len(got), got)
	}
	for _, in := range got {
		if !strings.Contains(in.Detail, "no majority") {
			t.Errorf("detail = %q, want it to say there was no majority", in.Detail)
		}
	}
}
