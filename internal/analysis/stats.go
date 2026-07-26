package analysis

import (
	"math"
	"sort"
	"time"
)

// Percentile returns the nearest-rank percentile of an unsorted sample set.
// p is expressed as a fraction, e.g. 0.99. It returns 0 for an empty set.
func Percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	if p <= 0 {
		p = 0
	}
	if p > 1 {
		p = 1
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	rank := int(math.Ceil(p * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

// EndpointSummary is the per-provider row of the audit report.
type EndpointSummary struct {
	Endpoint string `json:"endpoint"`
	Provider string `json:"provider,omitempty"`
	Region   string `json:"region"`
	Chain    string `json:"chain"`

	Samples int            `json:"samples"`
	OK      int            `json:"ok"`
	Errors  map[string]int `json:"errors,omitempty"`

	// Availability is the share of polls that returned a usable height.
	Availability float64 `json:"availability"`

	LatencyP50 time.Duration `json:"latency_p50"`
	LatencyP90 time.Duration `json:"latency_p90"`
	LatencyP99 time.Duration `json:"latency_p99"`
	LatencyMax time.Duration `json:"latency_max"`

	LagBlocksP50 float64 `json:"lag_blocks_p50"`
	LagBlocksP99 float64 `json:"lag_blocks_p99"`
	LagBlocksMax uint64  `json:"lag_blocks_max"`

	LagSecondsP50 float64 `json:"lag_seconds_p50"`
	LagSecondsP99 float64 `json:"lag_seconds_p99"`
	LagSecondsMax float64 `json:"lag_seconds_max"`

	// LeaderShare is how often this endpoint defined the reference head. A
	// provider that is never the leader is systematically behind its peers.
	LeaderShare float64 `json:"leader_share"`
	// StaleShare is the share of healthy polls at or over the lag threshold.
	StaleShare float64 `json:"stale_share"`

	First time.Time `json:"first_sample"`
	Last  time.Time `json:"last_sample"`
}

// Aggregator accumulates scored samples into per-endpoint summaries.
type Aggregator struct {
	lagBlocksThreshold uint64
	byEndpoint         map[string]*acc
}

type acc struct {
	sum        EndpointSummary
	latencies  []float64
	lagBlocks  []float64
	lagSeconds []float64
	leaders    int
	stale      int
}

// NewAggregator builds an aggregator; lagBlocksThreshold defines "stale" for
// the stale-share column.
func NewAggregator(lagBlocksThreshold uint64) *Aggregator {
	return &Aggregator{lagBlocksThreshold: lagBlocksThreshold, byEndpoint: map[string]*acc{}}
}

// Add folds one scored sample in.
func (a *Aggregator) Add(l Lag) {
	e, ok := a.byEndpoint[l.Endpoint]
	if !ok {
		e = &acc{sum: EndpointSummary{
			Endpoint: l.Endpoint,
			Provider: l.Provider,
			Region:   l.Region,
			Chain:    l.Chain,
			Errors:   map[string]int{},
			First:    l.At,
		}}
		a.byEndpoint[l.Endpoint] = e
	}
	e.sum.Samples++
	if !l.At.IsZero() {
		if e.sum.First.IsZero() || l.At.Before(e.sum.First) {
			e.sum.First = l.At
		}
		if l.At.After(e.sum.Last) {
			e.sum.Last = l.At
		}
	}
	if l.Latency > 0 {
		e.latencies = append(e.latencies, float64(l.Latency))
		if l.Latency > e.sum.LatencyMax {
			e.sum.LatencyMax = l.Latency
		}
	}
	if !l.Healthy() {
		class := l.ErrClass
		if class == "" {
			class = "unknown"
		}
		e.sum.Errors[class]++
		return
	}
	e.sum.OK++
	e.lagBlocks = append(e.lagBlocks, float64(l.LagBlocks))
	e.lagSeconds = append(e.lagSeconds, l.LagSeconds)
	if l.LagBlocks > e.sum.LagBlocksMax {
		e.sum.LagBlocksMax = l.LagBlocks
	}
	if l.LagSeconds > e.sum.LagSecondsMax {
		e.sum.LagSecondsMax = l.LagSeconds
	}
	if l.Leader {
		e.leaders++
	}
	if a.lagBlocksThreshold > 0 && l.LagBlocks >= a.lagBlocksThreshold {
		e.stale++
	}
}

// Summaries returns one row per endpoint, sorted by name.
func (a *Aggregator) Summaries() []EndpointSummary {
	out := make([]EndpointSummary, 0, len(a.byEndpoint))
	for _, e := range a.byEndpoint {
		s := e.sum
		if s.Samples > 0 {
			s.Availability = float64(s.OK) / float64(s.Samples)
		}
		if s.OK > 0 {
			s.LeaderShare = float64(e.leaders) / float64(s.OK)
			s.StaleShare = float64(e.stale) / float64(s.OK)
		}
		s.LatencyP50 = time.Duration(Percentile(e.latencies, 0.50))
		s.LatencyP90 = time.Duration(Percentile(e.latencies, 0.90))
		s.LatencyP99 = time.Duration(Percentile(e.latencies, 0.99))
		s.LagBlocksP50 = Percentile(e.lagBlocks, 0.50)
		s.LagBlocksP99 = Percentile(e.lagBlocks, 0.99)
		s.LagSecondsP50 = Percentile(e.lagSeconds, 0.50)
		s.LagSecondsP99 = Percentile(e.lagSeconds, 0.99)
		if len(s.Errors) == 0 {
			s.Errors = nil
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Chain != out[j].Chain {
			return out[i].Chain < out[j].Chain
		}
		return out[i].Endpoint < out[j].Endpoint
	})
	return out
}
