// Package analysis derives the numbers the audit is actually sold on: how far
// behind each endpoint is, in blocks and in seconds, and whether two endpoints
// disagree about the canonical chain at a finalised height.
package analysis

import (
	"sort"
	"time"
)

// HeadSample is one endpoint's answer to a head-height poll.
type HeadSample struct {
	At       time.Time     `json:"ts"`
	Endpoint string        `json:"endpoint"`
	Provider string        `json:"provider,omitempty"`
	Region   string        `json:"region"`
	Chain    string        `json:"chain"`
	Height   uint64        `json:"height"`
	Latency  time.Duration `json:"latency_ns"`
	// ErrClass is "ok" for a healthy sample, otherwise the rpc error class.
	ErrClass string `json:"err_class"`
	Err      string `json:"err,omitempty"`
	Status   int    `json:"http_status,omitempty"`
}

// Healthy reports whether this sample carried a usable height.
func (s HeadSample) Healthy() bool { return s.ErrClass == "" || s.ErrClass == "ok" }

// Lag is a sample enriched with its distance behind the fastest healthy peer.
type Lag struct {
	HeadSample
	LagBlocks  uint64  `json:"lag_blocks"`
	LagSeconds float64 `json:"lag_seconds"`
	// Estimated is true when lag_seconds could not be derived from observed
	// height transitions and had to fall back to a coarser measure.
	Estimated bool `json:"lag_seconds_estimated,omitempty"`
	// Leader marks the endpoint(s) defining the reference head this tick.
	Leader bool `json:"leader,omitempty"`
	// BestHeight is the reference head lag was measured against.
	BestHeight uint64 `json:"best_height"`
}

// HeightClock remembers when each height was first seen by any endpoint. That
// is what converts a block-count lag into a defensible number of seconds: the
// probe never trusts a provider's own block timestamp for this.
type HeightClock struct {
	firstSeen map[uint64]time.Time
	highest   uint64
	keep      uint64
}

// NewHeightClock keeps first-seen times for the most recent keep heights.
func NewHeightClock(keep uint64) *HeightClock {
	if keep == 0 {
		keep = 512
	}
	return &HeightClock{firstSeen: make(map[uint64]time.Time), keep: keep}
}

// Observe records that height was seen at time at. The earliest observation
// wins, so a late-reporting endpoint cannot move the reference.
func (h *HeightClock) Observe(height uint64, at time.Time) {
	if height == 0 {
		return
	}
	if prev, ok := h.firstSeen[height]; !ok || at.Before(prev) {
		h.firstSeen[height] = at
	}
	if height > h.highest {
		h.highest = height
		h.prune()
	}
}

func (h *HeightClock) prune() {
	if h.highest <= h.keep {
		return
	}
	cutoff := h.highest - h.keep
	for height := range h.firstSeen {
		if height < cutoff {
			delete(h.firstSeen, height)
		}
	}
}

// FirstSeen returns when a height was first observed.
func (h *HeightClock) FirstSeen(height uint64) (time.Time, bool) {
	t, ok := h.firstSeen[height]
	return t, ok
}

// ComputeLag scores one tick's worth of samples for a single chain.
//
// The reference head is the highest height reported by a healthy endpoint this
// tick. Lag in seconds is the wall-clock age of the endpoint's head: the time
// since the network moved past it, taken from the height clock. When that is
// unknown the difference in first-seen times between the reference head and
// the endpoint's head is used instead, and the result is flagged as estimated.
func ComputeLag(samples []HeadSample, at time.Time, clock *HeightClock) []Lag {
	var best uint64
	for _, s := range samples {
		if s.Healthy() && s.Height > best {
			best = s.Height
		}
	}
	if clock != nil {
		for _, s := range samples {
			if s.Healthy() {
				clock.Observe(s.Height, at)
			}
		}
	}

	out := make([]Lag, 0, len(samples))
	for _, s := range samples {
		l := Lag{HeadSample: s, BestHeight: best}
		if !s.Healthy() || best == 0 {
			out = append(out, l)
			continue
		}
		l.LagBlocks = best - s.Height
		l.Leader = s.Height == best
		if l.LagBlocks > 0 && clock != nil {
			if stale, ok := clock.FirstSeen(s.Height + 1); ok {
				if d := at.Sub(stale); d > 0 {
					l.LagSeconds = d.Seconds()
				}
			} else {
				bestSeen, okB := clock.FirstSeen(best)
				mineSeen, okM := clock.FirstSeen(s.Height)
				if okB && okM {
					if d := bestSeen.Sub(mineSeen); d > 0 {
						l.LagSeconds = d.Seconds()
					}
				}
				l.Estimated = true
			}
		}
		out = append(out, l)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Endpoint < out[j].Endpoint })
	return out
}

// FinalisedHeight returns the height at which hashes are safe to compare, i.e.
// deep enough behind the reference head that an ordinary reorg cannot explain
// a disagreement. It returns false when the chain has not produced enough
// blocks yet.
func FinalisedHeight(bestHead, depth uint64) (uint64, bool) {
	if bestHead == 0 || bestHead <= depth {
		return 0, false
	}
	return bestHead - depth, true
}
