package analysis

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Incident kinds.
const (
	KindLag         = "lag"
	KindUnavailable = "unavailable"
	KindDivergence  = "divergence"
)

// Incident is one row of the audit deliverable's incident table.
type Incident struct {
	Kind     string    `json:"kind"`
	Endpoint string    `json:"endpoint"`
	Provider string    `json:"provider,omitempty"`
	Region   string    `json:"region"`
	Chain    string    `json:"chain"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Samples  int       `json:"samples"`

	PeakLagBlocks  uint64  `json:"peak_lag_blocks,omitempty"`
	PeakLagSeconds float64 `json:"peak_lag_seconds,omitempty"`
	Height         uint64  `json:"height,omitempty"`
	Detail         string  `json:"detail,omitempty"`
}

// Duration of the incident window.
func (i Incident) Duration() time.Duration { return i.End.Sub(i.Start) }

// IncidentRules are the thresholds an incident is declared against. They come
// from the alerting config so the report and the alerts cannot drift apart.
type IncidentRules struct {
	LagBlocks  uint64
	LagSeconds float64
	// MinSamples suppresses single-tick blips; an incident must persist for at
	// least this many consecutive polls.
	MinSamples int
}

// DetectLagIncidents walks scored samples in time order and emits one incident
// per continuous run where an endpoint breached the thresholds. Errors and
// timeouts open an "unavailable" incident rather than a lag one, because a
// provider that is not answering is a different conversation than a provider
// that is answering with stale state.
func DetectLagIncidents(points []Lag, rules IncidentRules) []Incident {
	if rules.MinSamples < 1 {
		rules.MinSamples = 1
	}
	byEndpoint := map[string][]Lag{}
	var order []string
	for _, p := range points {
		if _, ok := byEndpoint[p.Endpoint]; !ok {
			order = append(order, p.Endpoint)
		}
		byEndpoint[p.Endpoint] = append(byEndpoint[p.Endpoint], p)
	}
	sort.Strings(order)

	var out []Incident
	for _, name := range order {
		series := byEndpoint[name]
		sort.SliceStable(series, func(i, j int) bool { return series[i].At.Before(series[j].At) })
		out = append(out, scanSeries(series, rules)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].Start.Equal(out[j].Start) {
			return out[i].Start.Before(out[j].Start)
		}
		return out[i].Endpoint < out[j].Endpoint
	})
	return out
}

func scanSeries(series []Lag, rules IncidentRules) []Incident {
	var out []Incident
	var cur *Incident

	flush := func() {
		if cur != nil && cur.Samples >= rules.MinSamples {
			if cur.Kind == KindLag {
				cur.Detail = fmt.Sprintf("peak %d blocks / %.1fs behind the fastest peer", cur.PeakLagBlocks, cur.PeakLagSeconds)
			}
			out = append(out, *cur)
		}
		cur = nil
	}

	for _, p := range series {
		kind := ""
		switch {
		case !p.Healthy():
			kind = KindUnavailable
		case breached(p, rules):
			kind = KindLag
		}
		if kind == "" {
			flush()
			continue
		}
		if cur != nil && cur.Kind != kind {
			flush()
		}
		if cur == nil {
			cur = &Incident{
				Kind:     kind,
				Endpoint: p.Endpoint,
				Provider: p.Provider,
				Region:   p.Region,
				Chain:    p.Chain,
				Start:    p.At,
			}
			if kind == KindUnavailable {
				cur.Detail = p.ErrClass
			}
		}
		cur.End = p.At
		cur.Samples++
		if p.LagBlocks > cur.PeakLagBlocks {
			cur.PeakLagBlocks = p.LagBlocks
		}
		if p.LagSeconds > cur.PeakLagSeconds {
			cur.PeakLagSeconds = p.LagSeconds
		}
		if kind == KindUnavailable && p.ErrClass != "" && cur.Detail != p.ErrClass {
			cur.Detail = cur.Detail + "," + p.ErrClass
		}
	}
	flush()
	return out
}

func breached(p Lag, rules IncidentRules) bool {
	if rules.LagBlocks > 0 && p.LagBlocks >= rules.LagBlocks {
		return true
	}
	if rules.LagSeconds > 0 && p.LagSeconds >= rules.LagSeconds {
		return true
	}
	return false
}

// DivergenceIncidents turns divergence events into incident rows, one per
// endpoint on a minority hash.
func DivergenceIncidents(events []DivergenceEvent) []Incident {
	var out []Incident
	for _, ev := range events {
		detail := fmt.Sprintf("%d distinct hashes at finalised height %d", len(ev.Clusters), ev.Height)
		if ev.MajorityHash != "" {
			detail += fmt.Sprintf("; majority %s", short(ev.MajorityHash))
		} else {
			detail += "; no majority"
		}
		targets := ev.Minority
		if len(targets) == 0 {
			for _, c := range ev.Clusters {
				targets = append(targets, c.Endpoints...)
			}
		}
		for _, ep := range targets {
			out = append(out, Incident{
				Kind:     KindDivergence,
				Endpoint: ep,
				Region:   regionFor(ev, ep),
				Chain:    ev.Chain,
				Start:    ev.DetectedAt,
				End:      ev.DetectedAt,
				Samples:  1,
				Height:   ev.Height,
				Detail:   detail + "; served " + short(hashFor(ev, ep)),
			})
		}
	}
	return out
}

// regionFor reports the vantage point a divergent answer was seen from. When a
// cluster spans several regions they are all listed: the finding is that these
// regions agreed with each other and not with the rest.
func regionFor(ev DivergenceEvent, endpoint string) string {
	for _, c := range ev.Clusters {
		for _, e := range c.Endpoints {
			if e == endpoint {
				return strings.Join(c.Regions, "+")
			}
		}
	}
	return ""
}

func hashFor(ev DivergenceEvent, endpoint string) string {
	for _, c := range ev.Clusters {
		for _, e := range c.Endpoints {
			if e == endpoint {
				return c.Hash
			}
		}
	}
	return ""
}

func short(hash string) string {
	if len(hash) <= 18 {
		return hash
	}
	return hash[:10] + "…" + hash[len(hash)-6:]
}
