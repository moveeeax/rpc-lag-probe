// Package report turns an evidence log into the audit deliverable: a summary,
// a per-provider lag and availability table, an incident table and the raw
// divergence findings.
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/moveeeax/rpc-lag-probe/internal/analysis"
	"github.com/moveeeax/rpc-lag-probe/internal/evidence"
)

// Options control the rendered report.
type Options struct {
	// Customer appears in the title. Optional.
	Customer string
	// Rules are the thresholds incidents are declared against. They should
	// match the alerting config used during the measurement window.
	Rules analysis.IncidentRules
	// Now is the generation timestamp; zero means time.Now.
	Now time.Time
	// TopIncidents caps the incident table. 0 means no cap.
	TopIncidents int
}

func (o *Options) applyDefaults() {
	if o.Rules.LagBlocks == 0 && o.Rules.LagSeconds == 0 {
		o.Rules.LagBlocks = 3
	}
	if o.Rules.MinSamples == 0 {
		o.Rules.MinSamples = 2
	}
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
}

// Result is the analysed evidence behind a rendered report.
type Result struct {
	Summaries []analysis.EndpointSummary
	Incidents []analysis.Incident
	Bundle    *evidence.Bundle
	Options   Options
}

// Analyse folds an evidence bundle into summaries and incidents.
func Analyse(b *evidence.Bundle, opts Options) *Result {
	opts.applyDefaults()
	agg := analysis.NewAggregator(opts.Rules.LagBlocks)
	for _, l := range b.Lags {
		agg.Add(l)
	}
	incidents := analysis.DetectLagIncidents(b.Lags, opts.Rules)
	incidents = append(incidents, analysis.DivergenceIncidents(b.Divergences)...)
	sort.SliceStable(incidents, func(i, j int) bool {
		if !incidents[i].Start.Equal(incidents[j].Start) {
			return incidents[i].Start.Before(incidents[j].Start)
		}
		return incidents[i].Endpoint < incidents[j].Endpoint
	})
	return &Result{Summaries: agg.Summaries(), Incidents: incidents, Bundle: b, Options: opts}
}

// Markdown renders the audit deliverable.
func Markdown(b *evidence.Bundle, opts Options) string {
	r := Analyse(b, opts)
	var w strings.Builder

	title := "RPC endpoint lag and divergence audit"
	if r.Options.Customer != "" {
		title += " — " + r.Options.Customer
	}
	fmt.Fprintf(&w, "# %s\n\n", title)

	window := "no samples"
	if !b.First.IsZero() {
		window = fmt.Sprintf("%s → %s (%s)",
			b.First.UTC().Format(time.RFC3339), b.Last.UTC().Format(time.RFC3339),
			roundDuration(b.Last.Sub(b.First)))
	}
	fmt.Fprintf(&w, "| | |\n|---|---|\n")
	fmt.Fprintf(&w, "| Measurement window | %s |\n", window)
	fmt.Fprintf(&w, "| Vantage points | %s |\n", joinOr(b.Regions, "unknown"))
	fmt.Fprintf(&w, "| Chains | %s |\n", joinOr(b.Chains, "unknown"))
	fmt.Fprintf(&w, "| Endpoints measured | %d |\n", len(r.Summaries))
	fmt.Fprintf(&w, "| Head polls recorded | %d |\n", len(b.Lags))
	fmt.Fprintf(&w, "| Divergence events | %d |\n", len(b.Divergences))
	fmt.Fprintf(&w, "| Report generated | %s |\n\n", r.Options.Now.UTC().Format(time.RFC3339))

	fmt.Fprintf(&w, "Lag threshold used for incidents: %d block(s)", r.Options.Rules.LagBlocks)
	if r.Options.Rules.LagSeconds > 0 {
		fmt.Fprintf(&w, " or %.0fs", r.Options.Rules.LagSeconds)
	}
	fmt.Fprintf(&w, ", sustained for at least %d consecutive polls.\n\n", r.Options.Rules.MinSamples)

	writeFindings(&w, r)
	writeLagTable(&w, r)
	writeIncidentTable(&w, r)
	writeDivergence(&w, r)
	writeMethod(&w, r)
	return w.String()
}

func writeFindings(w *strings.Builder, r *Result) {
	fmt.Fprintf(w, "## Findings\n\n")
	if len(r.Summaries) == 0 {
		fmt.Fprintf(w, "- No samples in the evidence log.\n\n")
		return
	}
	var lines []string
	for _, s := range r.Summaries {
		if s.Availability < 0.99 {
			lines = append(lines, fmt.Sprintf("- **%s** answered %.2f%% of head polls (%d of %d), from %s.",
				s.Endpoint, s.Availability*100, s.OK, s.Samples, s.Region))
		}
		if s.StaleShare > 0 {
			lines = append(lines, fmt.Sprintf("- **%s** was at or over the lag threshold in %.2f%% of healthy polls; worst observed lag %d blocks / %.1fs.",
				s.Endpoint, s.StaleShare*100, s.LagBlocksMax, s.LagSecondsMax))
		}
		if s.LeaderShare == 0 && s.OK > 0 {
			lines = append(lines, fmt.Sprintf("- **%s** never led the field: it was behind at least one peer on every single poll.", s.Endpoint))
		}
	}
	for _, ev := range r.Bundle.Divergences {
		lines = append(lines, fmt.Sprintf("- **Hash divergence** on %s at finalised height %d between %s.",
			ev.Chain, ev.Height, describeClusters(ev)))
	}
	if len(lines) == 0 {
		lines = append(lines, "- No endpoint breached the lag threshold and no hash divergence was observed during the window.")
	}
	fmt.Fprintf(w, "%s\n\n", strings.Join(lines, "\n"))
}

func writeLagTable(w *strings.Builder, r *Result) {
	fmt.Fprintf(w, "## Lag and availability by endpoint\n\n")
	if len(r.Summaries) == 0 {
		fmt.Fprintf(w, "_No samples._\n\n")
		return
	}
	fmt.Fprintf(w, "| Endpoint | Region | Chain | Polls | Availability | Lag blocks p50 / p99 / max | Lag seconds p50 / p99 / max | Latency p50 / p99 | Leader share |\n")
	fmt.Fprintf(w, "|---|---|---|---:|---:|---|---|---|---:|\n")
	for _, s := range r.Summaries {
		fmt.Fprintf(w, "| %s | %s | %s | %d | %.2f%% | %.0f / %.0f / %d | %.1f / %.1f / %.1f | %s / %s | %.1f%% |\n",
			s.Endpoint, s.Region, s.Chain, s.Samples, s.Availability*100,
			s.LagBlocksP50, s.LagBlocksP99, s.LagBlocksMax,
			s.LagSecondsP50, s.LagSecondsP99, s.LagSecondsMax,
			roundDuration(s.LatencyP50), roundDuration(s.LatencyP99),
			s.LeaderShare*100)
	}
	fmt.Fprintf(w, "\n")

	var withErrors []analysis.EndpointSummary
	for _, s := range r.Summaries {
		if len(s.Errors) > 0 {
			withErrors = append(withErrors, s)
		}
	}
	if len(withErrors) > 0 {
		fmt.Fprintf(w, "### Errors by class\n\n| Endpoint | Class | Count | Share of polls |\n|---|---|---:|---:|\n")
		for _, s := range withErrors {
			classes := make([]string, 0, len(s.Errors))
			for c := range s.Errors {
				classes = append(classes, c)
			}
			sort.Strings(classes)
			for _, c := range classes {
				share := 0.0
				if s.Samples > 0 {
					share = float64(s.Errors[c]) / float64(s.Samples) * 100
				}
				fmt.Fprintf(w, "| %s | %s | %d | %.2f%% |\n", s.Endpoint, c, s.Errors[c], share)
			}
		}
		fmt.Fprintf(w, "\n")
	}
}

func writeIncidentTable(w *strings.Builder, r *Result) {
	fmt.Fprintf(w, "## Incidents\n\n")
	if len(r.Incidents) == 0 {
		fmt.Fprintf(w, "_No incident crossed the configured thresholds during the window._\n\n")
		return
	}
	incidents := r.Incidents
	truncated := 0
	if r.Options.TopIncidents > 0 && len(incidents) > r.Options.TopIncidents {
		truncated = len(incidents) - r.Options.TopIncidents
		incidents = incidents[:r.Options.TopIncidents]
	}
	fmt.Fprintf(w, "| # | Start (UTC) | Duration | Endpoint | Region | Kind | Detail |\n|---:|---|---:|---|---|---|---|\n")
	for i, in := range incidents {
		fmt.Fprintf(w, "| %d | %s | %s | %s | %s | %s | %s |\n",
			i+1, in.Start.UTC().Format("2006-01-02 15:04:05"), roundDuration(in.Duration()),
			in.Endpoint, in.Region, in.Kind, in.Detail)
	}
	if truncated > 0 {
		fmt.Fprintf(w, "\n_%d further incident(s) omitted; the full set is in the evidence log._\n", truncated)
	}
	fmt.Fprintf(w, "\n")
}

func writeDivergence(w *strings.Builder, r *Result) {
	fmt.Fprintf(w, "## Hash divergence\n\n")
	if len(r.Bundle.Divergences) == 0 {
		fmt.Fprintf(w, "_No two endpoints reported different hashes at the same finalised height during the window._\n\n")
		return
	}
	for _, ev := range r.Bundle.Divergences {
		fmt.Fprintf(w, "### %s height %d — %s\n\n", ev.Chain, ev.Height, ev.DetectedAt.UTC().Format(time.RFC3339))
		fmt.Fprintf(w, "| Hash | Endpoints | Regions |\n|---|---|---|\n")
		for _, c := range ev.Clusters {
			fmt.Fprintf(w, "| `%s` | %s | %s |\n", c.Hash, strings.Join(c.Endpoints, ", "), joinOr(c.Regions, "—"))
		}
		if ev.MajorityHash != "" {
			fmt.Fprintf(w, "\nMajority hash: `%s`. Minority: %s.\n", ev.MajorityHash, joinOr(ev.Minority, "—"))
		} else {
			fmt.Fprintf(w, "\nNo majority: the endpoints split evenly. Every cluster is listed as a minority.\n")
		}
		if len(ev.Unanswered) > 0 {
			fmt.Fprintf(w, "\nNot compared (no answer at this height): %s.\n", strings.Join(ev.Unanswered, ", "))
		}
		fmt.Fprintf(w, "\nRaw provider payloads for this height are in the evidence log under `\"type\":\"divergence\"`.\n\n")
	}
}

func writeMethod(w *strings.Builder, r *Result) {
	fmt.Fprintf(w, "## Method\n\n")
	fmt.Fprintf(w, "- Every endpoint is polled for `eth_blockNumber` on the same tick, from the vantage points listed above. No traffic is proxied and no endpoint sits in a request path.\n")
	fmt.Fprintf(w, "- Lag in blocks is measured against the highest head reported by any healthy endpoint on the same chain at that tick.\n")
	fmt.Fprintf(w, "- Lag in seconds is wall-clock: the time since the probe first saw the network move past the endpoint's current head. Provider-reported block timestamps are never used for this.\n")
	fmt.Fprintf(w, "- Hashes are compared with `eth_getBlockByNumber` at a height far enough behind the head that an ordinary reorg cannot explain a disagreement, so a divergence event is a real inconsistency and not a race.\n")
	fmt.Fprintf(w, "- Every number in this report is reproducible from the append-only JSONL evidence log that accompanies it.\n\n")
	fmt.Fprintf(w, "Generated by rpc-lag-probe.\n")
}

func describeClusters(ev analysis.DivergenceEvent) string {
	parts := make([]string, 0, len(ev.Clusters))
	for _, c := range ev.Clusters {
		parts = append(parts, fmt.Sprintf("%s (`%s`)", strings.Join(c.Endpoints, "+"), shortHash(c.Hash)))
	}
	return strings.Join(parts, " vs ")
}

func shortHash(h string) string {
	if len(h) <= 18 {
		return h
	}
	return h[:10] + "…" + h[len(h)-6:]
}

func joinOr(xs []string, fallback string) string {
	if len(xs) == 0 {
		return fallback
	}
	return strings.Join(xs, ", ")
}

func roundDuration(d time.Duration) string {
	switch {
	case d == 0:
		return "0s"
	case d < time.Millisecond:
		return d.Round(time.Microsecond).String()
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	case d < time.Minute:
		return d.Round(100 * time.Millisecond).String()
	default:
		return d.Round(time.Second).String()
	}
}
