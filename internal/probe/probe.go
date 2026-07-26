// Package probe is the scheduler: it polls every configured endpoint on a
// fixed tick, scores the results, records evidence, updates metrics and gates
// alerts. It never proxies or retries a customer's traffic — the probe is a
// measurement device and must stay out of the request path.
package probe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/moveeeax/rpc-lag-probe/internal/alert"
	"github.com/moveeeax/rpc-lag-probe/internal/analysis"
	"github.com/moveeeax/rpc-lag-probe/internal/config"
	"github.com/moveeeax/rpc-lag-probe/internal/evidence"
	"github.com/moveeeax/rpc-lag-probe/internal/metrics"
	"github.com/moveeeax/rpc-lag-probe/internal/rpc"
)

// Probe measures a set of endpoints.
type Probe struct {
	cfg      *config.Config
	clients  map[string]*rpc.Client
	clocks   map[config.Chain]*analysis.HeightClock
	registry *metrics.Registry
	writer   *evidence.Writer
	notifier alert.Notifier
	gate     *alert.Gate
	log      *slog.Logger

	mu            sync.Mutex
	lastHashCheck map[config.Chain]time.Time
	// lastChecked stops the probe re-comparing a finalised height it already
	// compared, which would double-count a single divergence.
	lastChecked map[config.Chain]uint64
}

// Option configures a Probe.
type Option func(*Probe)

// WithEvidence attaches an evidence log.
func WithEvidence(w *evidence.Writer) Option { return func(p *Probe) { p.writer = w } }

// WithMetrics attaches a metrics registry.
func WithMetrics(r *metrics.Registry) Option { return func(p *Probe) { p.registry = r } }

// WithNotifier attaches an alert sink.
func WithNotifier(n alert.Notifier) Option { return func(p *Probe) { p.notifier = n } }

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option { return func(p *Probe) { p.log = l } }

// New builds a probe from validated configuration.
func New(cfg *config.Config, opts ...Option) (*Probe, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p := &Probe{
		cfg:           cfg,
		clients:       make(map[string]*rpc.Client, len(cfg.Endpoints)),
		clocks:        map[config.Chain]*analysis.HeightClock{},
		lastHashCheck: map[config.Chain]time.Time{},
		lastChecked:   map[config.Chain]uint64{},
		log:           slog.Default(),
		gate:          alert.NewGate(cfg.Alerts.ForDuration, cfg.Alerts.Cooldown),
	}
	for _, o := range opts {
		o(p)
	}
	for _, e := range cfg.Endpoints {
		p.clients[e.Name] = rpc.New(e.URL, e.Headers, cfg.Timeout)
	}
	for _, ch := range cfg.Chains() {
		p.clocks[ch] = analysis.NewHeightClock(4096)
	}
	return p, nil
}

// TickResult is what one round observed, returned for tests and for --once.
type TickResult struct {
	At          time.Time
	Lags        []analysis.Lag
	Divergences []analysis.DivergenceEvent
}

// Run polls until the context is cancelled. The first tick fires immediately
// so a short run still produces evidence.
func (p *Probe) Run(ctx context.Context) error {
	p.record(evidence.Record{
		TS: time.Now(), Type: evidence.TypeRunStarted, Region: p.cfg.Region,
		Message: fmt.Sprintf("probing %d endpoints across %d chain(s) every %s",
			len(p.cfg.Endpoints), len(p.cfg.Chains()), p.cfg.Interval),
	})
	defer p.record(evidence.Record{TS: time.Now(), Type: evidence.TypeRunFinished, Region: p.cfg.Region})

	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()
	for {
		res := p.Tick(ctx, time.Now())
		p.logTick(res)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Tick runs exactly one measurement round for every chain.
func (p *Probe) Tick(ctx context.Context, at time.Time) TickResult {
	at = at.UTC()
	res := TickResult{At: at}
	for _, ch := range p.cfg.Chains() {
		lags := p.tickChain(ctx, ch, at)
		res.Lags = append(res.Lags, lags...)
		if ev := p.maybeCheckHashes(ctx, ch, lags, at); ev != nil {
			res.Divergences = append(res.Divergences, *ev)
		}
	}
	return res
}

func (p *Probe) tickChain(ctx context.Context, ch config.Chain, at time.Time) []analysis.Lag {
	endpoints := p.cfg.EndpointsFor(ch)
	samples := make([]analysis.HeadSample, len(endpoints))

	var wg sync.WaitGroup
	for i, e := range endpoints {
		wg.Add(1)
		go func(i int, e config.Endpoint) {
			defer wg.Done()
			samples[i] = p.pollHead(ctx, e, at)
		}(i, e)
	}
	wg.Wait()

	lags := analysis.ComputeLag(samples, at, p.clocks[ch])
	rules := analysis.IncidentRules{LagBlocks: p.cfg.Alerts.LagBlocks, LagSeconds: p.cfg.Alerts.LagSeconds}
	for _, l := range lags {
		if p.registry != nil {
			p.registry.ObserveLag(l)
		}
		p.record(evidence.Record{TS: l.At, Type: evidence.TypeLag, Region: l.Region, Chain: l.Chain, Lag: &l})
		p.maybeAlert(ctx, l, rules, at)
	}
	return lags
}

func (p *Probe) pollHead(ctx context.Context, e config.Endpoint, at time.Time) analysis.HeadSample {
	callCtx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()

	s := analysis.HeadSample{
		At: at, Endpoint: e.Name, Provider: e.Provider,
		Region: e.Region, Chain: string(e.Chain), ErrClass: string(rpc.ClassOK),
	}
	height, latency, err := p.clients[e.Name].BlockNumber(callCtx)
	s.Latency = latency
	if err != nil {
		s.ErrClass = string(rpc.ClassOf(err))
		s.Err = err.Error()
		var rerr *rpc.Error
		if errors.As(err, &rerr) {
			s.Status = rerr.HTTPStatus
		}
		return s
	}
	s.Height = height
	return s
}

// maybeCheckHashes compares block hashes at a finalised height, no more often
// than the configured hash-check interval and never twice at the same height.
func (p *Probe) maybeCheckHashes(ctx context.Context, ch config.Chain, lags []analysis.Lag, at time.Time) *analysis.DivergenceEvent {
	var best uint64
	for _, l := range lags {
		if l.Healthy() && l.Height > best {
			best = l.Height
		}
	}
	height, ok := analysis.FinalisedHeight(best, p.cfg.FinalityDepth)
	if !ok {
		return nil
	}

	p.mu.Lock()
	last := p.lastHashCheck[ch]
	if !last.IsZero() && at.Sub(last) < p.cfg.HashCheckInterval {
		p.mu.Unlock()
		return nil
	}
	if p.lastChecked[ch] == height {
		p.mu.Unlock()
		return nil
	}
	p.lastHashCheck[ch] = at
	p.lastChecked[ch] = height
	p.mu.Unlock()

	obs := p.fetchHashes(ctx, ch, height)
	ev, found := analysis.DetectDivergence(string(ch), height, obs, at)
	if !found {
		return nil
	}
	if p.registry != nil {
		p.registry.ObserveDivergence(string(ch))
	}
	p.record(evidence.Record{TS: at, Type: evidence.TypeDivergence, Region: p.cfg.Region, Chain: string(ch), Divergence: ev})
	p.log.Warn("hash divergence", "chain", ch, "height", height, "clusters", len(ev.Clusters))
	if p.cfg.Alerts.OnDivergence {
		a := alert.FromDivergence(*ev)
		if p.gate.Allow(a.Key(), true, at) {
			p.send(ctx, a)
		}
	}
	return ev
}

func (p *Probe) fetchHashes(ctx context.Context, ch config.Chain, height uint64) []analysis.HashObservation {
	endpoints := p.cfg.EndpointsFor(ch)
	obs := make([]analysis.HashObservation, len(endpoints))

	var wg sync.WaitGroup
	for i, e := range endpoints {
		wg.Add(1)
		go func(i int, e config.Endpoint) {
			defer wg.Done()
			callCtx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
			defer cancel()
			o := analysis.HashObservation{Endpoint: e.Name, Provider: e.Provider, Region: e.Region, Height: height}
			blk, _, err := p.clients[e.Name].BlockByNumber(callCtx, height)
			switch {
			case errors.Is(err, rpc.ErrBlockNotFound):
				o.ErrClass = "not_found"
				o.Err = err.Error()
			case err != nil:
				o.ErrClass = string(rpc.ClassOf(err))
				o.Err = err.Error()
			default:
				o.Hash = blk.Hash
				o.Raw = blk.Raw
			}
			obs[i] = o
		}(i, e)
	}
	wg.Wait()
	return obs
}

func (p *Probe) maybeAlert(ctx context.Context, l analysis.Lag, rules analysis.IncidentRules, at time.Time) {
	if p.notifier == nil {
		return
	}
	unavailable := !l.Healthy()
	lagging := !unavailable && breaches(l, rules)

	unavailKey := analysis.KindUnavailable + "/" + l.Chain + "/" + l.Endpoint
	lagKey := analysis.KindLag + "/" + l.Chain + "/" + l.Endpoint
	if p.gate.Allow(unavailKey, unavailable, at) {
		p.send(ctx, alert.FromUnavailable(l))
	}
	if p.gate.Allow(lagKey, lagging, at) {
		p.send(ctx, alert.FromLag(l))
	}
}

func breaches(l analysis.Lag, rules analysis.IncidentRules) bool {
	if rules.LagBlocks > 0 && l.LagBlocks >= rules.LagBlocks {
		return true
	}
	if rules.LagSeconds > 0 && l.LagSeconds >= rules.LagSeconds {
		return true
	}
	return false
}

func (p *Probe) send(ctx context.Context, a alert.Alert) {
	if p.notifier == nil {
		return
	}
	if err := p.notifier.Notify(ctx, a); err != nil {
		p.log.Error("alert delivery failed", "kind", a.Kind, "endpoint", a.Endpoint, "err", err)
		return
	}
	p.record(evidence.Record{
		TS: a.At, Type: evidence.TypeAlert, Region: a.Region, Chain: a.Chain,
		Message: a.Summary, Meta: map[string]string{"kind": a.Kind, "severity": a.Severity, "endpoint": a.Endpoint},
	})
}

func (p *Probe) record(r evidence.Record) {
	if p.writer == nil {
		return
	}
	if err := p.writer.Write(r); err != nil {
		p.log.Error("evidence write failed", "err", err)
	}
}

func (p *Probe) logTick(res TickResult) {
	for _, l := range res.Lags {
		if !l.Healthy() {
			p.log.Warn("poll failed", "endpoint", l.Endpoint, "class", l.ErrClass, "err", l.Err)
			continue
		}
		p.log.Debug("poll", "endpoint", l.Endpoint, "height", l.Height,
			"lag_blocks", l.LagBlocks, "lag_seconds", l.LagSeconds, "latency_ms", l.Latency.Milliseconds())
	}
}
