// Package alert turns probe findings into outbound notifications.
//
// Delivery is a plain JSON webhook. That is deliberate: the probe should not
// grow one client per chat product, and every gateway worth using (including
// the owner's telegram-rest-gateway) already accepts a JSON POST.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/moveeeax/rpc-lag-probe/internal/analysis"
)

// Severity levels.
const (
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Alert is one outbound notification.
type Alert struct {
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Endpoint string    `json:"endpoint,omitempty"`
	Provider string    `json:"provider,omitempty"`
	Region   string    `json:"region,omitempty"`
	Chain    string    `json:"chain,omitempty"`
	Summary  string    `json:"summary"`
	Details  any       `json:"details,omitempty"`
}

// Key identifies the alerting series, for throttling.
func (a Alert) Key() string { return a.Kind + "/" + a.Chain + "/" + a.Endpoint }

// FromLag builds a lag alert from a breaching sample.
func FromLag(l analysis.Lag) Alert {
	sev := SeverityWarning
	if l.LagBlocks >= 10 {
		sev = SeverityCritical
	}
	return Alert{
		At:       l.At,
		Kind:     analysis.KindLag,
		Severity: sev,
		Endpoint: l.Endpoint,
		Provider: l.Provider,
		Region:   l.Region,
		Chain:    l.Chain,
		Summary: fmt.Sprintf("%s is %d blocks (%.1fs) behind the fastest peer on %s, head %d vs %d, seen from %s",
			l.Endpoint, l.LagBlocks, l.LagSeconds, l.Chain, l.Height, l.BestHeight, l.Region),
		Details: l,
	}
}

// FromUnavailable builds an alert for an endpoint that stopped answering.
func FromUnavailable(l analysis.Lag) Alert {
	return Alert{
		At:       l.At,
		Kind:     analysis.KindUnavailable,
		Severity: SeverityWarning,
		Endpoint: l.Endpoint,
		Provider: l.Provider,
		Region:   l.Region,
		Chain:    l.Chain,
		Summary:  fmt.Sprintf("%s failed its head poll from %s: %s (%s)", l.Endpoint, l.Region, l.ErrClass, l.Err),
		Details:  l,
	}
}

// FromDivergence builds a divergence alert. Divergence is always critical: two
// endpoints disagreeing about a finalised block is the finding the audit sells.
func FromDivergence(ev analysis.DivergenceEvent) Alert {
	names := make([]string, 0, len(ev.Clusters))
	for _, c := range ev.Clusters {
		names = append(names, fmt.Sprintf("%s=%s", strings.Join(c.Endpoints, "+"), c.Hash))
	}
	return Alert{
		At:       ev.DetectedAt,
		Kind:     analysis.KindDivergence,
		Severity: SeverityCritical,
		Chain:    ev.Chain,
		Summary: fmt.Sprintf("hash divergence on %s at finalised height %d: %s",
			ev.Chain, ev.Height, strings.Join(names, ", ")),
		Details: ev,
	}
}

// Notifier delivers an alert.
type Notifier interface {
	Notify(ctx context.Context, a Alert) error
}

// Webhook posts alerts as JSON.
type Webhook struct {
	URL    string
	Client *http.Client
}

// NewWebhook builds a webhook notifier with a delivery timeout.
func NewWebhook(url string, timeout time.Duration) *Webhook {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Webhook{URL: url, Client: &http.Client{Timeout: timeout}}
}

// Notify delivers one alert. A non-2xx response is an error: silent alert loss
// is worse than a noisy log line.
func (w *Webhook) Notify(ctx context.Context, a Alert) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.Client.Do(req)
	if err != nil {
		return fmt.Errorf("deliver alert: %w", err)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// Gate suppresses flapping and repeat alerts. A condition must hold for For
// before it fires, and cannot fire again within Cooldown.
type Gate struct {
	For      time.Duration
	Cooldown time.Duration

	mu     sync.Mutex
	since  map[string]time.Time
	fired  map[string]time.Time
	active map[string]bool
}

// NewGate builds a gate.
func NewGate(forDuration, cooldown time.Duration) *Gate {
	return &Gate{
		For:      forDuration,
		Cooldown: cooldown,
		since:    map[string]time.Time{},
		fired:    map[string]time.Time{},
		active:   map[string]bool{},
	}
}

// Allow reports whether an alert for key should be sent now. Callers pass the
// current truth of the condition on every tick, including when it is false, so
// the gate can reset.
func (g *Gate) Allow(key string, breaching bool, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !breaching {
		delete(g.since, key)
		delete(g.active, key)
		return false
	}
	start, ok := g.since[key]
	if !ok {
		g.since[key] = now
		start = now
	}
	if now.Sub(start) < g.For {
		return false
	}
	if last, ok := g.fired[key]; ok && now.Sub(last) < g.Cooldown {
		return false
	}
	g.fired[key] = now
	g.active[key] = true
	return true
}

// Resolved reports whether a previously firing key has recovered, and clears
// it. Used to send a single recovery notice.
func (g *Gate) Resolved(key string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active[key] {
		delete(g.active, key)
		delete(g.since, key)
		delete(g.fired, key)
		return true
	}
	return false
}
