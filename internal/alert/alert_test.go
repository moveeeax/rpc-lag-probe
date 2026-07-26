package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moveeeax/rpc-lag-probe/internal/analysis"
)

var t0 = time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)

func TestGateRequiresConditionToHoldForDuration(t *testing.T) {
	g := NewGate(30*time.Second, 10*time.Minute)
	if g.Allow("k", true, t0) {
		t.Error("fired immediately, before the for-duration elapsed")
	}
	if g.Allow("k", true, t0.Add(20*time.Second)) {
		t.Error("fired early")
	}
	if !g.Allow("k", true, t0.Add(30*time.Second)) {
		t.Error("did not fire once the condition had held long enough")
	}
}

func TestGateCooldownSuppressesRepeats(t *testing.T) {
	g := NewGate(0, 5*time.Minute)
	if !g.Allow("k", true, t0) {
		t.Fatal("first alert suppressed")
	}
	for _, d := range []time.Duration{time.Second, time.Minute, 4 * time.Minute} {
		if g.Allow("k", true, t0.Add(d)) {
			t.Errorf("re-fired after %s, inside the cooldown", d)
		}
	}
	if !g.Allow("k", true, t0.Add(5*time.Minute)) {
		t.Error("did not re-fire after the cooldown expired")
	}
}

func TestGateResetsWhenConditionClears(t *testing.T) {
	g := NewGate(10*time.Second, time.Hour)
	g.Allow("k", true, t0)
	if g.Allow("k", false, t0.Add(5*time.Second)) {
		t.Error("a cleared condition must not alert")
	}
	// The for-duration restarts from the new breach, not from the old one.
	if g.Allow("k", true, t0.Add(11*time.Second)) {
		t.Error("fired using the stale breach start time")
	}
	if !g.Allow("k", true, t0.Add(21*time.Second)) {
		t.Error("did not fire after the new breach held long enough")
	}
}

func TestGateKeysAreIndependent(t *testing.T) {
	g := NewGate(0, time.Hour)
	if !g.Allow("a", true, t0) || !g.Allow("b", true, t0) {
		t.Error("one endpoint's alert suppressed another's")
	}
}

func TestGateResolved(t *testing.T) {
	g := NewGate(0, time.Hour)
	g.Allow("k", true, t0)
	if !g.Resolved("k", t0.Add(time.Minute)) {
		t.Error("a firing key should resolve exactly once")
	}
	if g.Resolved("k", t0.Add(2*time.Minute)) {
		t.Error("resolved twice")
	}
	// After resolving, the same key can fire again straight away.
	if !g.Allow("k", true, t0.Add(3*time.Minute)) {
		t.Error("key did not re-arm after resolving")
	}
}

func TestGateIsConcurrencySafe(t *testing.T) {
	g := NewGate(0, time.Hour)
	var wg sync.WaitGroup
	fired := make(chan bool, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fired <- g.Allow("shared", true, t0)
		}()
	}
	wg.Wait()
	close(fired)
	n := 0
	for f := range fired {
		if f {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d goroutines fired the same alert, want exactly 1", n)
	}
}

func TestWebhookDelivers(t *testing.T) {
	var got Alert
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	a := FromLag(analysis.Lag{
		HeadSample: analysis.HeadSample{
			At: t0, Endpoint: "provider-c", Region: "ap-southeast-1", Chain: "ethereum", Height: 19999994, ErrClass: "ok",
		},
		LagBlocks: 6, LagSeconds: 62, BestHeight: 20000000,
	})
	if err := NewWebhook(srv.URL, time.Second).Notify(context.Background(), a); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if contentType != "application/json" {
		t.Errorf("content-type = %q", contentType)
	}
	if got.Endpoint != "provider-c" || got.Chain != "ethereum" {
		t.Errorf("payload = %+v", got)
	}
	if !strings.Contains(got.Summary, "6 blocks") || !strings.Contains(got.Summary, "ap-southeast-1") {
		t.Errorf("summary is not actionable: %q", got.Summary)
	}
}

func TestWebhookReportsNonSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "gateway exploded")
	}))
	defer srv.Close()

	err := NewWebhook(srv.URL, time.Second).Notify(context.Background(), Alert{Kind: "lag"})
	if err == nil {
		t.Fatal("a 500 from the gateway must not be swallowed")
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "gateway exploded") {
		t.Errorf("error = %q", err)
	}
}

func TestSeverityEscalatesWithLag(t *testing.T) {
	small := FromLag(analysis.Lag{HeadSample: analysis.HeadSample{Endpoint: "e"}, LagBlocks: 3})
	big := FromLag(analysis.Lag{HeadSample: analysis.HeadSample{Endpoint: "e"}, LagBlocks: 12})
	if small.Severity != SeverityWarning || big.Severity != SeverityCritical {
		t.Errorf("severities = %s, %s", small.Severity, big.Severity)
	}
}

func TestFromDivergenceIsAlwaysCritical(t *testing.T) {
	ev := analysis.DivergenceEvent{
		DetectedAt: t0, Chain: "ethereum", Height: 19999936,
		Clusters: []analysis.HashCluster{
			{Hash: "0xaaa", Endpoints: []string{"a", "b"}},
			{Hash: "0xbbb", Endpoints: []string{"c"}},
		},
	}
	a := FromDivergence(ev)
	if a.Severity != SeverityCritical {
		t.Errorf("severity = %s, want critical", a.Severity)
	}
	if !strings.Contains(a.Summary, "19999936") || !strings.Contains(a.Summary, "0xbbb") {
		t.Errorf("summary = %q", a.Summary)
	}
	if a.Key() != "divergence/ethereum/" {
		t.Errorf("key = %q", a.Key())
	}
}

func TestFromUnavailableCarriesTheErrorClass(t *testing.T) {
	a := FromUnavailable(analysis.Lag{HeadSample: analysis.HeadSample{
		Endpoint: "e", Region: "eu-central-1", ErrClass: "timeout", Err: "context deadline exceeded",
	}})
	if !strings.Contains(a.Summary, "timeout") || !strings.Contains(a.Summary, "context deadline exceeded") {
		t.Errorf("summary = %q", a.Summary)
	}
}
