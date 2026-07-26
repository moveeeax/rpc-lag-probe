// Package metrics exposes the probe's state in Prometheus text exposition
// format. It is hand-rolled rather than pulling in the client library: the
// metric set is small, fixed, and the binary stays dependency-light, which
// matters for something customers deploy into their own accounts.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moveeeax/rpc-lag-probe/internal/analysis"
)

// LatencyBuckets are the upper bounds, in seconds, of the request-duration
// histogram. They straddle the range where a paid RPC endpoint stops being
// useful for a trading or indexing workload.
var LatencyBuckets = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type histogram struct {
	counts []uint64
	sum    float64
	total  uint64
}

func (h *histogram) observe(v float64) {
	if h.counts == nil {
		h.counts = make([]uint64, len(LatencyBuckets))
	}
	h.sum += v
	h.total++
	for i, b := range LatencyBuckets {
		if v <= b {
			h.counts[i]++
		}
	}
}

type endpointMetrics struct {
	endpoint, provider, region, chain string

	head        uint64
	lagBlocks   uint64
	lagSeconds  float64
	up          float64
	lastSeen    time.Time
	latency     histogram
	requests    map[string]uint64
	rateLimited uint64
}

// Registry holds every series the probe exports.
type Registry struct {
	mu          sync.RWMutex
	version     string
	endpoints   map[string]*endpointMetrics
	divergences map[string]uint64
	startedAt   time.Time
}

// New builds an empty registry.
func New(version string) *Registry {
	return &Registry{
		version:     version,
		endpoints:   map[string]*endpointMetrics{},
		divergences: map[string]uint64{},
		startedAt:   time.Now(),
	}
}

func (r *Registry) forEndpoint(l analysis.Lag) *endpointMetrics {
	m, ok := r.endpoints[l.Endpoint]
	if !ok {
		m = &endpointMetrics{
			endpoint: l.Endpoint,
			provider: l.Provider,
			region:   l.Region,
			chain:    l.Chain,
			requests: map[string]uint64{},
		}
		r.endpoints[l.Endpoint] = m
	}
	return m
}

// ObserveLag folds one scored sample into the registry.
func (r *Registry) ObserveLag(l analysis.Lag) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.forEndpoint(l)
	m.lastSeen = l.At
	if l.Latency > 0 {
		m.latency.observe(l.Latency.Seconds())
	}
	class := l.ErrClass
	if class == "" {
		class = "ok"
	}
	m.requests[class]++
	if !l.Healthy() {
		m.up = 0
		if class == "rate_limited" {
			m.rateLimited++
		}
		return
	}
	m.up = 1
	m.head = l.Height
	m.lagBlocks = l.LagBlocks
	m.lagSeconds = l.LagSeconds
}

// ObserveDivergence counts a divergence event on a chain.
func (r *Registry) ObserveDivergence(chain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.divergences[chain]++
}

// Write renders the exposition format.
func (r *Registry) Write(w *strings.Builder) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.endpoints))
	for n := range r.endpoints {
		names = append(names, n)
	}
	sort.Strings(names)

	fmt.Fprintf(w, "# HELP rpc_probe_build_info Build information for the running probe.\n")
	fmt.Fprintf(w, "# TYPE rpc_probe_build_info gauge\n")
	fmt.Fprintf(w, "rpc_probe_build_info{version=\"%s\"} 1\n", escape(r.version))

	header(w, "rpc_probe_up", "gauge", "1 when the endpoint answered the last head poll.")
	for _, n := range names {
		m := r.endpoints[n]
		fmt.Fprintf(w, "rpc_probe_up%s %s\n", m.labels(), formatFloat(m.up))
	}

	header(w, "rpc_probe_head_block", "gauge", "Latest block height reported by the endpoint.")
	for _, n := range names {
		m := r.endpoints[n]
		fmt.Fprintf(w, "rpc_probe_head_block%s %d\n", m.labels(), m.head)
	}

	header(w, "rpc_probe_lag_blocks", "gauge", "Blocks behind the fastest healthy peer on the same chain.")
	for _, n := range names {
		m := r.endpoints[n]
		fmt.Fprintf(w, "rpc_probe_lag_blocks%s %d\n", m.labels(), m.lagBlocks)
	}

	header(w, "rpc_probe_lag_seconds", "gauge", "Wall-clock age of the endpoint's head, measured by the probe.")
	for _, n := range names {
		m := r.endpoints[n]
		fmt.Fprintf(w, "rpc_probe_lag_seconds%s %s\n", m.labels(), formatFloat(m.lagSeconds))
	}

	header(w, "rpc_probe_requests_total", "counter", "Head polls by outcome class.")
	for _, n := range names {
		m := r.endpoints[n]
		classes := make([]string, 0, len(m.requests))
		for c := range m.requests {
			classes = append(classes, c)
		}
		sort.Strings(classes)
		for _, c := range classes {
			fmt.Fprintf(w, "rpc_probe_requests_total%s %d\n", m.labelsWith("class", c), m.requests[c])
		}
	}

	header(w, "rpc_probe_rate_limited_total", "counter", "Head polls rejected with HTTP 429 or a throttling JSON-RPC error.")
	for _, n := range names {
		m := r.endpoints[n]
		fmt.Fprintf(w, "rpc_probe_rate_limited_total%s %d\n", m.labels(), m.rateLimited)
	}

	header(w, "rpc_probe_request_duration_seconds", "histogram", "Head poll round-trip latency.")
	for _, n := range names {
		m := r.endpoints[n]
		var cumulative uint64
		for i, b := range LatencyBuckets {
			if m.latency.counts != nil {
				cumulative = m.latency.counts[i]
			}
			fmt.Fprintf(w, "rpc_probe_request_duration_seconds_bucket%s %d\n",
				m.labelsWith("le", strconv.FormatFloat(b, 'g', -1, 64)), cumulative)
		}
		fmt.Fprintf(w, "rpc_probe_request_duration_seconds_bucket%s %d\n", m.labelsWith("le", "+Inf"), m.latency.total)
		fmt.Fprintf(w, "rpc_probe_request_duration_seconds_sum%s %s\n", m.labels(), formatFloat(m.latency.sum))
		fmt.Fprintf(w, "rpc_probe_request_duration_seconds_count%s %d\n", m.labels(), m.latency.total)
	}

	header(w, "rpc_probe_divergence_events_total", "counter", "Finalised-height hash disagreements observed between endpoints.")
	chains := make([]string, 0, len(r.divergences))
	for c := range r.divergences {
		chains = append(chains, c)
	}
	sort.Strings(chains)
	if len(chains) == 0 {
		fmt.Fprintf(w, "rpc_probe_divergence_events_total{chain=\"none\"} 0\n")
	}
	for _, c := range chains {
		fmt.Fprintf(w, "rpc_probe_divergence_events_total{chain=\"%s\"} %d\n", escape(c), r.divergences[c])
	}
}

// Handler serves the registry at /metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var b strings.Builder
		r.Write(&b)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(b.String()))
	})
}

// String renders the exposition format, for tests and for `--once` runs.
func (r *Registry) String() string {
	var b strings.Builder
	r.Write(&b)
	return b.String()
}

func header(w *strings.Builder, name, typ, help string) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func (m *endpointMetrics) labels() string {
	return fmt.Sprintf("{endpoint=\"%s\",provider=\"%s\",region=\"%s\",chain=\"%s\"}",
		escape(m.endpoint), escape(m.provider), escape(m.region), escape(m.chain))
}

func (m *endpointMetrics) labelsWith(k, v string) string {
	base := m.labels()
	return base[:len(base)-1] + fmt.Sprintf(",%s=\"%s\"}", k, escape(v))
}

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func escape(s string) string { return labelEscaper.Replace(s) }
