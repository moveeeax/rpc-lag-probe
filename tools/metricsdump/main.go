// Command metricsdump prints the probe's Prometheus exposition with a sample
// of every series filled in. CI feeds it to `promtool check metrics` so a
// hand-rolled exposition format cannot quietly drift out of spec.
package main

import (
	"fmt"
	"time"

	"github.com/moveeeax/rpc-lag-probe/internal/analysis"
	"github.com/moveeeax/rpc-lag-probe/internal/metrics"
)

func main() {
	reg := metrics.New("dev")
	now := time.Now().UTC()

	samples := []analysis.Lag{
		{HeadSample: analysis.HeadSample{
			At: now, Endpoint: "provider-a", Provider: "provider-a", Region: "eu-central-1",
			Chain: "ethereum", Height: 20000000, Latency: 45 * time.Millisecond, ErrClass: "ok",
		}, Leader: true, BestHeight: 20000000},
		{HeadSample: analysis.HeadSample{
			At: now, Endpoint: "provider-b", Provider: "provider-b", Region: "us-east-1",
			Chain: "ethereum", Height: 19999997, Latency: 310 * time.Millisecond, ErrClass: "ok",
		}, LagBlocks: 3, LagSeconds: 36, BestHeight: 20000000},
		{HeadSample: analysis.HeadSample{
			At: now, Endpoint: "provider-c", Provider: "provider-c", Region: "ap-southeast-1",
			Chain: "base", Latency: 20 * time.Millisecond, ErrClass: "rate_limited", Err: "HTTP 429", Status: 429,
		}},
	}
	for _, s := range samples {
		reg.ObserveLag(s)
	}
	reg.ObserveDivergence("ethereum")
	fmt.Print(reg.String())
}
