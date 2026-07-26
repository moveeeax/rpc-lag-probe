// Command rpc-lag-probe measures whether paid RPC endpoints are serving stale
// or divergent chain state, from the regions a customer actually runs in, and
// turns the resulting evidence log into an audit deliverable.
//
// It is a measurement device. It never proxies, retries or fails over a
// customer's traffic: nothing here belongs in a request path.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/moveeeax/rpc-lag-probe/internal/alert"
	"github.com/moveeeax/rpc-lag-probe/internal/analysis"
	"github.com/moveeeax/rpc-lag-probe/internal/config"
	"github.com/moveeeax/rpc-lag-probe/internal/evidence"
	"github.com/moveeeax/rpc-lag-probe/internal/metrics"
	"github.com/moveeeax/rpc-lag-probe/internal/probe"
	"github.com/moveeeax/rpc-lag-probe/internal/report"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "v0.1.0"

const usage = `rpc-lag-probe %s — independent evidence that an RPC endpoint is serving stale state.

Usage:
  rpc-lag-probe run       --config FILE [--duration D] [--once]
  rpc-lag-probe report    --evidence FILE [--format markdown|erpc|json]
  rpc-lag-probe validate  --config FILE
  rpc-lag-probe version

Run "rpc-lag-probe <command> --help" for the flags of a command.
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flagHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "rpc-lag-probe:", err)
		os.Exit(1)
	}
}

var flagHelp = errors.New("help requested")

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, version)
		return errors.New("no command given")
	}
	switch args[0] {
	case "run":
		return cmdRun(args[1:], stdout, stderr)
	case "report":
		return cmdReport(args[1:], stdout, stderr)
	case "validate":
		return cmdValidate(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version)
		return nil
	case "help", "--help", "-h":
		fmt.Fprintf(stdout, usage, version)
		return nil
	default:
		fmt.Fprintf(stderr, usage, version)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func cmdRun(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("run", stderr)
	var (
		cfgPath     = fs.String("config", "", "path to the probe configuration (required)")
		duration    = fs.Duration("duration", 0, "stop after this long; 0 runs until interrupted")
		once        = fs.Bool("once", false, "run a single measurement round and exit")
		evidencePth = fs.String("evidence", "", "override the evidence log path from the config")
		metricsAddr = fs.String("metrics-addr", "", "override the Prometheus listen address from the config")
		logLevel    = fs.String("log-level", "info", "debug, info, warn or error")
	)
	if err := parse(fs, args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("--config is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *evidencePth != "" {
		cfg.EvidenceLog = *evidencePth
	}
	if *metricsAddr != "" {
		cfg.MetricsAddr = *metricsAddr
	}

	log := newLogger(stderr, *logLevel)
	registry := metrics.New(version)
	opts := []probe.Option{probe.WithMetrics(registry), probe.WithLogger(log)}

	if cfg.EvidenceLog != "" {
		w, err := evidence.Open(cfg.EvidenceLog)
		if err != nil {
			return err
		}
		defer w.Close()
		opts = append(opts, probe.WithEvidence(w))
		log.Info("evidence log open", "path", w.Path())
	}
	if cfg.Alerts.WebhookURL != "" {
		opts = append(opts, probe.WithNotifier(alert.NewWebhook(cfg.Alerts.WebhookURL, cfg.Timeout)))
		log.Info("alert webhook configured")
	}

	p, err := probe.New(cfg, opts...)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}

	if cfg.MetricsAddr != "" {
		srv := startMetrics(cfg.MetricsAddr, registry, log)
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		}()
	}

	for _, e := range cfg.Endpoints {
		log.Info("endpoint", "name", e.Name, "chain", e.Chain, "region", e.Region, "url", e.RedactedURL())
	}

	if *once {
		res := p.Tick(ctx, time.Now())
		return printTick(stdout, res)
	}
	log.Info("probe started", "interval", cfg.Interval, "endpoints", len(cfg.Endpoints), "region", cfg.Region)
	return p.Run(ctx)
}

func printTick(w io.Writer, res probe.TickResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		At          time.Time                  `json:"at"`
		Lags        []analysis.Lag             `json:"lags"`
		Divergences []analysis.DivergenceEvent `json:"divergences,omitempty"`
	}{res.At, res.Lags, res.Divergences})
}

func startMetrics(addr string, registry *metrics.Registry, log *slog.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", registry.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server stopped", "err", err)
		}
	}()
	log.Info("metrics listening", "addr", addr, "path", "/metrics")
	return srv
}

func cmdReport(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("report", stderr)
	var (
		evidencePth = fs.String("evidence", "", "path to the JSONL evidence log (required)")
		format      = fs.String("format", "markdown", "markdown, erpc or json")
		out         = fs.String("out", "", "write to this file instead of stdout")
		customer    = fs.String("customer", "", "customer name for the report title")
		lagBlocks   = fs.Uint64("lag-blocks", 3, "blocks behind the leader before a sample counts as an incident")
		lagSeconds  = fs.Float64("lag-seconds", 0, "seconds behind before a sample counts as an incident; 0 disables")
		minSamples  = fs.Int("min-samples", 2, "consecutive breaching polls required to open an incident")
		top         = fs.Int("top-incidents", 50, "cap the incident table; 0 shows all")
	)
	if err := parse(fs, args); err != nil {
		return err
	}
	if *evidencePth == "" {
		return errors.New("--evidence is required")
	}
	bundle, err := evidence.Load(*evidencePth)
	if err != nil {
		return err
	}
	if bundle.Malformed > 0 {
		fmt.Fprintf(stderr, "warning: %d malformed line(s) in %s were skipped\n", bundle.Malformed, *evidencePth)
	}
	opts := report.Options{
		Customer:     *customer,
		Rules:        analysis.IncidentRules{LagBlocks: *lagBlocks, LagSeconds: *lagSeconds, MinSamples: *minSamples},
		TopIncidents: *top,
	}

	var rendered string
	switch strings.ToLower(*format) {
	case "markdown", "md":
		rendered = report.Markdown(bundle, opts)
	case "erpc":
		rendered = report.ERPC(report.Analyse(bundle, opts))
	case "json":
		res := report.Analyse(bundle, opts)
		b, err := json.MarshalIndent(struct {
			Endpoints []analysis.EndpointSummary `json:"endpoints"`
			Incidents []analysis.Incident        `json:"incidents"`
			Diverged  []analysis.DivergenceEvent `json:"divergences"`
		}{res.Summaries, res.Incidents, bundle.Divergences}, "", "  ")
		if err != nil {
			return err
		}
		rendered = string(b) + "\n"
	default:
		return fmt.Errorf("unknown --format %q: want markdown, erpc or json", *format)
	}

	if *out == "" {
		_, err := io.WriteString(stdout, rendered)
		return err
	}
	if err := os.WriteFile(*out, []byte(rendered), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "wrote %s (%d bytes)\n", *out, len(rendered))
	return nil
}

func cmdValidate(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("validate", stderr)
	cfgPath := fs.String("config", "", "path to the probe configuration (required)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("--config is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "config OK: %s\n", *cfgPath)
	fmt.Fprintf(stdout, "  region             %s\n", cfg.Region)
	fmt.Fprintf(stdout, "  interval           %s (timeout %s)\n", cfg.Interval, cfg.Timeout)
	fmt.Fprintf(stdout, "  finality depth     %d blocks, hash check every %s\n", cfg.FinalityDepth, cfg.HashCheckInterval)
	fmt.Fprintf(stdout, "  evidence log       %s\n", orNone(cfg.EvidenceLog))
	fmt.Fprintf(stdout, "  metrics            %s\n", orNone(cfg.MetricsAddr))
	fmt.Fprintf(stdout, "  alert webhook      %s\n", boolWord(cfg.Alerts.WebhookURL != "", "configured", "not configured"))
	fmt.Fprintf(stdout, "  lag thresholds     %d blocks / %.0fs, for %s, cooldown %s\n",
		cfg.Alerts.LagBlocks, cfg.Alerts.LagSeconds, cfg.Alerts.ForDuration, cfg.Alerts.Cooldown)
	fmt.Fprintf(stdout, "  endpoints          %d across %d chain(s)\n\n", len(cfg.Endpoints), len(cfg.Chains()))
	for _, e := range cfg.Endpoints {
		fmt.Fprintf(stdout, "  - %-20s %-9s %-16s %s\n", e.Name, e.Chain, e.Region, e.RedactedURL())
		if h := e.RedactedHeaders(); len(h) > 0 {
			names := make([]string, 0, len(h))
			for k := range h {
				names = append(names, k)
			}
			fmt.Fprintf(stdout, "    %-20s headers: %s (values redacted)\n", "", strings.Join(names, ", "))
		}
	}
	return nil
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parse turns -h into a sentinel the caller can exit cleanly on, so asking for
// help is not reported as a failure.
func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return flagHelp
		}
		return err
	}
	return nil
}

func newLogger(w io.Writer, level string) *slog.Logger {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lv}))
}

func orNone(s string) string {
	if s == "" {
		return "(disabled)"
	}
	return s
}

func boolWord(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}
