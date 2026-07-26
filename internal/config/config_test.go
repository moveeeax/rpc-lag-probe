package config

import (
	"strings"
	"testing"
	"time"
)

const minimal = `
region: eu-central-1
interval: 2s
timeout: 1s
endpoints:
  - name: a
    url: https://a.example/rpc
    chain: ethereum
  - name: b
    url: https://b.example/rpc
    chain: ethereum
`

func env(pairs map[string]string) LookupFunc {
	return func(k string) (string, bool) {
		v, ok := pairs[k]
		return v, ok
	}
}

func TestParseAppliesDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimal), env(nil))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Interval != 2*time.Second || cfg.Timeout != time.Second {
		t.Errorf("durations not decoded: interval=%s timeout=%s", cfg.Interval, cfg.Timeout)
	}
	if cfg.FinalityDepth != DefaultFinalityDepth {
		t.Errorf("finality depth = %d, want %d", cfg.FinalityDepth, DefaultFinalityDepth)
	}
	if cfg.HashCheckInterval != DefaultHashCheckInterval {
		t.Errorf("hash check interval = %s, want %s", cfg.HashCheckInterval, DefaultHashCheckInterval)
	}
	if cfg.Alerts.Cooldown != DefaultCooldown {
		t.Errorf("cooldown = %s, want %s", cfg.Alerts.Cooldown, DefaultCooldown)
	}
	for _, e := range cfg.Endpoints {
		if e.Region != "eu-central-1" {
			t.Errorf("endpoint %s inherited region %q, want the global one", e.Name, e.Region)
		}
	}
	if got := cfg.Endpoints[0].Provider; got != "a" {
		t.Errorf("provider inferred as %q, want %q", got, "a")
	}
	if chains := cfg.Chains(); len(chains) != 1 || chains[0] != ChainEthereum {
		t.Errorf("chains = %v", chains)
	}
}

func TestParseExpandsPlaceholders(t *testing.T) {
	src := `
region: r1
interval: 2s
timeout: 1s
alerts:
  webhook_url: ${HOOK}
endpoints:
  - name: a
    url: https://a.example/v2/${A_KEY}
    chain: base
    headers:
      X-Api-Key: ${A_KEY}
  - name: b
    url: https://b.example/rpc
    chain: base
`
	cfg, err := Parse([]byte(src), env(map[string]string{
		"HOOK":  "https://hooks.example/abc",
		"A_KEY": "secret-key-value-1234567",
	}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.HasSuffix(cfg.Endpoints[0].URL, "secret-key-value-1234567") {
		t.Errorf("url not expanded: %s", cfg.Endpoints[0].URL)
	}
	if cfg.Endpoints[0].Headers["X-Api-Key"] != "secret-key-value-1234567" {
		t.Errorf("header not expanded: %v", cfg.Endpoints[0].Headers)
	}
	if cfg.Alerts.WebhookURL != "https://hooks.example/abc" {
		t.Errorf("webhook not expanded: %s", cfg.Alerts.WebhookURL)
	}
}

func TestParseReportsEveryMissingVariable(t *testing.T) {
	src := `
region: r1
interval: 2s
timeout: 1s
alerts:
  webhook_url: ${HOOK}
endpoints:
  - name: a
    url: https://a.example/v2/${A_KEY}
    chain: ethereum
  - name: b
    url: https://b.example/v2/${B_KEY}
    chain: ethereum
`
	_, err := Parse([]byte(src), env(map[string]string{"A_KEY": "x"}))
	if err == nil {
		t.Fatal("expected an error for unset variables")
	}
	for _, want := range []string{"B_KEY", "HOOK"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
	if strings.Contains(err.Error(), "A_KEY") {
		t.Errorf("error mentions the variable that was set: %q", err)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	src := minimal + "\nunexpected_field: 1\n"
	if _, err := Parse([]byte(src), env(nil)); err == nil {
		t.Fatal("expected an error for an unknown top-level field")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"timeout over interval", func(c *Config) { c.Timeout = 10 * time.Second }, "must not exceed interval"},
		{"single peer on a chain", func(c *Config) { c.Endpoints = c.Endpoints[:1] }, "at least 2 peers"},
		{"duplicate names", func(c *Config) { c.Endpoints[1].Name = c.Endpoints[0].Name }, "duplicate endpoint name"},
		{"unsupported chain", func(c *Config) { c.Endpoints[0].Chain = "solana" }, "chain must be"},
		{"bad scheme", func(c *Config) { c.Endpoints[0].URL = "ws://a.example" }, "scheme must be http"},
		{"shallow finality", func(c *Config) { c.FinalityDepth = 1 }, "finality_depth must be at least 2"},
		{"hash check faster than tick", func(c *Config) { c.HashCheckInterval = time.Millisecond }, "must be at least the poll interval"},
		{"missing region", func(c *Config) { c.Endpoints[0].Region = "" }, "region is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte(minimal), env(nil))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			tc.mut(cfg)
			err = cfg.Validate()
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestRedactedURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://eth.example/v2/abcdefghijklmnopqrstuvwxyz", "https://eth.example/v2/REDACTED"},
		{"https://eth.example/rpc?apikey=supersecret", "https://eth.example/rpc?apikey=REDACTED"},
		{"https://user:pass@eth.example/rpc", "https://REDACTED@eth.example/rpc"},
		{"https://eth.example/rpc", "https://eth.example/rpc"},
		{"https://eth.example/v1/short", "https://eth.example/v1/short"},
	}
	for _, tc := range tests {
		got := Endpoint{URL: tc.in}.RedactedURL()
		if got != tc.want {
			t.Errorf("RedactedURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.Contains(got, "supersecret") || strings.Contains(got, "abcdefghijklmnopqrstuvwxyz") {
			t.Errorf("redaction leaked the secret: %q", got)
		}
	}
}

func TestRedactedHeadersKeepsOnlyNames(t *testing.T) {
	e := Endpoint{Headers: map[string]string{"X-Api-Key": "supersecret", "Accept": "application/json"}}
	got := e.RedactedHeaders()
	for k, v := range got {
		if v != "REDACTED" {
			t.Errorf("header %s = %q, want REDACTED", k, v)
		}
	}
	if len(got) != 2 {
		t.Errorf("got %d headers, want 2", len(got))
	}
}

func TestProviderFromURL(t *testing.T) {
	tests := map[string]string{
		"https://eth-mainnet.provider-a.example/v2/key": "provider-a",
		"https://rpc.provider-b.example/ethereum":       "provider-b",
		"https://localhost:8545":                        "localhost",
		"not a url at all %%":                           "unknown",
	}
	for in, want := range tests {
		if got := providerFromURL(in); got != want {
			t.Errorf("providerFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestChainID(t *testing.T) {
	if ChainEthereum.ChainID() != 1 || ChainBase.ChainID() != 8453 {
		t.Errorf("unexpected chain ids: %d %d", ChainEthereum.ChainID(), ChainBase.ChainID())
	}
	if Chain("dogecoin").ChainID() != 0 {
		t.Error("unknown chain should have id 0")
	}
}

func TestEndpointsFor(t *testing.T) {
	src := minimal + `
  - name: c
    url: https://c.example/rpc
    chain: base
  - name: d
    url: https://d.example/rpc
    chain: base
`
	cfg, err := Parse([]byte(src), env(nil))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := len(cfg.EndpointsFor(ChainBase)); got != 2 {
		t.Errorf("base endpoints = %d, want 2", got)
	}
	if got := len(cfg.EndpointsFor(ChainEthereum)); got != 2 {
		t.Errorf("ethereum endpoints = %d, want 2", got)
	}
}
