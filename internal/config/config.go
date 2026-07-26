// Package config loads and validates the probe configuration.
//
// Secrets never live in the config file. Any ${VAR} placeholder in an endpoint
// URL or header value is resolved from the process environment at load time,
// and every code path that renders an endpoint back to a human or to disk uses
// the redacted form.
package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Chain is a supported EVM chain. v1 is deliberately limited to two.
type Chain string

const (
	ChainEthereum Chain = "ethereum"
	ChainBase     Chain = "base"
)

// ChainID returns the EVM chain id, used when generating eRPC upstreams.
func (c Chain) ChainID() int {
	switch c {
	case ChainEthereum:
		return 1
	case ChainBase:
		return 8453
	default:
		return 0
	}
}

// Endpoint is one RPC endpoint under measurement.
type Endpoint struct {
	Name     string            `yaml:"name"`
	URL      string            `yaml:"url"`
	Chain    Chain             `yaml:"chain"`
	Region   string            `yaml:"region"`
	Provider string            `yaml:"provider"`
	Headers  map[string]string `yaml:"headers"`
}

// Alerts controls when the probe fires and where it sends.
type Alerts struct {
	WebhookURL   string        `yaml:"webhook_url"`
	LagBlocks    uint64        `yaml:"lag_blocks_threshold"`
	LagSeconds   float64       `yaml:"lag_seconds_threshold"`
	ForDuration  time.Duration `yaml:"for"`
	Cooldown     time.Duration `yaml:"cooldown"`
	OnDivergence bool          `yaml:"on_divergence"`
}

// Config is the whole probe configuration.
type Config struct {
	Region        string        `yaml:"region"`
	Interval      time.Duration `yaml:"interval"`
	Timeout       time.Duration `yaml:"timeout"`
	FinalityDepth uint64        `yaml:"finality_depth"`
	// HashCheckInterval is how often hashes are compared at a finalised
	// height. It is far coarser than the head poll on purpose: a full block
	// header fetch on every endpoint every two seconds burns paid quota for no
	// extra signal.
	HashCheckInterval time.Duration `yaml:"hash_check_interval"`
	EvidenceLog       string        `yaml:"evidence_log"`
	MetricsAddr       string        `yaml:"metrics_addr"`
	Alerts            Alerts        `yaml:"alerts"`
	Endpoints         []Endpoint    `yaml:"endpoints"`
}

// Defaults applied before validation.
const (
	DefaultInterval          = 2 * time.Second
	DefaultTimeout           = 3 * time.Second
	DefaultFinalityDepth     = 64
	DefaultCooldown          = 5 * time.Minute
	DefaultHashCheckInterval = 30 * time.Second
)

var placeholderRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Load reads, expands and validates a configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw, os.LookupEnv)
}

// LookupFunc resolves a ${VAR} placeholder. os.LookupEnv satisfies it.
type LookupFunc func(string) (string, bool)

// Parse decodes YAML, expands placeholders through lookup and validates.
func Parse(raw []byte, lookup LookupFunc) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.expand(lookup); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Interval == 0 {
		c.Interval = DefaultInterval
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.FinalityDepth == 0 {
		c.FinalityDepth = DefaultFinalityDepth
	}
	if c.HashCheckInterval == 0 {
		c.HashCheckInterval = DefaultHashCheckInterval
	}
	if c.Alerts.Cooldown == 0 {
		c.Alerts.Cooldown = DefaultCooldown
	}
	for i := range c.Endpoints {
		if c.Endpoints[i].Region == "" {
			c.Endpoints[i].Region = c.Region
		}
		if c.Endpoints[i].Provider == "" {
			c.Endpoints[i].Provider = providerFromURL(c.Endpoints[i].URL)
		}
	}
}

// expand resolves every ${VAR} placeholder. Missing variables are reported
// together so a first run does not turn into a guessing game.
func (c *Config) expand(lookup LookupFunc) error {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	missing := map[string]bool{}
	sub := func(s string) string {
		return placeholderRe.ReplaceAllStringFunc(s, func(m string) string {
			name := placeholderRe.FindStringSubmatch(m)[1]
			v, ok := lookup(name)
			if !ok || v == "" {
				missing[name] = true
				return m
			}
			return v
		})
	}
	for i := range c.Endpoints {
		c.Endpoints[i].URL = sub(c.Endpoints[i].URL)
		for k, v := range c.Endpoints[i].Headers {
			c.Endpoints[i].Headers[k] = sub(v)
		}
	}
	c.Alerts.WebhookURL = sub(c.Alerts.WebhookURL)
	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for n := range missing {
			names = append(names, n)
		}
		sort.Strings(names)
		return fmt.Errorf("unset environment variables referenced by config: %s", strings.Join(names, ", "))
	}
	return nil
}

// Validate checks the semantic rules the probe depends on.
func (c *Config) Validate() error {
	if len(c.Endpoints) == 0 {
		return fmt.Errorf("no endpoints configured")
	}
	if c.Interval <= 0 {
		return fmt.Errorf("interval must be positive, got %s", c.Interval)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive, got %s", c.Timeout)
	}
	if c.Timeout > c.Interval {
		return fmt.Errorf("timeout (%s) must not exceed interval (%s), or polls will overlap", c.Timeout, c.Interval)
	}
	if c.HashCheckInterval < c.Interval {
		return fmt.Errorf("hash_check_interval (%s) must be at least the poll interval (%s)", c.HashCheckInterval, c.Interval)
	}
	if c.FinalityDepth < 2 {
		return fmt.Errorf("finality_depth must be at least 2, got %d: comparing hashes near the head turns every reorg into a false positive", c.FinalityDepth)
	}
	seen := map[string]bool{}
	chains := map[Chain]bool{}
	for i, e := range c.Endpoints {
		where := fmt.Sprintf("endpoints[%d]", i)
		if e.Name == "" {
			return fmt.Errorf("%s: name is required", where)
		}
		if seen[e.Name] {
			return fmt.Errorf("%s: duplicate endpoint name %q", where, e.Name)
		}
		seen[e.Name] = true
		if e.Chain != ChainEthereum && e.Chain != ChainBase {
			return fmt.Errorf("%s (%s): chain must be %q or %q, got %q", where, e.Name, ChainEthereum, ChainBase, e.Chain)
		}
		chains[e.Chain] = true
		u, err := url.Parse(e.URL)
		if err != nil {
			return fmt.Errorf("%s (%s): invalid url: %w", where, e.Name, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%s (%s): url scheme must be http or https, got %q", where, e.Name, u.Scheme)
		}
		if u.Host == "" {
			return fmt.Errorf("%s (%s): url has no host", where, e.Name)
		}
		if e.Region == "" {
			return fmt.Errorf("%s (%s): region is required (set it per endpoint or globally)", where, e.Name)
		}
	}
	// Lag is only meaningful between peers on the same chain.
	for ch := range chains {
		if count := c.countChain(ch); count < 2 {
			return fmt.Errorf("chain %q has %d endpoint(s): lag needs at least 2 peers to compare against", ch, count)
		}
	}
	return nil
}

func (c *Config) countChain(ch Chain) int {
	n := 0
	for _, e := range c.Endpoints {
		if e.Chain == ch {
			n++
		}
	}
	return n
}

// Chains returns the distinct chains under measurement, sorted.
func (c *Config) Chains() []Chain {
	set := map[Chain]bool{}
	for _, e := range c.Endpoints {
		set[e.Chain] = true
	}
	out := make([]Chain, 0, len(set))
	for ch := range set {
		out = append(out, ch)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// EndpointsFor returns the endpoints on one chain, in config order.
func (c *Config) EndpointsFor(ch Chain) []Endpoint {
	var out []Endpoint
	for _, e := range c.Endpoints {
		if e.Chain == ch {
			out = append(out, e)
		}
	}
	return out
}

// RedactedURL returns the endpoint URL with credential-shaped material masked:
// userinfo, query values and any path segment that looks like a key.
func (e Endpoint) RedactedURL() string {
	u, err := url.Parse(e.URL)
	if err != nil {
		return "<unparseable url>"
	}
	if u.User != nil {
		u.User = url.User("REDACTED")
	}
	if q := u.Query(); len(q) > 0 {
		for k := range q {
			q.Set(k, "REDACTED")
		}
		u.RawQuery = q.Encode()
	}
	parts := strings.Split(u.Path, "/")
	for i, p := range parts {
		if looksLikeSecret(p) {
			parts[i] = "REDACTED"
		}
	}
	u.Path = strings.Join(parts, "/")
	u.Fragment = ""
	return u.String()
}

// looksLikeSecret flags long opaque path segments (API keys, project ids).
func looksLikeSecret(s string) bool {
	if len(s) < 16 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// RedactedHeaders returns header names with values masked. Header values are
// never safe to print: they are the most common place an API key lives.
func (e Endpoint) RedactedHeaders() map[string]string {
	if len(e.Headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(e.Headers))
	for k := range e.Headers {
		out[k] = "REDACTED"
	}
	return out
}

func providerFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "unknown"
	}
	host := u.Hostname()
	labels := strings.Split(host, ".")
	if len(labels) >= 2 {
		return labels[len(labels)-2]
	}
	return host
}
