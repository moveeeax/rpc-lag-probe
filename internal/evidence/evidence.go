// Package evidence writes and reads the append-only JSONL log that the audit
// deliverable is built from. Every line is a self-contained, timestamped fact
// with the region it was observed from; divergence lines carry the raw
// provider payloads so a customer can take the file to their provider without
// having to trust the probe.
package evidence

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/moveeeax/rpc-lag-probe/internal/analysis"
)

// Record types.
const (
	TypeRunStarted  = "run_started"
	TypeLag         = "lag"
	TypeDivergence  = "divergence"
	TypeAlert       = "alert"
	TypeRunFinished = "run_finished"
)

// Record is one line of the evidence log.
type Record struct {
	TS     time.Time `json:"ts"`
	Type   string    `json:"type"`
	Region string    `json:"region,omitempty"`
	Chain  string    `json:"chain,omitempty"`
	Probe  string    `json:"probe,omitempty"`

	Lag        *analysis.Lag             `json:"lag,omitempty"`
	Divergence *analysis.DivergenceEvent `json:"divergence,omitempty"`
	Message    string                    `json:"message,omitempty"`
	Meta       map[string]string         `json:"meta,omitempty"`
}

// Writer appends records to a JSONL file. It is safe for concurrent use.
type Writer struct {
	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
	path string
}

// Open opens (or creates) an evidence log for appending. Parent directories
// are created. The file is never truncated: an audit log that can be rewritten
// is not evidence.
func Open(path string) (*Writer, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create evidence directory: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open evidence log: %w", err)
	}
	return &Writer{f: f, enc: json.NewEncoder(f), path: path}, nil
}

// Path of the underlying file.
func (w *Writer) Path() string { return w.path }

// Write appends one record. Divergence records are fsynced immediately: they
// are the expensive findings and must survive a crashing probe.
func (w *Writer) Write(r Record) error {
	if r.TS.IsZero() {
		r.TS = time.Now().UTC()
	} else {
		r.TS = r.TS.UTC()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.enc.Encode(r); err != nil {
		return fmt.Errorf("write evidence record: %w", err)
	}
	if r.Type == TypeDivergence {
		return w.f.Sync()
	}
	return nil
}

// Close flushes and closes the log.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Sync()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	w.f = nil
	return err
}

// Bundle is a parsed evidence log.
type Bundle struct {
	Lags        []analysis.Lag
	Divergences []analysis.DivergenceEvent
	Alerts      []Record
	Runs        []Record
	Regions     []string
	Chains      []string
	First       time.Time
	Last        time.Time
	// Malformed counts lines that could not be decoded. They are reported
	// rather than silently dropped.
	Malformed int
}

// Load parses an evidence log. Unknown record types are ignored so a newer
// probe writing extra facts does not break an older report generator.
func Load(path string) (*Bundle, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads JSONL records from r.
func Parse(r io.Reader) (*Bundle, error) {
	b := &Bundle{}
	regions := map[string]bool{}
	chains := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(trimSpace(line)) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			b.Malformed++
			continue
		}
		if !rec.TS.IsZero() {
			if b.First.IsZero() || rec.TS.Before(b.First) {
				b.First = rec.TS
			}
			if rec.TS.After(b.Last) {
				b.Last = rec.TS
			}
		}
		if rec.Region != "" {
			regions[rec.Region] = true
		}
		if rec.Chain != "" {
			chains[rec.Chain] = true
		}
		switch rec.Type {
		case TypeLag:
			if rec.Lag != nil {
				l := *rec.Lag
				if l.At.IsZero() {
					l.At = rec.TS
				}
				if l.Region == "" {
					l.Region = rec.Region
				}
				if l.Chain == "" {
					l.Chain = rec.Chain
				}
				b.Lags = append(b.Lags, l)
				regions[l.Region] = true
				chains[l.Chain] = true
			}
		case TypeDivergence:
			if rec.Divergence != nil {
				b.Divergences = append(b.Divergences, *rec.Divergence)
			}
		case TypeAlert:
			b.Alerts = append(b.Alerts, rec)
		case TypeRunStarted, TypeRunFinished:
			b.Runs = append(b.Runs, rec)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read evidence log: %w", err)
	}
	delete(regions, "")
	delete(chains, "")
	b.Regions = sortedKeys(regions)
	b.Chains = sortedKeys(chains)
	return b, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\t' || b[start] == '\r' || b[start] == '\n') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\r' || b[end-1] == '\n') {
		end--
	}
	return b[start:end]
}
