// Package rpc is a minimal JSON-RPC 2.0 client for the handful of EVM methods
// the probe needs. It deliberately does not depend on go-ethereum: the probe
// must be able to see and classify malformed or throttled responses that a
// full client would hide behind a generic error.
package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// maxBody caps how much of a response we read. Evidence records embed raw
// payloads, so an endpoint must not be able to fill the log with one reply.
const maxBody = 1 << 20 // 1 MiB

// ErrorClass buckets a failed call for counters and for the audit report.
type ErrorClass string

const (
	ClassOK          ErrorClass = "ok"
	ClassTimeout     ErrorClass = "timeout"
	ClassRateLimited ErrorClass = "rate_limited"
	ClassHTTP        ErrorClass = "http_error"
	ClassRPC         ErrorClass = "rpc_error"
	ClassMalformed   ErrorClass = "malformed"
	ClassTransport   ErrorClass = "transport"
)

// Error is a classified call failure.
type Error struct {
	Class      ErrorClass
	HTTPStatus int
	RPCCode    int
	Message    string
	// RetryAfter is the parsed Retry-After header on a 429, if present.
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	switch e.Class {
	case ClassRateLimited:
		return fmt.Sprintf("rate limited (HTTP %d): %s", e.HTTPStatus, e.Message)
	case ClassHTTP:
		return fmt.Sprintf("HTTP %d: %s", e.HTTPStatus, e.Message)
	case ClassRPC:
		return fmt.Sprintf("json-rpc error %d: %s", e.RPCCode, e.Message)
	default:
		return fmt.Sprintf("%s: %s", e.Class, e.Message)
	}
}

// ClassOf returns the class of any error produced by this package.
func ClassOf(err error) ErrorClass {
	if err == nil {
		return ClassOK
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Class
	}
	return ClassTransport
}

// Client calls one endpoint.
type Client struct {
	url     string
	headers map[string]string
	http    *http.Client
	id      atomic.Int64
}

// New builds a client with a per-call timeout applied by the caller's context.
func New(url string, headers map[string]string, timeout time.Duration) *Client {
	return &Client{
		url:     url,
		headers: headers,
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   4,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   timeout,
				ResponseHeaderTimeout: timeout,
			},
		},
	}
}

type request struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int64  `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Call issues one JSON-RPC request and returns the raw result payload along
// with the wall-clock latency of the round trip.
func (c *Client) Call(ctx context.Context, method string, params ...any) (json.RawMessage, time.Duration, error) {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(request{JSONRPC: "2.0", ID: c.id.Add(1), Method: method, Params: params})
	if err != nil {
		return nil, 0, &Error{Class: ClassMalformed, Message: err.Error()}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, &Error{Class: ClassTransport, Message: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		latency := time.Since(start)
		class := ClassTransport
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			class = ClassTimeout
		}
		return nil, latency, &Error{Class: class, Message: err.Error()}
	}
	defer resp.Body.Close()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	latency := time.Since(start)
	if readErr != nil {
		class := ClassTransport
		if isTimeout(readErr) {
			class = ClassTimeout
		}
		return nil, latency, &Error{Class: class, HTTPStatus: resp.StatusCode, Message: readErr.Error()}
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, latency, &Error{
			Class:      ClassRateLimited,
			HTTPStatus: resp.StatusCode,
			Message:    snippet(raw),
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, latency, &Error{Class: ClassHTTP, HTTPStatus: resp.StatusCode, Message: snippet(raw)}
	}

	var out response
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, latency, &Error{Class: ClassMalformed, HTTPStatus: resp.StatusCode, Message: snippet(raw)}
	}
	if out.Error != nil {
		// Some providers signal throttling inside a 200 JSON-RPC error.
		class := ClassRPC
		if isThrottleMessage(out.Error.Message) {
			class = ClassRateLimited
		}
		return nil, latency, &Error{Class: class, HTTPStatus: resp.StatusCode, RPCCode: out.Error.Code, Message: out.Error.Message}
	}
	if len(out.Result) == 0 {
		return nil, latency, &Error{Class: ClassMalformed, HTTPStatus: resp.StatusCode, Message: "response has neither result nor error"}
	}
	return out.Result, latency, nil
}

// BlockNumber returns the current head height.
func (c *Client) BlockNumber(ctx context.Context) (uint64, time.Duration, error) {
	raw, latency, err := c.Call(ctx, "eth_blockNumber")
	if err != nil {
		return 0, latency, err
	}
	var hex string
	if err := json.Unmarshal(raw, &hex); err != nil {
		return 0, latency, &Error{Class: ClassMalformed, Message: "eth_blockNumber result is not a string: " + snippet(raw)}
	}
	n, err := ParseHexUint(hex)
	if err != nil {
		return 0, latency, &Error{Class: ClassMalformed, Message: err.Error()}
	}
	return n, latency, nil
}

// Block is the subset of eth_getBlockByNumber the probe compares.
type Block struct {
	Number     uint64
	Hash       string
	ParentHash string
	Timestamp  time.Time
	// Raw is the untouched provider payload, kept for divergence evidence.
	Raw json.RawMessage
}

// ErrBlockNotFound means the endpoint returned null: it has not reached that
// height (or has pruned it). That is a miss, not a divergence.
var ErrBlockNotFound = errors.New("block not found at requested height")

// BlockByNumber fetches a block header at an exact height, without transactions.
func (c *Client) BlockByNumber(ctx context.Context, height uint64) (*Block, time.Duration, error) {
	raw, latency, err := c.Call(ctx, "eth_getBlockByNumber", HexUint(height), false)
	if err != nil {
		return nil, latency, err
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		return nil, latency, ErrBlockNotFound
	}
	var b struct {
		Number     string `json:"number"`
		Hash       string `json:"hash"`
		ParentHash string `json:"parentHash"`
		Timestamp  string `json:"timestamp"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, latency, &Error{Class: ClassMalformed, Message: "block is not an object: " + snippet(raw)}
	}
	if b.Hash == "" {
		return nil, latency, &Error{Class: ClassMalformed, Message: "block has no hash: " + snippet(raw)}
	}
	n, err := ParseHexUint(b.Number)
	if err != nil {
		return nil, latency, &Error{Class: ClassMalformed, Message: "block number: " + err.Error()}
	}
	ts, err := ParseHexUint(b.Timestamp)
	if err != nil {
		return nil, latency, &Error{Class: ClassMalformed, Message: "block timestamp: " + err.Error()}
	}
	return &Block{
		Number:     n,
		Hash:       strings.ToLower(b.Hash),
		ParentHash: strings.ToLower(b.ParentHash),
		Timestamp:  time.Unix(int64(ts), 0).UTC(),
		Raw:        append(json.RawMessage(nil), raw...),
	}, latency, nil
}

// HexUint renders a height the way JSON-RPC expects it.
func HexUint(n uint64) string { return "0x" + strconv.FormatUint(n, 16) }

// ParseHexUint parses a 0x-prefixed quantity, tolerating a decimal string from
// providers that do not follow the spec.
func ParseHexUint(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty quantity")
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		n, err := strconv.ParseUint(s[2:], 16, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid hex quantity %q", s)
		}
		return n, nil
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid quantity %q", s)
	}
	return n, nil
}

func isTimeout(err error) bool {
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}

func isThrottleMessage(msg string) bool {
	m := strings.ToLower(msg)
	for _, needle := range []string{"rate limit", "too many requests", "throttle", "capacity exceeded", "request limit"} {
		if strings.Contains(m, needle) {
			return true
		}
	}
	return false
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
