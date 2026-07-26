package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// jsonRPC serves a fixed result for every request.
func jsonRPC(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.JSONRPC != "2.0" {
			t.Errorf("jsonrpc = %q, want 2.0", req.JSONRPC)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestBlockNumber(t *testing.T) {
	srv := jsonRPC(t, `{"jsonrpc":"2.0","id":1,"result":"0x1312d00"}`)
	c := New(srv.URL, nil, time.Second)
	n, latency, err := c.BlockNumber(context.Background())
	if err != nil {
		t.Fatalf("BlockNumber: %v", err)
	}
	if n != 20000000 {
		t.Errorf("height = %d, want 20000000", n)
	}
	if latency <= 0 {
		t.Error("latency was not measured")
	}
}

func TestBlockNumberSendsHeaders(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Api-Key")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
	}))
	defer srv.Close()
	c := New(srv.URL, map[string]string{"X-Api-Key": "placeholder-key"}, time.Second)
	if _, _, err := c.BlockNumber(context.Background()); err != nil {
		t.Fatalf("BlockNumber: %v", err)
	}
	if got != "placeholder-key" {
		t.Errorf("X-Api-Key = %q, want the configured value", got)
	}
}

func TestErrorClassification(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		headers map[string]string
		want    ErrorClass
	}{
		{"rate limited", http.StatusTooManyRequests, `{"error":"quota"}`, map[string]string{"Retry-After": "7"}, ClassRateLimited},
		{"server error", http.StatusBadGateway, "bad gateway", nil, ClassHTTP},
		{"rpc error", http.StatusOK, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"header not found"}}`, nil, ClassRPC},
		{"throttle inside 200", http.StatusOK, `{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"Your app has exceeded its compute units capacity exceeded"}}`, nil, ClassRateLimited},
		{"not json", http.StatusOK, `<html>maintenance</html>`, nil, ClassMalformed},
		{"empty envelope", http.StatusOK, `{"jsonrpc":"2.0","id":1}`, nil, ClassMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for k, v := range tc.headers {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			c := New(srv.URL, nil, time.Second)
			_, _, err := c.BlockNumber(context.Background())
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := ClassOf(err); got != tc.want {
				t.Errorf("class = %q, want %q (err: %v)", got, tc.want, err)
			}
			var re *Error
			if errors.As(err, &re) && tc.name == "rate limited" {
				if re.RetryAfter != 7*time.Second {
					t.Errorf("Retry-After = %s, want 7s", re.RetryAfter)
				}
				if re.HTTPStatus != http.StatusTooManyRequests {
					t.Errorf("status = %d", re.HTTPStatus)
				}
			}
		})
	}
}

func TestTimeoutIsClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, nil, 20*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, _, err := c.BlockNumber(ctx)
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if got := ClassOf(err); got != ClassTimeout {
		t.Errorf("class = %q, want %q (err: %v)", got, ClassTimeout, err)
	}
}

const blockBody = `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1312d00","hash":"0xAABBCCDDEEFF00112233445566778899aabbccddeeff00112233445566778899","parentHash":"0x1111111111111111111111111111111111111111111111111111111111111111","timestamp":"0x6689a0c0"}}`

func TestBlockByNumber(t *testing.T) {
	var gotParams []any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotParams = req.Params
		_, _ = w.Write([]byte(blockBody))
	}))
	defer srv.Close()

	c := New(srv.URL, nil, time.Second)
	blk, _, err := c.BlockByNumber(context.Background(), 20000000)
	if err != nil {
		t.Fatalf("BlockByNumber: %v", err)
	}
	if len(gotParams) != 2 || gotParams[0] != "0x1312d00" || gotParams[1] != false {
		t.Errorf("params = %#v, want [0x1312d00 false]", gotParams)
	}
	if blk.Number != 20000000 {
		t.Errorf("number = %d", blk.Number)
	}
	if blk.Hash != "0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" {
		t.Errorf("hash not normalised to lower case: %s", blk.Hash)
	}
	if blk.Timestamp.UTC().Format(time.RFC3339) != "2024-07-06T19:53:36Z" {
		t.Errorf("timestamp = %s", blk.Timestamp.UTC())
	}
	if len(blk.Raw) == 0 {
		t.Error("raw payload was not kept; divergence evidence needs it")
	}
}

func TestBlockByNumberNullIsNotFound(t *testing.T) {
	srv := jsonRPC(t, `{"jsonrpc":"2.0","id":1,"result":null}`)
	c := New(srv.URL, nil, time.Second)
	_, _, err := c.BlockByNumber(context.Background(), 20000000)
	if !errors.Is(err, ErrBlockNotFound) {
		t.Fatalf("err = %v, want ErrBlockNotFound", err)
	}
}

func TestBlockByNumberRejectsHashlessBlock(t *testing.T) {
	srv := jsonRPC(t, `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","timestamp":"0x2"}}`)
	c := New(srv.URL, nil, time.Second)
	_, _, err := c.BlockByNumber(context.Background(), 1)
	if ClassOf(err) != ClassMalformed {
		t.Fatalf("err = %v, want a malformed classification", err)
	}
}

func TestParseHexUint(t *testing.T) {
	ok := map[string]uint64{"0x0": 0, "0x1312d00": 20000000, "0X10": 16, "  0x2a  ": 42, "12345": 12345}
	for in, want := range ok {
		got, err := ParseHexUint(in)
		if err != nil {
			t.Errorf("ParseHexUint(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseHexUint(%q) = %d, want %d", in, got, want)
		}
	}
	for _, in := range []string{"", "0xzz", "latest", "0x"} {
		if _, err := ParseHexUint(in); err == nil {
			t.Errorf("ParseHexUint(%q) should have failed", in)
		}
	}
}

func TestHexUint(t *testing.T) {
	if got := HexUint(20000000); got != "0x1312d00" {
		t.Errorf("HexUint = %s", got)
	}
}

func TestClassOfNilAndForeignErrors(t *testing.T) {
	if ClassOf(nil) != ClassOK {
		t.Error("nil error should classify as ok")
	}
	if ClassOf(errors.New("boom")) != ClassTransport {
		t.Error("foreign errors should classify as transport")
	}
}
