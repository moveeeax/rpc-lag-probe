# rpc-lag-probe

Independent, region-correct evidence that a team's paid RPC endpoints are serving stale or divergent chain state.

A provider's status page says "operational". Your indexer says otherwise. `rpc-lag-probe` settles it: it polls every endpoint you pay for on the same tick, from the regions you actually run in, and produces an append-only evidence log plus an audit report you can put in front of the provider — or in front of an SLA-credit claim.

It is a measurement device. It never proxies, retries or fails over your traffic, and it never sits in a request path. When the evidence says you need routing, it hands you an [eRPC](https://github.com/erpc/erpc) upstream config derived from the numbers rather than from a vendor's marketing page.

**Scope:** Ethereum mainnet and Base, EVM JSON-RPC over HTTP. No WebSocket subscriptions, no mempool timing, no archive-node correctness checks, no leaderboard, no hosted SaaS.

## What it measures

| | |
|---|---|
| **Head lag, in blocks** | Against the highest head any healthy endpoint on that chain reported on the same tick. |
| **Head lag, in seconds** | Wall-clock: how long ago the probe saw the network move past this endpoint's current head. Provider-supplied block timestamps are never used — they are the thing under test. |
| **Hash divergence** | `eth_getBlockByNumber` at a height far enough behind the head that an ordinary reorg cannot explain a disagreement. Endpoints are clustered by hash; the raw payloads are kept so the finding is self-evidencing. |
| **Availability and throttling** | Every poll is classified: `ok`, `timeout`, `rate_limited` (HTTP 429 *and* the 200-with-a-throttling-message that several providers prefer), `http_error`, `rpc_error`, `malformed`, `transport`. |
| **Latency distribution** | p50 / p90 / p99 / max per endpoint, plus a Prometheus histogram. |

## Install

```sh
go install github.com/moveeeax/rpc-lag-probe@latest
```

Or from a clone:

```sh
git clone https://github.com/moveeeax/rpc-lag-probe.git
cd rpc-lag-probe
go build -o rpc-lag-probe .
```

Go 1.22 or newer. One dependency (`gopkg.in/yaml.v3`) — the binary is meant to be dropped onto a small VM in each region you care about.

## Usage

### Turn an evidence log into the audit deliverable

The repository ships a two-minute sample evidence log, so this runs immediately after a clone, with no accounts and no credentials:

```sh
./rpc-lag-probe report \
  --evidence testdata/sample-evidence.jsonl \
  --lag-blocks 2 \
  --customer "Example Labs"
```

```
# RPC endpoint lag and divergence audit — Example Labs

| | |
|---|---|
| Measurement window | 2026-07-20T09:00:00Z → 2026-07-20T09:01:58Z (1m58s) |
| Vantage points | ap-southeast-1, eu-central-1, us-east-1 |
| Chains | ethereum |
| Endpoints measured | 3 |
| Head polls recorded | 180 |
| Divergence events | 1 |

## Findings

- **provider-c** answered 95.00% of head polls (57 of 60), from ap-southeast-1.
- **provider-c** was at or over the lag threshold in 45.61% of healthy polls; worst observed lag 6 blocks / 62.0s.
- **Hash divergence** on ethereum at finalised height 19999942 between provider-a+provider-b (`0x3f0c1a9d…10ffee`) vs provider-c (`0x9a17be44…6e7f80`).

## Lag and availability by endpoint

| Endpoint | Region | Chain | Polls | Availability | Lag blocks p50 / p99 / max | Lag seconds p50 / p99 / max | Latency p50 / p99 | Leader share |
|---|---|---|---:|---:|---|---|---|---:|
| provider-a | eu-central-1 | ethereum | 60 | 100.00% | 0 / 0 / 0 | 0.0 / 0.0 / 0.0 | 55ms / 71ms | 100.0% |
| provider-b | us-east-1 | ethereum | 60 | 100.00% | 0 / 1 / 1 | 0.0 / 10.0 / 10.0 | 120ms / 148ms | 86.7% |
| provider-c | ap-southeast-1 | ethereum | 60 | 95.00% | 1 / 6 / 6 | 6.0 / 62.0 / 62.0 | 273ms / 409ms | 43.9% |
```

…followed by an incident table, the full divergence detail with both hashes, and a method section. `--format json` gives the same analysis for a dashboard; `--out FILE` writes instead of printing.

### Generate an eRPC upstream config from the measurements

```sh
./rpc-lag-probe report --evidence testdata/sample-evidence.jsonl --format erpc
```

```yaml
projects:
  - id: main
    upstreams:
      # measured: availability 100.00%, lag p99 0 blocks / 0.0s, latency p99 71ms, leader 100.0% of polls
      - id: provider-a
        endpoint: ${PROVIDER_A_URL}
        type: evm
        evm:
          chainId: 1
        failsafe:
          timeout:
            duration: 1s
          retry:
            maxAttempts: 1
```

Upstreams are ranked by measured lag first and availability second — a fast endpoint serving stale state is worse than a slightly slower one that is current. Timeouts come from the observed p99, retries from the observed availability, and a hedge is only suggested for endpoints whose tail is genuinely far off their median. Endpoint URLs are emitted as environment placeholders because the evidence log deliberately contains no URL and no API key. Review the values against the eRPC docs for your version before deploying.

### Check a configuration

```sh
export PROVIDER_A_KEY=your-key-here
export PROVIDER_B_KEY=your-key-here
export RPC_LAG_PROBE_WEBHOOK_URL=https://your-gateway.example/alerts

./rpc-lag-probe validate --config examples/endpoints.yaml
```

```
config OK: examples/endpoints.yaml
  region             eu-central-1
  interval           2s (timeout 1.5s)
  finality depth     64 blocks, hash check every 30s
  endpoints          5 across 2 chain(s)

  - provider-a-eth       ethereum  eu-central-1     https://eth-mainnet.provider-a.example/v2/REDACTED
  - provider-b-eth       ethereum  eu-central-1     https://rpc.provider-b.example/ethereum
                         headers: X-Api-Key (values redacted)
```

Validation is strict on purpose. Unknown config keys, a timeout longer than the poll interval, a single endpoint on a chain (there is nothing to compare it against), a finality depth shallow enough to turn reorgs into false positives, and any unset `${VAR}` are all refused before the first request goes out.

### Run the probe

```sh
./rpc-lag-probe run --config examples/endpoints.yaml
```

It polls on the tick, appends to the evidence log, serves `/metrics`, and posts alerts to the webhook once a breach has persisted for `alerts.for` — subject to `alerts.cooldown`, so a flapping provider does not become a pager storm. `--once` runs a single round and prints it as JSON; `--duration 72h` bounds a measurement window.

## Configuration

See [`examples/endpoints.yaml`](examples/endpoints.yaml) for a commented file. The shape:

```yaml
region: eu-central-1          # the vantage point; stamped on every metric and evidence line
interval: 2s
timeout: 1500ms
finality_depth: 64            # compare hashes this far behind the head, never at the head
hash_check_interval: 30s      # far coarser than the head poll: block fetches cost quota

evidence_log: ./evidence/eu-central-1.jsonl
metrics_addr: "127.0.0.1:9102"

alerts:
  webhook_url: ${RPC_LAG_PROBE_WEBHOOK_URL}
  lag_blocks_threshold: 3
  lag_seconds_threshold: 30
  for: 30s
  cooldown: 10m
  on_divergence: true

endpoints:
  - name: provider-a-eth
    url: https://eth-mainnet.provider-a.example/v2/${PROVIDER_A_KEY}
    chain: ethereum           # ethereum | base
    region: eu-central-1
    headers:
      X-Api-Key: ${PROVIDER_B_KEY}
```

**Secrets never live in the config file.** `${VAR}` placeholders are resolved from the environment at startup, and every path that prints or persists an endpoint — logs, `validate` output, the evidence log, the generated eRPC config — uses the redacted form: userinfo, query values, key-shaped path segments and *all* header values are masked.

## Evidence log

One JSON object per line, append-only, never truncated on reopen:

```json
{"ts":"2026-07-20T09:01:00Z","type":"lag","region":"ap-southeast-1","chain":"ethereum",
 "lag":{"endpoint":"provider-c","height":20000003,"lag_blocks":6,"lag_seconds":62,"best_height":20000009,"latency_ns":273000000,"err_class":"ok"}}
{"ts":"2026-07-20T09:01:12Z","type":"divergence","chain":"ethereum",
 "divergence":{"height":19999942,"clusters":[{"hash":"0x3f0c...","endpoints":["provider-a","provider-b"],"raw":{}}],"majority_hash":"0x3f0c...","minority_endpoints":["provider-c"]}}
```

Divergence records are fsynced as they are written and carry the raw provider payloads. Every number in a generated report is reproducible from this file; the report generator tolerates unknown record types, so a newer probe writing extra facts will not break an older reader.

## Metrics

`GET /metrics`, Prometheus text format, no client library:

```
rpc_probe_up{endpoint,provider,region,chain}
rpc_probe_head_block{endpoint,provider,region,chain}
rpc_probe_lag_blocks{endpoint,provider,region,chain}
rpc_probe_lag_seconds{endpoint,provider,region,chain}
rpc_probe_requests_total{endpoint,provider,region,chain,class}
rpc_probe_rate_limited_total{endpoint,provider,region,chain}
rpc_probe_request_duration_seconds{endpoint,provider,region,chain}   # histogram
rpc_probe_divergence_events_total{chain}
rpc_probe_build_info{version}
```

`rpc_probe_head_block` keeps the last known good height across a failed poll, so a hiccup does not draw a cliff to zero on a dashboard.

## Development

```sh
go test -race ./...
go vet ./...
gofmt -l .
```

Tests run against local `httptest` servers impersonating RPC endpoints — including a node that serves a different hash for the same finalised block — so divergence detection is exercised on every commit rather than on a lucky day. `testdata/sample-evidence.jsonl` is a synthetic but internally consistent two-minute window: three endpoints in three regions, one sustained lag incident, three rate-limited polls and one hash divergence.

## Status

First slice. The probe, the evidence log, the metrics endpoint, the webhook alerting and the report generator are implemented and tested. Not yet here: the multi-region Terraform examples, a Grafana dashboard, and any measurement against real paid endpoints — that needs provider accounts.
