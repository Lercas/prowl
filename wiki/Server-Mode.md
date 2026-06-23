# Server Mode

`prowl serve` runs Prowl as a **stateless HTTP scan worker**. You send it content over HTTP, it returns findings as JSON. It holds no state between requests, so you scale it horizontally: run N replicas behind a load balancer or a Kubernetes Deployment with an HPA.

```sh
prowl serve --addr :8080
```

```sh
# scan a single blob of content
curl -s localhost:8080/scan \
  -H 'content-type: application/json' \
  -d '{"source":"code","path":"config/prod.env","content":"AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"}'
```

```json
{
  "count": 1,
  "findings": [
    {
      "detector": "aws-access-key",
      "type": "AWS Access Key",
      "confidence": 0.95,
      "severity": "high",
      "source": "code",
      "path": "config/prod.env",
      "line": 1,
      "col": 23,
      "redacted": "AKIA****MPLE",
      "stage": "L1",
      "fingerprint": "9f2c…"
    }
  ]
}
```

## Starting the worker

```sh
prowl serve [--addr :8080] [--max-concurrent N]
```

| Flag | Default | Purpose |
|------|---------|---------|
| `--addr` | `:8080` | Listen address (`host:port`). |
| `--max-concurrent` | `2 × NumCPU` | Size of the in-flight concurrency semaphore. Requests beyond this are rejected with `503` (backpressure). |

The worker uses the same detection engine, taxonomy, external rules, and config (`.prowl.yaml` allowlist) as the CLI — see [Configuration](Configuration.md). The detector and allowlist are loaded once at startup; the worker is safe for concurrent use.

On `SIGINT`/`SIGTERM` the server stops accepting new connections and drains in-flight requests within a 10s deadline before exiting.

## API

All scan endpoints accept and return `application/json`. **Every error response is `application/json` too** — a uniform `{"error":"…"}` body (never `text/plain`), for every status the worker emits and for the `404`/`405` that `net/http` itself produces on an unknown route or wrong method. Integrators can decode one shape on every path.

### `POST /scan`

Scan a single item. Request body:

| Field | Type | Notes |
|-------|------|-------|
| `content` | string | The text to scan. |
| `source` | string | Logical source label. Defaults to `code` if empty. One of `code`, `jira`, `confluence`, `slack`, `log`. |
| `path` | string | Path/identifier echoed back on each finding. |

Response:

```json
{ "count": <int>, "findings": [ <Finding>, … ] }
```

Each `Finding` carries `detector`, `type`, `confidence`, `severity`, `source`, `path`, `line`, `col`, `redacted`, `stage`, and a stable `fingerprint`; `verified` and `rationale` appear when present. Secret values are always **redacted** — the raw value never leaves the worker. See [Output Formats](Output-Formats.md) for the full finding shape.

```sh
curl -s localhost:8080/scan \
  -H 'content-type: application/json' \
  -d '{"source":"slack","path":"#deploys","content":"token: xoxb-123456789012-abcdefghijklmnop"}' | jq
```

### `POST /scan/batch`

Scan many items in one request. The body is a **JSON array** of the same item shape:

```sh
curl -s localhost:8080/scan/batch \
  -H 'content-type: application/json' \
  -d '[
        {"source":"code","path":"a.py","content":"key = \"AKIAIOSFODNN7EXAMPLE\""},
        {"source":"log","path":"app.log","content":"no secrets here"}
      ]' | jq
```

The response is a single aggregated object — findings from all items are flattened into one `findings` array, and `count` is the total across the batch:

```json
{ "count": 1, "findings": [ … ] }
```

If the client disconnects mid-batch, the worker stops promptly rather than finishing the remaining items.

### `GET /healthz`

Liveness/readiness probe. Returns `200` with body `ok`. Use it for load-balancer health checks and Kubernetes `livenessProbe`/`readinessProbe`.

```sh
curl -s localhost:8080/healthz   # -> ok
```

### `GET /metrics`

Returns a JSON snapshot of process counters (atomic, cumulative since start):

```json
{
  "scanned":  1240,
  "findings": 87,
  "errors":   3,
  "rejected": 12,
  "inflight": 2,
  "capacity": 16
}
```

| Counter | Meaning |
|---------|---------|
| `scanned` | Items scanned (each batch item counts once). |
| `findings` | Total findings returned. |
| `errors` | Decode failures, oversized/over-cap rejections, client-disconnect aborts. |
| `rejected` | Requests turned away by backpressure (`503`). |
| `inflight` | Requests currently being processed. |
| `capacity` | Concurrency limit (`--max-concurrent`). |

This is a plain JSON object, not Prometheus exposition format — scrape it with a JSON exporter or a sidecar if you need Prometheus.

### `GET /limits`

Returns the worker's compiled-in size and count caps as JSON, so a client can size its requests up front instead of discovering a cap by getting a `413`:

```sh
curl -s localhost:8080/limits | jq
```

```json
{
  "max_request_bytes": 16777216,
  "max_batch_bytes":   8388608,
  "max_batch_items":   10000,
  "max_item_bytes":    4194304
}
```

| Field | Meaning |
|-------|---------|
| `max_request_bytes` | Max `POST /scan` body, in bytes (16 MiB). |
| `max_batch_bytes` | Max `POST /scan/batch` body, in bytes (8 MiB). |
| `max_batch_items` | Max items in one `POST /scan/batch` array. |
| `max_item_bytes` | Max scanned `content` per item, in bytes (4 MiB). On a single scan this is a `413`; in a batch the oversized item is skipped and annotated rather than failing the request. |

These mirror the caps documented under [Limits and backpressure](#limits-and-backpressure) below; `/limits` lets a client read them at runtime rather than hard-coding the numbers.

## Limits and backpressure

The worker enforces hard limits to bound memory and resist DoS. These are compiled-in, not configurable:

| Limit | Value | Endpoint | Behaviour on breach |
|-------|-------|----------|---------------------|
| Max request body | 16 MiB | `POST /scan` | `413 Request Entity Too Large` |
| Max request body | 8 MiB | `POST /scan/batch` | `413 Request Entity Too Large` |
| Max batch items | 10000 | `POST /scan/batch` | `413 Request Entity Too Large` (`too many items`) |
| Concurrency | `--max-concurrent` | both scan endpoints | `503 Service Unavailable` + `Retry-After: 1` |

The batch body cap is tighter (8 MiB vs 16 MiB) because one input item can fan out to many findings and the whole response is buffered before being written.

Server timeouts (slowloris / resource-pinning guards):

| Timeout | Value | Guards against |
|---------|-------|----------------|
| ReadHeaderTimeout | 5s | Slow header senders. |
| ReadTimeout | 30s | Slow request bodies (whole request must arrive in time). |
| WriteTimeout | 120s | Time spent streaming a large response. |
| IdleTimeout | 120s | Idle keep-alive connections pinning resources. |

### `503` is expected backpressure, not an error

When all concurrency slots are busy, the worker immediately returns `503 Service Unavailable` with a `Retry-After: 1` header instead of queueing unboundedly. **This is normal load-shedding, not a failure.** Clients should treat `503` as "retry shortly" — back off and resend. A rising `rejected` counter or sustained `503`s means you need more replicas (or a higher `--max-concurrent` if the box has headroom).

Malformed JSON returns `400 Bad Request` (`invalid JSON body`). A panic inside a handler is recovered and returned as `500 internal server error` without leaking a stack trace. Both — like every error the worker emits — carry the uniform `application/json` `{"error":"…"}` body.

## Scaling and deployment

The worker is stateless, so scaling is pure replication:

- Run multiple `prowl serve` processes behind any L4/L7 load balancer.
- In Kubernetes, use a `Deployment` + `Service`, point `livenessProbe`/`readinessProbe` at `/healthz`, and drive an `HorizontalPodAutoscaler` off CPU (or the `inflight`/`rejected` metrics via a custom-metrics adapter).
- Set `--max-concurrent` to match each replica's CPU allotment; let the LB spread load and let `503`/`Retry-After` shed overflow rather than over-provisioning a single big instance.
- Size client request bodies under the 16 MiB / 8 MiB caps; split large corpora across `/scan/batch` calls of ≤ 10000 items.

## See also

- [Scanning Files](Scanning-Files.md)
- [Output Formats](Output-Formats.md)
- [Configuration](Configuration.md)
- [CI/CD Integration](CI-CD-Integration.md)
- [Home](README.md)
