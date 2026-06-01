# MaybeEdgeScanner Go Sidecar

The sidecar is a standalone HTTP service for higher-volume target and DNS scans. It has no Python dependency and can run directly on a workstation, VPS, container host, or CI worker.

## What It Provides

- Browser dashboard at `/`.
- Streaming target-first scans over newline-delimited JSON.
- Standards-based DNS scans using `github.com/miekg/dns`.
- IPv4 and IPv6 target parsing.
- ALPN validation for `h2` and `http/1.1`.
- uTLS ClientHello fingerprint selection and rotation for Chrome, Firefox, iOS, and randomized TLS probes.
- Alt-Svc HTTP/3 hint capture from HTTP probe responses.
- TLS certificate and HTTP header metadata capture.
- Best-effort provider/network classification hints.
- Randomized target ordering, pacing, and jitter controls.
- Bundled safety-prefix loading from `assets/do_not_scan_cidrs.txt`.
- Strict CIDR expansion limits to avoid accidental whole-internet or huge-subnet expansion.
- Adaptive backoff when timeout/reset rates rise during a paced scan.
- Prometheus-style metrics at `/metrics`.
- Ready-to-import Grafana dashboard at `/grafana-dashboard.json`.
- Nmap XML export at `/api/export/nmap`.
- Structured `slog` logging.
- Graceful shutdown through `/api/stop` and process signals.

## Run Locally

```powershell
go run .
```

Open:

```text
http://127.0.0.1:10808
```

Build a local binary:

```powershell
go test ./...
go build -trimpath -ldflags='-s -w' -o maybescanner-sidecar.exe .
```

## Docker

```powershell
docker compose up --build
```

The compose file maps the dashboard and API to:

```text
http://127.0.0.1:10808
```

The GitHub worker also publishes a dependency-warmed build image to:

- `ghcr.io/<owner>/<repo>-deps:latest`
- `ghcr.io/<owner>/<repo>-deps:<sha>`

That image is cached with BuildKit `gha` and registry layers so dependency downloads are reused across worker runs.

## API

- `GET /` returns the browser dashboard.
- `GET /health` returns process health, goroutine count, and heap bytes (authenticated local API read).
- `GET /metrics` returns Prometheus-style metrics (authenticated local API read).
- `GET /grafana-dashboard.json` returns the bundled Grafana dashboard.
- `POST /api/scan` streams NDJSON scan results.
- `POST /api/dns` streams NDJSON DNS resolver results.
- `POST /api/stop` requests graceful cancellation/shutdown.
- `POST /api/export/nmap` returns Nmap XML for compatible tooling.

### Local API Auth Policy

- Sidecar read and mutation endpoints require local sidecar auth; unauthenticated requests return `LOCAL_API_UNAUTHORIZED`.
- Accepted auth paths are:
  - `Authorization: Bearer <token>`
  - `X-Sidecar-Token: <token>`
  - HttpOnly API-scoped sidecar cookie (browser dashboard flow)
- Query-string tokens are rejected.
- Token verification compares fixed-length hashes in constant time; raw token values are never echoed in public error payloads.

## Scan Request

`POST /api/scan` accepts JSON with targets, ports, HTTP path, worker count, timeout, optional pacing controls, and `tls_fingerprint`. Valid fingerprint values are `rotate`, `chrome`, `firefox`, `ios`, `randomized`, and `randomized-no-alpn`. Literal IP scans do not receive a default SNI; hostname-derived names are used only when present in the target plan or explicitly requested. Results stream as each target is processed, which keeps memory use predictable during large scans.

Empty scan requests are rejected with a structured target-selection error instead of falling back to bundled public targets.

### NDJSON stream shape (scan and DNS)

- `init` records include `expansion` with `submitted_tokens`, `expanded_targets`, and `safety_skipped` when CIDR/range expansion runs.
- Each scan `result` record may include `phase_results[]`, `final_phase`, and top-level `error_code`. Phases cover DNS resolution failure, TCP connect, TLS handshake, and HTTP/1 or HTTP/2 probes (from ALPN).
- Each DNS `result` record includes the same `phase_results` / `final_phase` fields summarizing UDP/TCP resolver attempts plus stable `error_code` values.
- Public HTTP errors use the structured envelope documented in `public_api_errors.go` (`error_code`, `message`, `status`, `phase`, `retryable`, `request_id`, redacted `details`).

Typical result fields include target, IP, port, SNI mode/name where applicable, TCP status, TLS status, HTTP status, latency, ALPN, selected TLS fingerprint, Alt-Svc and HTTP/3 hints, certificate subject/issuer/SAN values, server headers, best-effort network classification, and score.

## DNS Scan Request

`POST /api/dns` supports:

- Resolvers: IP or host resolver endpoints.
- Domains: one or more query names.
- Query types: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`.
- Worker count and timeout.
- EDNS and DNSSEC/AD signal capture where available.

Example:

```powershell
Invoke-WebRequest http://127.0.0.1:10808/api/dns `
  -Method POST `
  -ContentType 'application/json' `
  -Body '{"resolvers":["1.1.1.1","8.8.8.8"],"domains":["cloudflare.com"],"qtypes":["A","AAAA","MX"],"workers":16,"timeout_ms":1500}'
```

## Prometheus And Grafana

Prometheus scrape target (include an Authorization header or API cookie):

```yaml
scrape_configs:
  - job_name: maybescanner-sidecar
    static_configs:
      - targets: ["127.0.0.1:10808"]
```

Import `grafana-dashboard.json` in Grafana, or download it from the running service at:

```text
http://127.0.0.1:10808/grafana-dashboard.json
```

Dashboard panels include scan throughput, HTTP/TLS pass rates, timeout/reset rates, goroutines, and heap usage.

## Support

Project repository: [MaybeScanner](https://github.com/maybeknott/MaybeScanner/)

Optional support for ongoing development:

- BTC: `bc1qt2mxzmlcv3re4pjemshejzq0hj3c8dgp0e5tvx`
- EVM-compatible networks such as ETH/ERC20/BNB/BEP20: `0x8988ed09DA218799e99Fb1E94243cC1C1cB41A40`

Please verify the asset and network before sending funds.

## Safe Operating Guidance

Use bounded workers, batches, timeouts, and cancellation-aware clients. For broad scans, start with small samples and increase gradually while watching local CPU, memory, router stability, and network policy.

Safety mode skips private, reserved, documentation, multicast, link-local, loopback, and locally configured do-not-scan CIDRs. Add organization-specific exclusions to `assets/do_not_scan_cidrs.txt`.

Raw packet scanning generally requires root or `CAP_NET_RAW`; the supported baseline is TCP connect scanning plus UDP DNS probing.

## Safety Boundary

This sidecar is for owned, authorized, and diagnostic scanner workflows. It intentionally excludes exploit execution, destructive traffic generation, credential capture, stealth abuse workflows, DPI poisoning, decoy traffic generation, and automated vulnerability exploitation.
