# MaybeEdgeScanner Go Sidecar

The sidecar is a standalone HTTP service for higher-volume edge and DNS scans. It has no Python dependency and can run directly on a workstation, VPS, container host, or CI worker.

## What It Provides

- Browser dashboard at `/`.
- Streaming edge scans over newline-delimited JSON.
- Standards-based DNS scans using `github.com/miekg/dns`.
- IPv4 and IPv6 target parsing.
- ALPN validation for `h2` and `http/1.1`.
- uTLS ClientHello fingerprint selection and rotation for Chrome, Firefox, iOS, and randomized TLS probes.
- Alt-Svc HTTP/3 hint capture from HTTP probe responses.
- TLS certificate and HTTP header metadata capture.
- CDN classification hints.
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
go build -trimpath -ldflags='-s -w' -o maybeedgescanner-sidecar.exe .
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
- `GET /health` returns process health, goroutine count, and heap bytes.
- `GET /metrics` returns Prometheus-style metrics.
- `GET /grafana-dashboard.json` returns the bundled Grafana dashboard.
- `POST /api/scan` streams NDJSON edge results.
- `POST /api/dns` streams NDJSON DNS resolver results.
- `POST /api/stop` requests graceful cancellation/shutdown.
- `POST /api/export/nmap` returns Nmap XML for compatible tooling.

## Edge Scan Request

`POST /api/scan` accepts JSON with targets, SNIs, ports, HTTP path, worker count, timeout, optional pacing controls, and `tls_fingerprint`. Valid fingerprint values are `rotate`, `chrome`, `firefox`, `ios`, `randomized`, and `randomized-no-alpn`. Results stream as each target is processed, which keeps memory use predictable during large scans.

Typical result fields include target, IP, port, SNI, TCP status, TLS status, HTTP status, latency, ALPN, selected TLS fingerprint, Alt-Svc and HTTP/3 hints, certificate subject/issuer/SAN values, server headers, CDN hint, and score.

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

Prometheus scrape target:

```yaml
scrape_configs:
  - job_name: maybeedgescanner-sidecar
    static_configs:
      - targets: ["127.0.0.1:10808"]
```

Import `grafana-dashboard.json` in Grafana, or download it from the running service at:

```text
http://127.0.0.1:10808/grafana-dashboard.json
```

Dashboard panels include scan throughput, HTTP/TLS pass rates, timeout/reset rates, goroutines, and heap usage.

## Support

Project repository: [MaybeEdgeScanner](https://github.com/maybeknott/MaybeEdgeScanner/)

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
