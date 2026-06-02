# MaybeEdgeScanner Release Notes (Draft)

Date: 2026-06-01

## Verified in this cycle

- Route execution truthfulness tightened for unsupported/not-ready provider paths.
- Proxy-route parser regression coverage expanded (CONNECT/SOCKS edge cases + hostname remote-DNS attribution).
- Sidecar auth hardening and read-auth regression coverage (`/metrics`, `/health`, Bearer + cookie).
- Diagnostics copy privacy improvements with redacted/full flows and JVM tests.
- Lifecycle guard: service no longer enters `running` with `0` planned checks.
- Notification cancel and heartbeat-loss JVM lifecycle coverage expanded.
- Background/foreground lifecycle contract coverage expanded (JVM).
- Compatibility, provenance, and SBOM baseline documentation added.


## Known open blockers (not release-ready yet)

- Device/emulator screenshot matrix for release-critical UI states.
- Signed release artifact verification (requires signing material in environment).
- Device-level instrumentation coverage for notification-stop, heartbeat-loss, and export-after-recreate.
- Full Psiphon/Windscribe Android provider lifecycle/session integration.
- Full SPDX/CycloneDX release-grade SBOM export.

## Explicit non-claims

- No claim that all provider route profiles are execution-attachable today.
- No claim of completed signed-release verification in this environment.
- No claim of complete device-level lifecycle instrumentation coverage.
