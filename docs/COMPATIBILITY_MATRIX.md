# MaybeEdgeScanner Compatibility Matrix

Last updated: 2026-06-01

## Runtime and Build Surface

| Surface | Status | Notes |
| --- | --- | --- |
| Android app variant | `universalDebug` validated | JVM unit tests and Java compile pass in CI/local script gate. |
| Android min/target SDK | Defined in app Gradle | Must be re-verified per release cut. |
| Go sidecar | Supported | `go test ./...` and `go vet ./...` passing. |
| Sidecar API transport | Loopback HTTP + NDJSON | Current baseline; binary telemetry is deferred/ADR backlog. |
| Auth transport | Bearer + HttpOnly cookie | Query-token auth disabled. |

## Network and Feature Compatibility

| Feature | Current Compatibility | Notes |
| --- | --- | --- |
| Route-pairing scan flows | Supported (current runtime depth) | Requested/observed route evidence and unsupported/not-ready provider errors are enforced. |
| Direct/SOCKS5/HTTP CONNECT route execution | Supported | Covered by sidecar route tests. |
| Observer-only provider routes | Explicitly unsupported at execution | Must return `ROUTE_UNSUPPORTED` / `ROUTE_NOT_READY` instead of silent direct fallback. |
| Psiphon/Windscribe full Android lifecycle integration | Partial | Runtime taxonomy exists; end-to-end provider session lifecycle remains open. |
| Shizuku-assisted diagnostics | Conditional | Requires user grant + runtime capability checks; no root assumptions. |

## Test Evidence Snapshot

| Evidence | Status |
| --- | --- |
| `gradlew testUniversalDebugUnitTest --offline` | Passing |
| `gradlew compileUniversalDebugJavaWithJavac --offline` | Passing |
| `go test ./...` (sidecar) | Passing |
| `go vet ./...` (sidecar) | Passing |
| `scripts/verify-release-readiness.ps1` | Passing |

## Open Compatibility Blockers Before Stable Release

- Real device/emulator screenshot matrix for release-critical UI states.
- Signed release APK verification.
- Formal SBOM output and release-packaged provenance bundle.
- Device-level lifecycle instrumentation for notification stop, heartbeat-loss, and export-after-recreate flows.
- Provider-specific lifecycle/session validation for Psiphon/Windscribe adapters.
