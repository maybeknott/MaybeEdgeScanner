# MaybeEdgeScanner

MaybeEdgeScanner is an Android network scanner focused on route-pairing workflows (target IP + SNI route behavior), with an optional Go sidecar for higher-throughput scans and export/observability workflows.

## What It Does

- Runs TCP/TLS/HTTP probing across managed/custom targets and SNI route sets.
- Provides live scan progress, result ranking, and export views.
- Includes diagnostics tooling (logs, network checks, optional Shizuku-assisted radio diagnostics).
- Supports an optional local Go sidecar (`go-sidecar`) for desktop/server-driven scan sessions.

## Project Scope

- This repo is the **route-pairing** scanner product.
- Windscribe, Psiphon, and local-proxy routes are integrated as external provider routes: the app opens/observes provider state, keeps provider credentials inside the provider apps, and attaches route status to scans.
- If you only need target-first scanning without route pairing, use the sibling project: `MaybeScanner`.

## Repository Layout

```text
MaybeEdgeScanner/
├── app/                 # Android app
├── go-sidecar/          # Optional Go sidecar
├── .github/workflows/   # CI and release workflows
└── docs/                # User, verification, and architecture docs
```

## Build & Verify (Local)

From repository root:

```powershell
.\gradlew.bat --no-daemon :app:lintUniversalDebug :app:assembleUniversalDebug
```

From `go-sidecar/`:

```powershell
go test ./...
go vet ./...
```

From workspace root (if `shared-contracts/` is available):

```powershell
py shared-contracts\validate_contracts.py
```

## CI & Release

The workflow in `.github/workflows/build.yml` runs:

- secret scanning
- Go sidecar tests/vet/race (race on Linux)
- Android lint/build gates
- artifact publication
- dependency image publication with SBOM/provenance enabled

## Documentation

- [User Guide](./docs/USER_GUIDE.md)
- [Verification Guide](./docs/VERIFICATION_GUIDE.md)
- [Architectural Guide](./docs/ARCHITECTURAL_GUIDE.md)

## License

AGPL-3.0. See [LICENSE](./LICENSE).
