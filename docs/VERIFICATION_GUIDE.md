# MaybeEdgeScanner Verification & Build Guide

This guide defines the minimum verification bar for local development and CI.

## 1. Prerequisites

* JDK 17
* Android SDK and build-tools
* Go 1.21+
* Python 3 (for shared contract validation when the `shared-contracts` workspace is present)

## 2. Go Sidecar Verification

Run from `go-sidecar/`:

```bash
go test ./...
go vet ./...
```

Race checks require Linux/macOS with cgo enabled:

```bash
go test -race ./...
```

## 3. Android Verification

Run from repository root:

```bash
gradle --no-daemon :app:lintUniversalDebug
gradle --no-daemon :app:testUniversalDebugUnitTest
gradle --no-daemon :app:assembleDebug
```

`assembleDebug` produces `armv7`, `armv8`, and `universal` debug artifacts under `app/build/outputs/apk/`.

## 4. Shared Contract Verification

From workspace root (when present):

```bash
py shared-contracts\validate_contracts.py
```

Expected summary includes `OK schemas 22` and fixture pass lines.

## 5. CI Gates

The `build.yml` workflow enforces:

1. Secret scanning (`gitleaks`)
2. Go dependency lock resolution + test/vet/race
3. Android lint, unit-test, and build checks
4. Dependency image publication with SBOM/provenance enabled

## 6. Release Checks

Before every release:

1. Manually bump `APP_VERSION_NAME` and `APP_BASE_VERSION_CODE` in `gradle.properties`.
2. Commit that version bump before building or tagging the release.
3. Run `gradle --no-daemon :app:printResolvedVersion` and confirm the output is not the previous release number.

Release builds fail if the committed version properties are missing or the version name is not an explicit semantic version. APK filenames include version name and version code so new artifacts do not silently overwrite previous release outputs. Release jobs also verify signed APK outputs with `apksigner`, package sidecar artifacts, and publish benchmark/compliance assets.
