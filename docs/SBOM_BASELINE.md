# MaybeEdgeScanner SBOM Baseline (Pre-Release)

Last generated: 2026-06-01

This is a reproducible dependency baseline artifact for pre-release review.
It is **not** a full SPDX/CycloneDX export yet.

## Generation Commands

```bash
cd go-sidecar
go list -m all
```

```bash
cd app
# dependency declarations extracted from app/build.gradle
```

## Go Sidecar Modules

- `github.com/andybalholm/brotli v1.0.6`
- `github.com/davecgh/go-spew v1.1.0`
- `github.com/google/go-cmp v0.6.0`
- `github.com/klauspost/compress v1.17.4`
- `github.com/miekg/dns v1.1.72`
- `github.com/pmezard/go-difflib v1.0.0`
- `github.com/refraction-networking/utls v1.8.2`
- `github.com/stretchr/objx v0.1.0`
- `github.com/stretchr/testify v1.3.0`
- `github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb`
- `github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415`
- `github.com/xeipuuv/gojsonschema v1.2.0`
- `github.com/yuin/goldmark v1.4.13`
- `golang.org/x/crypto v0.46.0`
- `golang.org/x/mod v0.31.0`
- `golang.org/x/net v0.48.0`
- `golang.org/x/sync v0.19.0`
- `golang.org/x/sys v0.39.0`
- `golang.org/x/telemetry v0.0.0-20251203150158-8fff8a5912fc`
- `golang.org/x/term v0.38.0`
- `golang.org/x/text v0.32.0`
- `golang.org/x/time v0.15.0`
- `golang.org/x/tools v0.40.0`

## Android Dependencies (Declared)

- `dev.rikka.shizuku:api:${shizukuVersion}`
- `dev.rikka.shizuku:provider:${shizukuVersion}`
- `androidx.recyclerview:recyclerview:1.3.2`
- `com.android.tools:desugar_jdk_libs:2.1.5`
- `junit:junit:4.13.2` (test)
- `androidx.test.ext:junit:1.2.1` (androidTest)
- `androidx.test:core:1.6.1` (androidTest)
- `androidx.test:runner:1.6.2` (androidTest)

## Remaining Step for Stable Release

- Generate and archive machine-readable SPDX or CycloneDX artifacts from the exact release build outputs.
