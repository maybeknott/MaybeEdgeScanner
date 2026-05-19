# MaybeEdgeScanner Final Product Notes

MaybeEdgeScanner is a scanner-first Android product with an optional Go sidecar. It is not a VPN client. The final product model is:

- `Sources`: choose corpora, custom targets, SNI routes, workflow stages, scan volume, timeout, threads, and performance posture.
- `Results`: inspect result cards, filter, sort, paginate, change visualization/density, copy, and export the visible result set.
- `Diagnostics`: inspect logs, network state, Shizuku radio controls, support links, and project reference material.

## Release Artifacts

The Android builder emits three release APK families:

- `MaybeEdgeScanner-universal-release.apk`
- `MaybeEdgeScanner-armv7-release.apk`
- `MaybeEdgeScanner-armv8-release.apk`

The universal APK is the safest public default. ABI-specific APKs are produced for release-channel clarity and future native-library readiness.

## Shizuku Scope

Shizuku is implemented as an explicit diagnostics tool. It can read common `preferred_network_mode` keys and can write guarded LTE-only, 5G/LTE, Auto, or sanitized custom numeric values after confirmation.

It is intentionally not connected to scan start/stop, automatic retry, background work, widgets, or Quick Settings tiles. Radio control is device-specific and must remain user-directed.

## Cleanup Boundary

Generated APKs, `.signing`, local `signing.properties`, build outputs, Gradle state, and sidecar binaries are ignored. Private signing files are not garbage; they are operator state and must stay outside git. Production signing secrets belong in GitHub Actions secrets or another encrypted secret manager.

## Verification

The canonical verification path is GitHub Actions. The workflow downloads Go and Gradle dependencies, runs sidecar tests, builds sidecars, builds all Android release flavors, verifies signatures, uploads artifacts, and publishes the dependency-warmed container when needed.
