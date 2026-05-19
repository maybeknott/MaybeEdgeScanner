# MaybeEdgeScanner Final Product Notes

MaybeEdgeScanner is a scanner-first Android product with an optional Go sidecar. It is not a VPN client. The final product model is:

- `Sources`: choose corpora, custom targets, SNI routes, workflow stages, scan volume, timeout, threads, and performance posture.
- `Results`: inspect result cards, quick-filter common views, extract best SNIs, sort, paginate, change visualization/density, copy, and export the visible result set.
- `Diagnostics`: inspect logs, enriched network state, Shizuku radio controls, support links, and project reference material.

## Product Scope

MaybeEdgeScanner is the SNI/IP route-pairing product. It keeps target endpoints and SNI routes as separate scan-shaping inputs so users can test primary-route behavior or expand across all bundled/custom SNI hosts.

MaybeScanner is the IP-first sibling and intentionally avoids SNI route pairing. Keeping this split makes both products easier to understand and support.

## Interaction Model

- Sticky top tabs keep `Sources`, `Results`, and `Diagnostics` visible.
- Horizontal swipes move between tabs.
- Managed target corpora, managed SNI routes, per-source sample steppers, custom targets, and custom SNI routes stay separated.
- Compact density is treated as a performance mode: it caps rendered route cards and avoids heavyweight visual panels while preserving route readability.
- The source-health card summarizes target composition, SNI route composition, endpoint expansion, cap behavior, route mode, and load posture.
- Primary-SNI and All-SNI route buttons make the central route decision explicit.
- Results quick buttons jump to working routes, TLS/HTTP evidence, or best-route ranking without changing the scan queue.

## Release Artifacts

The Android builder emits three release APK families:

- `MaybeEdgeScanner-universal-release.apk`
- `MaybeEdgeScanner-armv7-release.apk`
- `MaybeEdgeScanner-armv8-release.apk`

The universal APK is the safest public default. ABI-specific APKs are produced for release-channel clarity and future native-library readiness.

## Publication Notes

Public release text should describe MaybeEdgeScanner as an authorized edge route scanner for IP/SNI testing. It should not market VPN behavior, exploit verification, stealth scanning, DPI bypass, or automatic radio switching.

Release tags are generated from version, versionCode, workflow run number, and commit SHA so new runs do not overwrite an old `v1.0.0` release.

## Shizuku Scope

Shizuku is implemented as an explicit diagnostics tool. It can read common `preferred_network_mode` keys and can write guarded LTE-only, 5G/LTE, Auto, or sanitized custom numeric values after confirmation.

It is intentionally not connected to scan start/stop, automatic retry, background work, widgets, or Quick Settings tiles. Radio control is device-specific and must remain user-directed.

## Cleanup Boundary

Generated APKs, `.signing`, local `signing.properties`, build outputs, Gradle state, and sidecar binaries are ignored. Private signing files are not garbage; they are operator state and must stay outside git. Production signing secrets belong in GitHub Actions secrets or another encrypted secret manager.

## Verification

The canonical verification path is GitHub Actions. The workflow downloads Go and Gradle dependencies, runs sidecar tests, builds sidecars, builds all Android release flavors, verifies signatures, uploads artifacts, and publishes the dependency-warmed container when needed.
