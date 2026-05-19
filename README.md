# MaybeEdgeScanner

MaybeEdgeScanner is an Android edge scanner with an optional Go sidecar. It helps users test owned or authorized target lists for TCP reachability, TLS metadata, HTTP response behavior, CDN classification, latency, ranking, filtering, and export.

The app is scanner-only. It is not a VPN client.

## Capabilities

- Bundled target corpora for community edge IPs, community `/24` CIDRs, Akamai, AWS CloudFront, Fastly, Cloudflare, GitHub Pages, Azure Front Door, Google CDN, Bunny CDN, StackPath/Edgio, and conventional cloud/CDN ranges.
- Bundled SNI corpus can be enabled or disabled, merged with user-added SNIs, and deduplicated before scanning.
- Three-part Android UI: `Sources` for scan setup, `Results` for cards/filtering/export/visualizations, and `Diagnostics` for logs, enriched network/system context, Shizuku radio tools, support, and reference material.
- Sticky full-width top navigation with swipe gestures between `Sources`, `Results`, and `Diagnostics`.
- Source-health summary that separates managed corpora, manual targets, managed SNI routes, custom SNI routes, expanded endpoint count, and phone-load posture.
- Checkbox-driven provider sources, comfort performance modes, compact exact sample counts, horizontal sample scrubbers, score sorting, progress, live counters, guided help, visual density modes, and high-contrast result semantics.
- Explicit SNI route controls for primary-SNI probing or all-SNI route expansion.
- Scan profiles: Quick TCP, Standard TLS, Deep HTTP + SNI, and Verify CDN edge.
- Workflow modes: run one selected profile, run the automatic TCP to TLS to HTTP to Verify ladder, or run manually selected scanner stages.
- Filters for working status, TLS/HTTP status, known-CDN status, TLS 1.3, SNI text, CDN text, certificate text, max latency, and minimum score.
- Quick result buttons for working routes, TLS/HTTP evidence, and best route ranking.
- Sorting by newest, latency, score, CDN, SNI, HTTP-first, and TLS-first.
- Results include analytics, local stable observations, status heatmaps, latency distribution, CDN/SNI mix, and tap-to-copy result tiles.
- Copy/export filtered results as line-separated IPs, comma-separated IPs, IP/SNI pairs, SNI-only lists, CSV, or JSON.
- Shizuku-backed radio diagnostics for explicit user-controlled network-mode reads and guarded LTE/5G/Auto writes on supported devices.
- Android home-screen quick scan widget and Quick Settings tile.
- Optional Go sidecar with streaming scan and DNS endpoints.
- Safety mode with bundled do-not-scan CIDRs, strict CIDR expansion caps, reserved/special-use address skipping, pacing, jitter, and adaptive backoff when timeout/reset rates rise.
- GitHub Actions worker that downloads Go and Gradle dependencies, builds sidecar binaries, builds APKs, uploads artifacts, and publishes a dependency-warmed GHCR container.

## Current Status

The Android UI is implemented with Java/programmatic views. The active structure is `Sources`, `Results`, and `Diagnostics`: scan inputs stay in Sources, visible result shaping stays in Results, and operational context stays in Diagnostics. Sources includes a source-health panel for target/SNI composition and load posture. Result cards remain the primary artifact; copy/export never replaces the visual card surface with raw text.

The Go sidecar is a standalone HTTP service. It uses structured `slog` logging, graceful HTTP shutdown, IPv4/IPv6 target parsing, uTLS ClientHello rotation, ALPN negotiation for `h2` and `http/1.1`, Alt-Svc HTTP/3 hint capture, and `github.com/miekg/dns` for DNS queries.

The sidecar also uses pooled HTTP readers, bounded CIDR expansion, dynamic safety-prefix loading from `go-sidecar/assets/do_not_scan_cidrs.txt`, and adaptive scan backoff when recent results show a high timeout/reset ratio.

## Android Build

Open the repository in Android Studio, or build from PowerShell with Gradle 8.x and JDK 17 available on `PATH`.

```powershell
$env:JAVA_HOME='C:\Program Files\Eclipse Adoptium\jdk-17.0.19.10-hotspot'
gradle --no-daemon :app:assembleDebug :app:assembleRelease
```

The GitHub worker is the recommended clean build path when local Android tooling is not installed.

Generated APKs:

- `app/build/outputs/apk/universal/debug/MaybeEdgeScanner-universal-debug.apk`
- `app/build/outputs/apk/universal/release/MaybeEdgeScanner-universal-release.apk`
- `app/build/outputs/apk/armv7/release/MaybeEdgeScanner-armv7-release.apk`
- `app/build/outputs/apk/armv8/release/MaybeEdgeScanner-armv8-release.apk`

The `universal` artifact is the default recommendation. `armv7` targets `armeabi-v7a`; `armv8` targets `arm64-v8a`. The app is mostly Java, so the split artifacts are primarily release-channel clarity and future native-library readiness rather than a runtime requirement.

## Shizuku Radio Diagnostics

Diagnostics includes a guarded Shizuku panel for users who explicitly want to inspect or change Android radio preference settings.

- Uses the official `dev.rikka.shizuku` API and provider.
- Requests Shizuku permission only after the user taps the action.
- Links directly to the official Shizuku GitHub release for APK install/update checks, while still linking the official setup guide.
- Shows binder state, server version, and backend identity so users can distinguish root (`UID 0`) from ADB shell (`UID 2000`).
- Includes a safe bridge probe that prints Android version, device identity, command reach, and current radio readback before any write is attempted.
- Reads common `preferred_network_mode` keys before/after changes.
- Provides guarded `LTE only`, `5G/LTE`, and `Auto` actions with confirmation dialogs.
- Provides a sanitized advanced key/value override for OEM and SIM-slot variants.
- Does not expose arbitrary shell commands.
- Does not run during scans or change radio state automatically.

### Modern Android Compatibility

Shizuku remains viable on newer phones, but the startup path depends on Android version and device policy:

- Android 11 and newer: users can usually start Shizuku fully on-device through Android's Wireless debugging flow. This is the best path for modern non-rooted phones because it does not require a computer after setup.
- Android 13 and newer: recent Shizuku releases include newer-platform startup improvements, including trusted-WLAN auto-start support on supported builds.
- Android 16-era devices: current Shizuku releases are still being updated for new platform behavior. Use the latest official GitHub release when testing brand-new Android builds.
- Android 10 and older: Shizuku can still be used, but non-rooted devices normally need computer ADB again after reboot.
- Rooted devices: Shizuku can run with root, or users can use Sui. The app detects `UID 0` vs `UID 2000` so the diagnostics are honest about the backend.

For our app, the direct GitHub Release link is preferable to making Google Play the main path because it is universal, version-visible, and works for users without Play access. The official Shizuku download page is still useful as a hub because it lists Play Store, GitHub, and F-Droid-style options.

### Architecture Notes

Shizuku does not magically grant every permission to this app. It supplies a privileged Binder bridge or a privileged process identity. ADB-backed Shizuku runs as shell (`UID 2000`), which has many Android shell permissions but is still constrained by SELinux, vendor policy, hidden API restrictions, modem/carrier behavior, and Android version changes. Root/Sui has broader reach (`UID 0`) but still deserves explicit user confirmation for risky actions.

This app currently keeps Shizuku usage narrow: status checks, a safe bridge probe, readback, and guarded `settings` writes for radio preference keys. The deeper future refinement would be a Shizuku UserService/AIDL module for richer privileged APIs without parsing shell text. That is the right direction for anything beyond these small, auditable radio commands.

Hidden API bypass libraries are intentionally not included right now. They are useful when calling restricted framework APIs directly from the app process, but this app currently uses Shizuku for narrow shell-backed diagnostics. Adding hidden API bypass before a real Binder/UserService need would add distribution risk without improving the current radio panel.

Android radio integers, shell permissions, and settings keys vary by OEM, carrier, Android version, modem, and SIM slot. ADB-backed Shizuku is powerful but not the same as root; it can use many shell-granted Android permissions, but it cannot bypass every platform, SELinux, or vendor restriction. If a device behaves unexpectedly, use `Auto`, the Android network settings button, or the Shizuku readback output to restore the intended mode.

## Install Identity

- Release package: `com.maybeknott.maybeedgescanner`
- Debug package: `com.maybeknott.maybeedgescanner.debug`
- Java namespace: `com.maybeedgescanner`
- App label: `MaybeEdgeScanner`
- Launcher icon: `@mipmap/ic_launcher`
- Round launcher icon: `@mipmap/ic_launcher_round`

Debug builds install separately from release builds so local testing does not overwrite a signed release app.

## Sources And SNI Routes

Bundled assets live under `app/src/main/assets`.

Important groups:

- Default target list.
- Default SNI list.
- Extra community edge list.
- Provider-specific corpora under `scan-corpora`.

Provider checkboxes enable or disable managed sources without dumping sampled corpora into custom text boxes. User-entered IPs, CIDRs, domains, and SNIs remain first-class custom additions. Several CDN families can be selected for one run, and the default SNI route corpus can be selected or deselected like any other source. The source-health panel keeps route mode visible so users know whether the scanner will try the primary SNI first or expand across all SNI routes.

Per-source sample controls decide how many entries to load from each source. Type an exact number for repeatable runs, scrub horizontally for coarse adjustment, or use `0` for the complete source. The global total cap controls the final expanded scan sample, and compact density caps card rendering while skipping heavyweight visual panels so mode changes stay responsive.

## In-App Reference

The app includes a `Reference` button. It explains:

- What targets are.
- What SNI means.
- Which scan profile to use.
- How total cap, batch, threads, and timeout affect speed and battery.
- How filtering, score sorting, and filtered copy/export work.
- How visual modes work.
- How the live analytics panel summarizes visible status, latency, and CDN distribution.

## Scan Workflows

- `Single selected profile`: runs only Quick, Standard, Deep, or Verify.
- `Auto multi-step ladder`: runs TCP, then TLS, then HTTP/SNI, then CDN verification.
- `Manual selected steps`: runs the checked TCP/TLS/HTTP/Verify stages.

Manual mode is useful when you want the same target/SNI inputs but only certain probes.

## Filtering And Exporting

Filtered copy uses the exact visible result set after filters and sort are applied.

Clipboard/export formats:

- Line-separated IPs
- Comma-separated IPs
- IP/SNI pairs
- CSV rows
- JSON

Score sorting rewards successful TCP/TLS/HTTP checks, TLS 1.3, certificate metadata, known CDN classification, and lower latency.

## Go Sidecar

```powershell
cd go-sidecar
go test ./...
go build -trimpath -ldflags='-s -w' -o maybeedgescanner-sidecar.exe .
.\maybeedgescanner-sidecar.exe
```

Docker deployment:

```powershell
cd go-sidecar
docker compose up --build
```

Useful endpoints:

- `GET /`
- `GET /health`
- `GET /metrics`
- `GET /grafana-dashboard.json`
- `POST /api/scan`
- `POST /api/dns`
- `POST /api/stop`
- `POST /api/export/nmap`

The scan endpoint streams newline-delimited JSON so large scans can be consumed incrementally. The DNS endpoint supports `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, and `SOA` records with EDNS and DNSSEC/AD signal capture where available.

## Observability

Prometheus can scrape:

```text
http://127.0.0.1:10808/metrics
```

Grafana can import `go-sidecar/grafana-dashboard.json`, or download the same dashboard from:

```text
http://127.0.0.1:10808/grafana-dashboard.json
```

The dashboard tracks scan throughput, pass rates, timeout/reset rates, goroutines, and heap usage.

## GitHub Worker

`.github/workflows/build.yml` is the canonical clean build path. It:

- Downloads Go modules with `go mod tidy` and `go mod download`.
- Uploads the resolved `go-sidecar/go.sum` so the GitHub worker can finish dependency lock updates when local networks block module downloads.
- Runs `go test ./...` for the sidecar.
- Builds Linux, Windows, and macOS sidecar binaries.
- Downloads Gradle dependencies before Android compilation.
- Builds universal, armv7, and armv8 Android APK artifacts.
- Verifies every signed release APK with `apksigner`.
- Uploads all APK and sidecar artifacts.
- Publishes `ghcr.io/<owner>/<repo>-deps:<sha>` and `ghcr.io/<owner>/<repo>-deps:latest`.
- Uses BuildKit `gha` and registry cache layers so the dependency image reuses prior Go/Gradle layers and only refreshes changed dependency inputs.
- Checks whether dependency manifests changed or the image is missing before publishing the dependency image, so app-only commits do not rebuild dependency layers from zero.

## Support

Project repository: [MaybeEdgeScanner](https://github.com/maybeknott/MaybeEdgeScanner/)

Optional support for ongoing development:

- BTC: `bc1qt2mxzmlcv3re4pjemshejzq0hj3c8dgp0e5tvx`
- EVM-compatible networks such as ETH/ERC20/BNB/BEP20: `0x8988ed09DA218799e99Fb1E94243cC1C1cB41A40`

Please verify the asset and network before sending funds. This section is informational and optional; MaybeEdgeScanner remains fully usable without donations.

## Signing

Release signing is enabled when `signing.properties` exists. Keep real signing material private and do not commit production keystores to public repositories.

```properties
STORE_FILE=.signing/your-keystore.jks
STORE_PASSWORD=...
KEY_ALIAS=...
KEY_PASSWORD=...
```

For CI/CD, store signing values in GitHub Secrets or another encrypted secret manager and materialize them only during the worker run.

## Safe Scope

MaybeEdgeScanner is for owned, authorized, and diagnostic scanning. It intentionally excludes exploit execution, destructive traffic generation, credential capture, stealth abuse workflows, DPI poisoning, decoy traffic generation, and automated vulnerability exploitation.

Large scans can stress phones, routers, and networks. The app provides warnings, validation, sampling controls, cancellation, and pacing options so users can choose responsible limits for their environment.

Safety mode skips private, reserved, documentation, multicast, link-local, loopback, and locally configured do-not-scan CIDRs. The bundled file is intentionally editable so operators can add organization-specific opt-out ranges without changing code.

## Roadmap

Planned safe improvements include Kotlin/Compose migration, MVVM state separation, coroutine-based scan orchestration, persistent scan history, foreground-service continuity, richer analytics, better accessibility semantics, optional GeoIP/ASN tagging from user-provided databases, expanded IPv6 testing, OpenAPI documentation, and deeper CI release automation.

Advanced evasion, offensive reconnaissance, exploit verification, destructive active-defense payloads, and stealth traffic generation are outside the supported product direction.

## License

MaybeEdgeScanner is distributed under the GNU Affero General Public License v3.0. See `LICENSE`.
