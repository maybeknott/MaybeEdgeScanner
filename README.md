# 🛰️ MaybeEdgeScanner

[![Android Build](https://img.shields.io/badge/Android-Build%20Passed-success?style=for-the-badge&logo=android&color=3DDC84)](https://github.com/maybeknott/MaybeEdgeScanner)
[![Go Backend](https://img.shields.io/badge/Go%20Sidecar-Verified-blue?style=for-the-badge&logo=go&color=00ADD8)](https://github.com/maybeknott/MaybeEdgeScanner)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-red.svg?style=for-the-badge)](https://www.gnu.org/licenses/agpl-3.0)

**MaybeEdgeScanner** is a professional-grade, high-performance SNI/IP route-pairing scanner for Android, complete with an optional, high-throughput Go backend sidecar (`go-sidecar`). Engineered with a modern, glassmorphic programmatic user interface and direct type-safe telephony binder diagnostic capabilities, it represents a premium standard in network auditing and performance measurements.

---

## 🎨 Premium Visual Design & Glassmorphic Aesthetics

MaybeEdgeScanner features a state-of-the-art **Glassmorphic UI Engine** built entirely in programmatically optimized Java, ensuring fluid rendering and sub-millisecond drawing times.
* **Curated Harmonious Palette**: Designed around a compliant dark-mode system utilizing high-contrast WCAG cyan (`#17C0EB`), deep midnight blue gradients (`#0D1C27` to `#09141D`), and soft slate muted coordinate layers.
* **Micro-Animations & Easing**: Every interactive element features touch scale-down states (`0.98f`), fluid rotational arrow transitions (`▼` to `▲`) powered by decel-interpolator easing vectors, and tactile haptic clicks (`HapticFeedbackConstants.CONTEXT_CLICK`).
* **Ultra-Premium Glassmorphism**: Cards and overlay panels utilize a semi-transparent dark backing. On high-density screens, the glass stroke border is set to exactly `1` physical pixel (rather than using `dp(1)`) with a lowered opacity to construct an incredibly subtle, state-of-the-art glass outline.
* **Adaptive Coordinate Layouts**: Built without absolute pixel bounds, all layouts leverage dynamic relative scaling and weight rules. The coordinate scaffold automatically adapts to **Multi-Window**, **Split-Screen resizes**, high-DPI tablets, and foldable phones without layout clipping or text overlap.

---

## 🚀 Key Capabilities

### 📱 Android Native Scanner
* **Multi-Tab Glassmorphic Navigation**: Seamless swipe gestures and smooth visibility toggles between `Sources` (target setup), `Results` (observability panels), and `Diagnostics` (logs and baseband systems), preserving scroll states and eliminating layout jumps.
* **Direct Network Probes**: Symmetrically engineered socket connect engine executing raw TCP, TLS 1.3 handshakes, and HTTP/1.1 HEAD transactions. Utilizes a secure nested try-with-resources model providing mathematical file descriptor (fd) and socket leak protection under high parallel loads.
* **Symmetrical Route Pairing**: Managed checkbox-driven target lists (Cloudflare, Akamai, Fastly, CloudFront, etc.) coupled with explicit SNI route controllers. Supports testing against the primary SNI host or expanding across all custom and bundled SNI hostnames.
* **Diagnostic Telephony & Suite**: Direct privileged connection to Android's internal `phone` binder proxy (`ITelephony.aidl`) over Shizuku, allowing guarded preferred-network mutations and real-time cellular diagnostics. Equipped with a real-time, case-insensitive log filter/search widget and an automated, non-blocking Network Diagnostic Suite (checking VPN/Proxy status, DNS latency, raw TCP connectivity, secure HTTPS negotiation, and JVM heap memory allocations).

### ⚙️ Go Backend Sidecar
* **High-Throughput Concurrent Scan**: Lock-free IP and SNI pairing expansions mapped directly into custom Go channels.
* **Longest-Prefix Radix Tree Matching**: Fast IP-to-CDN classification utilizing a custom prefix routing lookup structure.
* **Evasion & Safety Safeguards**: Skips reserved, special-use, loopback, multicast, and operator-defined blacklisted ranges.
* **Rolling Deadlines**: Dynamic read/write deadline pacing (e.g. `SetReadDeadline`) preventing connection hanging, pipeline blockages, or socket starvation.
* **Observability Pipeline**: Native Prometheus metrics exporter and built-in Grafana dashboard streaming for professional network operation centers.

---

## ⚖️ Symmetrical Sibling Differences

MaybeEdgeScanner maintains absolute layout and subsystem symmetry with its sibling project, **MaybeScanner**, sharing identical layouts, diagnostics, and platform boundaries. The single intentional difference is their scan target mapping scope:
1. **MaybeEdgeScanner (Route-Pairing)**: Symmetrically pairs explicit target endpoints with SNI hostnames to check complex CDN edge configurations and routing tables.
2. **MaybeScanner (Target-First)**: Audits target IPs/domains directly. SNIs extracted from remote TLS certificates during handshakes are logged as host hints.

---

## 📂 Project Structure

```text
MaybeEdgeScanner/
├── .github/workflows/   # CI/CD semantic dynamic tag workflows
├── app/                 # Android Client
│   ├── src/main/aidl/   # Type-safe ITelephony.aidl definitions
│   ├── src/main/assets/ # Pre-flight default scan corpora & preset lists
│   └── src/main/java/   # Programmatic UI and Scanner Engine
├── go-sidecar/          # Standalone Go Probing Sidecar Service
│   ├── assets/          # Safety CIDR blacklists
│   └── main.go          # High-performance parallel scanning logic
├── docs/                # Architecture, User, and Verification manuals
└── README.md            # Primary Product Portal
```

---

## ⚡ Newcomer Quick Start

### 1. Prerequisites
* **Android Development**: Java Development Kit (JDK) 17 and Android SDK.
* **Go Sidecar**: Go 1.21 or newer.

### 2. Building the Android App
Configure Java 17 and run the Gradle task from your terminal:
```powershell
# Set JDK 17 environment variables
$env:JAVA_HOME="C:\Program Files\Eclipse Adoptium\jdk-17.0.19.10-hotspot"

# Clean and build debug configuration APK
./gradlew.bat clean assembleDebug

# Clean and build release configuration APK
./gradlew.bat clean assembleRelease
```
*Output APKs are generated under `app/build/outputs/apk/debug/` and `app/build/outputs/apk/release/`.*

### 3. Running the Go Sidecar
Navigate to the sidecar directory and execute the test runner and compiler:
```bash
cd go-sidecar

# Run all backend unit tests
go test -v ./...

# Build the binary
go build -o sidecar .

# Run the sidecar service
./sidecar
```
*Open your local browser to `http://127.0.0.1:10808` to access the responsive web control dashboard and Prometheus telemetry endpoint `/metrics`.*

---

## 📜 Documentation Index

We maintain comprehensive, institutional-grade documentation under the `docs/` folder:
* **[Architectural Guide & Design Manual](file:///C:/Users/ACER/Documents/GitHub/Scanners/MaybeEdgeScanner/docs/ARCHITECTURAL_GUIDE.md)**: Deep technical exploration of uTLS socket designs, Shizuku binder transactions, and lifecycle memory handling.
* **[User Guide & Operator Manual](file:///C:/Users/ACER/Documents/GitHub/Scanners/MaybeEdgeScanner/docs/USER_GUIDE.md)**: Practical operation, scanning workflows, Shizuku cell diagnostic setups, and optimization checklists.
* **[Verification & Build Manual](file:///C:/Users/ACER/Documents/GitHub/Scanners/MaybeEdgeScanner/docs/VERIFICATION_GUIDE.md)**: Symmetrical compilations, unit testing protocols, and signature verification commands.

---

## 🤝 Support & Licensing

Project Portal: [MaybeEdgeScanner GitHub](https://github.com/maybeknott/MaybeEdgeScanner)

*MaybeEdgeScanner is distributed under the **GNU Affero General Public License v3.0**. Built with ❤️ by developers for professionals.*
