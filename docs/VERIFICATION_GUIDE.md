# MaybeEdgeScanner Verification & Build Guide

This manual outlines the process for building, testing, and verifying the **MaybeEdgeScanner** suite.

---

## 1. Prerequisites

Ensure you have the following environments configured on your development system:
* **JDK 17** (with `JAVA_HOME` pointing to your Adoptium or similar OpenJDK installation)
* **Android SDK** (with `ANDROID_HOME` or `sdk.dir` in `local.properties` set correctly)
* **Go 1.21+** (for building and testing the sidecar routing engine)
* **Gradle 8.14+** (already bundled inside the project via `gradlew`)

---

## 2. Testing the Go Backend Engine

The Go routing engine contains integrated unit tests evaluating address expansion, duplicate filtering, loop limits, and DNS message parsing.

Run all Go tests inside the `go-sidecar` directory:
```bash
cd go-sidecar
go test -v ./...
```

If all tests compile and execute successfully, you will see a green report:
```text
=== RUN   TestParseDNSMessageCapturesAnswersAndFlags
--- PASS: TestParseDNSMessageCapturesAnswersAndFlags (0.00s)
=== RUN   TestDNSTypeCodeUsesMiekgRegistry
--- PASS: TestDNSTypeCodeUsesMiekgRegistry (0.00s)
=== RUN   TestCandidateSNIsKeepsTargetsAndCorpusSeparate
--- PASS: TestCandidateSNIsKeepsTargetsAndCorpusSeparate (0.00s)
=== RUN   TestExpandTargetsExpandsIPv4RangesAndSmallCIDRs
--- PASS: TestExpandTargetsExpandsIPv4RangesAndSmallCIDRs (0.00s)
PASS
ok  	maybeedgescanner-sidecar
```

---

## 3. Building the Android Client

To compile the Android client application and package the APK binaries, run the following Gradle commands.

### 3.1 Local Manual Build (Debug Mode)
Use the local Java 17 path to trigger Gradle:
```powershell
# In PowerShell:
$env:JAVA_HOME="C:\Program Files\Eclipse Adoptium\jdk-17.0.19.10-hotspot"
./gradlew.bat assembleDebug
```

This compiles three APK architectures under `app/build/outputs/apk/`:
1. **Universal debug flavor**: `app-universal-debug.apk` (Supports all major device architectures, contains standard debugging symbols).
2. **ARMv7 debug flavor**: `app-armv7-debug.apk` (Highly compressed for legacy 32-bit devices).
3. **ARMv8 debug flavor**: `app-armv8-debug.apk` (Optimized for modern 64-bit devices).

---

## 4. Production Release Pipeline & Verification

The production builds are automated symmetrically inside GitHub Actions pipelines.

### 4.1 CI/CD Workflow Steps
On every git push or pull request to primary branches, the `.github/workflows/build.yml` pipeline:
1. Installs Go and Gradle toolchains inside container runners.
2. Checks Go code quality and executes sidecar tests.
3. Automatically computes unique, semantic, non-colliding release tags matching versions and runtime logs:
   - Example format: `v1.0.0-1-52-a3b4c5d-20260521123045` (Includes short commit SHA and dynamic timestamp to avoid key collisions).
4. Compiles, optimizes, and signs release-ready APK packages for production rollout.

### 4.2 Signature Integrity Checks
To verify that the output debug/release APK complies with Android signature constraints:
```bash
apksigner verify --verbose app-universal-debug.apk
```
Confirm the exit code is `0` and signatures verify successfully against SDK v1, v2, and v3 schemes.

---

## 5. Verification of Diagnostic Suite & Log Filters

To verify the correct operation of log search and the network diagnostic checks on a running instance:
1. **Log Search Filter**:
   - Navigate to the **Diagnostics** tab (Tab 3).
   - Enter a search query in the **Search logs...** text field (e.g., `tcp` or `http`).
   - Observe that the console logs filter instantly and show only matching entries case-insensitively, returning to the full log list when the field is cleared.
2. **Network Diagnostics**:
   - Tap the **Run Diagnostics** button.
   - Observe that the button disables, and status indicator text updates to `"Running diagnostic suite..."` without blocking UI interactions or tab-swapping (no ANR).
   - Once completed, verify the report block renders detailed findings: VPN/Proxy statuses, resolved IP addresses and DNS resolution speed, raw TCP 443 connection latency, HTTP/HTTPS GET response times, device profile models, and current JVM memory allocations.
