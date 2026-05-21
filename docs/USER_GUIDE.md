# MaybeEdgeScanner User & Operator Manual

Welcome to **MaybeEdgeScanner**! This guide is designed to help operators, network engineers, and newcomers quickly master the application's comprehensive features.

---

## 1. Quick Setup & Installation

### 1.1 Device Compatibility & Requirements
* **Android OS**: Android 8.0 (API 26) through modern Android 16-era releases.
* **Hardware Requirements**: Minimum 3GB RAM recommended for large multi-threaded scans.
* **Privileged State**: Sui/Shizuku is fully optional but highly recommended to access mobile cellular diagnostics and baseband mutators.

### 1.2 Running the Go Sidecar (Optional Desktop Mode)
If you are planning to perform massive, enterprise-scale network audits from a desktop or server, the Go sidecar is your preferred interface:
```bash
./sidecar
```
Open your local browser to `http://127.0.0.1:10808` to access the responsive HTML control panel, Prometheus metrics (`/metrics`), and Grafana dashboard assets.

---

## 2. Navigating the Interface

MaybeEdgeScanner organizes its capabilities into a clean, modern **Three-Tab Glassmorphic Navigation Scaffold**. You can switch between tabs by tapping the top indicators or simply swiping horizontally.

```text
+-------------------------------------------------------+
|  🛰️ MaybeEdgeScanner                                 |
|  [Sources]                [Results]      [Diagnostics]|
+-------------------------------------------------------+
|                                                       |
|   Target Setup & Route Pairing ---> Swipe Left/Right  |
|                                                       |
+-------------------------------------------------------+
```

### Tab 1: Sources
This is your scanning command center:
* **Pre-flight Presets**: Select from a robust list of global CDNs (Cloudflare, Akamai, Fastly, AWS CloudFront, etc.) to target.
* **Managed Sampling Horizontal Scrubbers**: Use the slider to select an exact sample count from each preset. Setting the slider to `0` will load the complete preset.
* **SNI Route-Pairing Mode**:
  - *Target SNI Input*: Manual entry for specific SNI hosts to pair with the targets.
  - *Multi-SNI Checkbox*: Toggles between checking only the primary target domain or expanding probes across all bundled and custom SNI host configurations.
* **Manual Targets input**: Enter custom target ranges (IPv4, IPv6, hostnames, CIDRs, or hyphen ranges) separated by spaces or commas.
* **Performance Posture (Source-Health panel)**: Evaluates target configurations dynamically and indicates whether your configuration represents a `LIGHT` (1-16 threads), `BALANCED` (17-64 threads), or `HIGH` (65+ threads) load on your device's battery and processor.

### Tab 2: Results
Analyzes incoming telemetry findings in real time:
* **Interactive Result Cards**: Tap any card to view detailed TLS versions, cipher suites, ALPN values, HTTP status codes, paired SNI hosts, and certificate fingerprints.
* **Visual Telemetry Graphs**: Direct real-time charts illustrating endpoint working ratios, latency distributions, and CDN distributions.
* **Quick Action Filters**: Jump to "Working Endpoints," "Evidence Records," or the "Best Ranked per IP."
* **Advanced Filter Bars**: Filter results instantly by status, known CDNs, latency caps, or quality scores.
* **Flexible Export Panels**: Copy or export filtered targets as line-separated lists, JSON objects, or CSV files.

### Tab 3: Diagnostics
System health and low-level adjustments:
* **Live System Logs & Search**: View runtime engine logs. Features a real-time, case-insensitive log filter/search widget allowing rapid string lookup across large scrolling logs without UI stutter.
* **Automated Network Diagnostic Suite**: Clickable diagnostic test runner executing in a dedicated background thread. Tests VPN/Proxy transport indicators, evaluates multi-domain DNS resolution latency (e.g. `one.one.one.one`, `dns.google`, `aparat.com`), tests raw TCP connect speed (port 443), validates secure HTTPS protocol negotiations, and dumps JVM heap allocations.
* **Privileged Shizuku Controls**: Direct, guarded access to mobile baseband configurations.

---

## 3. Custom Target Input Formats

The manual targets text area in `Sources` accepts complex inputs. You can combine multiple formats separated by spaces, newlines, or commas:

| Input Example | Target Resolution |
| :--- | :--- |
| `1.1.1.1` | Single IPv4 address |
| `2606:4700:4700::1111` | Single IPv6 address |
| `one.one.one.one` | Resolved hostname address |
| `192.168.1.0/24` | CIDR notation (expands up to the safe CIDR limit) |
| `192.168.1.10-192.168.1.20` | Hyphen-separated IP range |

> [!IMPORTANT]
> To prevent app lag and system battery drain, very large CIDR expansions (such as `/16` subnets) are capped by a strict built-in safety limit.

---

## 4. Setting up Scan Profiles

MaybeEdgeScanner supports four core auditing profiles:
1. **Quick TCP**: Measures basic port reachability and latency. Extremely fast, ideal for checking general uptime.
2. **Standard TLS**: Performs complete TLS 1.3 handshakes, extracts certificate authorities, verified names, and cipher suites.
3. **Deep HTTP**: Upgrades the TCP/TLS probe to send a full `HEAD` request, verifying remote HTTP responses, server headers, and ALPN flags.
4. **Verify CDN Edge**: Queries CDN metadata, checking headers for cache and provider identity.

---

## 5. Operating Privileged Cell Diagnostics (Shizuku)

If Shizuku is configured on your device, you can use the **Diagnostics** panel to modify your preferred mobile cell bands:

```text
            [ Start Shizuku Service ]
                        │
           [ Execute Safe Bridge Probe ]
                        │
   ┌────────────────────┼────────────────────┐
   ▼                    ▼                    ▼
 [ LTE Only ]       [ 5G / LTE ]          [ Auto ]
```

### Steps to Mutate Preferred Networks Safely:
1. **Start Shizuku**: Confirm Shizuku is active on your device.
2. **Execute Bridge Probe**: Tap the probe button to verify that the app can read system settings keys.
3. **Select Radio Preference**: Tap a mode (e.g., **5G/LTE**). A warning dialog will ask you to confirm.
4. **Mutate**: The app will bundle settings keys and apply the changes via type-safe binder transactions. Cell handovers take 5-10 seconds to stabilize.

---

## 6. Advanced Go Sidecar Capabilities

When running in sidecar mode, you can monitor performance logs dynamically:
* **Prometheus Endpoint**: Connect your local Prometheus instance to `http://localhost:10808/metrics`.
* **Grafana Integration**: Import the bundled `go-sidecar/grafana-dashboard.json` into your local Grafana portal to access real-time charts.
* **Safety Opt-out list**: Add target ranges to `go-sidecar/assets/do_not_scan_cidrs.txt` to completely block the sidecar from auditing specific subnets.

---

## 7. Operational Troubleshooting

| Symptom | Cause | Remediation |
| :--- | :--- | :--- |
| **Shizuku Binding Fails** | Shizuku Manager is not authorized or not running. | Open Shizuku app, start the service, and grant permission to MaybeEdgeScanner. |
| **All Probes Timeout** | Local firewall, VPN, or network interface blocking raw outbound sockets. | Disable custom DNS proxies or active VPNs, and verify standard internet connectivity. |
| **Out-Of-Memory / App Crash** | Too many parallel threads or extremely large CIDR expansions. | Reduce threads to 32 or less, and set a smaller target cap slider on Tab 1. |
