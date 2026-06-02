package com.maybeedgescanner;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.os.Build;
import android.os.Handler;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.TextView;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.function.Consumer;
import org.json.JSONObject;

final class NetworkDiagnosticsRunner {
    private NetworkDiagnosticsRunner() {}

    static void run(
            Context context,
            Handler ui,
            TextView diagnosticOutputView,
            Button runDiagnosticsButton,
            CheckBox diagnosticsOfflineMode,
            CheckBox diagnosticsIncludePublicIp,
            Consumer<String> appendLog
    ) {
        if (diagnosticOutputView == null || runDiagnosticsButton == null) return;
        runDiagnosticsButton.setEnabled(false);
        diagnosticOutputView.setText("Running diagnostic suite...\n");
        appendLog.accept("Network diagnostics: starting...");

        new Thread(() -> {
            StringBuilder sb = new StringBuilder();
            ArrayList<String> externalServices = new ArrayList<>();
            boolean offlineMode = diagnosticsOfflineMode != null && diagnosticsOfflineMode.isChecked();
            boolean includePublicIp = diagnosticsIncludePublicIp != null && diagnosticsIncludePublicIp.isChecked() && !offlineMode;
            sb.append("=== EDGE ROUTE DIAGNOSTIC REPORT ===\n");
            sb.append("Timestamp: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date())).append("\n\n");
            sb.append("[0] Diagnostic mode:\n");
            sb.append(" - Offline mode: ").append(offlineMode ? "ON" : "OFF").append('\n');
            sb.append(" - Public IP lookup: ").append(includePublicIp ? "ON" : "OFF").append('\n');
            sb.append('\n');

            sb.append("[1] Checking proxy & VPN posture:\n");
            try {
                ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    Network network = cm.getActiveNetwork();
                    if (network != null) {
                        NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                        if (caps != null) {
                            boolean isVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                            sb.append(" - VPN active: ").append(isVpn ? "YES (Traffic routed via VPN tunnel)" : "NO").append("\n");
                        }
                    }
                    ProxyInfo proxy = cm.getDefaultProxy();
                    if (proxy != null && proxy.getHost() != null) {
                        sb.append(" - System proxy: ").append(proxy.getHost()).append(":").append(proxy.getPort()).append("\n");
                    } else {
                        sb.append(" - System proxy: none detected\n");
                    }
                }
            } catch (Exception e) {
                sb.append(" - Error querying connection managers: ").append(e.getMessage()).append("\n");
            }
            sb.append("\n");

            if (offlineMode) {
                sb.append("[2] DNS/TCP/HTTPS checks:\n");
                sb.append(" - Skipped in offline diagnostics mode\n\n");
            } else {
                sb.append("[2] Testing DNS resolution latency:\n");
                String[] dnsHosts = {"one.one.one.one", "dns.google", "aparat.com"};
                for (String host : dnsHosts) {
                    long start = System.currentTimeMillis();
                    try {
                        InetAddress[] addrs = InetAddress.getAllByName(host);
                        long elapsed = System.currentTimeMillis() - start;
                        sb.append(" - Resolved ").append(host).append(" in ").append(elapsed).append("ms -> [");
                        for (int i = 0; i < addrs.length; i++) {
                            sb.append(addrs[i].getHostAddress());
                            if (i < addrs.length - 1) sb.append(", ");
                        }
                        sb.append("]\n");
                    } catch (Exception e) {
                        sb.append(" - Resolution failed for ").append(host).append(": ").append(e.toString()).append("\n");
                    }
                }
                sb.append("\n");

                sb.append("[3] Testing raw TCP connection latency (Port 443):\n");
                String[][] tcpHosts = {
                        {"Cloudflare", "1.1.1.1"},
                        {"Google DNS", "8.8.8.8"},
                        {"Akamai DNS", "184.26.160.25"},
                };
                for (String[] pair : tcpHosts) {
                    String name = pair[0];
                    String ip = pair[1];
                    long start = System.currentTimeMillis();
                    try (Socket s = new Socket()) {
                        s.connect(new InetSocketAddress(ip, 443), 2000);
                        long elapsed = System.currentTimeMillis() - start;
                        sb.append(" - Connected to ").append(name).append(" (").append(ip).append(") in ").append(elapsed).append("ms\n");
                    } catch (Exception e) {
                        sb.append(" - Connection failed to ").append(name).append(" (").append(ip).append("): ").append(e.getMessage()).append("\n");
                    }
                }
                sb.append("\n");

                sb.append("[4] Testing secure HTTPS negotiation handshake:\n");
                String[] httpsTargets = {"https://1.1.1.1", "https://8.8.8.8", "https://www.google.com"};
                for (String target : httpsTargets) {
                    long start = System.currentTimeMillis();
                    HttpURLConnection conn = null;
                    try {
                        conn = (HttpURLConnection) new URL(target).openConnection();
                        conn.setConnectTimeout(2500);
                        conn.setReadTimeout(2500);
                        conn.setRequestMethod("GET");
                        int code = conn.getResponseCode();
                        long elapsed = System.currentTimeMillis() - start;
                        sb.append(" - GET ").append(target).append(" status ").append(code).append(" in ").append(elapsed).append("ms\n");
                        externalServices.add(target);
                    } catch (Exception e) {
                        sb.append(" - HTTPS negotiation failed for ").append(target).append(": ").append(e.toString()).append("\n");
                    } finally {
                        if (conn != null) conn.disconnect();
                    }
                }
                sb.append("\n");
                if (includePublicIp) {
                    sb.append("[5] Public IP lookup:\n");
                    String publicIpURL = "https://api.ipify.org?format=json";
                    try {
                        JSONObject publicIp = fetchJson(publicIpURL, 2500);
                        sb.append(" - api.ipify.org response: ").append(publicIp.optString("ip", "unknown")).append('\n');
                        externalServices.add(publicIpURL);
                    } catch (Exception e) {
                        sb.append(" - Public IP lookup failed: ").append(e.getMessage()).append('\n');
                    }
                    sb.append('\n');
                }
            }

            sb.append("[6] Local sidecar state:\n");
            SidecarController.SidecarSnapshot sidecar = SidecarController.get().refreshHeartbeat(1200);
            if (sidecar.reachable) {
                sb.append(" - heartbeat version=").append(sidecar.version)
                        .append(" state=").append(sidecar.state)
                        .append(" uptime_ms=").append(sidecar.uptimeMs).append('\n');
            } else {
                sb.append(" - heartbeat unavailable: ").append(sidecar.detail).append('\n');
            }
            try {
                JSONObject corpus = SidecarController.get().fetchProviderCorpusJson(1200);
                if (corpus != null) {
                    sb.append(" - provider corpus id=").append(corpus.optString("corpus_id", "unknown"))
                            .append(" stale=").append(corpus.optBoolean("stale", false))
                            .append(" stale_after=").append(corpus.optString("stale_after", "unknown")).append('\n');
                } else {
                    sb.append(" - provider corpus status unavailable\n");
                }
            } catch (Exception e) {
                sb.append(" - provider corpus status unavailable: ").append(e.getMessage()).append('\n');
            }
            sb.append('\n');

            sb.append("[7] Route-aware runtime environments:\n");
            sb.append(" - Device: ").append(Build.MANUFACTURER).append(" ").append(Build.MODEL).append("\n");
            sb.append(" - Android version: ").append(Build.VERSION.RELEASE).append(" (API ").append(Build.VERSION.SDK_INT).append(")\n");
            Runtime rt = Runtime.getRuntime();
            long freeHeap = rt.freeMemory() / (1024 * 1024);
            long totalHeap = rt.totalMemory() / (1024 * 1024);
            sb.append(" - JVM Heap memory: total ").append(totalHeap).append("MB, free ").append(freeHeap).append("MB\n");
            sb.append('\n');

            sb.append("[8] External services contacted:\n");
            if (externalServices.isEmpty()) {
                sb.append(" - none\n");
            } else {
                LinkedHashSet<String> unique = new LinkedHashSet<>(externalServices);
                for (String service : unique) sb.append(" - ").append(service).append('\n');
            }

            String report = sb.toString();
            appendLog.accept("Network diagnostics: completed.");
            ui.post(() -> {
                diagnosticOutputView.setText(report);
                runDiagnosticsButton.setEnabled(true);
            });
        }, "network-diagnostic-thread").start();
    }

    private static JSONObject fetchJson(String endpoint, int timeoutMs) throws Exception {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(endpoint).openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            int statusCode = conn.getResponseCode();
            InputStream stream = statusCode >= 200 && statusCode < 300 ? conn.getInputStream() : conn.getErrorStream();
            if (stream == null) throw new IOException("HTTP " + statusCode);
            String text;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) sb.append(line);
                text = sb.toString();
            }
            if (statusCode < 200 || statusCode >= 300) throw new IOException("HTTP " + statusCode + ": " + text);
            return new JSONObject(text);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }
}
