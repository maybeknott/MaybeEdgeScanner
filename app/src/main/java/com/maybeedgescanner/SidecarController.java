package com.maybeedgescanner;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

/** Service-owned loopback sidecar heartbeat and shutdown control. */
final class SidecarController {
    static final String BASE_URL = "http://127.0.0.1:10808";

    private static final SidecarController INSTANCE = new SidecarController();
    private final AtomicReference<SidecarSnapshot> lastSnapshot = new AtomicReference<>(SidecarSnapshot.unavailable("never probed"));
    private volatile String authToken = "";

    private SidecarController() {}

    static SidecarController get() {
        return INSTANCE;
    }

    SidecarSnapshot snapshot() {
        return lastSnapshot.get();
    }

    void setAuthToken(String token) {
        authToken = token == null ? "" : token.trim();
    }

    String authToken() {
        return authToken;
    }

    SidecarSnapshot refreshHeartbeat(int timeoutMs) {
        SidecarSnapshot next;
        try {
            JSONObject payload = fetchJson(BASE_URL + "/api/heartbeat", timeoutMs);
            next = SidecarSnapshot.fromHeartbeat(payload);
        } catch (Exception e) {
            next = SidecarSnapshot.unavailable(e.getMessage());
        }
        lastSnapshot.set(next);
        return next;
    }

    SidecarSnapshot requestShutdown(int timeoutMs) {
        SidecarSnapshot next;
        try {
            postEmpty(BASE_URL + "/api/shutdown", timeoutMs);
            next = SidecarSnapshot.unavailable("shutdown requested");
        } catch (Exception e) {
            next = SidecarSnapshot.unavailable("shutdown failed: " + e.getMessage());
        }
        lastSnapshot.set(next);
        return next;
    }

    org.json.JSONObject fetchProviderCorpusJson(int timeoutMs) {
        try {
            return fetchJson(BASE_URL + "/api/provider-corpus", timeoutMs);
        } catch (Exception e) {
            return null;
        }
    }

    void requestShutdownAsync() {
        Thread worker = new Thread(() -> requestShutdown(2500), "sidecar-shutdown");
        worker.setDaemon(true);
        worker.start();
    }

    private static JSONObject fetchJson(String endpoint, int timeoutMs) throws Exception {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(endpoint).openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            applyAuth(conn);
            int statusCode = conn.getResponseCode();
            InputStream stream = statusCode >= 200 && statusCode < 300 ? conn.getInputStream() : conn.getErrorStream();
            if (stream == null) throw new java.io.IOException("HTTP " + statusCode);
            String text;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) sb.append(line);
                text = sb.toString();
            }
            if (statusCode < 200 || statusCode >= 300) throw new java.io.IOException("HTTP " + statusCode + ": " + text);
            return new JSONObject(text);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static void applyAuth(HttpURLConnection conn) {
        String token = INSTANCE.authToken;
        if (token == null || token.isEmpty()) return;
        conn.setRequestProperty("Authorization", "Bearer " + token);
        conn.setRequestProperty("X-Sidecar-Token", token);
    }

    private static void postEmpty(String endpoint, int timeoutMs) throws Exception {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(endpoint).openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Accept", "application/json");
            applyAuth(conn);
            try (OutputStream out = conn.getOutputStream()) {
                out.write("{}".getBytes(StandardCharsets.UTF_8));
            }
            int statusCode = conn.getResponseCode();
            if (statusCode < 200 || statusCode >= 300) {
                throw new java.io.IOException("HTTP " + statusCode);
            }
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    static final class SidecarSnapshot {
        final boolean reachable;
        final String state;
        final int version;
        final long uptimeMs;
        final String detail;

        SidecarSnapshot(boolean reachable, String state, int version, long uptimeMs, String detail) {
            this.reachable = reachable;
            this.state = state == null ? "unknown" : state;
            this.version = version;
            this.uptimeMs = uptimeMs;
            this.detail = detail == null ? "" : detail;
        }

        static SidecarSnapshot fromHeartbeat(JSONObject payload) {
            return new SidecarSnapshot(
                    true,
                    payload.optString("state", "unknown"),
                    payload.optInt("version"),
                    payload.optLong("uptime_ms"),
                    "");
        }

        static SidecarSnapshot unavailable(String detail) {
            return new SidecarSnapshot(false, "unavailable", 0, 0L, detail == null ? "" : detail);
        }
    }
}
