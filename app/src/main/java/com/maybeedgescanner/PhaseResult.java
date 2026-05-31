package com.maybeedgescanner;

import org.json.JSONObject;

import java.util.Locale;

/** Per-phase probe outcome aligned with sidecar PhaseResult v1. */
final class PhaseResult {
    final String phase;
    final String status;
    final long durationMs;
    final String errorCode;
    final boolean retryable;

    PhaseResult(String phase, String status, long durationMs, String errorCode, boolean retryable) {
        this.phase = phase == null ? "" : phase;
        this.status = status == null ? "failed" : status;
        this.durationMs = Math.max(0L, durationMs);
        this.errorCode = errorCode == null ? "" : errorCode;
        this.retryable = retryable;
    }

    static PhaseResult success(String phase, long durationMs) {
        return new PhaseResult(phase, "success", durationMs, "", false);
    }

    static PhaseResult failure(String phase, long durationMs, Exception error, String errorCode) {
        String code = errorCode == null || errorCode.isEmpty() ? classifyCode(error, phase) : errorCode;
        return new PhaseResult(phase, statusFromCode(code), durationMs, code, retryableFromCode(code));
    }

    JSONObject toJson() throws Exception {
        JSONObject payload = new JSONObject();
        payload.put("phase", phase);
        payload.put("status", status);
        payload.put("duration_ms", durationMs);
        payload.put("retryable", retryable);
        if (!errorCode.isEmpty()) payload.put("error_code", errorCode);
        payload.put("evidence", new JSONObject());
        return payload;
    }

    static String classifyCode(Exception error, String phase) {
        String prefix = "SCAN";
        if ("dns".equals(phase)) {
            prefix = "DNS";
        } else if ("tcp".equals(phase)) {
            prefix = "TCP_CONNECT";
        } else if ("tls".equals(phase)) {
            prefix = "TLS_HANDSHAKE";
        } else if ("http1".equals(phase) || "http2".equals(phase) || "http".equals(phase)) {
            prefix = "HTTP";
        } else if ("route".equals(phase)) {
            prefix = "ROUTE";
        }
        if (error == null) {
            return prefix + "_FAILED";
        }
        String lower = String.valueOf(error.getMessage()).toLowerCase(Locale.US);
        if (lower.contains("timeout") || lower.contains("timed out")) {
            return prefix + "_TIMEOUT";
        }
        if (lower.contains("reset")) {
            return prefix + "_RESET";
        }
        if (lower.contains("refused")) {
            return prefix + "_REFUSED";
        }
        return prefix + "_FAILED";
    }

    static String statusFromCode(String code) {
        String upper = code == null ? "" : code.toUpperCase(Locale.US);
        if (upper.isEmpty()) {
            return "failed";
        }
        if (upper.endsWith("_TIMEOUT")) {
            return "timeout";
        }
        if (upper.endsWith("_REFUSED")) {
            return "refused";
        }
        if (upper.endsWith("_RESET")) {
            return "reset";
        }
        if (upper.contains("_SKIPPED") || upper.endsWith("_EXCLUDED")) {
            return "skipped";
        }
        if (upper.contains("_UNSUPPORTED")) {
            return "unsupported";
        }
        return "failed";
    }

    static boolean retryableFromCode(String code) {
        String upper = code == null ? "" : code.toUpperCase(Locale.US);
        return upper.endsWith("_TIMEOUT") || upper.endsWith("_RESET");
    }

    static String httpPhaseFromAlpn(String alpn) {
        if (alpn != null && alpn.toLowerCase(Locale.US).contains("h2")) {
            return "http2";
        }
        return "http1";
    }

    static String displayLabel(String errorCode, String phase, String status) {
        if (errorCode != null && !errorCode.isEmpty()) {
            return humanizeCode(errorCode);
        }
        if ("success".equals(status)) {
            return capitalize(phase) + " ok";
        }
        if (phase != null && !phase.isEmpty()) {
            return capitalize(phase) + " " + (status == null || status.isEmpty() ? "failed" : status);
        }
        return "";
    }

    String displayLabel() {
        return displayLabel(errorCode, phase, status);
    }

    private static String humanizeCode(String code) {
        String[] parts = code.toLowerCase(Locale.US).split("_");
        StringBuilder sb = new StringBuilder();
        for (String part : parts) {
            if (part.isEmpty()) continue;
            if (sb.length() > 0) sb.append(' ');
            sb.append(Character.toUpperCase(part.charAt(0)));
            if (part.length() > 1) sb.append(part.substring(1));
        }
        return sb.toString();
    }

    private static String capitalize(String value) {
        if (value == null || value.isEmpty()) return "";
        return Character.toUpperCase(value.charAt(0)) + value.substring(1);
    }
}
