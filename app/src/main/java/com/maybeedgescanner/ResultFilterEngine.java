package com.maybeedgescanner;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class ResultFilterEngine {
    static final class Spec {
        boolean requireWorking;
        boolean requireTlsOrHttp;
        boolean requireHttp;
        boolean requireKnownClassification;
        boolean requireTls13;
        boolean bestPerEndpoint;
        int maxLatency;
        int minQuality;
        int sortMode;
        String networkPreset;
        String networkText;
        String certText;
        String hostText;
    }

    interface Accessor<T> {
        boolean working(T row);
        boolean tlsPass(T row);
        boolean httpPass(T row);
        String tlsVersion(T row);
        long totalLatency(T row);
        double quality(T row);
        String networkClassification(T row);
        String certificateText(T row);
        String hostHintText(T row);
        String endpointKey(T row);
        String sortHostKey(T row);
    }

    private ResultFilterEngine() {}

    static <T> List<T> apply(List<T> source, Spec spec, Accessor<T> a) {
        List<T> snapshot = new ArrayList<>();
        String networkText = safeLower(spec.networkText);
        String certText = safeLower(spec.certText);
        String hostText = safeLower(spec.hostText);
        for (T r : source) {
            if (spec.requireWorking && !a.working(r)) continue;
            if (spec.requireTlsOrHttp && !(a.tlsPass(r) || a.httpPass(r))) continue;
            if (spec.requireHttp && !a.httpPass(r)) continue;
            String classification = safe(a.networkClassification(r));
            if (spec.requireKnownClassification && "UNKNOWN".equalsIgnoreCase(classification)) continue;
            if (!providerMatches(spec.networkPreset, classification)) continue;
            if (spec.requireTls13 && !safe(a.tlsVersion(r)).contains("1.3")) continue;
            long latency = a.totalLatency(r);
            if (spec.maxLatency > 0 && (latency <= 0 || latency > spec.maxLatency)) continue;
            if (spec.minQuality > 0 && a.quality(r) < spec.minQuality) continue;
            if (!networkText.isEmpty() && !safeLower(classification).contains(networkText)) continue;
            // Edge workflows bind SNI/Host pairs; keep host filter tolerant by
            // matching either SNI hint or certificate text evidence.
            if (!hostText.isEmpty()) {
                boolean inHostHint = safeLower(a.hostHintText(r)).contains(hostText);
                boolean inCert = safeLower(a.certificateText(r)).contains(hostText);
                if (!inHostHint && !inCert) continue;
            }
            if (!certText.isEmpty() && !safeLower(a.certificateText(r)).contains(certText)) continue;
            snapshot.add(r);
        }
        if (spec.bestPerEndpoint) {
            Map<String, T> best = new LinkedHashMap<>();
            for (T r : snapshot) {
                String key = safe(a.endpointKey(r));
                if (key.isEmpty()) continue;
                T old = best.get(key);
                if (old == null || a.quality(r) > a.quality(old)) best.put(key, r);
            }
            snapshot = new ArrayList<>(best.values());
        }
        sort(snapshot, spec.sortMode, a);
        return snapshot;
    }

    private static <T> void sort(List<T> rows, int sortMode, Accessor<T> a) {
        if (sortMode == 1) {
            rows.sort(Comparator.comparingLong(r -> {
                long latency = a.totalLatency(r);
                return latency > 0 ? latency : Long.MAX_VALUE;
            }));
            return;
        }
        if (sortMode == 2) {
            rows.sort((x, y) -> Double.compare(a.quality(y), a.quality(x)));
            return;
        }
        if (sortMode == 3) {
            rows.sort(Comparator.comparing((T r) -> safe(a.networkClassification(r)))
                    .thenComparing((x, y) -> Double.compare(a.quality(y), a.quality(x))));
            return;
        }
        if (sortMode == 4) {
            rows.sort(Comparator.comparing(r -> safeLower(a.sortHostKey(r))));
            return;
        }
        if (sortMode == 5) {
            rows.sort((x, y) -> {
                int httpCmp = Boolean.compare(a.httpPass(y), a.httpPass(x));
                if (httpCmp != 0) return httpCmp;
                return Double.compare(a.quality(y), a.quality(x));
            });
            return;
        }
        if (sortMode == 6) {
            rows.sort((x, y) -> {
                int tlsCmp = Boolean.compare(a.tlsPass(y), a.tlsPass(x));
                if (tlsCmp != 0) return tlsCmp;
                return Double.compare(a.quality(y), a.quality(x));
            });
            return;
        }
        Collections.reverse(rows);
    }

    static boolean providerMatches(String preset, String provider) {
        String choice = safeLower(preset);
        String classification = safeLower(provider);
        if (choice.isEmpty() || choice.startsWith("any")) return true;
        if (choice.contains("windscribe")) return classification.contains("windscribe");
        if (choice.contains("psiphon")) return classification.contains("psiphon");
        if (choice.contains("proxy")) return classification.contains("proxy") || classification.contains("socks") || classification.contains("http connect");
        if (choice.startsWith("known")) return !classification.isEmpty() && !"unknown".equals(classification);
        if (choice.startsWith("unknown")) return classification.isEmpty() || "unknown".equals(classification);
        if (choice.contains("cloudfront") || choice.contains("aws")) return classification.contains("cloudfront") || classification.contains("aws") || classification.contains("amazon");
        if (choice.contains("cloudflare")) return classification.contains("cloudflare");
        if (choice.contains("akamai")) return classification.contains("akamai");
        if (choice.contains("fastly")) return classification.contains("fastly");
        if (choice.contains("github")) return classification.contains("github");
        if (choice.contains("google")) return classification.contains("google") || classification.contains("gcp");
        if (choice.contains("azure")) return classification.contains("azure") || classification.contains("microsoft");
        if (choice.contains("bunny")) return classification.contains("bunny");
        return classification.contains(choice);
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static String safeLower(String value) {
        return safe(value).trim().toLowerCase(Locale.US);
    }
}
