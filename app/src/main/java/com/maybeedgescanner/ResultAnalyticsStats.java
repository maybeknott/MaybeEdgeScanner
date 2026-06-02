package com.maybeedgescanner;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

final class ResultAnalyticsStats {
    int total;
    int http;
    int tls;
    int tcp;
    int down;
    int fast;
    int medium;
    int slow;
    int verySlow;
    final Map<String, Integer> networkGroups = new TreeMap<>();

    static ResultAnalyticsStats from(List<MainActivity.Result> rows) {
        ResultAnalyticsStats s = new ResultAnalyticsStats();
        if (rows == null) return s;
        s.total = rows.size();
        for (MainActivity.Result r : rows) {
            if (r.httpPass) s.http++;
            else if (r.tlsPass) s.tls++;
            else if (r.tcpPass) s.tcp++;
            else s.down++;
            long latency = r.totalLatency();
            if (latency > 0 && latency < 120) s.fast++;
            else if (latency < 300) s.medium++;
            else if (latency < 700) s.slow++;
            else if (latency > 0) s.verySlow++;
            String network = networkKey(r.networkClassification);
            s.networkGroups.put(network, s.networkGroups.containsKey(network) ? s.networkGroups.get(network) + 1 : 1);
        }
        return s;
    }

    static String networkKey(String networkClassification) {
        return networkClassification == null || networkClassification.trim().isEmpty()
                ? "UNKNOWN"
                : networkClassification.toUpperCase(Locale.US);
    }
}
