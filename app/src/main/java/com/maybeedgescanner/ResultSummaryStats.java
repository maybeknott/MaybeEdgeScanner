package com.maybeedgescanner;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class ResultSummaryStats {
    static final class Row {
        final boolean working;
        final long totalLatency;
        final double quality;
        final boolean httpPass;
        final boolean tlsPass;
        final List<String> hostCandidates;

        Row(boolean working, long totalLatency, double quality, boolean httpPass, boolean tlsPass, List<String> hostCandidates) {
            this.working = working;
            this.totalLatency = totalLatency;
            this.quality = quality;
            this.httpPass = httpPass;
            this.tlsPass = tlsPass;
            this.hostCandidates = hostCandidates;
        }
    }

    private ResultSummaryStats() {}

    static String format(List<Row> rows, int rawCount, String filterSummary) {
        int working = 0;
        long latencySum = 0;
        long best = Long.MAX_VALUE;
        int latencyCount = 0;
        for (Row r : rows) {
            if (r.working) working++;
            if (r.totalLatency > 0) {
                latencySum += r.totalLatency;
                latencyCount++;
                best = Math.min(best, r.totalLatency);
            }
        }
        int success = rows.isEmpty() ? 0 : Math.round(working * 100f / rows.size());
        return "Visible results: " + rows.size() + " of " + rawCount +
                " | alive/working " + working +
                " | success " + success + "%" +
                " | best " + (best == Long.MAX_VALUE ? "--" : best + "ms") +
                " | avg " + (latencyCount == 0 ? "--" : Math.round(latencySum / (float) latencyCount) + "ms") +
                " | " + bestHostLine(rows) +
                " | filters " + filterSummary;
    }

    private static String bestHostLine(List<Row> rows) {
        LinkedHashMap<String, Double> scores = new LinkedHashMap<>();
        for (Row r : rows) {
            for (String host : r.hostCandidates) {
                Double old = scores.get(host);
                double score = r.quality + (r.httpPass ? 8 : 0) + (r.tlsPass ? 10 : 0) - Math.max(0, r.totalLatency) / 900.0;
                if (old == null || score > old) scores.put(host, score);
            }
        }
        if (scores.isEmpty()) return "Best SNIs: none visible";
        ArrayList<Map.Entry<String, Double>> ordered = new ArrayList<>(scores.entrySet());
        ordered.sort((a, b) -> Double.compare(b.getValue(), a.getValue()));
        ArrayList<String> top = new ArrayList<>();
        for (int i = 0; i < Math.min(5, ordered.size()); i++) {
            Map.Entry<String, Double> e = ordered.get(i);
            top.add(e.getKey() + " q" + Math.round(e.getValue()));
        }
        return "Best SNIs: " + joinComma(top);
    }

    private static String joinComma(List<String> xs) {
        StringBuilder sb = new StringBuilder();
        for (String x : xs) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(x);
        }
        return sb.toString();
    }
}
