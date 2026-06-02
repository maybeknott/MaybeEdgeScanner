package com.maybeedgescanner;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.function.BiFunction;
import java.util.function.Function;

final class ScanInputAnalyzer {
    private ScanInputAnalyzer() {}

    static String customTargetStatsText(
            String raw,
            Function<List<String>, Integer> estimateExpandedTargetCount,
            BiFunction<String, Integer, Integer> estimateCidrCount,
            BiFunction<String, Integer, Integer> estimateRangeCount
    ) {
        InputStats stats = analyzeInput(raw, true, estimateExpandedTargetCount, estimateCidrCount, estimateRangeCount);
        if (stats.items == 0) return "Custom IPs: none";
        StringBuilder sb = new StringBuilder();
        sb.append("Custom IPs: ").append(stats.items).append(" items, ")
                .append(stats.valid).append(" valid, ")
                .append(stats.invalid).append(" invalid, ")
                .append(stats.duplicates).append(" duplicates, about ")
                .append(countLabel(stats.estimatedIps)).append(" IPs");
        if (stats.cidrs > 0 || stats.ranges > 0 || stats.hostnames > 0) {
            sb.append(" (").append(stats.cidrs).append(" CIDR, ")
                    .append(stats.ranges).append(" ranges, ")
                    .append(stats.hostnames).append(" hostnames)");
        }
        if (!stats.preview.isEmpty()) {
            sb.append(stats.items <= 8 && stats.invalid == 0 ? ". Values: " : ". Preview: ");
            sb.append(joinComma(stats.preview));
        }
        return sb.toString();
    }

    static String customSniStatsText(String raw) {
        InputStats stats = analyzeInput(raw, false, null, null, null);
        if (stats.items == 0) return "Custom SNI hosts: none";
        StringBuilder sb = new StringBuilder();
        sb.append("Custom SNI hosts: ").append(stats.items).append(" items, ")
                .append(stats.valid).append(" valid, ")
                .append(stats.invalid).append(" invalid, ")
                .append(stats.duplicates).append(" duplicates");
        if (!stats.preview.isEmpty()) {
            sb.append(stats.items <= 8 && stats.invalid == 0 ? ". Values: " : ". Preview: ");
            sb.append(joinComma(stats.preview));
        }
        return sb.toString();
    }

    static List<String> previewExpandedTargets(List<String> raw, int limit, BiFunction<String, Integer, String> sampleOneExpandedTarget) {
        ArrayList<String> out = new ArrayList<>();
        int cap = Math.max(1, limit);
        int index = 0;
        for (String token : raw) {
            if (out.size() >= cap) break;
            String clean = cleanToken(token);
            if (clean.isEmpty()) continue;
            out.add((ScanTargetPlanner.looksLikePrefix(clean) || ScanTargetPlanner.looksLikeIpv4Range(clean)) ? sampleOneExpandedTarget.apply(clean, index++) : clean);
        }
        return out;
    }

    static boolean validTargetToken(String value) {
        if (value == null || value.trim().isEmpty()) return false;
        String v = value.trim();
        if (ScanTargetPlanner.looksLikePrefix(v)) {
            String[] p = v.split("/", 2);
            try {
                int prefix = Integer.parseInt(p[1]);
                return p.length == 2 && ScanTargetPlanner.isIp(p[0]) && prefix >= 0 && prefix <= (p[0].contains(":") ? 128 : 32);
            } catch (Exception ignored) { return false; }
        }
        if (v.contains("-") && !ScanTargetPlanner.looksLikeIpv4Range(v) && !validDomainToken(v)) return false;
        if (ScanTargetPlanner.looksLikeIpv4Range(v)) return true;
        return ScanTargetPlanner.isIp(v) || validDomainToken(v);
    }

    static boolean validDomainToken(String value) {
        return value != null && value.matches("(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$");
    }

    static boolean hasValidTargets(String rawTargetsText) {
        InputStats stats = analyzeInput(rawTargetsText, true, list -> 1, (v, m) -> 0, (v, m) -> 0);
        return stats.valid > 0;
    }

    private static InputStats analyzeInput(
            String raw,
            boolean targets,
            Function<List<String>, Integer> estimateExpandedTargetCount,
            BiFunction<String, Integer, Integer> estimateCidrCount,
            BiFunction<String, Integer, Integer> estimateRangeCount
    ) {
        InputStats stats = new InputStats();
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        for (String line : raw == null ? Collections.<String>emptyList() : Arrays.asList(raw.split("\\r?\\n"))) {
            if (!line.trim().isEmpty()) stats.lines++;
            for (String part : line.split("[,;\\s]+")) {
                String clean = targets ? cleanToken(part) : part.trim().toLowerCase(Locale.US);
                if (clean.isEmpty()) continue;
                stats.items++;
                boolean valid = targets ? validTargetToken(clean) : validDomainToken(clean);
                if (!seen.add(clean)) stats.duplicates++;
                if (!valid) {
                    stats.invalid++;
                    continue;
                }
                stats.valid++;
                if (targets) {
                    int estimated = estimateExpandedTargetCount.apply(Collections.singletonList(clean));
                    stats.estimatedIps += Math.max(1, estimated);
                    if (ScanTargetPlanner.looksLikePrefix(clean) && estimateCidrCount.apply(clean, Integer.MAX_VALUE) > 0) stats.cidrs++;
                    else if (ScanTargetPlanner.looksLikeIpv4Range(clean) && estimateRangeCount.apply(clean, Integer.MAX_VALUE) > 0) stats.ranges++;
                    else if (ScanTargetPlanner.isIp(clean)) stats.ips++;
                    else stats.hostnames++;
                }
                if (stats.preview.size() < 12 && !stats.preview.contains(clean)) stats.preview.add(clean);
            }
        }
        return stats;
    }

    private static final class InputStats {
        int lines, items, valid, invalid, duplicates, ips, cidrs, ranges, hostnames;
        long estimatedIps;
        final ArrayList<String> preview = new ArrayList<>();
    }

    private static String cleanToken(String token) {
        if (token == null) return "";
        return token.trim();
    }

    private static String joinComma(List<String> values) {
        StringBuilder sb = new StringBuilder();
        for (String value : values) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(value);
        }
        return sb.toString();
    }

    private static String countLabel(long n) {
        if (n >= 1_000_000L) return String.format(Locale.US, "%.1fm", n / 1_000_000.0);
        if (n >= 1_000L) return String.format(Locale.US, "%.1fk", n / 1_000.0);
        return String.valueOf(n);
    }
}
