package com.maybeedgescanner;

import org.json.JSONArray;

import java.util.LinkedHashSet;
import java.util.List;

final class ResultExportFormatter {
    private static final String CSV_HEADER = "target,ip,port,sni,tcp,tls,http,http_status,latency_ms,alpn,tls_profile,http3_hint,network_classification,quality,reason\n";

    private ResultExportFormatter() {}

    static MainActivity.ExportPayload buildSelectedFormat(
            List<MainActivity.Result> rows,
            int format,
            String selectedLabel
    ) throws Exception {
        if (format == 5) {
            JSONArray arr = new JSONArray();
            for (MainActivity.Result r : rows) arr.put(r.json());
            return new MainActivity.ExportPayload("JSON", arr.toString(2));
        }

        StringBuilder sb = new StringBuilder();
        if (format == 4) {
            sb.append(CSV_HEADER);
        }
        LinkedHashSet<String> dedupe = new LinkedHashSet<>();
        for (MainActivity.Result r : rows) {
            if (r.ip == null || r.ip.isEmpty()) continue;
            if (format == 0 || format == 1) {
                dedupe.add(r.ip);
                continue;
            }
            if (format == 2) {
                String sni = r.sni == null ? "" : r.sni.trim();
                dedupe.add((r.address() + " " + sni).trim());
                continue;
            }
            if (format == 3) {
                if (r.sni != null && !r.sni.trim().isEmpty()) dedupe.add(r.sni.trim());
                continue;
            }
            if (format == 4) {
                sb.append(r.csv()).append('\n');
            }
        }

        if (format == 0 || format == 2 || format == 3) {
            sb.append(joinLines(dedupe));
        } else if (format == 1) {
            sb.append(joinComma(dedupe));
        }
        return new MainActivity.ExportPayload(String.valueOf(selectedLabel), sb.toString());
    }

    static String buildVisibleCsv(List<MainActivity.Result> rows) {
        StringBuilder sb = new StringBuilder(CSV_HEADER);
        for (MainActivity.Result r : rows) sb.append(r.csv()).append('\n');
        return sb.toString();
    }

    private static String joinLines(LinkedHashSet<String> values) {
        StringBuilder sb = new StringBuilder();
        for (String v : values) {
            if (sb.length() > 0) sb.append('\n');
            sb.append(v);
        }
        return sb.toString();
    }

    private static String joinComma(LinkedHashSet<String> values) {
        StringBuilder sb = new StringBuilder();
        for (String v : values) {
            if (sb.length() > 0) sb.append(',');
            sb.append(v);
        }
        return sb.toString();
    }
}

