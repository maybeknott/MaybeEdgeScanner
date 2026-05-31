package com.maybeedgescanner;

import android.content.Context;
import android.content.pm.PackageManager;

import org.json.JSONObject;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** Writes immutable session-result snapshots to export files (service-owned). */
final class ScanResultExporter {
    private ScanResultExporter() {}

    static final class Result {
        final String path;
        final String error;

        Result(String path, String error) {
            this.path = path == null ? "" : path;
            this.error = error == null ? "" : error;
        }

        boolean success() {
            return error.isEmpty() && !path.isEmpty();
        }
    }

    static Result exportSession(Context context, ScanExportSpec spec, List<MainActivity.Result> rows,
                                String sessionId, long scanStartedAtEpochMs) {
        if (context == null || spec == null) {
            return new Result("", "export spec missing");
        }
        if (rows == null || rows.isEmpty()) {
            return new Result("", "no results to export");
        }
        try {
            String extension = extensionForFormat(spec.format);
            File out = new File(context.getExternalFilesDir(null), spec.filePrefix + "_" + System.currentTimeMillis() + extension);
            JSONObject meta = buildExportMeta(context, spec, sessionId, scanStartedAtEpochMs, rows.size());
            try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8))) {
                writeExport(writer, spec, meta, rows);
            }
            return new Result(out.getAbsolutePath(), "");
        } catch (Exception e) {
            return new Result("", e.getMessage() == null ? "export failed" : e.getMessage());
        }
    }

    private static void writeExport(BufferedWriter writer, ScanExportSpec spec, JSONObject meta,
                                    List<MainActivity.Result> rows) throws Exception {
        if (spec.format == ScanExportSpec.FORMAT_JSONL) {
            JSONObject metaLine = new JSONObject(meta.toString());
            metaLine.put("record_type", "export_meta");
            writer.write(metaLine.toString());
            writer.newLine();
            for (MainActivity.Result row : rows) {
                JSONObject item = exportResultJson(row, spec.redactionMode);
                item.put("record_type", "scan_result");
                writer.write(item.toString());
                writer.newLine();
            }
            return;
        }
        if (spec.format == ScanExportSpec.FORMAT_CSV) {
            writer.write("# schema_version: " + meta.optInt("schema_version"));
            writer.newLine();
            writer.write("# app_version: " + meta.optString("app_version"));
            writer.newLine();
            writer.write("# scan_session_id: " + meta.optString("scan_session_id"));
            writer.newLine();
            writer.write("# product_mode: " + meta.optString("product_mode"));
            writer.newLine();
            writer.write("# redaction_mode: " + meta.optString("redaction_mode"));
            writer.newLine();
            writer.write("target,ip,port,sni,tcp,tls,http,http_status,latency_ms,alpn,tls_profile,http3_hint,network_classification,route_provider,route_dns_policy,quality,final_phase,error_code,phase_results,reason");
            writer.newLine();
            for (MainActivity.Result row : rows) {
                JSONObject item = exportResultJson(row, spec.redactionMode);
                writer.write(csvCell(item.optString("target")) + "," + csvCell(item.optString("ip")) + "," + item.optInt("port") + "," +
                        csvCell(item.optString("sni")) + "," + item.optBoolean("tcpPass") + "," + item.optBoolean("tlsPass") + "," +
                        item.optBoolean("httpPass") + "," + item.optInt("httpStatus") + "," + item.optLong("totalLatencyMs") + "," +
                        csvCell(item.optString("alpn")) + "," + csvCell(item.optString("tlsProfile")) + "," + item.optBoolean("http3Hint") + "," +
                        csvCell(item.optString("network_classification")) + "," + csvCell(item.optString("routeProviderId")) + "," +
                        csvCell(item.optString("routeDnsPolicy")) + "," + item.optLong("qualityRounded") + "," +
                        csvCell(item.optString("final_phase")) + "," + csvCell(item.optString("error_code")) + "," +
                        csvCell(item.optJSONArray("phase_results") == null ? "" : item.optJSONArray("phase_results").toString()) + "," +
                        csvCell(item.optString("reason")));
                writer.newLine();
            }
            return;
        }
        if (spec.format == ScanExportSpec.FORMAT_MARKDOWN) {
            writer.write("# MaybeEdgeScanner Report");
            writer.newLine();
            writer.newLine();
            writer.write("- schema_version: " + meta.optInt("schema_version"));
            writer.newLine();
            writer.write("- app_version: " + meta.optString("app_version"));
            writer.newLine();
            writer.write("- scan_session_id: " + meta.optString("scan_session_id"));
            writer.newLine();
            writer.write("- product_mode: " + meta.optString("product_mode"));
            writer.newLine();
            writer.write("- redaction_mode: " + meta.optString("redaction_mode"));
            writer.newLine();
            writer.write("- result_count: " + meta.optInt("result_count"));
            writer.newLine();
            writer.newLine();
            writer.write("| target | ip | sni | tcp/tls/http | network | route | ms | final_phase | error_code |");
            writer.newLine();
            writer.write("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
            writer.newLine();
            for (MainActivity.Result row : rows) {
                JSONObject item = exportResultJson(row, spec.redactionMode);
                String checks = (item.optBoolean("tcpPass") ? "T" : "-") + "/" + (item.optBoolean("tlsPass") ? "L" : "-") + "/" + (item.optBoolean("httpPass") ? "H" : "-");
                String route = item.optString("routeProviderId");
                if (route.isEmpty()) route = "--";
                writer.write("| " + safeMd(item.optString("target")) + " | " + safeMd(item.optString("ip")) + " | " + safeMd(item.optString("sni")) + " | " + checks + " | " + safeMd(item.optString("network_classification")) + " | " + safeMd(route) + " | " + item.optLong("totalLatencyMs") + " | " + safeMd(item.optString("final_phase")) + " | " + safeMd(item.optString("error_code")) + " |");
                writer.newLine();
            }
            return;
        }
        writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        writer.newLine();
        writer.write("<nmaprun scanner=\"MaybeEdgeScanner\" args=\"edge scan export\" product_mode=\"" + xmlEscape(meta.optString("product_mode")) + "\" redaction_mode=\"" + xmlEscape(meta.optString("redaction_mode")) + "\" scan_session_id=\"" + xmlEscape(meta.optString("scan_session_id")) + "\">");
        writer.newLine();
        for (MainActivity.Result row : rows) {
            JSONObject item = exportResultJson(row, spec.redactionMode);
            String ip = item.optString("ip");
            int port = item.optInt("port");
            if (ip.isEmpty() || port <= 0) continue;
            String state = (item.optBoolean("tcpPass") || item.optBoolean("tlsPass") || item.optBoolean("httpPass")) ? "open" : "closed";
            String addrType = ip.contains(":") ? "ipv6" : "ipv4";
            writer.write("<host><status state=\"up\"/><address addr=\"" + xmlEscape(ip) + "\" addrtype=\"" + addrType + "\"/><ports><port protocol=\"tcp\" portid=\"" + port + "\"><state state=\"" + state + "\"/><service name=\"" + xmlEscape(item.optString("sni")) + "\" product=\"" + xmlEscape(item.optString("network_classification")) + "\"/></port></ports></host>");
            writer.newLine();
        }
        writer.write("</nmaprun>");
        writer.newLine();
    }

    static JSONObject buildExportMeta(Context context, ScanExportSpec spec, String sessionId,
                                      long scanStartedAtEpochMs, int resultCount) throws Exception {
        JSONObject meta = new JSONObject();
        meta.put("schema_version", 1);
        meta.put("app_version", appVersionName(context));
        meta.put("scan_session_id", sessionId);
        meta.put("product_mode", spec.productMode);
        meta.put("format", formatLabel(spec.format));
        meta.put("redaction_mode", spec.redactionMode);
        meta.put("result_count", resultCount);
        meta.put("generated_at_ms", System.currentTimeMillis());
        meta.put("scan_started_at_ms", scanStartedAtEpochMs);
        return meta;
    }

    private static JSONObject exportResultJson(MainActivity.Result row, String redactionMode) throws Exception {
        JSONObject item = row.json();
        item.put("totalLatencyMs", row.totalLatency());
        item.put("qualityRounded", Math.round(row.quality));
        item.put("redaction_mode", redactionMode);
        if ("privacy".equals(redactionMode)) {
            item.put("ip", redactIp(item.optString("ip")));
            item.put("tlsCert", "[REDACTED]");
            item.put("certFingerprint", "[REDACTED]");
            redactRouteField(item, "routeId");
            redactRouteField(item, "routeProviderId");
            redactRouteField(item, "routeBinding");
            redactRouteField(item, "routeProtocolMode");
            redactRouteField(item, "routeAuthMode");
            redactRouteField(item, "routeDnsPolicy");
            redactRouteField(item, "routeReadiness");
        }
        return item;
    }

    private static void redactRouteField(JSONObject item, String key) throws Exception {
        if (item.has(key) && !item.optString(key).isEmpty()) {
            item.put(key, "[REDACTED]");
        }
    }

    private static String extensionForFormat(int format) {
        if (format == ScanExportSpec.FORMAT_CSV) return ".csv";
        if (format == ScanExportSpec.FORMAT_MARKDOWN) return ".md";
        if (format == ScanExportSpec.FORMAT_NMAP_XML) return ".xml";
        return ".jsonl";
    }

    private static String formatLabel(int format) {
        if (format == ScanExportSpec.FORMAT_CSV) return "csv";
        if (format == ScanExportSpec.FORMAT_MARKDOWN) return "markdown_report";
        if (format == ScanExportSpec.FORMAT_NMAP_XML) return "nmap_xml_like";
        return "jsonl";
    }

    private static String appVersionName(Context context) {
        try {
            return context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName;
        } catch (PackageManager.NameNotFoundException e) {
            return "unknown";
        }
    }

    private static String redactIp(String ip) {
        if (ip == null || ip.isEmpty()) return ip;
        if (ip.contains(".")) {
            String[] parts = ip.split("\\.");
            if (parts.length == 4) return parts[0] + "." + parts[1] + "." + parts[2] + ".x";
        }
        if (ip.contains(":")) {
            int idx = ip.indexOf("::");
            if (idx >= 0) return ip.substring(0, idx + 2) + "xxxx";
            String[] parts = ip.split(":");
            if (parts.length > 2) return parts[0] + ":" + parts[1] + ":xxxx::";
        }
        return "[REDACTED]";
    }

    private static String csvCell(String value) {
        if (value == null) value = "";
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private static String safeMd(String value) {
        if (value == null) return "";
        return value.replace("|", "\\|").replace("\n", " ");
    }

    private static String xmlEscape(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&apos;");
    }
}
