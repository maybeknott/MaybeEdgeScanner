package com.maybeedgescanner;

import org.json.JSONObject;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

/** Contract-shaped TargetPlan v1 snapshot attached to probe results. */
final class TargetPlanRecord {
    private final JSONObject payload;
    private final String planId;
    private final String correlationId;
    private final String productMode;
    private final String normalizedKind;
    private final String sniMode;
    private final String dedupeKey;
    private final String routeId;

    private TargetPlanRecord(JSONObject payload, String planId, String correlationId, String productMode,
                             String normalizedKind, String sniMode, String dedupeKey, String routeId) {
        this.payload = payload;
        this.planId = planId;
        this.correlationId = correlationId;
        this.productMode = productMode;
        this.normalizedKind = normalizedKind;
        this.sniMode = sniMode;
        this.dedupeKey = dedupeKey;
        this.routeId = routeId;
    }

    static TargetPlanRecord forRoutePairingProbe(String rawToken, String resolvedIp, int port, String sniHost,
                                                 boolean sniPairingEnabled, EdgeRouteProfile routeProfile) {
        return forRoutePairingProbe(rawToken, resolvedIp, port, sniHost, sniPairingEnabled, routeProfile, null);
    }

    static TargetPlanRecord forRoutePairingProbe(String rawToken, String resolvedIp, int port, String sniHost,
                                                 boolean sniPairingEnabled, EdgeRouteProfile routeProfile,
                                                 TargetExpansionMeta expansion) {
        String routeId = routeProfile == null ? "direct" : clean(routeProfile.routeId);
        if (routeId.isEmpty()) routeId = "direct";
        String routeType = routeProfile == null ? "direct" : mapRouteType(routeProfile);
        String networkPath = routeProfile == null ? "direct" : networkPathFor(routeProfile);
        return build("route_pairing", rawToken, resolvedIp, port, sniHost, sniPairingEnabled, routeId, routeType, networkPath, expansion);
    }

    private static TargetPlanRecord build(String productMode, String rawToken, String resolvedIp, int port, String sniHost,
                                          boolean sniPairingEnabled, String routeId, String routeType, String networkPath,
                                          TargetExpansionMeta expansion) {
        String token = clean(rawToken);
        String ip = clean(resolvedIp);
        String sni = clean(sniHost);
        if (expansion != null && expansion.hasExpansion()) {
            token = expansion.parentToken;
        }
        String kind = expansion != null && expansion.hasExpansion() ? "ip" : normalizedKind(token);
        String sniMode = sniModeFor(kind, sni, sniPairingEnabled);
        String hostname = hostnameFor(token, kind);
        String httpHost = httpHostFor(kind, sni, sniPairingEnabled);
        String dedupe = dedupeKey(productMode, ip, port, sni, httpHost, routeId, expansion);
        String planId = stableId("plan", dedupe);
        String correlationId = stableId("corr", dedupe);

        JSONObject o = new JSONObject();
        try {
            o.put("schema_version", 1);
            o.put("plan_id", planId);
            o.put("product_mode", productMode);
            o.put("raw_token", token.isEmpty() ? ip : token);
            o.put("source_type", "manual");
            o.put("source_provider", "manual");
            o.put("corpus_revision", JSONObject.NULL);
            o.put("normalized_kind", kind);
            o.put("original_hostname", hostname == null ? JSONObject.NULL : hostname);
            o.put("resolved_ip", ip.isEmpty() ? JSONObject.NULL : ip);
            o.put("ip_family", ipFamily(ip));
            o.put("port", Math.max(0, port));
            o.put("sni_host", sni.isEmpty() ? JSONObject.NULL : sni);
            o.put("sni_mode", sniMode);
            o.put("http_host", httpHost == null ? JSONObject.NULL : httpHost);
            o.put("verification_host", httpHost == null ? JSONObject.NULL : httpHost);
            o.put("dns_mode", ip.isEmpty() ? "system" : "pre_resolved");
            o.put("resolver_id", JSONObject.NULL);
            o.put("alpn_policy", "http1_http2");
            o.put("route_id", clean(routeId));
            o.put("route_type", clean(routeType));
            o.put("network_path", clean(networkPath));
            o.put("safety_status", "allowed");
            applyExpansionFields(o, expansion);
            o.put("dedupe_key", dedupe);
            o.put("result_correlation_id", correlationId);
        } catch (Exception ignored) {
        }
        return new TargetPlanRecord(o, planId, correlationId, productMode, kind, sniMode, dedupe, clean(routeId));
    }

    JSONObject toJson() {
        try {
            return new JSONObject(payload.toString());
        } catch (Exception e) {
            return payload;
        }
    }

    String planId() {
        return planId;
    }

    String correlationId() {
        return correlationId;
    }

    String productMode() {
        return productMode;
    }

    String normalizedKind() {
        return normalizedKind;
    }

    String sniMode() {
        return sniMode;
    }

    String dedupeKey() {
        return dedupeKey;
    }

    String routeId() {
        return routeId;
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim();
    }

    private static String normalizedKind(String token) {
        if (token.isEmpty()) return "ip";
        if (ScanTargetPlanner.isIp(token)) return "ip";
        if (ScanTargetPlanner.looksLikePrefix(token)) return "cidr";
        if (ScanTargetPlanner.looksLikeIpv4Range(token)) return "range";
        return "hostname";
    }

    private static String sniModeFor(String kind, String sni, boolean sniPairingEnabled) {
        if (!sniPairingEnabled || sni.isEmpty()) return "ip_only_no_sni";
        return "hostname".equals(kind) ? "domain_sni" : "explicit_sni";
    }

    private static String hostnameFor(String token, String kind) {
        return "hostname".equals(kind) ? token : null;
    }

    private static String httpHostFor(String kind, String sni, boolean sniPairingEnabled) {
        if (!sniPairingEnabled || sni.isEmpty()) return null;
        return sni;
    }

    private static String ipFamily(String ip) {
        if (ip.isEmpty()) return "unknown";
        try {
            return InetAddress.getByName(ip) instanceof Inet6Address ? "ipv6" : "ipv4";
        } catch (Exception ignored) {
            return ip.contains(":") ? "ipv6" : "ipv4";
        }
    }

    private static String mapRouteType(EdgeRouteProfile profile) {
        String plugin = clean(profile.pluginId);
        if ("direct".equals(clean(profile.routeId)) || plugin.isEmpty()) return "direct";
        if (plugin.contains("socks")) return "socks5";
        if (plugin.contains("proxy") || plugin.contains("connect")) return "http_connect";
        if (plugin.contains("vpn")) return "vpn";
        return "plugin";
    }

    private static String networkPathFor(EdgeRouteProfile profile) {
        String plugin = clean(profile.pluginId);
        if (plugin.isEmpty() || "direct".equals(clean(profile.routeId))) return "direct";
        return "plugin:" + plugin;
    }

    private static String dedupeKey(String productMode, String ip, int port, String sni, String httpHost, String routeId,
                                    TargetExpansionMeta expansion) {
        String base = productMode + "|" + ip + "|" + port + "|sni=" + sni + "|host=" + (httpHost == null ? "" : httpHost) + "|route=" + routeId;
        if (expansion != null && expansion.hasExpansion()) {
            return base + "|parent=" + expansion.parentToken + "|idx=" + expansion.index;
        }
        return base;
    }

    private static void applyExpansionFields(JSONObject o, TargetExpansionMeta expansion) throws Exception {
        if (expansion == null || !expansion.hasExpansion()) {
            o.put("expansion_parent", JSONObject.NULL);
            o.put("expansion_index", JSONObject.NULL);
            o.put("expansion_total_theoretical", JSONObject.NULL);
            o.put("expansion_total_capped", JSONObject.NULL);
            o.put("expansion_skipped_count", JSONObject.NULL);
            o.put("sampling_seed", JSONObject.NULL);
            return;
        }
        o.put("expansion_parent", expansion.parentToken);
        o.put("expansion_index", expansion.index);
        o.put("expansion_total_theoretical", expansion.totalTheoretical);
        o.put("expansion_total_capped", expansion.totalCapped);
        o.put("expansion_skipped_count", expansion.skippedCount);
        o.put("sampling_seed", expansion.samplingSeed.isEmpty() ? JSONObject.NULL : expansion.samplingSeed);
    }

    private static String dedupeKey(String productMode, String ip, int port, String sni, String httpHost, String routeId) {
        return dedupeKey(productMode, ip, port, sni, httpHost, routeId, null);
    }

    private static String stableId(String prefix, String seed) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(seed.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 4; i++) {
                hex.append(String.format(Locale.US, "%02x", hash[i]));
            }
            return prefix + "-" + hex;
        } catch (Exception ignored) {
            return prefix + "-" + Math.abs(seed.hashCode());
        }
    }
}
