package com.maybeedgescanner;

import org.json.JSONObject;

import java.io.Serializable;

final class EdgeRouteProfile implements Serializable {
    private static final long serialVersionUID = 1L;

    boolean enabled;
    String routeId = "";
    String pluginId = "";
    String providerId = "";
    String protocolMode = "";
    String authMode = "";
    String dnsPolicy = "";
    String splitTunnel = "";
    String upstreamMode = "";
    String downstreamMode = "";
    String gatewayMode = "";
    String routeBinding = "";
    String routeStrategy = "";
    String conduitMode = "";
    String providerChain = "";
    String frontingIpRef = "";
    String frontingSni = "";
    String chainUpstreamRef = "";
    String gatewayAuthRef = "";
    String lanSocksPort = "";
    String lanHttpPort = "";
    String profileRef = "";
    String credentialRef = "";
    String configRef = "";
    String endpoint = "";
    String packageName = "";
    boolean shareProxyOnLan;
    boolean beastMode;

    static EdgeRouteProfile direct() {
        EdgeRouteProfile profile = new EdgeRouteProfile();
        profile.enabled = false;
        profile.routeId = "direct";
        profile.routeBinding = "direct";
        profile.protocolMode = "direct";
        profile.routeStrategy = "direct";
        profile.providerChain = "none";
        profile.dnsPolicy = "system_or_route_default";
        profile.downstreamMode = "scanner_to_route";
        return profile;
    }

    EdgeRouteProfile copy() {
        EdgeRouteProfile copy = new EdgeRouteProfile();
        copy.enabled = enabled;
        copy.routeId = routeId;
        copy.pluginId = pluginId;
        copy.providerId = providerId;
        copy.protocolMode = protocolMode;
        copy.authMode = authMode;
        copy.dnsPolicy = dnsPolicy;
        copy.splitTunnel = splitTunnel;
        copy.upstreamMode = upstreamMode;
        copy.downstreamMode = downstreamMode;
        copy.gatewayMode = gatewayMode;
        copy.routeBinding = routeBinding;
        copy.routeStrategy = routeStrategy;
        copy.conduitMode = conduitMode;
        copy.providerChain = providerChain;
        copy.frontingIpRef = frontingIpRef;
        copy.frontingSni = frontingSni;
        copy.chainUpstreamRef = chainUpstreamRef;
        copy.gatewayAuthRef = gatewayAuthRef;
        copy.lanSocksPort = lanSocksPort;
        copy.lanHttpPort = lanHttpPort;
        copy.profileRef = profileRef;
        copy.credentialRef = credentialRef;
        copy.configRef = configRef;
        copy.endpoint = endpoint;
        copy.packageName = packageName;
        copy.shareProxyOnLan = shareProxyOnLan;
        copy.beastMode = beastMode;
        return copy;
    }

    JSONObject toSidecarJson() throws Exception {
        JSONObject root = new JSONObject();
        if (!enabled) return root;
        root.put("schema_version", 1);
        root.put("route_id", routeId);
        root.put("plugin_id", pluginId);
        root.put("enabled", true);
        root.put("remote_dns", !"no_dns".equals(dnsPolicy));
        putIfNotEmpty(root, "endpoint", endpoint);
        putIfNotEmpty(root, "credential_ref", credentialRef);
        putIfNotEmpty(root, "config_ref", configRef);
        putIfNotEmpty(root, "profile_ref", profileRef);
        JSONObject fields = new JSONObject();
        putIfNotEmpty(fields, "mode", protocolMode);
        putIfNotEmpty(fields, "auth_mode", authMode);
        putIfNotEmpty(fields, "dns_policy", dnsPolicy);
        putIfNotEmpty(fields, "split_tunnel", splitTunnel);
        putIfNotEmpty(fields, "upstream_mode", upstreamMode);
        putIfNotEmpty(fields, "downstream_mode", downstreamMode);
        putIfNotEmpty(fields, "proxy_gateway_scope", gatewayMode);
        putIfNotEmpty(fields, "route_strategy", routeStrategy);
        putIfNotEmpty(fields, "provider_chain", providerChain);
        if ("psiphon".equals(pluginId)) {
            putIfNotEmpty(fields, "conduit_mode", conduitMode);
            putIfNotEmpty(fields, "fronting_ip_ref", frontingIpRef);
            putIfNotEmpty(fields, "cdn_fronting_sni", frontingSni);
            putIfTrue(fields, "beast_mode", beastMode);
        }
        putIfNotEmpty(fields, "chain_upstream_ref", chainUpstreamRef);
        putIfNotEmpty(fields, "gateway_auth_ref", gatewayAuthRef);
        putIfNotEmpty(fields, "lan_socks_port", lanSocksPort);
        putIfNotEmpty(fields, "lan_http_port", lanHttpPort);
        putIfTrue(fields, "share_proxy_on_lan", shareProxyOnLan);
        putIfNotEmpty(fields, "package_name", packageName);
        root.put("fields", fields);
        return root;
    }

    String summary() {
        if (!enabled) return "direct";
        String provider = pluginId == null || pluginId.isEmpty() ? "local proxy" : pluginId;
        return provider + " route status, mode " + display(protocolMode) +
                ", binding " + display(routeBinding) +
                ", strategy " + display(routeStrategy) +
                ", chain " + display(providerChain) +
                ", DNS " + display(dnsPolicy) +
                ", LAN share " + (shareProxyOnLan ? "on" : "off");
    }

    private static String display(String value) {
        return value == null || value.trim().isEmpty() ? "--" : value.trim();
    }

    private static void putIfNotEmpty(JSONObject object, String key, String value) throws Exception {
        if (value != null && !value.trim().isEmpty()) object.put(key, value.trim());
    }

    private static void putIfTrue(JSONObject object, String key, boolean value) throws Exception {
        if (value) object.put(key, "true");
    }
}
