package com.maybeedgescanner;

final class RouteOptions {
    static final Option[] PROTOCOLS = options(
            "Use connected provider app", "external_vpn",
            "Local proxy", "local_proxy",
            "Windscribe app WireGuard", "wireguard",
            "OpenVPN UDP", "openvpn_udp",
            "OpenVPN TCP", "openvpn_tcp",
            "Plain TCP", "tcp",
            "Stealth", "stealth",
            "WebSocket tunnel", "wstunnel",
            "IKEv2", "ikev2",
            "Psiphon app route", "tunnel_core_supervised",
            "External VPN APK", "external_vpn_apk");

    static final Option[] AUTH = options(
            "None", "none",
            "Provider app session", "external_app",
            "Profile reference", "profile_ref",
            "Credential reference", "credential_ref",
            "Auth-token reference", "auth_token_ref",
            "External SSO", "sso_external",
            "Windscribe app session reference", "wsnet_session_ref",
            "Psiphon app config reference", "config_ref");

    static final Option[] DNS = options(
            "Use route default", "system_or_route_default",
            "Remote DNS", "remote_dns",
            "Route DNS", "route_dns",
            "Control D", "ctrld",
            "Control D legacy", "control_d",
            "Windscribe app ROBERT", "robert",
            "DNS over HTTPS", "doh",
            "DNS over TLS", "dot",
            "Custom DNS reference", "custom_dns_ref",
            "No DNS override", "no_dns");

    static final Option[] SPLIT = options(
            "Current network only", "scanner_app_only",
            "Include selected IPs", "include_targets",
            "Exclude selected IPs", "exclude_targets",
            "Use installed app VPN policy", "external_vpn_policy",
            "Disabled", "disabled");

    static final Option[] UPSTREAM = options(
            "None", "none",
            "System proxy", "system_proxy",
            "Proxy reference", "proxy_ref",
            "Current network", "direct",
            "Provider default", "provider_default");

    static final Option[] DOWNSTREAM = options(
            "Scanner to route", "scanner_to_route",
            "Local proxy gateway", "local_proxy_gateway",
            "VPN interface", "vpn_interface",
            "Provider default", "provider_default");

    static final Option[] GATEWAY = options(
            "Device only", "loopback_only",
            "Share on LAN", "lan_shared");

    static final Option[] STRATEGY = options(
            "Provider default", "provider_default",
            "Automatic", "auto",
            "Prefer Psiphon conduit", "conduit_first",
            "Psiphon conduit", "conduit",
            "CDN fronting", "cdn_fronting",
            "Current network", "direct",
            "Profile default", "profile_default");

    static final Option[] CONDUIT = options(
            "Automatic", "auto",
            "ShiroKhorshid", "shirokhorshid",
            "Public", "public");

    static final Option[] CHAIN = options(
            "None", "none",
            "Psiphon app over Windscribe app", "psiphon_over_windscribe",
            "Windscribe app over Psiphon app", "windscribe_over_psiphon",
            "Proxy over Windscribe app", "generic_proxy_over_windscribe",
            "Windscribe app over proxy", "windscribe_over_generic_proxy");

    private RouteOptions() {}

    static final class Option {
        final String label;
        final String value;

        Option(String label, String value) {
            this.label = label;
            this.value = value;
        }

        @Override public String toString() {
            return label;
        }
    }

    static String valueOf(Object item) {
        if (item instanceof Option) return ((Option) item).value;
        return item == null ? "" : String.valueOf(item).trim();
    }

    private static Option[] options(String... pairs) {
        Option[] out = new Option[pairs.length / 2];
        for (int i = 0; i < pairs.length; i += 2) {
            out[i / 2] = new Option(pairs[i], pairs[i + 1]);
        }
        return out;
    }
}
