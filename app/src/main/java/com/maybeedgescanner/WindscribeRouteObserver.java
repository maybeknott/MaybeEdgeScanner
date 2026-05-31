package com.maybeedgescanner;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

final class WindscribeRouteObserver {
    private WindscribeRouteObserver() {}

    static RouteObservation observe(Context context, EdgeRouteProfile profile, WindscribeAuthSession session) {
        RouteObservation observation = new RouteObservation();
        observation.providerId = "windscribe";
        observation.routeId = profile.routeId;
        observation.protocolMode = profile.protocolMode;
        observation.routeBinding = profile.routeBinding;
        observation.authBoundary = session.authBoundary();
        observation.dnsPolicy = profile.dnsPolicy;
        observation.splitTunnel = profile.splitTunnel;
        observation.upstreamMode = profile.upstreamMode;
        observation.downstreamMode = profile.downstreamMode;
        observation.gatewayMode = profile.gatewayMode;
        observation.routeStrategy = profile.routeStrategy;
        observation.providerChain = profile.providerChain;
        observation.shareProxyOnLan = profile.shareProxyOnLan || "lan_shared".equals(profile.gatewayMode);
        observation.profileBacked = profile.profileRef.startsWith("ref:");
        observation.sessionBacked = session.sessionRefAvailable;
        observation.configReady = observation.profileBacked || observation.sessionBacked || !profile.endpoint.isEmpty();
        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            Network active = cm == null ? null : cm.getActiveNetwork();
            NetworkCapabilities caps = active == null ? null : cm.getNetworkCapabilities(active);
            LinkProperties link = active == null ? null : cm.getLinkProperties(active);
            observation.vpnObserved = caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
            observation.interfaceName = link == null ? "" : String.valueOf(link.getInterfaceName());
            observation.dnsServers = new ArrayList<>();
            if (link != null) {
                for (java.net.InetAddress address : link.getDnsServers()) {
                    observation.dnsServers.add(address.getHostAddress());
                }
                ProxyInfo proxy = link.getHttpProxy();
                observation.localProxyObserved = proxy != null;
            }
        } catch (Exception e) {
            observation.error = e.getClass().getSimpleName();
        }
        if ("local_proxy".equals(profile.protocolMode)) {
            observation.localProxyObserved = profile.endpoint.startsWith("http://") || profile.endpoint.startsWith("socks5://");
        }
        observation.providerObserved = observation.vpnObserved || observation.localProxyObserved;
        observation.listenerReady = observation.localProxyObserved;
        observation.sessionReady = observation.sessionBacked || observation.profileBacked;
        observation.dialerReady = "local_proxy".equals(profile.protocolMode) && observation.listenerReady;
        observation.routeUsed = false;
        observation.ready = observation.dialerReady;
        return observation;
    }

    static final class RouteObservation implements Serializable {
        private static final long serialVersionUID = 1L;
        String providerId = "";
        String routeId = "";
        String protocolMode = "";
        String routeBinding = "";
        String authBoundary = "";
        String dnsPolicy = "";
        String splitTunnel = "";
        String upstreamMode = "";
        String downstreamMode = "";
        String gatewayMode = "";
        String routeStrategy = "";
        String providerChain = "";
        String interfaceName = "";
        String error = "";
        boolean vpnObserved;
        boolean localProxyObserved;
        boolean profileBacked;
        boolean sessionBacked;
        boolean configReady;
        boolean sessionReady;
        boolean providerObserved;
        boolean listenerReady;
        boolean dialerReady;
        boolean routeUsed;
        boolean shareProxyOnLan;
        boolean ready;
        List<String> dnsServers = new ArrayList<>();

        String summary() {
            return "Windscribe route status\n" +
                    "Status: " + (ready ? "dialer ready for attachable local proxy route" : "observer-only until local proxy listener is ready") + "\n" +
                    "Observed path: VPN " + yesNo(vpnObserved) + " | local proxy " + yesNo(localProxyObserved) +
                    " | profile ref " + yesNo(profileBacked) + " | session ref " + yesNo(sessionBacked) + "\n" +
                    "Readiness gates: config " + yesNo(configReady) +
                    " | session " + yesNo(sessionReady) +
                    " | provider observed " + yesNo(providerObserved) +
                    " | listener " + yesNo(listenerReady) +
                    " | dialer " + yesNo(dialerReady) +
                    " | route used " + yesNo(routeUsed) + "\n" +
                    "Mode: " + display(protocolMode) + " | binding " + display(routeBinding) + "\n" +
                    "Auth boundary: " + authBoundary + "\n" +
                    "DNS: " + display(dnsPolicy) + " | observed resolvers " + dnsServers + "\n" +
                    "Policy: split " + display(splitTunnel) + " | strategy " + display(routeStrategy) +
                    " | chain " + display(providerChain) + " | LAN share " + yesNo(shareProxyOnLan) + "\n" +
                    "Direction: upstream " + display(upstreamMode) + " | downstream " + display(downstreamMode) +
                    (interfaceName == null || interfaceName.isEmpty() ? "" : " iface=" + interfaceName) +
                    (error == null || error.isEmpty() ? "" : "\nObserver issue: " + error);
        }

        private static String yesNo(boolean value) {
            return value ? "yes" : "no";
        }

        private static String display(String value) {
            return value == null || value.trim().isEmpty() ? "--" : value.trim();
        }
    }
}
