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
        observation.ready = observation.vpnObserved || observation.localProxyObserved || observation.profileBacked || observation.sessionBacked;
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
        boolean shareProxyOnLan;
        boolean ready;
        List<String> dnsServers = new ArrayList<>();

        String summary() {
            return "Route readiness: Windscribe\n" +
                    "state=" + (ready ? "ready-for-metadata/observer" : "needs profile/session/app route") + "\n" +
                    "protocol=" + protocolMode + " binding=" + routeBinding + "\n" +
                    "auth=" + authBoundary + "\n" +
                    "strategy=" + routeStrategy + " chain=" + providerChain + " lanShare=" + shareProxyOnLan + "\n" +
                    "dns=" + dnsPolicy + " observedResolvers=" + dnsServers + "\n" +
                    "split=" + splitTunnel + " upstream=" + upstreamMode + " downstream=" + downstreamMode + "\n" +
                    "vpnObserved=" + vpnObserved + " localProxyObserved=" + localProxyObserved +
                    (interfaceName == null || interfaceName.isEmpty() ? "" : " iface=" + interfaceName) +
                    (error == null || error.isEmpty() ? "" : "\nobserverError=" + error);
        }
    }
}
