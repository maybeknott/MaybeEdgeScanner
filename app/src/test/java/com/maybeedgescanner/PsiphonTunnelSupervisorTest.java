package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PsiphonTunnelSupervisorTest {
    @Test
    public void externalVpnModeRequiresProfileOrPackage() {
        EdgeRouteProfile profile = EdgeRouteProfile.direct();
        profile.protocolMode = "external_vpn";
        profile.routeId = "route-1";
        profile.profileRef = "";
        profile.packageName = "";

        PsiphonTunnelSupervisor.Readiness readiness = PsiphonTunnelSupervisor.preview(profile);
        assertEquals("needs_profile_or_package", readiness.state);
        assertFalse(readiness.ready);
        assertFalse(readiness.providerObserved);
    }

    @Test
    public void localProxyEndpointMarksDialerReady() {
        EdgeRouteProfile profile = EdgeRouteProfile.direct();
        profile.protocolMode = "local_proxy";
        profile.routeId = "route-2";
        profile.configRef = "ref:cfg";
        profile.endpoint = "socks5://127.0.0.1:1080";

        PsiphonTunnelSupervisor.Readiness readiness = PsiphonTunnelSupervisor.preview(profile);
        assertTrue(readiness.dialerReady);
        assertTrue(readiness.ready);
        assertEquals("needs_tunnel_core_process", readiness.state);
    }

    @Test
    public void parseNoticeExtractsListeningProxyPorts() {
        PsiphonTunnelSupervisor.Readiness readiness = PsiphonTunnelSupervisor.parseNotice(
                "ListeningSocksProxyPort:1081 ListeningHttpProxyPort:8080");
        assertEquals(1081, readiness.socksPort);
        assertEquals(8080, readiness.httpProxyPort);
        assertTrue(readiness.listenerReady);
        assertEquals("proxy_listening", readiness.state);
    }

    @Test
    public void parseNoticeMarksFailureOnErrorNotices() {
        PsiphonTunnelSupervisor.Readiness readiness = PsiphonTunnelSupervisor.parseNotice(
                "tunnel failed with error: handshake");
        assertEquals("failed", readiness.state);
        assertEquals("PSIPHON_NOTICE_ERROR", readiness.errorCode);
        assertFalse(readiness.ready);
    }
}
