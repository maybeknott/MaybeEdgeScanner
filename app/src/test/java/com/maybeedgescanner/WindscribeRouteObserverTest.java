package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class WindscribeRouteObserverTest {
    @Test
    public void localProxyModeCanBeDialerReadyWithoutAndroidVpnObservation() {
        EdgeRouteProfile profile = EdgeRouteProfile.direct();
        profile.routeId = "wind-1";
        profile.protocolMode = "local_proxy";
        profile.routeBinding = "plugin";
        profile.dnsPolicy = "remote";
        profile.endpoint = "socks5://127.0.0.1:1080";
        profile.profileRef = "ref:profile";

        WindscribeAuthSession session = WindscribeAuthSession.fromRefs("ref:cred", "ref:profile");
        WindscribeRouteObserver.RouteObservation observation =
                WindscribeRouteObserver.observe(null, profile, session);

        assertTrue(observation.configReady);
        assertTrue(observation.sessionReady);
        assertTrue(observation.dialerReady);
        assertTrue(observation.ready);
    }

    @Test
    public void nonLocalProxyModeRemainsObserverOnly() {
        EdgeRouteProfile profile = EdgeRouteProfile.direct();
        profile.routeId = "wind-2";
        profile.protocolMode = "windscribe_wireguard";
        profile.routeBinding = "plugin";
        profile.dnsPolicy = "route_default";
        profile.profileRef = "ref:profile";

        WindscribeAuthSession session = WindscribeAuthSession.fromRefs("", "ref:profile");
        WindscribeRouteObserver.RouteObservation observation =
                WindscribeRouteObserver.observe(null, profile, session);

        assertTrue(observation.configReady);
        assertFalse(observation.dialerReady);
        assertFalse(observation.ready);
        assertFalse(observation.routeUsed);
    }
}
