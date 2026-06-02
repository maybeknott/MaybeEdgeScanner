package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class TargetPlanRecordTest {
    @Test
    public void routePairingPreservesRouteId() {
        EdgeRouteProfile route = EdgeRouteProfile.direct();
        route.enabled = true;
        route.routeId = "route-psiphon-android";
        route.pluginId = "psiphon";
        TargetPlanRecord plan = TargetPlanRecord.forRoutePairingProbe("198.51.100.34", "198.51.100.34", 443, "edge.example", true, route);
        assertEquals("route_pairing", plan.productMode());
        assertEquals("route-psiphon-android", plan.routeId());
        assertTrue(plan.dedupeKey().contains("route-psiphon-android"));
    }

    @Test
    public void hyphenatedHostnameKeepsHostnameKind() {
        EdgeRouteProfile route = EdgeRouteProfile.direct();
        TargetPlanRecord plan = TargetPlanRecord.forRoutePairingProbe(
                "edge-route.example.com", "198.51.100.34", 443, "edge-route.example.com", true, route);

        assertEquals("domain_sni", plan.sniMode());
        assertEquals("hostname", plan.normalizedKind());
    }

    @Test
    public void hostnamePassedAsResolvedIpIsSanitizedButStillRouteDistinct() {
        EdgeRouteProfile route = EdgeRouteProfile.direct();
        route.routeId = "route-direct";
        TargetPlanRecord first = TargetPlanRecord.forRoutePairingProbe(
                "alpha-edge.example.com", "alpha-edge.example.com", 443, "front.example.com", true, route);
        TargetPlanRecord second = TargetPlanRecord.forRoutePairingProbe(
                "beta-edge.example.com", "beta-edge.example.com", 443, "front.example.com", true, route);

        assertEquals("", first.resolvedIp());
        assertEquals("unknown", first.ipFamily());
        assertTrue(first.dedupeKey().contains("raw=alpha-edge.example.com"));
        assertTrue(first.dedupeKey().contains("route-direct"));
        assertNotEquals(first.planId(), second.planId());
    }

    @Test
    public void cidrExpansionPreservesParentAndRoute() {
        EdgeRouteProfile route = EdgeRouteProfile.direct();
        route.routeId = "route-direct";
        TargetExpansionMeta expansion = TargetExpansionMeta.forExpandedMember("198.51.100.0/30", 2, 4, 2);
        TargetPlanRecord plan = TargetPlanRecord.forRoutePairingProbe("198.51.100.3", "198.51.100.3", 443, "", false, route, expansion);
        assertEquals("route-direct", plan.routeId());
        assertTrue(plan.dedupeKey().contains("parent=198.51.100.0/30"));
        assertTrue(plan.dedupeKey().contains("idx=2"));
    }

    @Test
    public void expandedMembersHaveDistinctDedupeKeys() {
        EdgeRouteProfile route = EdgeRouteProfile.direct();
        TargetExpansionMeta first = TargetExpansionMeta.forExpandedMember("203.0.113.7-203.0.113.9", 0, 3, 3);
        TargetExpansionMeta second = TargetExpansionMeta.forExpandedMember("203.0.113.7-203.0.113.9", 1, 3, 3);
        TargetPlanRecord a = TargetPlanRecord.forRoutePairingProbe("203.0.113.7", "203.0.113.7", 443, "", false, route, first);
        TargetPlanRecord b = TargetPlanRecord.forRoutePairingProbe("203.0.113.8", "203.0.113.8", 443, "", false, route, second);
        assertNotEquals(a.dedupeKey(), b.dedupeKey());
    }
}
