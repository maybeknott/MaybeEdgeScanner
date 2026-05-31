package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
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
}
