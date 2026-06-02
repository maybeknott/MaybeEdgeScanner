package com.maybeedgescanner;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;

public class ScanTargetPlannerPreviewTest {
    @Test
    public void countDistinctPreviewPlansDedupesRepeatedIps() {
        assertEquals(2, ScanTargetPlanner.countDistinctPreviewPlans(
                Arrays.asList("1.1.1.1", "1.1.1.1", "8.8.8.8"), 443, false, EdgeRouteProfile.direct(), ""));
    }

    @Test
    public void countDistinctPreviewPlansKeepsUnresolvedRouteHostnamesDistinct() {
        assertEquals(2, ScanTargetPlanner.countDistinctPreviewPlans(
                Arrays.asList("alpha-edge.example.com", "beta-edge.example.com"),
                443,
                true,
                EdgeRouteProfile.direct(),
                "front.example.com"));
    }
}
