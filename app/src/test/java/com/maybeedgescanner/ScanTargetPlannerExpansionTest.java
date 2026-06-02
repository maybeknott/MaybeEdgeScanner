package com.maybeedgescanner;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class ScanTargetPlannerExpansionTest {
    @Test
    public void expandTargetsDetailedAttachesMetaForRangeMembers() {
        List<ScanTargetPlanner.ExpandedTarget> expanded = ScanTargetPlanner.expandTargetsDetailed(
                Collections.singletonList("203.0.113.7-203.0.113.9"), 10);
        assertEquals(3, expanded.size());
        assertEquals("203.0.113.8", expanded.get(1).address);
        assertNotNull(expanded.get(1).expansion);
        assertEquals("203.0.113.7-203.0.113.9", expanded.get(1).expansion.parentToken);
        assertEquals(1, expanded.get(1).expansion.index);
    }

    @Test
    public void expandTargetsDetailedLeavesHyphenatedHostnamesLiteral() {
        List<ScanTargetPlanner.ExpandedTarget> expanded = ScanTargetPlanner.expandTargetsDetailed(
                Arrays.asList("edge-route.example.com", "203.0.113.7-203.0.113.8"), 10);

        assertEquals(3, expanded.size());
        assertEquals("edge-route.example.com", expanded.get(0).address);
        assertNull(expanded.get(0).expansion);
        assertEquals("203.0.113.7", expanded.get(1).address);
        assertNotNull(expanded.get(1).expansion);
    }
}
