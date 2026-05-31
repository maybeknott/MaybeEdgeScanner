package com.maybeedgescanner;

import org.junit.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

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
}
