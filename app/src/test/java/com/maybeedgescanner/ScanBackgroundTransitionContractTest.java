package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/** JVM-safe background/foreground lifecycle contract checks. */
public class ScanBackgroundTransitionContractTest {
    @Test
    public void activeExecutorSurvivesBackgroundAndForeground() {
        ScanSessionTestHooks.Snapshot snapshot = new ScanSessionTestHooks.Snapshot(
                11L, false, true, true, false, 0L);
        assertNull(ScanSessionTestHooks.backgroundTransitionViolation(snapshot, true, true));
    }

    @Test
    public void backgroundTransitionFlagsLostOrchestrator() {
        ScanSessionTestHooks.Snapshot snapshot = new ScanSessionTestHooks.Snapshot(
                12L, false, true, false, false, 0L);
        assertEquals(
                "executor bound but orchestrator thread is not alive",
                ScanSessionTestHooks.backgroundTransitionViolation(snapshot, true, false));
    }
}
