package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class ScanSessionTestHooksTest {
    @Test
    public void idleSessionPassesInvariants() {
        ScanSessionTestHooks.Snapshot snapshot = new ScanSessionTestHooks.Snapshot(
                1L, false, false, false, false, 0L);
        assertNull(ScanSessionTestHooks.singleActiveSessionViolation(snapshot));
    }

    @Test
    public void stagedLaunchMustMatchGeneration() {
        ScanSessionTestHooks.Snapshot snapshot = new ScanSessionTestHooks.Snapshot(
                2L, false, false, false, true, 1L);
        assertEquals(
                "staged launch generation 1 != active session 2",
                ScanSessionTestHooks.singleActiveSessionViolation(snapshot));
    }

    @Test
    public void executorAndStagedLaunchConflict() {
        ScanSessionTestHooks.Snapshot snapshot = new ScanSessionTestHooks.Snapshot(
                3L, false, true, true, true, 3L);
        assertEquals(
                "executor running while staged launch is still pending commit",
                ScanSessionTestHooks.singleActiveSessionViolation(snapshot));
    }

    @Test
    public void runningExecutorRequiresLiveOrchestrator() {
        ScanSessionTestHooks.Snapshot snapshot = new ScanSessionTestHooks.Snapshot(
                4L, false, true, false, false, 0L);
        assertEquals(
                "executor bound but orchestrator thread is not alive",
                ScanSessionTestHooks.singleActiveSessionViolation(snapshot));
    }
}
