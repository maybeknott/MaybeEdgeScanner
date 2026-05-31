package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/** JVM-safe rotation/recreation contract checks (B1 slice 14). */
public class ScanRotationContractTest {
    @Test
    public void activeExecutorDuringRotationIsValid() {
        ScanSessionTestHooks.Snapshot snapshot = new ScanSessionTestHooks.Snapshot(
                5L, false, true, true, false, 0L);
        ScanSessionTestHooks.assertSingleActiveSession(snapshot);
    }

    @Test
    public void stagedLaunchSurvivesUntilCommit() {
        ScanSessionTestHooks.Snapshot snapshot = new ScanSessionTestHooks.Snapshot(
                7L, false, false, false, true, 7L);
        ScanSessionTestHooks.assertSingleActiveSession(snapshot);
    }

    @Test
    public void activityFinishWithRunningExecutorIsValid() {
        ScanSessionTestHooks.Snapshot snapshot = new ScanSessionTestHooks.Snapshot(
                9L, false, true, true, false, 0L);
        ScanSessionTestHooks.assertSingleActiveSession(snapshot);
        assertNull(ScanSessionTestHooks.activityFinishDuringActiveScanViolation(snapshot, true));
    }

    @Test
    public void configurationChangeMustNotLeavePendingStagedLaunchAfterRunning() {
        ScanSessionTestHooks.Snapshot snapshot = new ScanSessionTestHooks.Snapshot(
                8L, false, true, true, true, 8L);
        assertEquals(
                "rotation left staged launch pending while executor is running",
                ScanSessionTestHooks.rotationLifecycleViolation(snapshot, true));
    }
}
