package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

/** JVM contract tests for plan review gating and session clear (B1 slice 24). */
public class ScanPlanReviewContractTest {
    @Test
    public void startBlockedWhilePlanReviewPendingWithoutConfirmation() {
        ScanSessionTestHooks.Snapshot pending = new ScanSessionTestHooks.Snapshot(
                1L, false, false, false, false, 0L);
        assertEquals(
                "start blocked until plan confirmed",
                ScanSessionTestHooks.planReviewStartViolation(pending, true, false));
    }

    @Test
    public void startAllowedAfterPlanConfirmed() {
        ScanSessionTestHooks.Snapshot pending = new ScanSessionTestHooks.Snapshot(
                1L, false, false, false, false, 0L);
        assertNull(ScanSessionTestHooks.planReviewStartViolation(pending, true, true));
    }

    @Test
    public void clearSessionResetsRunningExecutorInvariant() {
        ScanSessionTestHooks.Snapshot cleared = new ScanSessionTestHooks.Snapshot(
                2L, false, false, false, false, 0L);
        ScanSessionTestHooks.assertSingleActiveSession(cleared);
        assertFalse(cleared.executorRunning);
    }
}
