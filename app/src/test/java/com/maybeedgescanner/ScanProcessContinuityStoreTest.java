package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ScanProcessContinuityStoreTest {
    @Test
    public void abandonedSessionDetailExplainsUnsupportedResume() {
        ScanProcessContinuityStore.AbandonedSession abandoned =
                new ScanProcessContinuityStore.AbandonedSession(7L, 42, 1234L, "Full scan");

        assertEquals(
                "Previous scan could not be resumed after app process restart (42 planned checks)",
                abandoned.detail());
    }

    @Test
    public void abandonedSessionDetailOmitsUnknownPlanCount() {
        ScanProcessContinuityStore.AbandonedSession abandoned =
                new ScanProcessContinuityStore.AbandonedSession(7L, -3, -1L, null);

        assertEquals(
                "Previous scan could not be resumed after app process restart",
                abandoned.detail());
    }
}
