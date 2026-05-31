package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ScanTerminalReasonTest {
    @Test
    public void completedWhenNotStopped() {
        assertEquals(ScanTerminalReason.COMPLETED, ScanTerminalReason.fromStopRequested(false, "activity_ui"));
    }

    @Test
    public void notificationStopUsesNotificationReason() {
        assertEquals(ScanTerminalReason.STOPPED_NOTIFICATION,
                ScanTerminalReason.fromStopRequested(true, "notification"));
    }

    @Test
    public void uiStopUsesUiReason() {
        assertEquals(ScanTerminalReason.STOPPED_UI,
                ScanTerminalReason.fromStopRequested(true, "activity_ui"));
    }

    @Test
    public void failedSidecarUsesFailedLifecycle() {
        assertEquals("failed", ScanTerminalReason.FAILED_SIDECAR.lifecycleState);
    }

    @Test
    public void processLostUsesProcessLostLifecycle() {
        assertEquals("process_lost", ScanTerminalReason.PROCESS_LOST.lifecycleState);
    }

    @Test
    public void failedProviderUsesFailedLifecycle() {
        assertEquals("failed", ScanTerminalReason.FAILED_PROVIDER.lifecycleState);
    }

    @Test
    public void failedStorageUsesFailedLifecycle() {
        assertEquals("failed", ScanTerminalReason.FAILED_STORAGE.lifecycleState);
    }
}
