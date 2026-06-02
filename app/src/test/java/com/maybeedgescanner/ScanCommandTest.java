package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ScanCommandTest {
    @Test
    public void clearSessionUsesClearKind() {
        ScanCommand command = ScanCommand.clearSession("activity_ui");
        assertEquals(ScanCommand.Kind.CLEAR_SESSION, command.kind);
        assertEquals("activity_ui", command.source);
    }

    @Test
    public void cancelScanCarriesGenerationAndSource() {
        ScanCommand command = ScanCommand.cancelScan("notification", 42L);
        assertEquals(ScanCommand.Kind.CANCEL_SCAN, command.kind);
        assertEquals("notification", command.source);
        assertEquals(42L, command.generation);
    }

    @Test
    public void commandBusFallbackMarksBlockedStartAsFailed() {
        ScanCommand command = ScanCommand.startScan("activity_ui");
        assertEquals("failed", ScanCommandBus.fallbackState(command));
        assertEquals("Scan start blocked by Android service restrictions",
                ScanCommandBus.blockedLaunchDetail(command));
    }

    @Test
    public void commandBusFallbackKeepsCancelInCancellingState() {
        ScanCommand command = ScanCommand.cancelScan("activity_ui", 42L);
        assertEquals("cancelling", ScanCommandBus.fallbackState(command));
        assertEquals("Stop request recorded; service start was blocked",
                ScanCommandBus.blockedLaunchDetail(command));
    }

    @Test
    public void commandBusFallbackKeepsClearIdle() {
        ScanCommand command = ScanCommand.clearSession("activity_ui");
        assertEquals("idle", ScanCommandBus.fallbackState(command));
        assertEquals("Clear request could not start service",
                ScanCommandBus.blockedLaunchDetail(command));
    }
}
