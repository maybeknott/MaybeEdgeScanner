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
}
