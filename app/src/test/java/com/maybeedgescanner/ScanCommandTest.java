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
}
