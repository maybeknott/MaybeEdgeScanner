package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DiagnosticsRedactorTest {

    @Test
    public void redact_hidesSensitiveNetworkAndTokenFields() {
        String input = "Public IP: 203.0.113.9\n"
                + "Local IP: 192.168.1.10\n"
                + "WAN IP: 198.51.100.22\n"
                + "Authorization: Bearer abc123\n"
                + "cookie=secret-cookie\n";

        String out = DiagnosticsRedactor.redact(input);

        assertTrue(out.contains("Public IP: [REDACTED]"));
        assertTrue(out.contains("Local IP: [REDACTED]"));
        assertTrue(out.contains("WAN IP: [REDACTED]"));
        assertTrue(out.toLowerCase().contains("authorization: [redacted]"));
        assertTrue(out.toLowerCase().contains("cookie: [redacted]"));
        assertFalse(out.contains("203.0.113.9"));
        assertFalse(out.contains("192.168.1.10"));
        assertFalse(out.contains("198.51.100.22"));
        assertFalse(out.contains("abc123"));
        assertFalse(out.contains("secret-cookie"));
    }

    @Test
    public void redact_handlesNullAndEmpty() {
        assertTrue(DiagnosticsRedactor.redact(null).isEmpty());
        assertTrue(DiagnosticsRedactor.redact("").isEmpty());
    }
}

