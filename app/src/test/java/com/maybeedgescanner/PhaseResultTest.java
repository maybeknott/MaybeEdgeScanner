package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class PhaseResultTest {
    @Test
    public void statusFromCodeMapsRefused() {
        assertEquals("refused", PhaseResult.statusFromCode("TCP_CONNECT_REFUSED"));
    }
}
