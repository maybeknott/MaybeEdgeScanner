package com.maybeedgescanner;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class ResultSessionStoreTest {
    @Test
    public void clearRotatesSessionIdentityAndDropsRows() {
        ResultSessionStore<String> store = new ResultSessionStore<>();
        String firstSession = store.sessionId();

        assertEquals(1, store.append("first"));
        List<String> snapshot = store.snapshot();
        snapshot.add("external");

        assertEquals(1, store.size());
        store.clear();

        assertTrue(store.isEmpty());
        assertNotEquals(firstSession, store.sessionId());
    }
}
