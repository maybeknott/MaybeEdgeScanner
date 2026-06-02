package com.maybeedgescanner;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class LocalObservationHistoryStoreTest {
    @Test
    public void mergeSuccessfulKeysCountsOncePerEndpointPerRun() throws Exception {
        String json = LocalObservationHistoryStore.mergeSuccessfulKeysJson(
                "{\"1.1.1.1:443\":2}",
                Arrays.asList("1.1.1.1:443", "1.1.1.1:443", "2.2.2.2:443", "", null));

        List<LocalObservationHistoryStore.Entry> rows = LocalObservationHistoryStore.loadTopStableFromJson(json, 1, 10);

        assertEquals("1.1.1.1:443", rows.get(0).key);
        assertEquals(3, rows.get(0).count);
        assertEquals("2.2.2.2:443", rows.get(1).key);
        assertEquals(1, rows.get(1).count);
    }

    @Test
    public void loadTopStableAppliesMinCountOrderingAndLimit() throws Exception {
        List<LocalObservationHistoryStore.Entry> rows = LocalObservationHistoryStore.loadTopStableFromJson(
                "{\"low:443\":1,\"top:443\":4,\"middle:443\":2}",
                2,
                2);

        assertEquals(2, rows.size());
        assertEquals("top:443", rows.get(0).key);
        assertEquals(4, rows.get(0).count);
        assertEquals("middle:443", rows.get(1).key);
        assertEquals("middle:443 x2 route pass", rows.get(1).displayLabel());
    }
}
