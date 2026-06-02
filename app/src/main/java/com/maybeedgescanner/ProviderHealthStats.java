package com.maybeedgescanner;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

final class ProviderHealthStats {
    private ProviderHealthStats() {}

    static List<Item> fromResults(List<MainActivity.Result> rows, int maxEntries) {
        Map<String, Item> map = new TreeMap<>();
        for (MainActivity.Result r : rows) {
            String network = ResultAnalyticsStats.networkKey(r.networkClassification);
            Item item = map.get(network);
            if (item == null) {
                item = new Item(network);
                map.put(network, item);
            }
            item.total++;
            if (r.working()) item.working++;
            long latency = r.totalLatency();
            if (latency > 0) {
                item.latencySum += latency;
                item.latencyCount++;
            }
            if (r.phaseStatusPresent("timeout") || r.errorCodeEndsWith("_TIMEOUT")) item.timeout++;
            if (r.phaseStatusPresent("reset") || r.errorCodeEndsWith("_RESET")) item.reset++;
        }
        ArrayList<Item> out = new ArrayList<>(map.values());
        out.sort((a, b) -> Integer.compare(b.working, a.working));
        return out.subList(0, Math.min(Math.max(0, maxEntries), out.size()));
    }

    static final class Item {
        final String name;
        int total;
        int working;
        int timeout;
        int reset;
        int latencyCount;
        long latencySum;

        Item(String name) {
            this.name = name;
        }

        String label() {
            int success = total == 0 ? 0 : Math.round(working * 100f / total);
            String avg = latencyCount == 0 ? "--" : Math.round(latencySum / (float) latencyCount) + "ms";
            return name + ": " + working + "/" + total + " pass, " + success + "%, avg " + avg
                    + ", timeout " + timeout + ", reset " + reset;
        }
    }
}
