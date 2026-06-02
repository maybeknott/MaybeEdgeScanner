package com.maybeedgescanner;

import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

final class LocalObservationHistoryStore {
    private static final String KEY_HISTORY = "stable_history_v1";

    private LocalObservationHistoryStore() {}

    static void mergeSuccessfulRun(SharedPreferences prefs, List<MainActivity.Result> results) throws Exception {
        prefs.edit().putString(KEY_HISTORY, mergeSuccessfulKeysJson(prefs.getString(KEY_HISTORY, "{}"), successfulKeys(results))).apply();
    }

    static String mergeSuccessfulKeysJson(String existingJson, List<String> successfulKeys) throws Exception {
        LinkedHashMap<String, Integer> root = parseCounterJson(existingJson);
        LinkedHashSet<String> seenThisRun = new LinkedHashSet<>();
        for (String key : successfulKeys) {
            if (key != null && !key.trim().isEmpty()) seenThisRun.add(key.trim());
        }
        for (String key : seenThisRun) root.put(key, root.getOrDefault(key, 0) + 1);
        return serializeCounterJson(root);
    }

    private static List<String> successfulKeys(List<MainActivity.Result> results) {
        ArrayList<String> keys = new ArrayList<>();
        for (MainActivity.Result r : results) {
            if (r.working() && r.ip != null && !r.ip.isEmpty()) keys.add(r.ip + ":" + r.port);
        }
        return keys;
    }

    static List<Entry> loadTopStable(SharedPreferences prefs, int minCount, int limit) throws Exception {
        return loadTopStableFromJson(prefs.getString(KEY_HISTORY, "{}"), minCount, limit);
    }

    static List<Entry> loadTopStableFromJson(String historyJson, int minCount, int limit) throws Exception {
        LinkedHashMap<String, Integer> root = parseCounterJson(historyJson);
        ArrayList<String> keys = new ArrayList<>(root.keySet());
        keys.sort((a, b) -> Integer.compare(root.getOrDefault(b, 0), root.getOrDefault(a, 0)));
        ArrayList<Entry> out = new ArrayList<>();
        for (String key : keys) {
            int count = root.getOrDefault(key, 0);
            if (count < minCount) continue;
            out.add(new Entry(key, count));
            if (out.size() >= limit) break;
        }
        return out;
    }

    private static LinkedHashMap<String, Integer> parseCounterJson(String value) {
        LinkedHashMap<String, Integer> out = new LinkedHashMap<>();
        if (value == null) return out;
        String body = value.trim();
        if (body.startsWith("{")) body = body.substring(1);
        if (body.endsWith("}")) body = body.substring(0, body.length() - 1);
        if (body.trim().isEmpty()) return out;
        for (String part : body.split(",")) {
            int quoteStart = part.indexOf('"');
            int quoteEnd = quoteStart < 0 ? -1 : findClosingQuote(part, quoteStart + 1);
            int colon = quoteEnd < 0 ? -1 : part.indexOf(':', quoteEnd + 1);
            if (quoteStart < 0 || quoteEnd <= quoteStart || colon < 0) continue;
            String key = unescape(part.substring(quoteStart + 1, quoteEnd));
            String countText = part.substring(colon + 1).trim();
            try {
                if (!key.isEmpty()) out.put(key, Math.max(0, Integer.parseInt(countText)));
            } catch (NumberFormatException ignored) {}
        }
        return out;
    }

    private static String serializeCounterJson(LinkedHashMap<String, Integer> values) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Integer> entry : values.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(escape(entry.getKey())).append('"').append(':').append(Math.max(0, entry.getValue()));
        }
        return sb.append('}').toString();
    }

    private static int findClosingQuote(String value, int start) {
        boolean escaped = false;
        for (int i = start; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                return i;
            }
        }
        return -1;
    }

    private static String unescape(String value) {
        return value.replace("\\\"", "\"").replace("\\\\", "\\");
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    static final class Entry {
        final String key;
        final int count;

        Entry(String key, int count) {
            this.key = key;
            this.count = count;
        }

        String displayLabel() {
            return key + " x" + count + " route pass";
        }
    }
}
