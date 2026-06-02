package com.maybeedgescanner;

import android.content.SharedPreferences;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;

final class LocalObservationHistoryStore {
    private static final String KEY_HISTORY = "stable_history_v1";

    private LocalObservationHistoryStore() {}

    static void mergeSuccessfulRun(SharedPreferences prefs, List<MainActivity.Result> results) throws Exception {
        JSONObject root = new JSONObject(prefs.getString(KEY_HISTORY, "{}"));
        LinkedHashSet<String> seenThisRun = new LinkedHashSet<>();
        for (MainActivity.Result r : results) {
            if (r.working() && r.ip != null && !r.ip.isEmpty()) seenThisRun.add(r.ip + ":" + r.port);
        }
        for (String key : seenThisRun) root.put(key, root.optInt(key, 0) + 1);
        prefs.edit().putString(KEY_HISTORY, root.toString()).apply();
    }

    static List<Entry> loadTopStable(SharedPreferences prefs, int minCount, int limit) throws Exception {
        JSONObject root = new JSONObject(prefs.getString(KEY_HISTORY, "{}"));
        ArrayList<String> keys = new ArrayList<>();
        Iterator<String> it = root.keys();
        while (it.hasNext()) keys.add(it.next());
        keys.sort((a, b) -> Integer.compare(root.optInt(b, 0), root.optInt(a, 0)));
        ArrayList<Entry> out = new ArrayList<>();
        for (String key : keys) {
            int count = root.optInt(key, 0);
            if (count < minCount) continue;
            out.add(new Entry(key, count));
            if (out.size() >= limit) break;
        }
        return out;
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
