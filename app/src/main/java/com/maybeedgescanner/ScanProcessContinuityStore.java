package com.maybeedgescanner;

import android.content.Context;
import android.content.SharedPreferences;

/** Records active scan ownership across process starts without pretending scans are resumable. */
final class ScanProcessContinuityStore {
    private static final String PREFS = "scan_process_continuity";
    private static final String KEY_ACTIVE = "active";
    private static final String KEY_GENERATION = "generation";
    private static final String KEY_PLANNED_CHECKS = "planned_checks";
    private static final String KEY_STARTED_AT = "started_at";
    private static final String KEY_WORKFLOW = "workflow";

    private ScanProcessContinuityStore() {}

    static void markActive(Context context, long generation, int plannedChecks, String workflow) {
        if (context == null) return;
        prefs(context).edit()
                .putBoolean(KEY_ACTIVE, true)
                .putLong(KEY_GENERATION, generation)
                .putInt(KEY_PLANNED_CHECKS, Math.max(0, plannedChecks))
                .putLong(KEY_STARTED_AT, System.currentTimeMillis())
                .putString(KEY_WORKFLOW, workflow == null ? "" : workflow)
                .apply();
    }

    static void markTerminal(Context context) {
        if (context == null) return;
        prefs(context).edit().clear().apply();
    }

    static AbandonedSession consumeAbandonedSession(Context context) {
        if (context == null) return null;
        SharedPreferences prefs = prefs(context);
        if (!prefs.getBoolean(KEY_ACTIVE, false)) return null;
        AbandonedSession abandoned = new AbandonedSession(
                prefs.getLong(KEY_GENERATION, 0L),
                prefs.getInt(KEY_PLANNED_CHECKS, 0),
                prefs.getLong(KEY_STARTED_AT, 0L),
                prefs.getString(KEY_WORKFLOW, ""));
        prefs.edit().clear().apply();
        return abandoned;
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    static final class AbandonedSession {
        final long generation;
        final int plannedChecks;
        final long startedAtEpochMs;
        final String workflow;

        AbandonedSession(long generation, int plannedChecks, long startedAtEpochMs, String workflow) {
            this.generation = generation;
            this.plannedChecks = Math.max(0, plannedChecks);
            this.startedAtEpochMs = Math.max(0L, startedAtEpochMs);
            this.workflow = workflow == null ? "" : workflow;
        }

        String detail() {
            String suffix = plannedChecks > 0 ? " (" + plannedChecks + " planned checks)" : "";
            return "Previous scan could not be resumed after app process restart" + suffix;
        }
    }
}
