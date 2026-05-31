package com.maybeedgescanner;

/** Pending scan row waiting for UI-thread drain into {@link ResultSessionStore}. */
final class ScanResultEvent {
    final MainActivity.Result result;
    final boolean suppressNoisyLogs;
    final long generation;

    ScanResultEvent(MainActivity.Result result, boolean suppressNoisyLogs, long generation) {
        this.result = result;
        this.suppressNoisyLogs = suppressNoisyLogs;
        this.generation = generation;
    }
}
