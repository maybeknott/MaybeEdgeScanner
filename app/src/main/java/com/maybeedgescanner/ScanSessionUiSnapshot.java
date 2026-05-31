package com.maybeedgescanner;

import java.io.Serializable;

/** Immutable render-only view of the active scan session (B1 slice 4). */
final class ScanSessionUiSnapshot implements Serializable {
    private static final long serialVersionUID = 1L;

    public static final String ACTION_SNAPSHOT = "com.maybeedgescanner.action.SESSION_SNAPSHOT";
    public static final String EXTRA_SNAPSHOT = "session_ui_snapshot";

    final long generation;
    final boolean running;
    final boolean stopRequested;
    final int checkedChecks;
    final int plannedChecks;
    final int resultCount;
    final int pendingCount;
    final long scanStartedAtEpochMs;
    final String lifecycleState;
    final String sessionId;

    ScanSessionUiSnapshot(
            long generation,
            boolean running,
            boolean stopRequested,
            int checkedChecks,
            int plannedChecks,
            int resultCount,
            int pendingCount,
            long scanStartedAtEpochMs,
            String lifecycleState,
            String sessionId) {
        this.generation = generation;
        this.running = running;
        this.stopRequested = stopRequested;
        this.checkedChecks = checkedChecks;
        this.plannedChecks = plannedChecks;
        this.resultCount = resultCount;
        this.pendingCount = pendingCount;
        this.scanStartedAtEpochMs = scanStartedAtEpochMs;
        this.lifecycleState = lifecycleState == null ? "idle" : lifecycleState;
        this.sessionId = sessionId == null ? "" : sessionId;
    }

    static ScanSessionUiSnapshot capture(ScanSessionController session) {
        ScanForegroundService.ScanSessionSnapshot serviceSession = ScanForegroundService.sessionSnapshot();
        ScanForegroundService.ScanLifecycleSnapshot lifecycle = ScanForegroundService.snapshot();
        return new ScanSessionUiSnapshot(
                session.currentGeneration(),
                session.isRunning(),
                session.isStopRequested(),
                session.checkedChecks(),
                session.totalTargets(),
                session.results().size(),
                session.pendingResults().size(),
                session.scanStartedAt(),
                lifecycle.state,
                serviceSession.sessionId);
    }
}
