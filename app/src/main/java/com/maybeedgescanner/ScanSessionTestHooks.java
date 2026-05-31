package com.maybeedgescanner;

/** Test-only helpers for asserting one active scan session per generation. */
final class ScanSessionTestHooks {
    private ScanSessionTestHooks() {}

    static final class Snapshot {
        final long generation;
        final boolean stopRequested;
        final boolean executorRunning;
        final boolean orchestratorAlive;
        final boolean hasStagedLaunch;
        final long stagedLaunchGeneration;

        Snapshot(
                long generation,
                boolean stopRequested,
                boolean executorRunning,
                boolean orchestratorAlive,
                boolean hasStagedLaunch,
                long stagedLaunchGeneration) {
            this.generation = generation;
            this.stopRequested = stopRequested;
            this.executorRunning = executorRunning;
            this.orchestratorAlive = orchestratorAlive;
            this.hasStagedLaunch = hasStagedLaunch;
            this.stagedLaunchGeneration = stagedLaunchGeneration;
        }
    }

    /** @return null when invariants hold; otherwise a short violation message. */
    static String singleActiveSessionViolation(Snapshot snapshot) {
        if (snapshot == null) return "snapshot is null";
        if (snapshot.hasStagedLaunch && snapshot.stagedLaunchGeneration != snapshot.generation) {
            return "staged launch generation " + snapshot.stagedLaunchGeneration
                    + " != active session " + snapshot.generation;
        }
        if (snapshot.executorRunning && snapshot.hasStagedLaunch) {
            return "executor running while staged launch is still pending commit";
        }
        if (snapshot.executorRunning && !snapshot.orchestratorAlive) {
            return "executor bound but orchestrator thread is not alive";
        }
        return null;
    }

    static void assertSingleActiveSession(Snapshot snapshot) {
        String violation = singleActiveSessionViolation(snapshot);
        if (violation != null) {
            throw new AssertionError(violation);
        }
    }

    /** Activity finish must not stop an in-flight scan; executor may outlive the UI host. */
    static String activityFinishDuringActiveScanViolation(Snapshot snapshot, boolean isFinishing) {
        if (!isFinishing || snapshot == null) return null;
        String base = singleActiveSessionViolation(snapshot);
        if (base != null) return base;
        if (snapshot.executorRunning && snapshot.hasStagedLaunch) {
            return "activity finish left staged launch pending while executor is running";
        }
        return null;
    }

    /** Rotation must not leave a pending staged launch while the executor is already running. */
    static String rotationLifecycleViolation(Snapshot snapshot, boolean afterConfigurationChange) {
        if (!afterConfigurationChange) return null;
        if (snapshot.executorRunning && snapshot.hasStagedLaunch) {
            return "rotation left staged launch pending while executor is running";
        }
        return null;
    }

    /** Start must not proceed while plan review is pending unless explicitly confirmed. */
    static String planReviewStartViolation(Snapshot snapshot, boolean planReviewPending, boolean planConfirmed) {
        if (!planReviewPending || planConfirmed) return null;
        String base = singleActiveSessionViolation(snapshot);
        if (base != null) return base;
        return "start blocked until plan confirmed";
    }
}
