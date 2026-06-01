package com.maybeedgescanner;

/** Pure decision policy for sidecar heartbeat checks. */
final class SidecarHeartbeatPolicy {
    private SidecarHeartbeatPolicy() {}

    enum Action {
        NOOP,
        STOP_ONLY,
        RESCHEDULE,
        FAIL_SIDECAR_AND_STOP
    }

    static Action decide(
            boolean active,
            boolean sessionRunning,
            boolean snapshotReachable,
            boolean sidecarWasReachable) {
        if (!active) return Action.NOOP;
        if (!sessionRunning) return Action.STOP_ONLY;
        if (snapshotReachable) return Action.RESCHEDULE;
        if (sidecarWasReachable) return Action.FAIL_SIDECAR_AND_STOP;
        return Action.STOP_ONLY;
    }
}
