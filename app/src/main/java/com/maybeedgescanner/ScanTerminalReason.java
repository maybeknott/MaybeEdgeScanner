package com.maybeedgescanner;

/** Canonical terminal reasons for an active scan session. */
enum ScanTerminalReason {
    COMPLETED("completed"),
    STOPPED_UI("stopped"),
    STOPPED_NOTIFICATION("stopped"),
    CLEARED("idle"),
    FAILED_EXPORT("failed"),
    FAILED_SIDECAR("failed"),
    FAILED_PROVIDER("failed"),
    FAILED_STORAGE("failed"),
    FAILED_NO_CHECKS("failed"),
    PROCESS_LOST("process_lost");

    final String lifecycleState;

    ScanTerminalReason(String lifecycleState) {
        this.lifecycleState = lifecycleState;
    }

    static ScanTerminalReason fromStopRequested(boolean stopRequested, String source) {
        if (!stopRequested) return COMPLETED;
        if ("notification".equals(source) || "notification_legacy".equals(source)) {
            return STOPPED_NOTIFICATION;
        }
        return STOPPED_UI;
    }
}
