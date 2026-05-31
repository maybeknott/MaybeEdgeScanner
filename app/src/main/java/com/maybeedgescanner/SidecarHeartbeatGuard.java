package com.maybeedgescanner;

import android.content.Context;

/** Watches sidecar heartbeat during an active scan and stops on mid-scan loss. */
final class SidecarHeartbeatGuard {
    private static final SidecarHeartbeatGuard INSTANCE = new SidecarHeartbeatGuard();
    private static final long INTERVAL_MS = 5000L;

    private final android.os.Handler handler = new android.os.Handler(android.os.Looper.getMainLooper());
    private volatile Context appContext;
    private volatile boolean sidecarWasReachable;
    private volatile boolean active;

    private SidecarHeartbeatGuard() {}

    static SidecarHeartbeatGuard get() {
        return INSTANCE;
    }

    void onScanStarted(Context context, boolean sidecarReachable) {
        appContext = context == null ? null : context.getApplicationContext();
        sidecarWasReachable = sidecarReachable;
        if (!sidecarReachable) {
            stop();
            return;
        }
        active = true;
        handler.removeCallbacks(probeRunnable);
        handler.postDelayed(probeRunnable, INTERVAL_MS);
    }

    void stop() {
        active = false;
        sidecarWasReachable = false;
        handler.removeCallbacks(probeRunnable);
    }

    private final Runnable probeRunnable = new Runnable() {
        @Override public void run() {
            if (!active) return;
            ScanSessionController session = ScanSessionController.get();
            if (!session.isRunning()) {
                stop();
                return;
            }
            SidecarController.SidecarSnapshot snapshot = SidecarController.get().refreshHeartbeat(1500);
            if (snapshot.reachable) {
                handler.postDelayed(this, INTERVAL_MS);
                return;
            }
            if (sidecarWasReachable) {
                session.requestStop();
                session.recordTerminalReason(ScanTerminalReason.FAILED_SIDECAR);
                Context context = appContext;
                if (context != null) {
                    ScanForegroundService.update(
                            context,
                            "failed",
                            "Sidecar heartbeat lost",
                            ScanForegroundService.snapshot().progress);
                }
            }
            stop();
        }
    };
}
