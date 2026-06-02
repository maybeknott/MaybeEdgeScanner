package com.maybeedgescanner;

import android.content.Context;
import android.content.Intent;
import android.os.Build;

/** Service-owned entry point for scan lifecycle commands (B1 slice 1). */
public final class ScanCommandBus {
    public static final String ACTION_SCAN_COMMAND = "com.maybeedgescanner.action.SCAN_COMMAND";
    public static final String EXTRA_COMMAND = "scan_command";

    private ScanCommandBus() {}

    public static void submit(Context context, ScanCommand command) {
        if (context == null || command == null) return;
        Intent intent = new Intent(context, ScanForegroundService.class)
                .setAction(ScanForegroundService.ACTION_COMMAND)
                .putExtra(EXTRA_COMMAND, command);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent);
            } else {
                context.startService(intent);
            }
        } catch (IllegalStateException blocked) {
            String state = fallbackState(command);
            if ("failed".equals(state) && command.kind == ScanCommand.Kind.START_SCAN) {
                ScanSessionController.get().recordTerminalReason(ScanTerminalReason.FAILED_START);
                ScanProcessContinuityStore.markTerminal(context);
            }
            ScanForegroundService.publishFallbackLifecycle(context, state, blockedLaunchDetail(command), 0);
        }
    }

    public static Intent commandBroadcast(ScanCommand command) {
        return new Intent(ACTION_SCAN_COMMAND).putExtra(EXTRA_COMMAND, command);
    }

    static String fallbackState(ScanCommand command) {
        if (command == null || command.kind == null) return "failed";
        switch (command.kind) {
            case START_SCAN:
                return "failed";
            case CANCEL_SCAN:
                return "cancelling";
            case CLEAR_SESSION:
                return "idle";
            default:
                return ScanForegroundService.snapshot().state;
        }
    }

    static String blockedLaunchDetail(ScanCommand command) {
        if (command == null || command.kind == null) {
            return "Service command could not start";
        }
        switch (command.kind) {
            case START_SCAN:
                return "Scan start blocked by Android service restrictions";
            case CANCEL_SCAN:
                return "Stop request recorded; service start was blocked";
            case CLEAR_SESSION:
                return "Clear request could not start service";
            case EXPORT_RESULTS:
                return "Export request could not start service";
            case STOP_SIDECAR:
                return "Sidecar stop request could not start service";
            case REFRESH_PROVIDER_READINESS:
                return "Provider readiness refresh could not start service";
            default:
                return "Service command could not start";
        }
    }
}
