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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    public static Intent commandBroadcast(ScanCommand command) {
        return new Intent(ACTION_SCAN_COMMAND).putExtra(EXTRA_COMMAND, command);
    }
}
