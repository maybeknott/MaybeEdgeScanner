package com.maybeedgescanner;

import android.content.Intent;

/** Broadcasts for service-owned export completion. */
final class ScanExportBus {
    static final String ACTION_EXPORT_COMPLETED = "com.maybeedgescanner.action.EXPORT_COMPLETED";
    static final String EXTRA_PATH = "export_path";
    static final String EXTRA_ERROR = "export_error";

    private ScanExportBus() {}

    static Intent completedBroadcast(String path, String error) {
        return new Intent(ACTION_EXPORT_COMPLETED)
                .putExtra(EXTRA_PATH, path == null ? "" : path)
                .putExtra(EXTRA_ERROR, error == null ? "" : error);
    }
}
