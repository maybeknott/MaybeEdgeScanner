package com.maybeedgescanner;

import java.io.Serializable;

/** Immutable export options staged before the service writes session results. */
final class ScanExportSpec implements Serializable {
    private static final long serialVersionUID = 1L;

    static final int FORMAT_JSONL = 0;
    static final int FORMAT_CSV = 1;
    static final int FORMAT_MARKDOWN = 2;
    static final int FORMAT_NMAP_XML = 3;

    final int format;
    final String redactionMode;
    final String productMode;
    final String filePrefix;

    ScanExportSpec(int format, String redactionMode, String productMode, String filePrefix) {
        this.format = format;
        this.redactionMode = redactionMode == null || redactionMode.isEmpty() ? "none" : redactionMode;
        this.productMode = productMode == null || productMode.isEmpty() ? "route_pairing" : productMode;
        this.filePrefix = filePrefix == null || filePrefix.isEmpty() ? "maybeedgescanner_export" : filePrefix;
    }
}
