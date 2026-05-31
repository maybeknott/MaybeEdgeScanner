package com.maybeedgescanner;

import java.io.Serializable;
import java.util.Locale;

/** Immutable scan lifecycle command routed through {@link ScanForegroundService}. */
public final class ScanCommand implements Serializable {
    private static final long serialVersionUID = 3L;

    public enum Kind {
        START_SCAN,
        CANCEL_SCAN,
        CLEAR_SESSION,
        STOP_SIDECAR,
        EXPORT_RESULTS,
        REFRESH_PROVIDER_READINESS
    }

    public final Kind kind;
    public final long generation;
    public final String source;
    public final long issuedAtEpochMs;
    public final ScanStagingRequest stagingRequest;
    public final ScanExportSpec exportSpec;
    public final EdgeRouteProfile routeRefreshProfile;

    private ScanCommand(
            Kind kind,
            long generation,
            String source,
            long issuedAtEpochMs,
            ScanStagingRequest stagingRequest,
            ScanExportSpec exportSpec,
            EdgeRouteProfile routeRefreshProfile) {
        this.kind = kind;
        this.generation = generation;
        this.source = source == null ? "unknown" : source;
        this.issuedAtEpochMs = issuedAtEpochMs;
        this.stagingRequest = stagingRequest;
        this.exportSpec = exportSpec;
        this.routeRefreshProfile = routeRefreshProfile == null ? null : routeRefreshProfile.copy();
    }

    public static ScanCommand startScan(String source) {
        return new ScanCommand(Kind.START_SCAN, 0L, source, System.currentTimeMillis(), null, null, null);
    }

    public static ScanCommand startScan(String source, ScanStagingRequest stagingRequest) {
        return new ScanCommand(Kind.START_SCAN, 0L, source, System.currentTimeMillis(), stagingRequest, null, null);
    }

    public static ScanCommand cancelScan(String source, long generation) {
        return new ScanCommand(Kind.CANCEL_SCAN, generation, source, System.currentTimeMillis(), null, null, null);
    }

    public static ScanCommand clearSession(String source) {
        return new ScanCommand(Kind.CLEAR_SESSION, 0L, source, System.currentTimeMillis(), null, null, null);
    }

    public static ScanCommand stopSidecar(String source) {
        return new ScanCommand(Kind.STOP_SIDECAR, 0L, source, System.currentTimeMillis(), null, null, null);
    }

    public static ScanCommand exportResults(String source) {
        return new ScanCommand(Kind.EXPORT_RESULTS, 0L, source, System.currentTimeMillis(), null, null, null);
    }

    public static ScanCommand exportResults(String source, ScanExportSpec exportSpec) {
        return new ScanCommand(Kind.EXPORT_RESULTS, 0L, source, System.currentTimeMillis(), null, exportSpec, null);
    }

    public static ScanCommand refreshProviderReadiness(String source) {
        return new ScanCommand(Kind.REFRESH_PROVIDER_READINESS, 0L, source, System.currentTimeMillis(), null, null, null);
    }

    public static ScanCommand refreshProviderReadiness(String source, EdgeRouteProfile routeProfile) {
        return new ScanCommand(Kind.REFRESH_PROVIDER_READINESS, 0L, source, System.currentTimeMillis(), null, null, routeProfile);
    }

    @Override public String toString() {
        return String.format(Locale.US, "ScanCommand{kind=%s, generation=%d, source=%s}", kind, generation, source);
    }
}
