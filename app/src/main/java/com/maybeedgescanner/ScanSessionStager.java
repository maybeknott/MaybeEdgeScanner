package com.maybeedgescanner;

import android.content.Context;

/** Applies a staged scan request inside the foreground service. */
final class ScanSessionStager {
    private ScanSessionStager() {}

    static Result apply(Context context, ScanStagingRequest request) {
        if (request == null) {
            return Result.failure("missing staging request");
        }
        if (request.targets.isEmpty() || request.ports.isEmpty() || request.workflowProfiles.isEmpty()) {
            return Result.failure("targets, ports, and workflow steps are required");
        }

        ScanSessionController session = ScanSessionController.get();
        long generation = session.startNewScanSession();
        session.setTotalTargets(request.plannedChecks);

        ScanForegroundService.updateRouteSnapshot(context, request.routeProfile);
        ScanForegroundService.RouteSessionSnapshot routeSession = ScanForegroundService.routeSnapshot();
        EdgeRouteProfile routeProfile = routeSession == null
                ? request.routeProfile.copy()
                : routeSession.profile.copy();

        session.stageLaunch(ScanLaunchSpec.create(
                generation,
                request.targets,
                request.snis,
                request.ports,
                request.workflowProfiles,
                request.batch,
                request.threads,
                request.timeout,
                request.tlsMode,
                request.allSniPreference,
                request.suppressNoisyLogs,
                request.sniPairingEnabled,
                request.httpPath,
                routeProfile));

        ScanForegroundService.beginSession(
                generation,
                request.plannedChecks,
                request.targets.size(),
                request.ports.size(),
                request.threads,
                request.workflowLabel);
        ScanForegroundService.start(context, "planning",
                "0 / " + request.plannedChecks + " checks", 0);
        session.notifyUiObservers();
        return Result.success(generation);
    }

    static final class Result {
        final boolean success;
        final long generation;
        final String error;

        private Result(boolean success, long generation, String error) {
            this.success = success;
            this.generation = generation;
            this.error = error == null ? "" : error;
        }

        static Result success(long generation) {
            return new Result(true, generation, "");
        }

        static Result failure(String error) {
            return new Result(false, 0L, error);
        }
    }
}
