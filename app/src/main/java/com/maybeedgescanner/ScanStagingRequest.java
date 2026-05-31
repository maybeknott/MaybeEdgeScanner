package com.maybeedgescanner;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/** UI-collected scan inputs staged by the foreground service (B1 slice 13). */
final class ScanStagingRequest implements Serializable {
    private static final long serialVersionUID = 3L;

    final ArrayList<String> targets;
    final ArrayList<TargetExpansionMeta> targetExpansion;
    final ArrayList<String> snis;
    final ArrayList<Integer> ports;
    final ArrayList<Integer> workflowProfiles;
    final int plannedChecks;
    final int batch;
    final int threads;
    final int timeout;
    final int tlsMode;
    final boolean allSniPreference;
    final boolean suppressNoisyLogs;
    final boolean sniPairingEnabled;
    final String httpPath;
    final String workflowLabel;
    final String logSummary;
    final EdgeRouteProfile routeProfile;
    final boolean planConfirmed;

    ScanStagingRequest(
            List<String> targets,
            List<TargetExpansionMeta> targetExpansion,
            List<String> snis,
            List<Integer> ports,
            List<Integer> workflowProfiles,
            int plannedChecks,
            int batch,
            int threads,
            int timeout,
            int tlsMode,
            boolean allSniPreference,
            boolean suppressNoisyLogs,
            boolean sniPairingEnabled,
            String httpPath,
            String workflowLabel,
            String logSummary,
            EdgeRouteProfile routeProfile,
            boolean planConfirmed) {
        this.targets = new ArrayList<>(targets);
        this.targetExpansion = new ArrayList<>();
        if (targetExpansion != null) {
            this.targetExpansion.addAll(targetExpansion);
        }
        while (this.targetExpansion.size() < this.targets.size()) {
            this.targetExpansion.add(null);
        }
        this.snis = new ArrayList<>(snis);
        this.ports = new ArrayList<>(ports);
        this.workflowProfiles = new ArrayList<>(workflowProfiles);
        this.plannedChecks = plannedChecks;
        this.batch = batch;
        this.threads = threads;
        this.timeout = timeout;
        this.tlsMode = tlsMode;
        this.allSniPreference = allSniPreference;
        this.suppressNoisyLogs = suppressNoisyLogs;
        this.sniPairingEnabled = sniPairingEnabled;
        this.httpPath = httpPath == null ? "" : httpPath;
        this.workflowLabel = workflowLabel == null ? "" : workflowLabel;
        this.logSummary = logSummary == null ? "" : logSummary;
        this.routeProfile = routeProfile == null ? EdgeRouteProfile.direct() : routeProfile.copy();
        this.planConfirmed = planConfirmed;
    }
}
