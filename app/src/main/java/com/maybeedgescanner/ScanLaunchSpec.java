package com.maybeedgescanner;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/** Immutable scan inputs staged before the foreground service starts workers. */
final class ScanLaunchSpec implements Serializable {
    private static final long serialVersionUID = 2L;

    final long generation;
    final ArrayList<String> targets;
    final ArrayList<TargetExpansionMeta> targetExpansion;
    final ArrayList<String> snis;
    final ArrayList<Integer> ports;
    final ArrayList<Integer> workflowProfiles;
    final int batch;
    final int threads;
    final int timeout;
    final int tlsMode;
    final boolean allSniPreference;
    final boolean suppressNoisyLogs;
    final boolean sniPairingEnabled;
    final String httpPath;
    final EdgeRouteProfile routeProfile;

    private ScanLaunchSpec(
            long generation,
            List<String> targets,
            List<TargetExpansionMeta> targetExpansion,
            List<String> snis,
            List<Integer> ports,
            List<Integer> workflowProfiles,
            int batch,
            int threads,
            int timeout,
            int tlsMode,
            boolean allSniPreference,
            boolean suppressNoisyLogs,
            boolean sniPairingEnabled,
            String httpPath,
            EdgeRouteProfile routeProfile) {
        this.generation = generation;
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
        this.batch = batch;
        this.threads = threads;
        this.timeout = timeout;
        this.tlsMode = tlsMode;
        this.allSniPreference = allSniPreference;
        this.suppressNoisyLogs = suppressNoisyLogs;
        this.sniPairingEnabled = sniPairingEnabled;
        this.httpPath = httpPath == null ? "" : httpPath;
        this.routeProfile = routeProfile == null ? EdgeRouteProfile.direct() : routeProfile.copy();
    }

    TargetExpansionMeta expansionAt(int index) {
        if (index < 0 || index >= targetExpansion.size()) return null;
        return targetExpansion.get(index);
    }

    static ScanLaunchSpec create(
            long generation,
            List<String> targets,
            List<TargetExpansionMeta> targetExpansion,
            List<String> snis,
            List<Integer> ports,
            List<Integer> workflowProfiles,
            int batch,
            int threads,
            int timeout,
            int tlsMode,
            boolean allSniPreference,
            boolean suppressNoisyLogs,
            boolean sniPairingEnabled,
            String httpPath,
            EdgeRouteProfile routeProfile) {
        return new ScanLaunchSpec(
                generation,
                targets,
                targetExpansion,
                snis,
                ports,
                workflowProfiles,
                batch,
                threads,
                timeout,
                tlsMode,
                allSniPreference,
                suppressNoisyLogs,
                sniPairingEnabled,
                httpPath,
                routeProfile);
    }
}
