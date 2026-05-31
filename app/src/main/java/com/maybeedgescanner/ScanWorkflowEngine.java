package com.maybeedgescanner;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;

/** Service-owned TCP/TLS/HTTP probe orchestration for staged scan launches. */
final class ScanWorkflowEngine implements ScanWorkflowRunner {
    private static final ScanWorkflowEngine INSTANCE = new ScanWorkflowEngine();

    private final ScanSessionController session = ScanSessionController.get();

    private ScanWorkflowEngine() {}

    static ScanWorkflowEngine get() {
        return INSTANCE;
    }

    static void ensureRegistered() {
        ScanSessionController.get().registerWorkflowRunner(INSTANCE);
    }

    @Override
    public void run(long generation, ExecutorService scanExecutor, ScanLaunchSpec spec) {
        List<Integer> profiles = spec.workflowProfiles;
        for (int i = 0; i < profiles.size() && session.shouldContinue(generation); i++) {
            int profile = profiles.get(i);
            boolean allSni = spec.sniPairingEnabled && (spec.allSniPreference || profile >= 2);
            appendLog("Workflow step " + (i + 1) + "/" + profiles.size() + ": " + profileName(profile)
                    + (spec.sniPairingEnabled
                    ? (allSni ? " with multi-SNI" : " with primary SNI")
                    : " with IP-only probing"));
            runBatches(generation, scanExecutor, spec, profile, allSni);
        }
        scanExecutor.shutdownNow();
        session.finishWorkflow(generation, scanExecutor, "service");
    }

    private void runBatches(long generation, ExecutorService scanExecutor, ScanLaunchSpec spec, int profile, boolean allSni) {
        List<String> targets = spec.targets;
        int batchSize = Math.max(1, spec.batch);
        int batches = (targets.size() + batchSize - 1) / batchSize;
        for (int start = 0, batchNo = 1; start < targets.size() && session.shouldContinue(generation); start += batchSize, batchNo++) {
            List<String> batch = targets.subList(start, Math.min(targets.size(), start + batchSize));
            appendLog(profileName(profile) + " batch " + batchNo + "/" + batches + ": " + batch.size() + " targets");
            CountDownLatch latch = new CountDownLatch(batch.size());
            for (String target : batch) {
                if (!session.shouldContinue(generation)) {
                    latch.countDown();
                    continue;
                }
                try {
                    scanExecutor.submit(() -> {
                        try {
                            scanTarget(generation, target, spec, profile, allSni);
                        } finally {
                            session.runOnUi(MainActivity::scheduleProgressUpdate);
                            latch.countDown();
                        }
                    });
                } catch (RejectedExecutionException ignored) {
                    latch.countDown();
                }
            }
            try {
                latch.await();
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void scanTarget(long generation, String target, ScanLaunchSpec spec, int profile, boolean allSni) {
        if (!session.shouldContinue(generation)) return;
        List<String> ips = ScanTargetPlanner.resolve(target);
        EdgeRouteProfile routeProfile = spec.routeProfile;
        if (ips.isEmpty()) {
            addResult(generation,
                    MainActivity.Result.down(target, "", 0, "", "dns_failed").withRoute(routeProfile),
                    spec.suppressNoisyLogs);
            return;
        }
        for (String ip : ips) {
            if (!session.shouldContinue(generation)) return;
            for (int port : spec.ports) {
                if (profile == 0) {
                    MainActivity.Result base = new MainActivity.Result(target, ip, port, "");
                    base.tcp(spec.timeout);
                    addResult(generation, base.withRoute(routeProfile).finish(), spec.suppressNoisyLogs);
                    continue;
                }
                List<String> candidates = spec.sniPairingEnabled
                        ? (allSni ? spec.snis : Collections.singletonList(isIp(target) ? first(spec.snis) : target))
                        : Collections.singletonList("");
                for (String sni : candidates) {
                    if (!session.shouldContinue(generation)) return;
                    String routeSni = sni == null ? "" : sni.trim();
                    MainActivity.Result result = new MainActivity.Result(target, ip, port, routeSni);
                    result.tls(spec.timeout, spec.tlsMode);
                    if (profile >= 2 && result.tlsPass) result.http(spec.timeout, spec.httpPath, spec.tlsMode);
                    addResult(generation, result.withRoute(routeProfile).finish(), spec.suppressNoisyLogs);
                    if (profile == 3 && result.httpPass) break;
                }
            }
        }
    }

    private void addResult(long generation, MainActivity.Result result, boolean suppressNoisyLogs) {
        if (session.offerResult(generation, result, suppressNoisyLogs)) {
            session.requestResultDrain();
        }
    }

    private void appendLog(String message) {
        session.runOnUi(activity -> activity.appendLogOnUi(message));
    }

    private static String profileName(int profile) {
        switch (profile) {
            case 0: return "TCP";
            case 1: return "TLS";
            case 2: return "HTTP";
            case 3: return "Verify";
            default: return "Profile " + profile;
        }
    }

    private static String first(List<String> values) {
        return values.isEmpty() ? "" : values.get(0);
    }

    private static boolean isIp(String value) {
        return ScanTargetPlanner.isIp(value);
    }
}
