package com.maybeedgescanner;

import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;

import java.lang.ref.WeakReference;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/** Process-scoped scan session state so configuration changes do not stop active work. */
final class ScanSessionController {
    static final int RESULT_QUEUE_CAPACITY = 8192;
    static final int RESULT_DRAIN_BATCH = 512;

    private static final ScanSessionController INSTANCE = new ScanSessionController();
    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    private final AtomicBoolean stop = new AtomicBoolean(false);
    private final AtomicLong scanGeneration = new AtomicLong(0);
    private final AtomicBoolean resultDrainQueued = new AtomicBoolean(false);
    private final AtomicInteger checkedTargets = new AtomicInteger(0);
    private final AtomicLong resultSequence = new AtomicLong(0);
    private final ResultSessionStore<MainActivity.Result> resultStore = new ResultSessionStore<>();
    private final BlockingQueue<ScanResultEvent> pendingResults =
            new ArrayBlockingQueue<>(RESULT_QUEUE_CAPACITY);
    private final ExecutorService drainExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "session-result-drain");
        thread.setDaemon(true);
        return thread;
    });
    private volatile ExecutorService executor;
    private volatile int totalTargets;
    private volatile long scanStartedAt;
    private volatile ScanLaunchSpec stagedLaunch;
    private volatile ScanExportSpec stagedExport;
    private volatile ScanWorkflowRunner workflowRunner;
    private volatile Thread orchestratorThread;
    private volatile ScanSessionUiSnapshot lastPublishedSnapshot;
    private volatile ScanTerminalReason lastTerminalReason = ScanTerminalReason.CLEARED;
    private volatile WeakReference<MainActivity> uiHost = new WeakReference<>(null);
    private volatile Context appContext;
    private volatile boolean planReviewPending;
    private volatile boolean processContinuityChecked;

    private ScanSessionController() {}

    static ScanSessionController get() {
        return INSTANCE;
    }

    long currentGeneration() {
        return scanGeneration.get();
    }

    boolean isStopRequested() {
        return stop.get();
    }

    boolean isGenerationActive(long generation) {
        return generation == scanGeneration.get();
    }

    boolean shouldContinue(long generation) {
        return !stop.get() && generation == scanGeneration.get();
    }

    boolean matchesCommandGeneration(long commandGeneration) {
        return commandGeneration <= 0 || commandGeneration == scanGeneration.get();
    }

    /** Clears result state, resets stop, and allocates the next generation id. */
    long startNewScanSession() {
        stop.set(false);
        prepareNewScan();
        return scanGeneration.incrementAndGet();
    }

    void requestStop() {
        stop.set(true);
    }

    void invalidateGeneration() {
        scanGeneration.incrementAndGet();
    }

    void markScanFullyChecked() {
        checkedTargets.set(totalTargets);
    }

    int checkedChecks() {
        return checkedTargets.get();
    }

    void clearResultDrainQueued() {
        resultDrainQueued.set(false);
    }

    ResultSessionStore<MainActivity.Result> results() {
        return resultStore;
    }

    BlockingQueue<ScanResultEvent> pendingResults() {
        return pendingResults;
    }

    int totalTargets() {
        return totalTargets;
    }

    void setTotalTargets(int value) {
        totalTargets = value;
    }

    long scanStartedAt() {
        return scanStartedAt;
    }

    void setScanStartedAt(long value) {
        scanStartedAt = value;
    }

    ExecutorService executor() {
        return executor;
    }

    void bindExecutor(ExecutorService next) {
        executor = next;
    }

    boolean isRunning() {
        ExecutorService active = executor;
        return active != null && !active.isShutdown();
    }

    void prepareNewScan() {
        resultStore.clear();
        pendingResults.clear();
        resultDrainQueued.set(false);
        resultSequence.set(0);
        checkedTargets.set(0);
        scanStartedAt = System.currentTimeMillis();
    }

    void clearSession() {
        prepareNewScan();
        totalTargets = 0;
        stagedLaunch = null;
        stagedExport = null;
    }

    void registerWorkflowRunner(ScanWorkflowRunner runner) {
        workflowRunner = runner;
    }

    void stageLaunch(ScanLaunchSpec spec) {
        stagedLaunch = spec;
    }

    void stageExport(ScanExportSpec spec) {
        stagedExport = spec;
    }

    ScanExportSpec stagedExport() {
        return stagedExport;
    }

    ScanTerminalReason lastTerminalReason() {
        return lastTerminalReason;
    }

    void recordTerminalReason(ScanTerminalReason reason) {
        if (reason != null) lastTerminalReason = reason;
    }

    void noteProcessContinuityLost() {
        requestStop();
        recordTerminalReason(ScanTerminalReason.PROCESS_LOST);
    }

    void noteSidecarFailure() {
        requestStop();
        recordTerminalReason(ScanTerminalReason.FAILED_SIDECAR);
    }

    void noteProviderFailure() {
        requestStop();
        recordTerminalReason(ScanTerminalReason.FAILED_PROVIDER);
    }

    void noteStorageFailure() {
        requestStop();
        recordTerminalReason(ScanTerminalReason.FAILED_STORAGE);
    }

    boolean isPlanReviewPending() {
        return planReviewPending;
    }

    void setPlanReviewPending(boolean pending) {
        planReviewPending = pending;
    }

    void performClearSession() {
        SidecarHeartbeatGuard.get().stop();
        shutdownExecutor();
        requestStop();
        clearSession();
        invalidateGeneration();
        planReviewPending = false;
        recordTerminalReason(ScanTerminalReason.CLEARED);
        ScanProcessContinuityStore.markTerminal(applicationContext());
    }

    void attachApplicationContext(Context context) {
        if (context != null) {
            appContext = context.getApplicationContext();
            reconcileProcessContinuity(appContext);
        }
    }

    Context applicationContext() {
        if (appContext != null) return appContext;
        MainActivity host = uiHost.get();
        return host == null ? null : host.getApplicationContext();
    }

    ScanResultExporter.Result runStagedExport(Context context) {
        ScanExportSpec spec = stagedExport;
        if (spec == null) {
            spec = new ScanExportSpec(ScanExportSpec.FORMAT_JSONL, "none", "route_pairing", "maybeedgescanner_export");
        }
        stagedExport = null;
        return ScanResultExporter.exportSession(
                context,
                spec,
                results().snapshot(),
                results().sessionId(),
                scanStartedAt());
    }

    ScanLaunchSpec stagedLaunch() {
        return stagedLaunch;
    }

    /** Creates the worker pool and orchestrator thread for a staged launch. Idempotent while running. */
    boolean commitStagedLaunch() {
        if (isRunning()) return true;
        ScanLaunchSpec spec = stagedLaunch;
        ScanWorkflowRunner runner = workflowRunner;
        if (spec == null || runner == null) return false;
        if (spec.generation != scanGeneration.get()) return false;
        stagedLaunch = null;
        stop.set(false);
        ExecutorService pool = Executors.newFixedThreadPool(Math.max(1, spec.threads));
        bindExecutor(pool);
        Thread orchestrator = new Thread(() -> runner.run(spec.generation, pool, spec), "scan-orchestrator");
        orchestrator.setDaemon(true);
        orchestratorThread = orchestrator;
        orchestrator.start();
        notifyUiObservers();
        return true;
    }

    ScanSessionUiSnapshot uiSnapshot() {
        return ScanSessionUiSnapshot.capture(this);
    }

    void notifyUiObservers() {
        publishUiSnapshot();
        runOnUi(MainActivity::applySessionSnapshot);
    }

    private void publishUiSnapshot() {
        Context context = broadcastContext();
        if (context == null) return;
        ScanSessionUiSnapshot next = ScanSessionUiSnapshot.capture(this);
        ScanSessionUiSnapshot previous = lastPublishedSnapshot;
        if (previous != null && snapshotsEqual(previous, next)) return;
        lastPublishedSnapshot = next;
        context.sendBroadcast(new Intent(ScanSessionUiSnapshot.ACTION_SNAPSHOT)
                .setPackage(context.getPackageName())
                .putExtra(ScanSessionUiSnapshot.EXTRA_SNAPSHOT, next));
    }

    private static boolean snapshotsEqual(ScanSessionUiSnapshot a, ScanSessionUiSnapshot b) {
        return a.generation == b.generation
                && a.running == b.running
                && a.stopRequested == b.stopRequested
                && a.checkedChecks == b.checkedChecks
                && a.plannedChecks == b.plannedChecks
                && a.resultCount == b.resultCount
                && a.pendingCount == b.pendingCount
                && a.scanStartedAtEpochMs == b.scanStartedAtEpochMs
                && a.lifecycleState.equals(b.lifecycleState)
                && a.sessionId.equals(b.sessionId);
    }

    private Context broadcastContext() {
        Context context = applicationContext();
        if (context != null) return context;
        MainActivity host = uiHost.get();
        return host == null ? null : host.getApplicationContext();
    }

    void finishWorkflow(long generation, ExecutorService scanExecutor, String stopSource) {
        if (generation != scanGeneration.get()) return;
        SidecarHeartbeatGuard.get().stop();
        if (executor() == scanExecutor) bindExecutor(null);
        boolean stopRequested = isStopRequested();
        ScanTerminalReason terminalReason = ScanTerminalReason.fromStopRequested(stopRequested, stopSource);
        recordTerminalReason(terminalReason);
        if (!stopRequested) markScanFullyChecked();
        Context context = applicationContext();
        ScanForegroundService.finishSession(terminalReason.lifecycleState);
        ScanProcessContinuityStore.markTerminal(context);
        if (context != null) {
            int progress = totalTargets <= 0 ? 0
                    : (int) Math.min(100, Math.round((checkedChecks() * 100.0) / totalTargets));
            ScanForegroundService.update(context, terminalReason.lifecycleState,
                    stopRequested ? "Scan stopped" : "Scan completed", progress);
            ScanForegroundService.stop(context, stopRequested ? "Scan stopped" : "Scan completed");
        }
        notifyUiObservers();
        runOnUi(activity -> activity.onWorkflowFinishedUi(generation, stopRequested, terminalReason));
    }

    boolean offerResult(long generation, MainActivity.Result result, boolean suppressNoisyLogs) {
        if (generation != scanGeneration.get()) return false;
        result.rowId = resultSequence.incrementAndGet();
        checkedTargets.incrementAndGet();
        ScanResultEvent event = new ScanResultEvent(result, suppressNoisyLogs, generation);
        boolean queued = false;
        while (!queued && !stop.get() && generation == scanGeneration.get()) {
            try {
                queued = pendingResults.offer(event, 250, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
            if (!queued) {
                requestResultDrain();
            }
        }
        return queued;
    }

    void requestResultDrain() {
        if (!resultDrainQueued.compareAndSet(false, true)) return;
        drainExecutor.execute(this::drainPendingResultsInternal);
    }

    private void drainPendingResultsInternal() {
        try {
            resultDrainQueued.set(false);
            int drained = 0;
            java.util.ArrayList<ScanResultEvent> logEvents = new java.util.ArrayList<>();
            ScanResultEvent event;
            long generation = scanGeneration.get();
            while (drained < RESULT_DRAIN_BATCH && (event = pendingResults.poll()) != null) {
                if (event.generation != generation) {
                    drained++;
                    continue;
                }
                int resultCount = resultStore.append(event.result);
                if (!event.suppressNoisyLogs) {
                    MainActivity.Result r = event.result;
                    if (r.tlsPass || r.httpPass || resultCount % 200 == 0) {
                        logEvents.add(event);
                    }
                }
                drained++;
            }
            if (drained > 0) {
                notifyUiObservers();
                if (!logEvents.isEmpty()) {
                    runOnUi(activity -> activity.onResultsDrained(logEvents));
                } else {
                    runOnUi(MainActivity::scheduleProgressUpdate);
                }
            }
            if (!pendingResults.isEmpty()) {
                requestResultDrain();
            }
        } catch (Exception ignored) {
            resultDrainQueued.set(false);
        }
    }

    void attachUi(MainActivity activity) {
        uiHost = new WeakReference<>(activity);
        attachApplicationContext(activity);
        requestResultDrain();
    }

    void detachUi(MainActivity activity) {
        MainActivity current = uiHost.get();
        if (current == activity) {
            uiHost = new WeakReference<>(null);
        }
    }

    void runOnUi(Consumer<MainActivity> action) {
        MainActivity host = uiHost.get();
        if (host != null && !host.isFinishing()) {
            if (Looper.myLooper() == Looper.getMainLooper()) {
                action.accept(host);
            } else {
                MAIN.post(() -> {
                    MainActivity retry = uiHost.get();
                    if (retry != null && !retry.isFinishing()) action.accept(retry);
                });
            }
            return;
        }
        MAIN.post(() -> {
            MainActivity retry = uiHost.get();
            if (retry != null && !retry.isFinishing()) action.accept(retry);
        });
    }

    void shutdownExecutor() {
        ExecutorService active = executor;
        executor = null;
        if (active != null) {
            active.shutdownNow();
        }
    }

    private void reconcileProcessContinuity(Context context) {
        if (processContinuityChecked || context == null || isRunning()) return;
        processContinuityChecked = true;
        ScanProcessContinuityStore.AbandonedSession abandoned =
                ScanProcessContinuityStore.consumeAbandonedSession(context);
        if (abandoned == null) return;
        requestStop();
        recordTerminalReason(ScanTerminalReason.PROCESS_LOST);
        totalTargets = abandoned.plannedChecks;
        scanStartedAt = abandoned.startedAtEpochMs;
        ScanForegroundService.restoreProcessLostSession(abandoned);
        notifyUiObservers();
    }

    void onActivityDestroy(MainActivity activity, boolean isChangingConfigurations, boolean isFinishing) {
        detachUi(activity);
        // Foreground service owns active scans; rotation and activity finish must not stop workers.
    }

    void testBindExecutor(ExecutorService pool) {
        bindExecutor(pool);
    }

    void testSimulateConfigurationChange() {
        uiHost = new WeakReference<>(null);
    }

    void testSimulateActivityFinish() {
        uiHost = new WeakReference<>(null);
    }

    /** Test-only snapshot for asserting one active session per generation. */
    ScanSessionTestHooks.Snapshot testSnapshot() {
        ScanLaunchSpec staged = stagedLaunch;
        Thread orchestrator = orchestratorThread;
        return new ScanSessionTestHooks.Snapshot(
                scanGeneration.get(),
                stop.get(),
                isRunning(),
                orchestrator != null && orchestrator.isAlive(),
                staged != null,
                staged == null ? 0L : staged.generation);
    }
}
