package com.maybeedgescanner;

import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

final class ShizukuRadioActions {
    private static final int COMMAND_TIMEOUT_SECONDS = 9;
    private static final String WORKER_NAME = "maybeedge-route-shizuku-radio";
    private static final String BUSY_OUTPUT = "Another MaybeEdgeScanner route/radio diagnostics action is still running. Wait for route readback before starting a new one.";
    private static final String BUSY_TOAST = "MaybeEdge route radio action already running";
    private static final String TIMEOUT_TEXT = "The privileged command did not finish within 9 seconds. MaybeEdgeScanner did not queue route or radio follow-up work.";

    private ShizukuRadioActions() {}

    interface CommandExecutor {
        ShizukuProcessRunner.CommandResult run(String[] command, int timeoutSeconds) throws Exception;
    }

    interface Completion {
        void onComplete(String output, int exitCode, boolean verifiedWrite, boolean bridgeProbeSucceeded);
    }

    static boolean beginRun(
            AtomicBoolean runningFlag,
            Consumer<String> outputSetter,
            Consumer<String> toaster
    ) {
        if (!runningFlag.compareAndSet(false, true)) {
            outputSetter.accept(BUSY_OUTPUT);
            toaster.accept(BUSY_TOAST);
            return false;
        }
        return true;
    }

    static void executeAsync(
            String label,
            String command,
            boolean writeAction,
            String expectedValue,
            String[] radioModeKeys,
            CommandExecutor executor,
            Completion completion
    ) {
        Thread worker = new Thread(() -> {
            String output;
            int exitCode = -1;
            try {
                String[] shell = new String[]{"/system/bin/sh", "-c", command};
                ShizukuProcessRunner.CommandResult result = executor.run(shell, COMMAND_TIMEOUT_SECONDS);
                exitCode = result.exitCode;
                if (result.exitCode == -2) {
                    output = "Action: " + label + "\nExit: timeout\n\n" + TIMEOUT_TEXT;
                } else {
                    String stdoutText = result.stdout.trim();
                    String stderrText = result.stderr.trim();
                    output = "Action: " + label + "\nExit: " + exitCode + "\n\n" + stdoutText;
                    if (!stderrText.isEmpty()) output += "\n\nstderr:\n" + stderrText;
                }
            } catch (Throwable e) {
                output = "Action: " + label + "\nFailed: " + e.getClass().getSimpleName() + ": " + ShizukuProcessRunner.safeMessage(e);
            }
            boolean verifiedWrite = !writeAction || verifyWrite(output, expectedValue, radioModeKeys);
            boolean bridgeProbeSucceeded = exitCode == 0 && label.toLowerCase(Locale.US).contains("bridge capability");
            completion.onComplete(output, exitCode, verifiedWrite, bridgeProbeSucceeded);
        }, WORKER_NAME);
        worker.start();
    }

    private static boolean verifyWrite(String output, String expectedValue, String[] radioModeKeys) {
        if (expectedValue == null || expectedValue.trim().isEmpty() || output == null) return false;
        String expected = expectedValue.trim();
        for (String line : output.split("\\R")) {
            String trimmed = line.trim();
            for (String key : radioModeKeys) {
                if (trimmed.equals(key + "=" + expected)) return true;
            }
        }
        return false;
    }
}
