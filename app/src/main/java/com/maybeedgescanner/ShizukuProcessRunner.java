package com.maybeedgescanner;

import android.os.Build;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import rikka.shizuku.Shizuku;

final class ShizukuProcessRunner {
    private ShizukuProcessRunner() {}

    static final class CommandResult {
        final int exitCode;
        final String stdout;
        final String stderr;

        CommandResult(int exitCode, String stdout, String stderr) {
            this.exitCode = exitCode;
            this.stdout = stdout == null ? "" : stdout;
            this.stderr = stderr == null ? "" : stderr;
        }
    }

    static Process startProcess(String[] command) throws Exception {
        try {
            java.lang.reflect.Method method = Shizuku.class.getDeclaredMethod("newProcess", String[].class, String[].class, String.class);
            method.setAccessible(true);
            return (Process) method.invoke(null, (Object) command, null, null);
        } catch (Exception e) {
            throw new RuntimeException("Shizuku process invocation failed via reflection", e);
        }
    }

    static CommandResult runCapture(String[] command, int timeoutSeconds) throws Exception {
        Process process = null;
        Thread stdoutThread = null;
        Thread stderrThread = null;
        StringBuilder stdout = new StringBuilder();
        StringBuilder stderr = new StringBuilder();
        try {
            process = startProcess(command);
            stdoutThread = collectProcessStream(process.getInputStream(), stdout);
            stderrThread = collectProcessStream(process.getErrorStream(), stderr);
            boolean finished = waitForProcess(process, timeoutSeconds);
            if (!finished) {
                terminateProcess(process);
                joinQuietly(stdoutThread);
                joinQuietly(stderrThread);
                return new CommandResult(-2, bufferedText(stdout), bufferedText(stderr));
            }
            int exitCode = process.exitValue();
            joinQuietly(stdoutThread);
            joinQuietly(stderrThread);
            return new CommandResult(exitCode, bufferedText(stdout), bufferedText(stderr));
        } finally {
            if (process != null) {
                try { process.getInputStream().close(); } catch (Throwable ignored) {}
                try { process.getErrorStream().close(); } catch (Throwable ignored) {}
                try { process.getOutputStream().close(); } catch (Throwable ignored) {}
                process.destroy();
            }
        }
    }

    static Thread collectProcessStream(InputStream in, StringBuilder out) {
        Thread thread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                int lines = 0;
                while (lines < 500 && (line = reader.readLine()) != null) {
                    synchronized (out) {
                        out.append(line).append('\n');
                    }
                    lines++;
                }
                if (lines >= 500) {
                    synchronized (out) {
                        out.append("[stream] truncated after 500 lines\n");
                    }
                }
            } catch (IOException e) {
                synchronized (out) {
                    out.append("[stream] ").append(e.getClass().getSimpleName()).append(": ").append(safeMessage(e)).append('\n');
                }
            }
        }, "shizuku-stream");
        thread.start();
        return thread;
    }

    static void joinQuietly(Thread thread) {
        if (thread == null) return;
        try {
            thread.join(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    static boolean waitForProcess(Process process, int timeoutSeconds) throws InterruptedException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        }
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(timeoutSeconds);
        while (System.currentTimeMillis() < deadline) {
            try {
                process.exitValue();
                return true;
            } catch (IllegalThreadStateException ignored) {
                Thread.sleep(50);
            }
        }
        return false;
    }

    static void terminateProcess(Process process) {
        if (process == null) return;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            process.destroyForcibly();
        } else {
            process.destroy();
        }
    }

    static String bufferedText(StringBuilder sb) {
        synchronized (sb) {
            return sb.toString();
        }
    }

    static String safeMessage(Throwable e) {
        return e.getMessage() == null ? "no message" : e.getMessage();
    }
}
