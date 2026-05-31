package com.maybeedgescanner;

import android.content.Context;
import android.content.res.AssetManager;
import android.os.Build;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Locale;

/** Service-owned sidecar binary extract + supervised process launch. */
final class SidecarLauncher {
    private static final String BINARY_NAME = "maybeedgescanner-sidecar";
    private static final int HEARTBEAT_WAIT_MS = 250;
    private static final int HEARTBEAT_ATTEMPTS = 12;

    private SidecarLauncher() {}

    static LaunchResult ensureRunning(Context context) {
        Context app = context.getApplicationContext();
        String token = SidecarTokenStore.getOrCreate(app);
        SidecarController.get().setAuthToken(token);

        SidecarController.SidecarSnapshot heartbeat = SidecarController.get().refreshHeartbeat(1200);
        if (heartbeat.reachable) {
            return LaunchResult.running(heartbeat, "already_running");
        }

        File binary = resolveBinary(app);
        if (binary == null) {
            return LaunchResult.unavailable("sidecar_binary_missing", heartbeat);
        }

        try {
            ProcessBuilder builder = new ProcessBuilder(binary.getAbsolutePath());
            builder.environment().put(SidecarTokenStore.ENV_NAME, token);
            builder.environment().put("MAYBESCANNER_SIDECAR_TOKEN", token);
            builder.redirectErrorStream(true);
            Process process = builder.start();
            drainLaunchOutput(process);
            for (int attempt = 0; attempt < HEARTBEAT_ATTEMPTS; attempt++) {
                Thread.sleep(HEARTBEAT_WAIT_MS);
                heartbeat = SidecarController.get().refreshHeartbeat(1200);
                if (heartbeat.reachable) {
                    return LaunchResult.running(heartbeat, "launched pid=" + processPid(process));
                }
            }
            return LaunchResult.unavailable("sidecar_launch_timeout", heartbeat);
        } catch (Exception e) {
            return LaunchResult.unavailable("sidecar_launch_failed: " + e.getMessage(), heartbeat);
        }
    }

    private static File resolveBinary(Context context) {
        File installed = new File(context.getFilesDir(), "sidecar/" + BINARY_NAME);
        if (installed.canExecute()) {
            return installed;
        }
        File extracted = extractBundledBinary(context, installed);
        return extracted != null && extracted.canExecute() ? extracted : null;
    }

    private static File extractBundledBinary(Context context, File target) {
        AssetManager assets = context.getAssets();
        String assetPath = assetPathForAbi();
        try (InputStream in = assets.open(assetPath)) {
            File parent = target.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                return null;
            }
            try (OutputStream out = new FileOutputStream(target)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) >= 0) {
                    out.write(buffer, 0, read);
                }
            }
            if (!target.setExecutable(true, false)) {
                return null;
            }
            return target;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String assetPathForAbi() {
        String abi = Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "arm64-v8a";
        return "sidecar/" + abi + "/" + BINARY_NAME;
    }

    private static void drainLaunchOutput(Process process) {
        Thread drain = new Thread(() -> {
            try (InputStream stream = process.getInputStream()) {
                byte[] buffer = new byte[512];
                while (stream.read(buffer) >= 0) {
                    // discard sidecar stdout during launch probe
                }
            } catch (Exception ignored) {
            }
        }, "sidecar-launch-drain");
        drain.setDaemon(true);
        drain.start();
    }

    private static String processPid(Process process) {
        try {
            return String.valueOf(process.getClass().getMethod("pid").invoke(process));
        } catch (Exception ignored) {
            return "unknown";
        }
    }

    static final class LaunchResult {
        final boolean reachable;
        final String detail;
        final SidecarController.SidecarSnapshot snapshot;

        private LaunchResult(boolean reachable, String detail, SidecarController.SidecarSnapshot snapshot) {
            this.reachable = reachable;
            this.detail = detail == null ? "" : detail;
            this.snapshot = snapshot == null
                    ? SidecarController.SidecarSnapshot.unavailable("unknown")
                    : snapshot;
        }

        static LaunchResult running(SidecarController.SidecarSnapshot snapshot, String detail) {
            return new LaunchResult(true, detail, snapshot);
        }

        static LaunchResult unavailable(String detail, SidecarController.SidecarSnapshot snapshot) {
            return new LaunchResult(false, detail, snapshot);
        }

        @Override public String toString() {
            return String.format(Locale.US, "LaunchResult{reachable=%s, detail=%s}", reachable, detail);
        }
    }
}
