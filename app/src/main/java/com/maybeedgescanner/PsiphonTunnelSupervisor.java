package com.maybeedgescanner;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

final class PsiphonTunnelSupervisor {
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Process process;

    synchronized Readiness start(File tunnelCoreBinary, File configFile) {
        Readiness readiness = new Readiness();
        readiness.routeId = "route-psiphon-android";
        readiness.mode = "tunnel_core_supervised";
        if (tunnelCoreBinary == null || configFile == null || !tunnelCoreBinary.canExecute() || !configFile.canRead()) {
            readiness.state = "needs_binary_and_config_ref";
            readiness.errorCode = "INPUT_INVALID";
            return readiness;
        }
        if (!running.compareAndSet(false, true)) {
            readiness.state = "already_running";
            return readiness;
        }
        try {
            ProcessBuilder builder = new ProcessBuilder(
                    tunnelCoreBinary.getAbsolutePath(),
                    "--config", configFile.getAbsolutePath());
            builder.redirectErrorStream(true);
            process = builder.start();
            readiness.state = "starting";
            new Thread(() -> readNotices(process), "psiphon-notice-reader").start();
        } catch (Exception e) {
            running.set(false);
            readiness.state = "failed";
            readiness.errorCode = e.getClass().getSimpleName();
        }
        return readiness;
    }

    synchronized void stop() {
        running.set(false);
        if (process != null) {
            process.destroy();
            process = null;
        }
    }

    private void readNotices(Process p) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while (running.get() && (line = reader.readLine()) != null) {
                parseNotice(line);
            }
        } catch (Exception ignored) {
        } finally {
            running.set(false);
        }
    }

    static Readiness preview(EdgeRouteProfile profile) {
        Readiness readiness = new Readiness();
        readiness.routeId = profile.routeId;
        readiness.mode = profile.protocolMode;
        readiness.routeStrategy = profile.routeStrategy;
        readiness.conduitMode = profile.conduitMode;
        readiness.frontingPolicy = profile.frontingSni.isEmpty() && profile.frontingIpRef.isEmpty() ? "" : "custom_cdn_fronting";
        readiness.providerChain = profile.providerChain;
        readiness.shareProxyOnLan = profile.shareProxyOnLan || "lan_shared".equals(profile.gatewayMode);
        readiness.beastMode = profile.beastMode;
        readiness.configRefPresent = profile.configRef.startsWith("ref:");
        readiness.packageName = profile.packageName;
        if ("external_vpn_apk".equals(profile.protocolMode) || "external_vpn".equals(profile.protocolMode)) {
            readiness.state = profile.profileRef.startsWith("ref:") || !profile.packageName.isEmpty()
                    ? "external_vpn_observation" : "needs_profile_or_package";
        } else {
            readiness.state = readiness.configRefPresent ? "needs_tunnel_core_process" : "needs_config_ref";
        }
        return readiness;
    }

    static Readiness parseNotice(String notice) {
        Readiness readiness = new Readiness();
        readiness.state = "starting";
        if (notice == null) return readiness;
        String lower = notice.toLowerCase(Locale.US);
        readiness.lastNotice = notice.length() > 180 ? notice.substring(0, 180) : notice;
        readiness.socksPort = extractPort(lower, "listeningsocksproxyport");
        readiness.httpProxyPort = extractPort(lower, "listeninghttpproxyport");
        if (readiness.socksPort > 0 || readiness.httpProxyPort > 0) readiness.state = "proxy_listening";
        if (lower.contains("failed") || lower.contains("error")) {
            readiness.state = "failed";
            readiness.errorCode = "PSIPHON_NOTICE_ERROR";
        }
        return readiness;
    }

    private static int extractPort(String notice, String key) {
        int idx = notice.indexOf(key.toLowerCase(Locale.US));
        if (idx < 0) return 0;
        String tail = notice.substring(idx + key.length()).replaceAll("[^0-9]", " ").trim();
        if (tail.isEmpty()) return 0;
        try {
            return Integer.parseInt(tail.split("\\s+")[0]);
        } catch (Exception ignored) {
            return 0;
        }
    }

    static final class Readiness implements Serializable {
        private static final long serialVersionUID = 1L;
        String routeId = "";
        String mode = "";
        String routeStrategy = "";
        String conduitMode = "";
        String frontingPolicy = "";
        String providerChain = "";
        String state = "not_checked";
        String packageName = "";
        String lastNotice = "";
        String errorCode = "";
        int socksPort;
        int httpProxyPort;
        boolean configRefPresent;
        boolean shareProxyOnLan;
        boolean beastMode;

        String summary() {
            return "Route readiness: Psiphon\n" +
                    "state=" + state + " mode=" + mode + "\n" +
                    "strategy=" + routeStrategy + " conduit=" + conduitMode +
                    " fronting=" + (frontingPolicy == null || frontingPolicy.isEmpty() ? "--" : frontingPolicy) +
                    " beast=" + beastMode + "\n" +
                    "chain=" + providerChain + " lanShare=" + shareProxyOnLan + "\n" +
                    "configRefPresent=" + configRefPresent + " package=" + (packageName == null || packageName.isEmpty() ? "--" : packageName) + "\n" +
                    "socksPort=" + (socksPort > 0 ? socksPort : 0) + " httpProxyPort=" + (httpProxyPort > 0 ? httpProxyPort : 0) +
                    (lastNotice == null || lastNotice.isEmpty() ? "" : "\nlastNotice=" + lastNotice) +
                    (errorCode == null || errorCode.isEmpty() ? "" : "\nerror=" + errorCode);
        }
    }
}
