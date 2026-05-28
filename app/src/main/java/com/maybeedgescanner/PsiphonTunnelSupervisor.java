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
            return "Psiphon route status\n" +
                    "Status: " + displayState(state) + "\n" +
                    "Mode: " + display(mode) + " | strategy " + display(routeStrategy) + " | conduit " + display(conduitMode) + "\n" +
                    "Config: " + (configRefPresent ? "config reference present" : "needs config reference") +
                    " | external package " + display(packageName) + "\n" +
                    "Fronting: " + display(frontingPolicy) + " | chain " + display(providerChain) +
                    " | LAN share " + yesNo(shareProxyOnLan) + " | aggressive mode " + yesNo(beastMode) + "\n" +
                    "Local proxy: SOCKS " + (socksPort > 0 ? socksPort : "--") +
                    " | HTTP " + (httpProxyPort > 0 ? httpProxyPort : "--") +
                    (lastNotice == null || lastNotice.isEmpty() ? "" : "\nLast notice: " + lastNotice) +
                    (errorCode == null || errorCode.isEmpty() ? "" : "\nIssue: " + errorCode);
        }

        private static String displayState(String state) {
            if ("external_vpn_observation".equals(state)) return "ready to observe the external Psiphon route";
            if ("needs_profile_or_package".equals(state)) return "enter a profile ref or package name for the external Psiphon app";
            if ("needs_tunnel_core_process".equals(state)) return "config reference present; tunnel-core process is not started here";
            if ("needs_config_ref".equals(state)) return "enter a Psiphon config reference first";
            if ("proxy_listening".equals(state)) return "local proxy is listening";
            if ("starting".equals(state)) return "starting";
            if ("failed".equals(state)) return "failed";
            if ("already_running".equals(state)) return "already running";
            return display(state);
        }

        private static String yesNo(boolean value) {
            return value ? "yes" : "no";
        }

        private static String display(String value) {
            return value == null || value.trim().isEmpty() ? "--" : value.trim();
        }
    }
}
