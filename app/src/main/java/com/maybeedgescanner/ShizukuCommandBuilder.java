package com.maybeedgescanner;

final class ShizukuCommandBuilder {
    private ShizukuCommandBuilder() {}

    static String buildReadModesCommand(String[] radioModeKeys) {
        StringBuilder cmd = new StringBuilder("echo radio-preferred-network-modes; ");
        for (String key : radioModeKeys) {
            cmd.append("echo ").append(key).append("=$(settings get global ").append(key).append(" 2>/dev/null); ");
        }
        return cmd.toString();
    }

    static String buildBridgeProbeCommand(String[] radioModeKeys) {
        return "echo shizuku-bridge-probe maybeedgescanner; "
                + "id; "
                + "echo uid=$(id -u 2>/dev/null); "
                + "echo sdk=$(getprop ro.build.version.sdk 2>/dev/null); "
                + "echo release=$(getprop ro.build.version.release 2>/dev/null); "
                + "echo device=$(getprop ro.product.manufacturer 2>/dev/null) $(getprop ro.product.model 2>/dev/null); "
                + "echo airplane=$(settings get global airplane_mode_on 2>/dev/null); "
                + "cmd connectivity help >/dev/null 2>&1 && echo connectivity-cmd=available || echo connectivity-cmd=limited; "
                + buildReadModesCommand(radioModeKeys);
    }
}
