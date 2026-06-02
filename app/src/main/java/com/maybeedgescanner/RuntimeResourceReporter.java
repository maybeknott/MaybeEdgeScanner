package com.maybeedgescanner;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;

final class RuntimeResourceReporter {
    private RuntimeResourceReporter() {}

    static String resourceLine(Context context) {
        Intent battery = context.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        int level = battery == null ? -1 : battery.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
        int scale = battery == null ? -1 : battery.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
        int status = battery == null ? -1 : battery.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
        int plugged = battery == null ? 0 : battery.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0);
        int pct = level >= 0 && scale > 0 ? Math.round(level * 100f / scale) : -1;
        boolean charging = status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL;
        String plug = plugged == BatteryManager.BATTERY_PLUGGED_USB ? "usb" :
                plugged == BatteryManager.BATTERY_PLUGGED_AC ? "ac" :
                plugged == BatteryManager.BATTERY_PLUGGED_WIRELESS ? "wireless" : "unplugged";
        Runtime rt = Runtime.getRuntime();
        long usedMb = (rt.totalMemory() - rt.freeMemory()) / (1024 * 1024);
        long maxMb = rt.maxMemory() / (1024 * 1024);
        return "route-power " + (pct >= 0 ? pct + "%" : "n/a") + " " +
                (charging ? "charging" : "battery") + "/" + plug +
                " | heap " + usedMb + "/" + maxMb + "MB" +
                " | cores " + rt.availableProcessors();
    }
}
