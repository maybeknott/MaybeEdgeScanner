package com.maybeedgescanner;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import java.util.concurrent.atomic.AtomicReference;

public class ScanForegroundService extends Service {
    public static final String ACTION_START = "com.maybeedgescanner.service.START";
    public static final String ACTION_UPDATE = "com.maybeedgescanner.service.UPDATE";
    public static final String ACTION_STOP = "com.maybeedgescanner.service.STOP";
    public static final String ACTION_CANCEL_SCAN = "com.maybeedgescanner.service.CANCEL_SCAN";
    public static final String ACTION_STATE_CHANGED = "com.maybeedgescanner.service.STATE_CHANGED";
    public static final String EXTRA_STATE = "state";
    public static final String EXTRA_DETAIL = "detail";
    public static final String EXTRA_PROGRESS = "progress";

    private static final String CHANNEL_ID = "scan_lifecycle";
    private static final int NOTIFICATION_ID = 1201;
    private static final AtomicReference<ScanLifecycleSnapshot> SNAPSHOT =
            new AtomicReference<>(new ScanLifecycleSnapshot("idle", "No active scan", 0));

    private PowerManager.WakeLock wakeLock;

    public static ScanLifecycleSnapshot snapshot() {
        return SNAPSHOT.get();
    }

    public static void start(Context context, String state, String detail, int progress) {
        Intent intent = new Intent(context, ScanForegroundService.class)
                .setAction(ACTION_START)
                .putExtra(EXTRA_STATE, state)
                .putExtra(EXTRA_DETAIL, detail)
                .putExtra(EXTRA_PROGRESS, progress);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    public static void update(Context context, String state, String detail, int progress) {
        Intent intent = new Intent(context, ScanForegroundService.class)
                .setAction(ACTION_UPDATE)
                .putExtra(EXTRA_STATE, state)
                .putExtra(EXTRA_DETAIL, detail)
                .putExtra(EXTRA_PROGRESS, progress);
        context.startService(intent);
    }

    public static void stop(Context context, String detail) {
        Intent intent = new Intent(context, ScanForegroundService.class)
                .setAction(ACTION_STOP)
                .putExtra(EXTRA_STATE, "idle")
                .putExtra(EXTRA_DETAIL, detail)
                .putExtra(EXTRA_PROGRESS, 0);
        context.startService(intent);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_UPDATE : intent.getAction();
        if (ACTION_CANCEL_SCAN.equals(action)) {
            sendBroadcast(new Intent(MainActivity.ACTION_SERVICE_STOP_SCAN).setPackage(getPackageName()));
            applySnapshot("cancelling", "Stop requested from notification", snapshot().progress);
            startForeground(NOTIFICATION_ID, buildNotification(snapshot()));
            return START_STICKY;
        }
        if (ACTION_STOP.equals(action)) {
            applySnapshot("idle", extra(intent, EXTRA_DETAIL, "Scan inactive"), 0);
            releaseWakeLock();
            stopForeground(true);
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        String state = extra(intent, EXTRA_STATE, "running");
        String detail = extra(intent, EXTRA_DETAIL, "Scan running");
        int progress = intent == null ? snapshot().progress : intent.getIntExtra(EXTRA_PROGRESS, snapshot().progress);
        applySnapshot(state, detail, progress);
        createChannel();
        if ("running".equals(state) || "cancelling".equals(state) || "planning".equals(state)) {
            acquireWakeLock();
        } else {
            releaseWakeLock();
        }
        startForeground(NOTIFICATION_ID, buildNotification(snapshot()));
        return START_STICKY;
    }

    @Override public IBinder onBind(Intent intent) {
        return null;
    }

    @Override public void onDestroy() {
        releaseWakeLock();
        super.onDestroy();
    }

    private void applySnapshot(String state, String detail, int progress) {
        int boundedProgress = Math.max(0, Math.min(100, progress));
        ScanLifecycleSnapshot next = new ScanLifecycleSnapshot(state, detail, boundedProgress);
        SNAPSHOT.set(next);
        sendBroadcast(new Intent(ACTION_STATE_CHANGED)
                .setPackage(getPackageName())
                .putExtra(EXTRA_STATE, next.state)
                .putExtra(EXTRA_DETAIL, next.detail)
                .putExtra(EXTRA_PROGRESS, next.progress));
    }

    private Notification buildNotification(ScanLifecycleSnapshot state) {
        Intent openIntent = new Intent(this, MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent open = PendingIntent.getActivity(this, 0, openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Intent cancelIntent = new Intent(this, ScanForegroundService.class).setAction(ACTION_CANCEL_SCAN);
        PendingIntent cancel = PendingIntent.getService(this, 1, cancelIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        builder.setSmallIcon(R.drawable.maybepsiphon_logo)
                .setContentTitle("MaybeEdgeScanner scan")
                .setContentText(state.detail)
                .setSubText(state.state)
                .setContentIntent(open)
                .setOngoing(!"idle".equals(state.state) && !"completed".equals(state.state) && !"failed".equals(state.state))
                .setOnlyAlertOnce(true)
                .setShowWhen(false)
                .addAction(R.drawable.maybepsiphon_logo, "Stop", cancel);
        if (state.progress > 0 && state.progress < 100) {
            builder.setProgress(100, state.progress, false);
        }
        return builder.build();
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (manager == null || manager.getNotificationChannel(CHANNEL_ID) != null) return;
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "Active scans", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Shows active scan lifecycle state and stop control.");
        manager.createNotificationChannel(channel);
    }

    private void acquireWakeLock() {
        if (wakeLock != null && wakeLock.isHeld()) return;
        PowerManager powerManager = (PowerManager) getSystemService(POWER_SERVICE);
        if (powerManager == null) return;
        wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "MaybeEdgeScanner:scan");
        wakeLock.setReferenceCounted(false);
        wakeLock.acquire(30 * 60 * 1000L);
    }

    private void releaseWakeLock() {
        if (wakeLock != null && wakeLock.isHeld()) {
            wakeLock.release();
        }
        wakeLock = null;
    }

    private static String extra(Intent intent, String key, String fallback) {
        if (intent == null) return fallback;
        String value = intent.getStringExtra(key);
        return value == null || value.trim().isEmpty() ? fallback : value;
    }

    public static final class ScanLifecycleSnapshot {
        public final String state;
        public final String detail;
        public final int progress;

        ScanLifecycleSnapshot(String state, String detail, int progress) {
            this.state = state;
            this.detail = detail;
            this.progress = progress;
        }
    }
}
