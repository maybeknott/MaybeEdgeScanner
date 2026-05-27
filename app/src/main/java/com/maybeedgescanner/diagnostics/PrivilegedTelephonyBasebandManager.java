package com.maybeedgescanner.diagnostics;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.telephony.SubscriptionManager;
import android.util.Log;

import com.android.internal.telephony.ITelephony;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import rikka.shizuku.Shizuku;

public class PrivilegedTelephonyBasebandManager {
    private static final String TAG = "PrivilegedTelephony";
    private static final String BINDER_SERVICE_KEY = "phone";
    private static final long RADIO_SETTLE_MS = 1500L;

    private final ExecutorService backgroundWorkerPool = Executors.newSingleThreadExecutor();
    private final Handler mainUiHandler = new Handler(Looper.getMainLooper());
    private final AtomicBoolean operationLockGate = new AtomicBoolean(false);
    private final AtomicLong operationSequence = new AtomicLong(0);

    private final Shizuku.OnBinderReceivedListener binderReceivedObserver = this::synchronizePlatformBinderBridge;
    private final Shizuku.OnBinderDeadListener binderTerminationObserver = this::handleBinderDisconnection;

    private Context appContext;
    private ITelephony privilegedTelephonyStub;
    private TelephonyLifecycleCallback statusObserver;
    private volatile PrivilegedCapabilityReport lastReport = PrivilegedCapabilityReport.unavailable("not initialized");

    public interface TelephonyLifecycleCallback {
        void onServiceConnectionStateChanged(boolean isConnectedActive);
        void onOperationComplete(boolean executionStateSuccess, String validationResponseText);
        default void onCapabilityReportUpdated(PrivilegedCapabilityReport report) {}
    }

    public void initializePrivilegeContext(Context context, TelephonyLifecycleCallback observer) {
        this.appContext = context == null ? null : context.getApplicationContext();
        this.statusObserver = observer;
        try {
            Shizuku.addBinderReceivedListener(binderReceivedObserver);
            Shizuku.addBinderDeadListener(binderTerminationObserver);
            synchronizePlatformBinderBridge();
        } catch (Throwable error) {
            Log.e(TAG, "Failed to register Shizuku proxy observers", error);
            publishReport(PrivilegedCapabilityReport.unavailable("listener registration failed: " + safeMessage(error)));
        }
    }

    public void terminatePrivilegeContext() {
        try {
            Shizuku.removeBinderReceivedListener(binderReceivedObserver);
            Shizuku.removeBinderDeadListener(binderTerminationObserver);
        } catch (Throwable ignored) {}
        try {
            backgroundWorkerPool.shutdownNow();
        } catch (Throwable ignored) {}
        this.statusObserver = null;
        this.privilegedTelephonyStub = null;
        this.appContext = null;
        publishReport(PrivilegedCapabilityReport.unavailable("terminated"));
    }

    public PrivilegedCapabilityReport capabilityReport() {
        return lastReport;
    }

    private void handleBinderDisconnection() {
        this.privilegedTelephonyStub = null;
        operationLockGate.set(false);
        publishReport(PrivilegedCapabilityReport.unavailable("binder disconnected"));
        notifyConnectionChange(false);
    }

    private synchronized void synchronizePlatformBinderBridge() {
        PrivilegedCapabilityReport.Builder report = collectBaseReport();
        if (!report.shizukuAvailable) {
            this.privilegedTelephonyStub = null;
            publishReport(report.add("Shizuku binder is not alive").build());
            notifyConnectionChange(false);
            return;
        }
        if (!report.shizukuPermissionGranted) {
            this.privilegedTelephonyStub = null;
            publishReport(report.add("Shizuku permission is not granted").build());
            notifyConnectionChange(false);
            return;
        }
        try {
            Class<?> serviceManagerClass = Class.forName("android.os.ServiceManager");
            Method getServiceMethod = serviceManagerClass.getMethod("getService", String.class);
            IBinder rawSystemBinderHandle = (IBinder) getServiceMethod.invoke(null, BINDER_SERVICE_KEY);
            if (rawSystemBinderHandle == null) {
                this.privilegedTelephonyStub = null;
                publishReport(report.add("phone binder service returned null").build());
                notifyConnectionChange(false);
                return;
            }
            Class<?> stubClass = Class.forName("com.android.internal.telephony.ITelephony$Stub");
            Method asInterfaceMethod = stubClass.getMethod("asInterface", IBinder.class);
            this.privilegedTelephonyStub = (ITelephony) asInterfaceMethod.invoke(null, rawSystemBinderHandle);
            report.binderAlive = true;
            report.hiddenTelephonyAccessAvailable = privilegedTelephonyStub != null;
            report.radioMutationSupported = privilegedTelephonyStub != null;
            if (privilegedTelephonyStub != null) {
                report.add("hidden ITelephony binder resolved");
            }
            publishReport(report.build());
            notifyConnectionChange(privilegedTelephonyStub != null);
        } catch (Throwable error) {
            Log.e(TAG, "Failed to map system telephony proxy stubs.", error);
            this.privilegedTelephonyStub = null;
            publishReport(report.add("hidden telephony binding failed: " + safeMessage(error)).build());
            notifyConnectionChange(false);
        }
    }

    public void invokeBasebandRadioMutation(final int requestedSubId, final int networkModeType) {
        PrivilegedCapabilityReport report = capabilityReport();
        if (!report.radioMutationSupported || privilegedTelephonyStub == null) {
            complete(false, "Radio mutation unavailable.\n\n" + report.toDisplayText());
            return;
        }

        if (!operationLockGate.compareAndSet(false, true)) {
            complete(false, "Baseband update is already in progress.");
            return;
        }

        final long operationId = operationSequence.incrementAndGet();
        backgroundWorkerPool.execute(() -> {
            boolean success = false;
            String message;
            int confirmedState = Integer.MIN_VALUE;
            int settledState = Integer.MIN_VALUE;
            try {
                boolean applied = privilegedTelephonyStub.setPreferredNetworkType(requestedSubId, networkModeType);
                if (!applied) {
                    message = "operation_id=" + operationId + "\nclassification=carrier_or_framework_rejected\nsetPreferredNetworkType returned false";
                } else {
                    confirmedState = privilegedTelephonyStub.getPreferredNetworkType(requestedSubId);
                    try {
                        Thread.sleep(RADIO_SETTLE_MS);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                    settledState = privilegedTelephonyStub.getPreferredNetworkType(requestedSubId);
                    success = confirmedState == networkModeType && settledState == networkModeType;
                    message = "operation_id=" + operationId +
                            "\nclassification=" + (success ? "verified" : "readback_mismatch_or_settling_timeout") +
                            "\nsub_id=" + requestedSubId +
                            "\nrequested_mode=" + networkModeType +
                            "\nreadback_initial=" + printableState(confirmedState) +
                            "\nreadback_after_settle=" + printableState(settledState) +
                            "\nsettle_ms=" + RADIO_SETTLE_MS;
                }
            } catch (SecurityException error) {
                message = "operation_id=" + operationId + "\nclassification=permission_denied\n" + safeMessage(error);
                success = false;
            } catch (Throwable error) {
                message = "operation_id=" + operationId + "\nclassification=ipc_fault\n" +
                        error.getClass().getSimpleName() + ": " + safeMessage(error);
                success = false;
            } finally {
                operationLockGate.set(false);
            }

            complete(success, "Binder Mutation:\n" + message + "\n\nCapability Report:\n" + capabilityReport().toDisplayText());
        });
    }

    private PrivilegedCapabilityReport.Builder collectBaseReport() {
        PrivilegedCapabilityReport.Builder report = new PrivilegedCapabilityReport.Builder();
        report.publicSubscriptionDataAvailable = hasPublicSubscriptionSignal();
        try {
            report.shizukuAvailable = Shizuku.pingBinder();
        } catch (Throwable error) {
            return report.add("Shizuku ping failed: " + safeMessage(error));
        }
        try {
            report.shizukuPreV11 = Shizuku.isPreV11();
        } catch (Throwable error) {
            report.add("Shizuku version probe failed: " + safeMessage(error));
        }
        try {
            report.shizukuApiVersion = Shizuku.getVersion();
        } catch (Throwable error) {
            report.add("Shizuku API version unavailable: " + safeMessage(error));
        }
        try {
            report.shellUid = Shizuku.getUid();
            report.mode = report.shellUid == 0 ? "root" : (report.shellUid == 2000 ? "adb" : "unknown");
        } catch (Throwable error) {
            report.add("Shizuku UID unavailable: " + safeMessage(error));
        }
        try {
            report.shizukuPermissionGranted = report.shizukuAvailable && !report.shizukuPreV11 &&
                    Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable error) {
            report.add("permission check failed: " + safeMessage(error));
        }
        report.newProcessAvailable = hasShizukuNewProcess();
        report.userServiceAvailable = hasShizukuUserServiceApi();
        report.binderAlive = report.shizukuAvailable;
        return report;
    }

    private boolean hasPublicSubscriptionSignal() {
        Context context = appContext;
        if (context == null) return false;
        try {
            Object service = context.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE);
            if (!(service instanceof SubscriptionManager)) return false;
            int defaultSubId = SubscriptionManager.getDefaultDataSubscriptionId();
            if (defaultSubId != SubscriptionManager.INVALID_SUBSCRIPTION_ID) return true;
            return context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private boolean hasShizukuNewProcess() {
        try {
            Shizuku.class.getDeclaredMethod("newProcess", String[].class, String[].class, String.class);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private boolean hasShizukuUserServiceApi() {
        for (Method method : Shizuku.class.getDeclaredMethods()) {
            if (method.getName().toLowerCase(Locale.US).contains("userservice")) {
                return true;
            }
        }
        return false;
    }

    private void publishReport(PrivilegedCapabilityReport report) {
        this.lastReport = report;
        mainUiHandler.post(() -> {
            if (statusObserver != null) statusObserver.onCapabilityReportUpdated(report);
        });
    }

    private void notifyConnectionChange(final boolean active) {
        mainUiHandler.post(() -> {
            if (statusObserver != null) statusObserver.onServiceConnectionStateChanged(active);
        });
    }

    private void complete(final boolean success, final String message) {
        mainUiHandler.post(() -> {
            if (statusObserver != null) statusObserver.onOperationComplete(success, message);
        });
    }

    private static String printableState(int state) {
        return state == Integer.MIN_VALUE ? "n/a" : String.valueOf(state);
    }

    private static String safeMessage(Throwable error) {
        String message = error == null ? "" : error.getMessage();
        return message == null || message.trim().isEmpty() ? "no detail" : message.replace('\n', ' ').replace('\r', ' ');
    }

    public static final class PrivilegedCapabilityReport {
        public final boolean shizukuAvailable;
        public final boolean shizukuPermissionGranted;
        public final int shizukuApiVersion;
        public final String mode;
        public final boolean binderAlive;
        public final boolean userServiceAvailable;
        public final boolean newProcessAvailable;
        public final boolean publicSubscriptionDataAvailable;
        public final boolean hiddenTelephonyAccessAvailable;
        public final boolean radioMutationSupported;
        public final int shellUid;
        public final List<String> observedCapabilities;

        private PrivilegedCapabilityReport(Builder builder) {
            shizukuAvailable = builder.shizukuAvailable;
            shizukuPermissionGranted = builder.shizukuPermissionGranted;
            shizukuApiVersion = builder.shizukuApiVersion;
            mode = builder.mode;
            binderAlive = builder.binderAlive;
            userServiceAvailable = builder.userServiceAvailable;
            newProcessAvailable = builder.newProcessAvailable;
            publicSubscriptionDataAvailable = builder.publicSubscriptionDataAvailable;
            hiddenTelephonyAccessAvailable = builder.hiddenTelephonyAccessAvailable;
            radioMutationSupported = builder.radioMutationSupported;
            shellUid = builder.shellUid;
            observedCapabilities = new ArrayList<>(builder.observedCapabilities);
        }

        static PrivilegedCapabilityReport unavailable(String reason) {
            return new Builder().add(reason).build();
        }

        public String toDisplayText() {
            StringBuilder sb = new StringBuilder();
            sb.append("shizuku_available=").append(shizukuAvailable)
                    .append("\nshizuku_permission_granted=").append(shizukuPermissionGranted)
                    .append("\nshizuku_api_version=").append(shizukuApiVersion <= 0 ? "unknown" : shizukuApiVersion)
                    .append("\nmode=").append(mode)
                    .append("\nbinder_alive=").append(binderAlive)
                    .append("\nuser_service_available=").append(userServiceAvailable)
                    .append("\nnew_process_available=").append(newProcessAvailable)
                    .append("\npublic_subscription_data_available=").append(publicSubscriptionDataAvailable)
                    .append("\nhidden_telephony_access_available=").append(hiddenTelephonyAccessAvailable)
                    .append("\nradio_mutation_supported=").append(radioMutationSupported)
                    .append("\nshell_uid=").append(shellUid < 0 ? "unknown" : shellUid);
            if (!observedCapabilities.isEmpty()) {
                sb.append("\nobserved_capabilities:");
                for (String capability : observedCapabilities) {
                    sb.append("\n- ").append(capability);
                }
            }
            return sb.toString();
        }

        private static final class Builder {
            boolean shizukuAvailable;
            boolean shizukuPermissionGranted;
            boolean shizukuPreV11;
            int shizukuApiVersion = -1;
            String mode = "unknown";
            boolean binderAlive;
            boolean userServiceAvailable;
            boolean newProcessAvailable;
            boolean publicSubscriptionDataAvailable;
            boolean hiddenTelephonyAccessAvailable;
            boolean radioMutationSupported;
            int shellUid = -1;
            final List<String> observedCapabilities = new ArrayList<>();

            Builder add(String capability) {
                if (capability != null && !capability.trim().isEmpty()) observedCapabilities.add(capability);
                return this;
            }

            PrivilegedCapabilityReport build() {
                return new PrivilegedCapabilityReport(this);
            }
        }
    }
}
