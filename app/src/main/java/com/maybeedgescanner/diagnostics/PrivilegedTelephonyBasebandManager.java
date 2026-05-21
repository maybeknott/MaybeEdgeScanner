package com.maybeedgescanner.diagnostics;

import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;
import com.android.internal.telephony.ITelephony;
import java.lang.reflect.Method;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import rikka.shizuku.Shizuku;

public class PrivilegedTelephonyBasebandManager {
    private static final String TAG = "PrivilegedTelephony";
    private static final String BINDER_SERVICE_KEY = "phone";
    
    private final ExecutorService backgroundWorkerPool = Executors.newSingleThreadExecutor();
    private final Handler mainUiHandler = new Handler(Looper.getMainLooper());
    private final AtomicBoolean operationLockGate = new AtomicBoolean(false);

    private final Shizuku.OnBinderReceivedListener binderReceivedObserver = this::synchronizePlatformBinderBridge;
    private final Shizuku.OnBinderDeadListener binderTerminationObserver = this::handleBinderDisconnection;

    private ITelephony privilegedTelephonyStub;
    private TelephonyLifecycleCallback statusObserver;

    public interface TelephonyLifecycleCallback {
        void onServiceConnectionStateChanged(boolean isConnectedActive);
        void onOperationComplete(boolean executionStateSuccess, String validationResponseText);
    }

    public void initializePrivilegeContext(TelephonyLifecycleCallback observer) {
        this.statusObserver = observer;
        try {
            Shizuku.addBinderReceivedListener(binderReceivedObserver);
            Shizuku.addBinderDeadListener(binderTerminationObserver);
            synchronizePlatformBinderBridge();
        } catch (Throwable error) {
            Log.e(TAG, "Failed to register Shizuku proxy observers", error);
        }
    }

    public void terminatePrivilegeContext() {
        try {
            Shizuku.removeBinderReceivedListener(binderReceivedObserver);
            Shizuku.removeBinderDeadListener(binderTerminationObserver);
        } catch (Throwable ignored) {}
        try {
            backgroundWorkerPool.shutdown();
        } catch (Throwable ignored) {}
        this.statusObserver = null;
        this.privilegedTelephonyStub = null;
    }

    private void handleBinderDisconnection() {
        this.privilegedTelephonyStub = null;
        operationLockGate.set(false);
        notifyConnectionChange(false);
    }

    private synchronized void synchronizePlatformBinderBridge() {
        if (!Shizuku.pingBinder()) {
            notifyConnectionChange(false);
            return;
        }
        try {
            Class<?> serviceManagerClass = Class.forName("android.os.ServiceManager");
            Method getServiceMethod = serviceManagerClass.getMethod("getService", String.class);
            IBinder rawSystemBinderHandle = (IBinder) getServiceMethod.invoke(null, BINDER_SERVICE_KEY);

            Class<?> stubClass = Class.forName("com.android.internal.telephony.ITelephony$Stub");
            Method asInterfaceMethod = stubClass.getMethod("asInterface", IBinder.class);
            
            this.privilegedTelephonyStub = (ITelephony) asInterfaceMethod.invoke(null, rawSystemBinderHandle);
            notifyConnectionChange(privilegedTelephonyStub != null);
        } catch (Throwable error) {
            Log.e(TAG, "Failed to map system telephony proxy stubs.", error);
            this.privilegedTelephonyStub = null;
            notifyConnectionChange(false);
        }
    }

    public void invokeBasebandRadioMutation(final int simSlotId, final int networkModeType) {
        if (privilegedTelephonyStub == null) {
            if (statusObserver != null) statusObserver.onOperationComplete(false, "Interface proxy binding is offline.");
            return;
        }

        if (!operationLockGate.compareAndSet(false, true)) {
            if (statusObserver != null) statusObserver.onOperationComplete(false, "Baseband update is already in progress.");
            return;
        }

        backgroundWorkerPool.execute(() -> {
            boolean success = false;
            String message;
            try {
                success = privilegedTelephonyStub.setPreferredNetworkType(simSlotId, networkModeType);
                if (success) {
                    int confirmedState = privilegedTelephonyStub.getPreferredNetworkType(simSlotId);
                    if (confirmedState == networkModeType) {
                        message = "Radio preference applied and verified successfully.";
                    } else {
                        message = "Verification failed: Carrier settings rejected requested parameters.";
                        success = false;
                    }
                } else {
                    message = "System manager rejected baseband preferences.";
                }
            } catch (Throwable error) {
                message = "IPC communication fault: " + error.getMessage();
                success = false;
            } finally {
                operationLockGate.set(false);
            }

            final boolean finalSuccess = success;
            final String finalMessage = message;
            mainUiHandler.post(() -> {
                if (statusObserver != null) statusObserver.onOperationComplete(finalSuccess, finalMessage);
            });
        });
    }

    private void notifyConnectionChange(final boolean active) {
        mainUiHandler.post(() -> {
            if (statusObserver != null) statusObserver.onServiceConnectionStateChanged(active);
        });
    }
}
