package com.android.internal.telephony;

interface ITelephony {
    boolean setPreferredNetworkType(int subId, int networkType);
    int getPreferredNetworkType(int subId);
    boolean isRadioOn(String callingPackage);
}
