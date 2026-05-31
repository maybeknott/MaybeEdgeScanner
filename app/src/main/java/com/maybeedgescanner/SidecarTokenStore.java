package com.maybeedgescanner;

import android.content.Context;
import android.content.SharedPreferences;

import java.security.SecureRandom;

/** Persists the loopback sidecar auth token shared with a supervised sidecar process. */
final class SidecarTokenStore {
    private static final String PREFS = "maybeedgescanner_sidecar_token";
    private static final String KEY_TOKEN = "token";
    static final String ENV_NAME = "MAYBEEDGESCANNER_SIDECAR_TOKEN";

    private SidecarTokenStore() {}

    static String getOrCreate(Context context) {
        Context app = context.getApplicationContext();
        SharedPreferences prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String token = prefs.getString(KEY_TOKEN, "");
        if (token == null || token.isEmpty()) {
            token = generateTokenHex(32);
            prefs.edit().putString(KEY_TOKEN, token).apply();
        }
        return token;
    }

    static String generateTokenHex(int bytes) {
        byte[] buf = new byte[Math.max(16, bytes)];
        new SecureRandom().nextBytes(buf);
        StringBuilder sb = new StringBuilder(buf.length * 2);
        for (byte value : buf) {
            sb.append(String.format(java.util.Locale.US, "%02x", value));
        }
        return sb.toString();
    }
}
