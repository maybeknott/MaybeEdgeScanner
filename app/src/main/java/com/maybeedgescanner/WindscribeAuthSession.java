package com.maybeedgescanner;

import java.io.Serializable;

final class WindscribeAuthSession implements Serializable {
    private static final long serialVersionUID = 1L;

    final String credentialRef;
    final String profileRef;
    final boolean loginRequired;
    final boolean sessionRefAvailable;

    private WindscribeAuthSession(String credentialRef, String profileRef) {
        this.credentialRef = cleanRef(credentialRef);
        this.profileRef = cleanRef(profileRef);
        this.sessionRefAvailable = this.credentialRef.startsWith("ref:");
        this.loginRequired = !sessionRefAvailable;
    }

    static WindscribeAuthSession fromRefs(String credentialRef, String profileRef) {
        return new WindscribeAuthSession(credentialRef, profileRef);
    }

    String authBoundary() {
        if (sessionRefAvailable) return "Windscribe stays external; this scan attaches only a stored session/profile reference.";
        return "Connect Windscribe first or enter a stored session/profile reference. No Windscribe password is collected here.";
    }

    private static String cleanRef(String value) {
        if (value == null) return "";
        return value.replace('\r', ' ').replace('\n', ' ').trim();
    }
}
