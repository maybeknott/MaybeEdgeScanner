package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class WindscribeAuthSessionTest {
    @Test
    public void credentialRefEnablesSessionBackedAuthBoundary() {
        WindscribeAuthSession session = WindscribeAuthSession.fromRefs("ref:cred", "");
        assertTrue(session.sessionRefAvailable);
        assertFalse(session.loginRequired);
        assertTrue(session.authBoundary().contains("stored session/profile reference"));
    }

    @Test
    public void missingCredentialRequiresLogin() {
        WindscribeAuthSession session = WindscribeAuthSession.fromRefs("", "ref:profile");
        assertFalse(session.sessionRefAvailable);
        assertTrue(session.loginRequired);
        assertTrue(session.authBoundary().contains("Connect Windscribe first"));
    }
}
