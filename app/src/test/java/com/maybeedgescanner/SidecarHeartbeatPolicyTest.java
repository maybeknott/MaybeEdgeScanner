package com.maybeedgescanner;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class SidecarHeartbeatPolicyTest {
    @Test
    public void inactiveGuardReturnsNoop() {
        assertEquals(
                SidecarHeartbeatPolicy.Action.NOOP,
                SidecarHeartbeatPolicy.decide(false, true, true, true));
    }

    @Test
    public void runningAndReachableReschedules() {
        assertEquals(
                SidecarHeartbeatPolicy.Action.RESCHEDULE,
                SidecarHeartbeatPolicy.decide(true, true, true, true));
    }

    @Test
    public void runningAndHeartbeatLostFailsWhenPreviouslyReachable() {
        assertEquals(
                SidecarHeartbeatPolicy.Action.FAIL_SIDECAR_AND_STOP,
                SidecarHeartbeatPolicy.decide(true, true, false, true));
    }

    @Test
    public void runningAndHeartbeatLostStopsOnlyWhenNeverReachable() {
        assertEquals(
                SidecarHeartbeatPolicy.Action.STOP_ONLY,
                SidecarHeartbeatPolicy.decide(true, true, false, false));
    }

    @Test
    public void nonRunningSessionStopsOnly() {
        assertEquals(
                SidecarHeartbeatPolicy.Action.STOP_ONLY,
                SidecarHeartbeatPolicy.decide(true, false, false, true));
    }
}
