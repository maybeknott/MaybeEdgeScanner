package com.maybeedgescanner;

import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

/** Device/emulator rotation and recreation smoke tests (B1 slice 22). */
@RunWith(AndroidJUnit4.class)
public class ScanLifecycleInstrumentationTest {
    @Test
    public void activityRecreateDoesNotCrash() {
        try (ActivityScenario<MainActivity> scenario = ActivityScenario.launch(MainActivity.class)) {
            scenario.recreate();
        }
    }

    @Test
    public void activityRecreateWhilePlanReviewPendingDoesNotCrash() {
        try (ActivityScenario<MainActivity> scenario = ActivityScenario.launch(MainActivity.class)) {
            scenario.onActivity(activity -> ScanForegroundService.enterPlanReview(activity, "instrumentation plan review"));
            scenario.recreate();
        }
    }
}
