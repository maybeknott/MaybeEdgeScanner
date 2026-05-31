package com.maybeedgescanner;

import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Optional B4 evidence capture. Run with:
 * {@code -Pandroid.testInstrumentationRunnerArguments.captureB4=true}
 * then pull {@code Android/data/com.maybeedgescanner/files/Pictures/b4-evidence/}.
 */
@RunWith(AndroidJUnit4.class)
public class B4UiEvidenceCaptureTest {
    @Before
    public void requireCaptureFlag() {
        Assume.assumeTrue(
                "Pass -Pandroid.testInstrumentationRunnerArguments.captureB4=true to capture frames",
                UiEvidenceCapture.enabled());
    }

    @Test
    public void captureBaselineTabsAndPlanReview() throws Exception {
        try (ActivityScenario<MainActivity> scenario = ActivityScenario.launch(MainActivity.class)) {
            scenario.onActivity(activity -> UiEvidenceCapture.capture(activity, "01_routes_tab"));
            scenario.onActivity(activity -> {
                UiEvidenceCapture.clickTabLabel(activity, "Results");
                UiEvidenceCapture.capture(activity, "02_results_tab");
            });
            scenario.onActivity(activity -> {
                UiEvidenceCapture.clickTabLabel(activity, "Diagnostics");
                UiEvidenceCapture.capture(activity, "03_diagnostics_tab");
            });
            scenario.onActivity(activity -> {
                ScanForegroundService.enterPlanReview(activity, "B4 evidence capture plan review");
                UiEvidenceCapture.clickTabLabel(activity, "Routes");
                UiEvidenceCapture.capture(activity, "04_plan_review_routes");
            });
        }
    }
}
