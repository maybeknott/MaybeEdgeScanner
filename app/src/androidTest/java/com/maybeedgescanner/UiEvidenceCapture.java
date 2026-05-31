package com.maybeedgescanner;

import android.app.Activity;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.Environment;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import androidx.test.platform.app.InstrumentationRegistry;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/** Saves PNG frames under app external storage for B4 release evidence pulls. */
final class UiEvidenceCapture {
    private UiEvidenceCapture() {}

    static boolean enabled() {
        Bundle args = InstrumentationRegistry.getArguments();
        return "true".equalsIgnoreCase(args.getString("captureB4"));
    }

    static File evidenceDir(Activity activity) {
        File base = activity.getExternalFilesDir(Environment.DIRECTORY_PICTURES);
        if (base == null) {
            base = activity.getFilesDir();
        }
        File dir = new File(base, "b4-evidence");
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IllegalStateException("could not create evidence dir: " + dir);
        }
        return dir;
    }

    static File capture(Activity activity, String frameName) throws IOException {
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
        Bitmap bitmap = InstrumentationRegistry.getInstrumentation().getUiAutomation().takeScreenshot();
        if (bitmap == null) {
            throw new IOException("UiAutomation.takeScreenshot returned null for " + frameName);
        }
        File out = new File(evidenceDir(activity), frameName + ".png");
        try (FileOutputStream stream = new FileOutputStream(out)) {
            if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, stream)) {
                throw new IOException("PNG compress failed for " + out);
            }
        } finally {
            bitmap.recycle();
        }
        return out;
    }

    static void clickTabLabel(Activity activity, String label) {
        activity.runOnUiThread(() -> {
            View root = activity.getWindow().getDecorView();
            Button button = findButton(root, label);
            if (button == null) {
                throw new IllegalStateException("tab button not found: " + label);
            }
            button.performClick();
        });
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
    }

    private static Button findButton(View root, String text) {
        if (root instanceof Button) {
            CharSequence current = ((Button) root).getText();
            if (current != null && text.contentEquals(current)) {
                return (Button) root;
            }
        }
        if (root instanceof TextView && !(root instanceof Button)) {
            CharSequence current = ((TextView) root).getText();
            if (current != null && text.contentEquals(current) && root.isClickable()) {
                return null;
            }
        }
        if (root instanceof android.view.ViewGroup) {
            android.view.ViewGroup group = (android.view.ViewGroup) root;
            for (int i = 0; i < group.getChildCount(); i++) {
                Button found = findButton(group.getChildAt(i), text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
