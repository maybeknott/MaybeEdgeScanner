package com.maybeedgescanner;

import android.os.Looper;
import android.widget.EditText;
import android.widget.TextView;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Deque;
import java.util.Locale;

final class DiagnosticsLogPipeline {
    static final int MAX_LINES = 300;
    static final long RENDER_CADENCE_MS = 220L;

    private DiagnosticsLogPipeline() {}

    static String timestamped(String message) {
        return new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date()) + "  " + message;
    }

    static void appendLine(Deque<String> lines, StringBuilder stableBuilder, String line, Runnable rebuildStableBuilder) {
        synchronized (lines) {
            lines.addLast(line);
            if (lines.size() > MAX_LINES) {
                lines.removeFirst();
                rebuildStableBuilder.run();
            } else {
                stableBuilder.append(line).append('\n');
            }
        }
    }

    static long render(TextView logView, int activeTab, EditText logFilterInput, Deque<String> lines,
                       StringBuilder stableBuilder, long lastRenderedAt, String lastRenderedText,
                       java.util.function.Consumer<String> updateLastRenderedText) {
        if (logView == null || activeTab != 2) return lastRenderedAt;
        long now = System.currentTimeMillis();
        if (now - lastRenderedAt < RENDER_CADENCE_MS) return lastRenderedAt;
        String filter = logFilterInput == null ? "" : safeLower(logFilterInput.getText().toString());
        String nextText;
        if (filter.isEmpty()) {
            nextText = stableBuilder.toString().trim();
        } else {
            StringBuilder sb = new StringBuilder();
            synchronized (lines) {
                for (String x : lines) {
                    if (safeLower(x).contains(filter)) sb.append(x).append('\n');
                }
            }
            nextText = sb.toString().trim();
        }
        if (!nextText.equals(lastRenderedText)) {
            logView.setText(nextText);
            updateLastRenderedText.accept(nextText);
        }
        return now;
    }

    static void dispatchRefresh(Runnable refreshDirect, android.os.Handler ui) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            refreshDirect.run();
        } else {
            ui.post(refreshDirect);
        }
    }

    static String bufferedText(StringBuilder sb) {
        return sb == null ? "" : sb.toString();
    }

    private static String safeLower(String s) {
        return s == null ? "" : s.trim().toLowerCase(Locale.US);
    }
}
