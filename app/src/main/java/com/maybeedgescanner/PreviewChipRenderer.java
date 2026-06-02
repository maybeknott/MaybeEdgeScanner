package com.maybeedgescanner;

import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

final class PreviewChipRenderer {
    private PreviewChipRenderer() {}

    interface Ui {
        TextView titleText();
        LinearLayout row();
        TextView chip();
        LinearLayout.LayoutParams chipLayoutParams();
        void bindChip(TextView view, String label, boolean ok);
    }

    static void render(
            LinearLayout panel,
            String title,
            List<String> values,
            boolean targets,
            int previewChipLimit,
            Ui ui
    ) {
        State state = state(panel, previewChipLimit, ui);
        int valid = 0;
        for (String value : values) {
            if (targets ? ScanInputAnalyzer.validTargetToken(value) : ScanInputAnalyzer.validDomainToken(value)) {
                valid++;
            }
        }
        state.title.setText(title + ": " + valid + "/" + values.size() + " ready");
        int shown = Math.min(values.size(), previewChipLimit);
        for (int i = 0; i < shown; i++) {
            String token = values.get(i);
            boolean ok = targets ? ScanInputAnalyzer.validTargetToken(token) : ScanInputAnalyzer.validDomainToken(token);
            ui.bindChip(state.chips.get(i), token, ok);
            state.chips.get(i).setVisibility(View.VISIBLE);
        }
        for (int i = shown; i < state.chips.size(); i++) {
            state.chips.get(i).setVisibility(View.GONE);
        }
        if (values.size() > shown) {
            ui.bindChip(state.overflowChip, "+" + (values.size() - shown) + " more", true);
            state.overflowChip.setVisibility(View.VISIBLE);
        } else {
            state.overflowChip.setVisibility(View.GONE);
        }
        if (values.isEmpty()) {
            ui.bindChip(state.emptyChip, targets ? "Paste IPs, CIDRs, ranges, domains" : "Paste hostnames for TLS SNI", true);
            state.emptyChip.setVisibility(View.VISIBLE);
        } else {
            state.emptyChip.setVisibility(View.GONE);
        }
    }

    private static State state(LinearLayout panel, int previewChipLimit, Ui ui) {
        Object tag = panel.getTag();
        if (tag instanceof State) return (State) tag;
        panel.removeAllViews();
        State state = new State();
        state.title = ui.titleText();
        panel.addView(state.title);
        LinearLayout row = null;
        for (int i = 0; i < previewChipLimit; i++) {
            if (i % 2 == 0) {
                row = ui.row();
                row.setGravity(Gravity.START);
                panel.addView(row);
            }
            TextView chip = ui.chip();
            chip.setVisibility(View.GONE);
            state.chips.add(chip);
            row.addView(chip, ui.chipLayoutParams());
        }
        LinearLayout metaRow = ui.row();
        metaRow.setGravity(Gravity.START);
        state.overflowChip = ui.chip();
        state.emptyChip = ui.chip();
        state.overflowChip.setVisibility(View.GONE);
        state.emptyChip.setVisibility(View.GONE);
        metaRow.addView(state.overflowChip, ui.chipLayoutParams());
        metaRow.addView(state.emptyChip, ui.chipLayoutParams());
        panel.addView(metaRow);
        panel.setTag(state);
        return state;
    }

    private static final class State {
        TextView title;
        final ArrayList<TextView> chips = new ArrayList<>();
        TextView overflowChip;
        TextView emptyChip;
    }
}

