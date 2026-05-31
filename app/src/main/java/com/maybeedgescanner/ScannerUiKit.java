package com.maybeedgescanner;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.text.InputType;
import android.text.Layout;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.TextView;

final class ScannerUiKit {
    private ScannerUiKit() {}

    static LinearLayout column(Context context) {
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.VERTICAL);
        return layout;
    }

    static LinearLayout row(Context context) {
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.HORIZONTAL);
        layout.setGravity(Gravity.CENTER);
        return layout;
    }

    @SuppressLint("WrongConstant")
    static TextView text(Context context, String value, int sp, int color, boolean bold) {
        TextView view = new TextView(context);
        view.setText(value);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        view.setTextColor(color);
        if (bold) view.setTypeface(Typeface.DEFAULT_BOLD);
        view.setPadding(0, dp(context, 4), 0, dp(context, 4));
        view.setLetterSpacing(0.02f);
        view.setBreakStrategy(Layout.BREAK_STRATEGY_HIGH_QUALITY);
        return view;
    }

    static TextView section(Context context, String value, int color) {
        TextView view = text(context, value, 12, color, true);
        view.setPadding(dp(context, 2), dp(context, 10), 0, dp(context, 4));
        view.setLetterSpacing(0f);
        return view;
    }

    static EditText input(Context context, String value, boolean number, int fieldColor, int strokeColor) {
        EditText editText = new EditText(context);
        editText.setText(value);
        editText.setTextColor(Color.WHITE);
        editText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        editText.setHintTextColor(Color.rgb(145, 174, 190));
        editText.setSingleLine(false);
        editText.setMaxLines(number ? 1 : 4);
        editText.setHorizontallyScrolling(false);
        int type = number ? InputType.TYPE_CLASS_NUMBER : (InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        editText.setInputType(type | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        editText.setBackground(glassBg(context, fieldColor, strokeColor, false, false));
        editText.setPadding(dp(context, 10), dp(context, 8), dp(context, 10), dp(context, 8));
        return editText;
    }

    static CheckBox check(Context context, String value, int accentColor) {
        CheckBox checkBox = new CheckBox(context);
        checkBox.setText(value);
        checkBox.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        checkBox.setTextColor(Color.WHITE);
        checkBox.setMinHeight(dp(context, 40));
        checkBox.setContentDescription(value);
        checkBox.setButtonTintList(android.content.res.ColorStateList.valueOf(accentColor));
        return checkBox;
    }

    static Button button(Context context, String value, int bg, int fg, int strokeColor) {
        Button button = new Button(context);
        button.setText(value);
        button.setTextColor(fg);
        button.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        button.setMinHeight(dp(context, 42));
        button.setAllCaps(false);
        button.setContentDescription(value.replace('\n', ' '));
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setBackground(glassBg(context, bg, strokeColor, false, false));
        button.setPadding(dp(context, 9), dp(context, 7), dp(context, 9), dp(context, 7));
        button.setOnTouchListener((v, e) -> {
            if (e.getAction() == MotionEvent.ACTION_DOWN) {
                v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                v.animate().scaleX(0.98f).scaleY(0.98f).setDuration(70).start();
            }
            if (e.getAction() == MotionEvent.ACTION_UP || e.getAction() == MotionEvent.ACTION_CANCEL) {
                v.animate().scaleX(1f).scaleY(1f).setDuration(130).setInterpolator(new DecelerateInterpolator()).start();
            }
            return false;
        });
        return button;
    }

    static Spinner spinner(Context context, String[] values, int fieldColor, int strokeColor) {
        Spinner spinner = new Spinner(context);
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(context, android.R.layout.simple_spinner_item, values) {
            @Override public View getView(int position, View convertView, android.view.ViewGroup parent) {
                return styleSpinnerText(context, super.getView(position, convertView, parent), false);
            }

            @Override public View getDropDownView(int position, View convertView, android.view.ViewGroup parent) {
                return styleSpinnerText(context, super.getDropDownView(position, convertView, parent), true);
            }
        };
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
        spinner.setBackground(glassBg(context, fieldColor, strokeColor, false, false));
        spinner.setPadding(dp(context, 8), dp(context, 5), dp(context, 8), dp(context, 5));
        spinner.setMinimumHeight(dp(context, 44));
        return spinner;
    }

    private static View styleSpinnerText(Context context, View view, boolean dropdown) {
        if (view instanceof TextView) {
            TextView text = (TextView) view;
            text.setTextColor(Color.WHITE);
            text.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
            text.setSingleLine(false);
            text.setMaxLines(2);
            text.setGravity(Gravity.CENTER_VERTICAL);
            text.setPadding(dp(context, 10), dp(context, dropdown ? 11 : 8), dp(context, 10), dp(context, dropdown ? 11 : 8));
            text.setBackgroundColor(dropdown ? Color.rgb(10, 24, 34) : Color.TRANSPARENT);
        }
        return view;
    }

    static LinearLayout box(Context context, String label, View child, int fill, int stroke, int sectionColor) {
        LinearLayout layout = column(context);
        layout.setBackground(glassBg(context, fill, stroke, false, false));
        layout.setPadding(dp(context, 7), dp(context, 2), dp(context, 7), dp(context, 7));
        layout.addView(section(context, label, sectionColor));
        layout.addView(child);
        return layout;
    }

    static LinearLayout.LayoutParams weight(Context context) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, -2, 1);
        lp.setMargins(dp(context, 4), dp(context, 4), dp(context, 4), dp(context, 4));
        return lp;
    }

    static LinearLayout.LayoutParams fixedWidth(Context context, int widthDp) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(dp(context, widthDp), -2);
        lp.setMargins(dp(context, 3), dp(context, 3), dp(context, 3), dp(context, 3));
        return lp;
    }

    static int dp(Context context, int value) {
        return (int) (value * context.getResources().getDisplayMetrics().density + 0.5f);
    }

    static GradientDrawable glassBg(Context context, int fill, int stroke, boolean highContrast, boolean compact) {
        int fillAlpha = highContrast ? 245 : 232;
        int shineAlpha = highContrast ? 28 : 48;
        GradientDrawable drawable = new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{Color.argb(fillAlpha, Color.red(fill), Color.green(fill), Color.blue(fill)), Color.argb(shineAlpha, 255, 255, 255)});
        drawable.setCornerRadius(dp(context, compact ? 7 : 10));
        drawable.setStroke(highContrast ? dp(context, 2) : 1, stroke);
        return drawable;
    }

    static void setOuterMargin(View view, int left, int top, int right, int bottom) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.setMargins(left, top, right, bottom);
        view.setLayoutParams(lp);
    }
}
