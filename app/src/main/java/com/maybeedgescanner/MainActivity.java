package com.maybeedgescanner;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.BatteryManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.widget.*;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLParameters;

public class MainActivity extends Activity {
    public static final String ACTION_QUICK_SCAN = "com.maybeedgescanner.action.QUICK_SCAN";
    private static final int BLUE = Color.rgb(55, 212, 255);
    private static final int BG = Color.rgb(7, 16, 24);
    private static final int PANEL = Color.rgb(13, 28, 39);
    private static final int FIELD = Color.rgb(9, 20, 29);
    private static final int MUTED = Color.rgb(140, 161, 178);
    private static final String SUPPORT_GITHUB = "https://github.com/maybeknott/MaybeEdgeScanner/";
    private static final String SUPPORT_EVM = "0x8988ed09DA218799e99Fb1E94243cC1C1cB41A40";
    private static final String SUPPORT_BTC = "bc1qt2mxzmlcv3re4pjemshejzq0hj3c8dgp0e5tvx";

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final AtomicBoolean stop = new AtomicBoolean(false);
    private final AtomicBoolean renderQueued = new AtomicBoolean(false);
    private final AtomicInteger checkedTargets = new AtomicInteger(0);
    private final List<Result> allResults = Collections.synchronizedList(new ArrayList<>());
    private ExecutorService executor;

    private LinearLayout resultList;
    private LinearLayout targetTab, liveTab, vaultTab;
    private LinearLayout targetChipPreview, sniChipPreview;
    private LinearLayout analyticsPanel;
    private LinearLayout stableHistoryPanel;
    private ScrollView mainScroll;
    private View targetAnchor, liveAnchor, vaultAnchor;
    private ProgressBar progress;
    private TextView status, metrics, bestView, countersView, logView, networkBanner, copyFallbackView;
    private TextView presetSummaryView;
    private TextView scanPlanView;
    private EditText targetsInput, snisInput, totalInput, batchInput, threadsInput, timeoutInput;
    private EditText communitySampleInput, akamaiSampleInput, cloudfrontSampleInput, fastlySampleInput, cloudflareSampleInput, otherCdnSampleInput;
    private EditText portsInput, pathInput, maxLatencyInput, resultLimitInput, cdnFilterInput, certFilterInput, sniFilterInput, minQualityInput;
    private CheckBox multiSni, filterWorking, filterSni, bestPerIp, hideNoisyLogs, requireHttp, requireKnownCdn, requireTls13, batteryFriendlyUi;
    private CheckBox stepTcp, stepTls, stepHttp, stepVerify;
    private Spinner profileSpinner, workflowSpinner, sortSpinner, presetSpinner, exportSpinner, vaultModeSpinner, visualModeSpinner, tlsModeSpinner;
    private Button startButton, stopButton, copyButton, copyCsvButton, exportButton, clearButton, applyPresetButton, appendPresetButton, helpButton;
    private Button tabTargetButton, tabLiveButton, tabVaultButton;
    private int totalTargets;
    private int activeTab;
    private float swipeStartX, swipeStartY;
    private long scanStartedAt;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        buildUi();
        loadDefaults();
        maybeShowOnboarding();
        if (ACTION_QUICK_SCAN.equals(getIntent().getAction())) {
            ui.postDelayed(this::startScan, 450);
        }
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        mainScroll = scroll;
        LinearLayout root = column();
        root.setPadding(dp(14), dp(14), dp(14), dp(22));
        root.setBackground(new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{Color.rgb(5, 14, 23), Color.rgb(8, 28, 38), Color.rgb(15, 18, 34)}));
        scroll.addView(root);

        root.addView(text("MaybeEdgeScanner", 27, Color.WHITE, true));
        root.addView(text("Standalone edge, SNI, CIDR, TCP, TLS, HTTP and CDN scanner", 13, MUTED, false));
        status = pill("Ready");
        root.addView(status);
        networkBanner = pill(networkContextLine());
        root.addView(networkBanner);
        root.addView(infoCard("Presets included", "Community-tested edges, provider CIDR corpora, and SNI hostnames are separate inputs. Provider sampling is taken from provider CIDR/range files, not from community-tested IPs."));
        root.addView(infoCard("No preset override", "Preset buttons merge into one target corpus and one SNI corpus. Duplicate ranges are deduped before expansion, so overlapping files do not override each other or silently erase your custom input."));
        root.addView(infoCard("Targets vs SNI", "Targets decide where sockets connect. SNI hosts decide what TLS/HTTP name is presented after connecting. They are intentionally separate: same target IP, many possible SNI/Host routes."));
        helpButton = button("Guide & parameter help", Color.rgb(23, 46, 63), Color.WHITE);
        root.addView(helpButton);
        LinearLayout tabs = row();
        tabTargetButton = button("Target Setup", Color.rgb(21, 45, 62), Color.WHITE);
        tabLiveButton = button("Live Terminal", Color.rgb(21, 45, 62), Color.WHITE);
        tabVaultButton = button("Edge Vault", Color.rgb(21, 45, 62), Color.WHITE);
        tabs.addView(tabTargetButton, weight());
        tabs.addView(tabLiveButton, weight());
        tabs.addView(tabVaultButton, weight());
        root.addView(tabs);

        LinearLayout quick = row();
        startButton = button("Start", BLUE, Color.rgb(2, 18, 24));
        stopButton = button("Stop", Color.rgb(255, 102, 122), Color.WHITE);
        clearButton = button("Clear", Color.rgb(34, 51, 66), Color.WHITE);
        stopButton.setEnabled(false);
        quick.addView(startButton, weight());
        quick.addView(stopButton, weight());
        quick.addView(clearButton, weight());
        root.addView(quick);

        targetTab = column();
        root.addView(targetTab);
        targetAnchor = section("Target Setup");
        targetTab.addView(targetAnchor);
        targetsInput = area("Targets: domains, IPv4, CIDR, ranges");
        snisInput = area("SNI hosts");
        LinearLayout presetRow = row();
        presetSpinner = spinner(new String[]{"Community defaults", "Akamai", "AWS CloudFront", "Fastly", "Cloudflare", "Other CDNs", "Everything bundled"});
        presetRow.addView(box("Preset corpus", presetSpinner), weight());
        targetTab.addView(presetRow);
        LinearLayout presetButtons = row();
        applyPresetButton = button("Replace with preset", Color.rgb(34, 51, 66), Color.WHITE);
        appendPresetButton = button("Append preset", Color.rgb(34, 51, 66), Color.WHITE);
        presetButtons.addView(applyPresetButton, weight());
        presetButtons.addView(appendPresetButton, weight());
        targetTab.addView(presetButtons);
        LinearLayout presetCards1 = row();
        presetCards1.addView(presetCard("Community /24s", "tested IPs expanded to subnets", 0), weight());
        presetCards1.addView(presetCard("Other providers", "GitHub, Azure, Google, Bunny", 5), weight());
        targetTab.addView(presetCards1);
        LinearLayout presetCards2 = row();
        presetCards2.addView(presetCard("Everything bundled", "community + provider corpora", 6), weight());
        targetTab.addView(presetCards2);
        presetSummaryView = glassText("Preset corpora are merged with user IPs/SNIs and deduplicated before scanning.");
        targetTab.addView(presetSummaryView);
        scanPlanView = glassText("Scan plan will update as you edit targets, SNIs, ports, workflow, and total cap.");
        targetTab.addView(scanPlanView);
        targetTab.addView(section("Targets"));
        targetTab.addView(infoCard("Custom ranges are welcome", "Paste IPs, CIDRs like 151.101.0.0/16, or ranges like 184.24.77.5-184.24.77.42. Preset cards are broad shortcuts; use the picker above for individual provider corpora."));
        targetTab.addView(targetsInput);
        targetChipPreview = chipPanel();
        targetTab.addView(targetChipPreview);
        targetTab.addView(section("SNI Hosts"));
        targetTab.addView(snisInput);
        sniChipPreview = chipPanel();
        targetTab.addView(sniChipPreview);

        LinearLayout row1 = row();
        profileSpinner = spinner(new String[]{"Quick TCP", "Standard TLS", "Deep HTTP + SNI", "Verify CDN edge"});
        workflowSpinner = spinner(new String[]{"Single selected profile", "Auto multi-step ladder", "Manual selected steps"});
        sortSpinner = spinner(new String[]{"Newest", "Latency", "Score", "CDN", "SNI", "HTTP first", "TLS first"});
        tlsModeSpinner = spinner(new String[]{"Android default", "Chrome-like ALPN", "Firefox-like ALPN", "HTTP/1.1 only", "Rotate per probe"});
        row1.addView(box("Profile", profileSpinner), weight());
        row1.addView(box("Workflow", workflowSpinner), weight());
        targetTab.addView(row1);
        LinearLayout row1b = row();
        row1b.addView(box("Sort", sortSpinner), weight());
        row1b.addView(box("TLS ClientHello", tlsModeSpinner), weight());
        targetTab.addView(row1b);
        targetTab.addView(infoCard("Multi-step scans", "Auto ladder runs TCP, then TLS, then HTTP/SNI, then CDN verification. Manual mode runs only the checked steps below."));
        LinearLayout stepRow1 = row();
        stepTcp = check("Step 1 TCP");
        stepTls = check("Step 2 TLS");
        stepHttp = check("Step 3 HTTP/SNI");
        stepVerify = check("Step 4 Verify");
        stepTcp.setChecked(true);
        stepTls.setChecked(true);
        stepHttp.setChecked(true);
        stepVerify.setChecked(true);
        stepRow1.addView(stepTcp, weight());
        stepRow1.addView(stepTls, weight());
        targetTab.addView(stepRow1);
        LinearLayout stepRow2 = row();
        stepRow2.addView(stepHttp, weight());
        stepRow2.addView(stepVerify, weight());
        targetTab.addView(stepRow2);

        targetTab.addView(infoCard("Performance modes", "Choose a comfort mode, then expand into the numbers below if you want exact control. These are presets, not caps."));
        LinearLayout modeRow = row();
        modeRow.addView(modeButton("Battery Saver", "16 / 2000 / 2500", 16, 2000, 2500), weight());
        modeRow.addView(modeButton("Balanced", "64 / 12000 / 3000", 64, 12000, 3000), weight());
        modeRow.addView(modeButton("Aggressive", "256 / 72000 / 5000", 256, 72000, 5000), weight());
        targetTab.addView(modeRow);

        LinearLayout row2 = row();
        totalInput = input("72000", true);
        batchInput = input("12000", true);
        threadsInput = input("64", true);
        timeoutInput = input("3000", true);
        row2.addView(box("Total cap", totalInput), weight());
        row2.addView(box("Batch", batchInput), weight());
        targetTab.addView(row2);
        LinearLayout row3 = row();
        row3.addView(box("Threads", threadsInput), weight());
        row3.addView(box("Timeout ms", timeoutInput), weight());
        targetTab.addView(row3);
        targetTab.addView(infoCard("Per-source sampling", "0 keeps the full source tokens. Any positive number samples expanded IPs from that source's whole CIDR/range space. Community tested IPs are normalized into /24 CIDRs; provider buckets sample provider-owned CIDRs."));
        LinearLayout sourceRow1 = row();
        communitySampleInput = input("0", true);
        akamaiSampleInput = input("0", true);
        cloudfrontSampleInput = input("0", true);
        sourceRow1.addView(box("Community /24s", communitySampleInput), weight());
        sourceRow1.addView(box("Provider Akamai", akamaiSampleInput), weight());
        sourceRow1.addView(box("Provider CloudFront", cloudfrontSampleInput), weight());
        targetTab.addView(sourceRow1);
        LinearLayout sourceRow2 = row();
        fastlySampleInput = input("0", true);
        cloudflareSampleInput = input("0", true);
        otherCdnSampleInput = input("0", true);
        sourceRow2.addView(box("Provider Fastly", fastlySampleInput), weight());
        sourceRow2.addView(box("Provider Cloudflare", cloudflareSampleInput), weight());
        sourceRow2.addView(box("Other CDNs", otherCdnSampleInput), weight());
        targetTab.addView(sourceRow2);

        LinearLayout row4 = row();
        portsInput = input("443", false);
        pathInput = input("/", false);
        row4.addView(box("Ports", portsInput), weight());
        row4.addView(box("HTTP path", pathInput), weight());
        targetTab.addView(row4);

        multiSni = check("All SNI hosts");
        filterWorking = check("Working only");
        filterSni = check("TLS/HTTP only");
        bestPerIp = check("Best per IP");
        hideNoisyLogs = check("Quiet logs");
        requireHttp = check("HTTP only");
        requireKnownCdn = check("Known CDN only");
        requireTls13 = check("TLS 1.3 only");
        batteryFriendlyUi = check("Battery-friendly UI");
        filterWorking.setChecked(true);
        bestPerIp.setChecked(true);
        LinearLayout checks1 = row();
        checks1.addView(multiSni, weight());
        checks1.addView(filterWorking, weight());
        targetTab.addView(checks1);
        LinearLayout checks2 = row();
        checks2.addView(filterSni, weight());
        checks2.addView(bestPerIp, weight());
        targetTab.addView(checks2);
        LinearLayout checks3 = row();
        checks3.addView(requireHttp, weight());
        checks3.addView(requireKnownCdn, weight());
        targetTab.addView(checks3);
        LinearLayout checks4 = row();
        checks4.addView(requireTls13, weight());
        checks4.addView(hideNoisyLogs, weight());
        targetTab.addView(checks4);
        LinearLayout checks5 = row();
        checks5.addView(batteryFriendlyUi, weight());
        targetTab.addView(checks5);

        LinearLayout row5 = row();
        maxLatencyInput = input("", true); maxLatencyInput.setHint("Max latency");
        resultLimitInput = input("250", true);
        row5.addView(box("Max latency ms", maxLatencyInput), weight());
        row5.addView(box("Result limit", resultLimitInput), weight());
        targetTab.addView(row5);
        LinearLayout row6 = row();
        cdnFilterInput = input("", false); cdnFilterInput.setHint("akamai, fastly...");
        certFilterInput = input("", false); certFilterInput.setHint("CN/O/cert contains");
        row6.addView(box("CDN filter", cdnFilterInput), weight());
        row6.addView(box("Cert filter", certFilterInput), weight());
        targetTab.addView(row6);
        LinearLayout row7 = row();
        sniFilterInput = input("", false); sniFilterInput.setHint("SNI contains");
        minQualityInput = input("", true); minQualityInput.setHint("Min quality");
        row7.addView(box("SNI filter", sniFilterInput), weight());
        row7.addView(box("Min quality", minQualityInput), weight());
        targetTab.addView(row7);
        targetTab.addView(supportFooter());

        liveTab = column();
        root.addView(liveTab);
        liveAnchor = section("Live Terminal");
        liveTab.addView(liveAnchor);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setMax(100);
        liveTab.addView(progress);
        metrics = text("0 / 0 | TCP 0 | TLS 0 | HTTP 0 | Q 0", 13, Color.WHITE, false);
        countersView = text("Down 0 | timeout 0 | reset 0 | cert 0 | DNS 0 | " + resourceLine(), 12, MUTED, false);
        bestView = panelText("Best result will appear here");
        liveTab.addView(metrics);
        liveTab.addView(countersView);
        liveTab.addView(bestView);
        analyticsPanel = column();
        analyticsPanel.setLayoutTransition(null);
        analyticsPanel.setBackground(glassBg(Color.rgb(9, 23, 34), Color.argb(105, 255, 255, 255)));
        analyticsPanel.setPadding(dp(12), dp(10), dp(12), dp(12));
        setOuterMargin(analyticsPanel, 0, dp(8), 0, dp(8));
        liveTab.addView(analyticsPanel);

        LinearLayout buttons = row();
        copyButton = button("Copy filtered", Color.rgb(34, 51, 66), Color.WHITE);
        copyCsvButton = button("Copy filtered CSV", Color.rgb(34, 51, 66), Color.WHITE);
        exportButton = button("Export JSON", Color.rgb(34, 51, 66), Color.WHITE);
        buttons.addView(copyButton, weight());
        buttons.addView(copyCsvButton, weight());
        buttons.addView(exportButton, weight());
        liveTab.addView(buttons);
        LinearLayout exportRow = row();
        exportSpinner = spinner(new String[]{"Line-separated IPs", "Comma-separated IPs", "IP SNI pairs", "CSV rows", "JSON"});
        exportRow.addView(box("Clipboard format", exportSpinner), weight());
        liveTab.addView(exportRow);
        copyFallbackView = panelText("Manual copy fallback appears here after copying filtered results.");
        copyFallbackView.setTextIsSelectable(true);
        copyFallbackView.setOnClickListener(v -> showManualCopyDialog("Manual copy fallback", copyFallbackView.getText().toString()));
        liveTab.addView(copyFallbackView);
        liveTab.addView(supportFooter());

        vaultTab = column();
        root.addView(vaultTab);
        vaultAnchor = section("Edge Vault");
        vaultTab.addView(vaultAnchor);
        vaultModeSpinner = spinner(new String[]{"List cards", "Heatmap overview"});
        vaultTab.addView(box("Vault view", vaultModeSpinner));
        visualModeSpinner = spinner(new String[]{"Glass comfort", "High contrast", "Compact analyst"});
        vaultTab.addView(box("Visual mode", visualModeSpinner));
        stableHistoryPanel = column();
        stableHistoryPanel.setBackground(glassBg(Color.rgb(9, 23, 34), Color.argb(90, 255, 255, 255)));
        stableHistoryPanel.setPadding(dp(12), dp(10), dp(12), dp(10));
        setOuterMargin(stableHistoryPanel, 0, dp(8), 0, dp(8));
        vaultTab.addView(stableHistoryPanel);
        resultList = column();
        resultList.setLayoutTransition(null);
        vaultTab.addView(resultList);
        vaultTab.addView(section("Logs"));
        logView = text("", 12, MUTED, false);
        logView.setTypeface(Typeface.MONOSPACE);
        vaultTab.addView(logView);
        vaultTab.addView(supportFooter());

        startButton.setOnClickListener(v -> startScan());
        stopButton.setOnClickListener(v -> stop.set(true));
        clearButton.setOnClickListener(v -> clearResults());
        helpButton.setOnClickListener(v -> showGuide());
        tabTargetButton.setOnClickListener(v -> selectTab(0));
        tabLiveButton.setOnClickListener(v -> selectTab(1));
        tabVaultButton.setOnClickListener(v -> selectTab(2));
        applyPresetButton.setOnClickListener(v -> applyPreset(false));
        appendPresetButton.setOnClickListener(v -> applyPreset(true));
        copyButton.setOnClickListener(v -> copySelectedFormat());
        copyCsvButton.setOnClickListener(v -> copyWorking(true));
        exportButton.setOnClickListener(v -> exportJson());
        View.OnClickListener refresh = v -> renderResults();
        filterWorking.setOnClickListener(refresh);
        filterSni.setOnClickListener(refresh);
        bestPerIp.setOnClickListener(refresh);
        requireHttp.setOnClickListener(refresh);
        requireKnownCdn.setOnClickListener(refresh);
        requireTls13.setOnClickListener(refresh);
        batteryFriendlyUi.setOnClickListener(v -> applyBatteryFriendlyUi());
        multiSni.setOnClickListener(v -> {
            renderResults();
            updateScanPlanPreview();
        });
        sortSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) { renderResults(); }
            @Override public void onNothingSelected(AdapterView<?> p) {}
        });
        AdapterView.OnItemSelectedListener planRefresh = new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) { updateScanPlanPreview(); }
            @Override public void onNothingSelected(AdapterView<?> p) {}
        };
        profileSpinner.setOnItemSelectedListener(planRefresh);
        workflowSpinner.setOnItemSelectedListener(planRefresh);
        tlsModeSpinner.setOnItemSelectedListener(planRefresh);
        vaultModeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) { renderResults(); }
            @Override public void onNothingSelected(AdapterView<?> p) {}
        });
        visualModeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) {
                renderResults();
                renderTokenPreviews();
            }
            @Override public void onNothingSelected(AdapterView<?> p) {}
        });
        targetsInput.addTextChangedListener(simpleWatcher(this::renderTokenPreviews));
        snisInput.addTextChangedListener(simpleWatcher(this::renderTokenPreviews));
        totalInput.addTextChangedListener(simpleWatcher(this::updateScanPlanPreview));
        portsInput.addTextChangedListener(simpleWatcher(this::updateScanPlanPreview));
        scroll.setOnTouchListener((v, e) -> {
            if (e.getAction() == android.view.MotionEvent.ACTION_DOWN) {
                swipeStartX = e.getX();
                swipeStartY = e.getY();
            } else if (e.getAction() == android.view.MotionEvent.ACTION_UP) {
                float dx = e.getX() - swipeStartX;
                float dy = e.getY() - swipeStartY;
                if (Math.abs(dx) > dp(96) && Math.abs(dx) > Math.abs(dy) * 1.4f) {
                    selectTab(activeTab + (dx < 0 ? 1 : -1));
                    return true;
                }
            }
            return false;
        });
        setContentView(scroll);
        applyAccessibilityLabels();
        updateAnalytics(Collections.emptyList());
        renderTokenPreviews();
        updateScanPlanPreview();
        selectTab(0);
    }

    private String networkContextLine() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (cm == null) return "Network context unavailable";
            Network network = cm.getActiveNetwork();
            if (network == null) return "Offline | scanner waiting for a network";
            NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            if (caps == null) return "Connected | network capabilities unknown";
            String transport;
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) transport = "Wi-Fi";
            else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) transport = "Cellular";
            else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) transport = "Ethernet";
            else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) transport = "VPN";
            else transport = "Network";
            String metered = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) ? "unmetered" : "metered";
            String internet = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ? "validated" : "checking";
            return "Connected via " + transport + " | " + metered + " | " + internet;
        } catch (Exception ignored) {
            return "Network context unavailable";
        }
    }

    private Button presetCard(String title, String subtitle, int presetIndex) {
        Button b = button(title + "\n" + subtitle, Color.rgb(16, 38, 52), Color.WHITE);
        b.setOnClickListener(v -> {
            presetSpinner.setSelection(presetIndex);
            applyPreset(true);
        });
        b.setContentDescription(title + " preset card. " + subtitle + ". Adds these targets and SNI hosts.");
        return b;
    }

    private Button modeButton(String title, String subtitle, int threads, int batch, int timeout) {
        Button b = button(title + "\n" + subtitle, Color.rgb(16, 38, 52), Color.WHITE);
        b.setOnClickListener(v -> {
            threadsInput.setText(String.valueOf(threads));
            batchInput.setText(String.valueOf(batch));
            timeoutInput.setText(String.valueOf(timeout));
            if (title.toLowerCase(Locale.US).contains("battery")) {
                batteryFriendlyUi.setChecked(true);
                applyBatteryFriendlyUi();
            }
            toast(title + " values applied. You can still edit them.");
        });
        b.setContentDescription(title + " performance preset: threads, batch, timeout " + subtitle);
        return b;
    }

    private void applyBatteryFriendlyUi() {
        boolean on = batteryFriendlyUi != null && batteryFriendlyUi.isChecked();
        if (hideNoisyLogs != null) hideNoisyLogs.setChecked(on || hideNoisyLogs.isChecked());
        if (resultLimitInput != null && on) resultLimitInput.setText("75");
        if (visualModeSpinner != null && on) visualModeSpinner.setSelection(2);
        if (analyticsPanel != null) analyticsPanel.setVisibility(on ? View.GONE : View.VISIBLE);
        if (logView != null) logView.setVisibility(on ? View.GONE : View.VISIBLE);
        renderResults();
        toast(on ? "Battery-friendly UI enabled" : "Battery-friendly UI disabled");
    }

    private boolean batteryFriendlyMode() {
        return batteryFriendlyUi != null && batteryFriendlyUi.isChecked();
    }

    private android.text.TextWatcher simpleWatcher(Runnable afterChange) {
        return new android.text.TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(android.text.Editable s) { afterChange.run(); }
        };
    }

    private LinearLayout chipPanel() {
        LinearLayout panel = column();
        panel.setPadding(dp(8), dp(6), dp(8), dp(6));
        panel.setBackground(glassBg(Color.rgb(9, 23, 34), Color.argb(80, 255, 255, 255)));
        setOuterMargin(panel, 0, dp(6), 0, dp(6));
        panel.setLayoutTransition(null);
        return panel;
    }

    private void renderTokenPreviews() {
        if (targetChipPreview == null || sniChipPreview == null || targetsInput == null || snisInput == null) return;
        renderChips(targetChipPreview, "Validated targets", lines(targetsInput.getText().toString()), true);
        renderChips(sniChipPreview, "Validated SNI hosts", lines(snisInput.getText().toString()), false);
        updateScanPlanPreview();
    }

    private void updateScanPlanPreview() {
        if (scanPlanView == null || targetsInput == null || snisInput == null || portsInput == null || totalInput == null) return;
        List<String> rawTargets = lines(targetsInput.getText().toString());
        List<String> expanded = expandTargets(rawTargets);
        int cap = Math.max(1, intValue(totalInput, 72000));
        int cappedTargets = Math.min(expanded.size(), cap);
        int sniCount = Math.max(1, lines(snisInput.getText().toString()).size());
        List<Integer> ports = parsePorts(portsInput.getText().toString());
        List<Integer> profiles = selectedWorkflowProfiles();
        boolean allSni = multiSni != null && multiSni.isChecked();
        int units = estimateAttemptUnits(cappedTargets, sniCount, ports.size(), profiles, allSni);
        scanPlanView.setText("Scan plan\n" +
                rawTargets.size() + " target tokens -> " + expanded.size() + " expanded endpoints -> " + cappedTargets + " after Total cap " + cap + "\n" +
                sniCount + " SNI host" + (sniCount == 1 ? "" : "s") + " kept separate for TLS/Host routing; ports " + ports + "\n" +
                "TLS ClientHello mode: " + (tlsModeSpinner == null ? "Android default" : tlsModeSpinner.getSelectedItem()) + "\n" +
                workflowLabels(profiles) + " -> about " + units + " probe units. Preset overlaps are deduped, not overridden.");
    }

    private int estimateAttemptUnits(int targets, int snis, int ports, List<Integer> profiles, boolean allSni) {
        long units = 0;
        int portCount = Math.max(1, ports);
        int routeCount = Math.max(1, snis);
        for (int profile : profiles) {
            int sniMultiplier = (profile >= 2 || allSni) ? routeCount : 1;
            units += (long) Math.max(0, targets) * portCount * Math.max(1, sniMultiplier);
        }
        if (units <= 0) return 1;
        return units > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) units;
    }

    private void renderChips(LinearLayout panel, String title, List<String> values, boolean targets) {
        panel.removeAllViews();
        int valid = 0;
        for (String value : values) if (targets ? validTargetToken(value) : validDomainToken(value)) valid++;
        panel.addView(text(title + ": " + valid + "/" + values.size() + " valid", 11, MUTED, true));
        LinearLayout row = row();
        row.setGravity(Gravity.START);
        int shown = Math.min(values.size(), 12);
        for (int i = 0; i < shown; i++) {
            String token = values.get(i);
            boolean ok = targets ? validTargetToken(token) : validDomainToken(token);
            row.addView(chip(token, ok), smallChipLp());
        }
        if (values.size() > shown) row.addView(chip("+" + (values.size() - shown) + " more", true), smallChipLp());
        if (values.isEmpty()) row.addView(chip(targets ? "Paste IPs, CIDRs, ranges, domains" : "Paste hostnames for TLS SNI", true), smallChipLp());
        panel.addView(row);
    }

    private TextView chip(String label, boolean ok) {
        TextView v = text(trim(label, 22), 11, Color.WHITE, false);
        int fill = ok ? Color.rgb(11, 58, 46) : Color.rgb(74, 26, 37);
        int stroke = ok ? Color.argb(150, 66, 230, 170) : Color.argb(170, 255, 120, 140);
        v.setBackground(glassBg(fill, stroke));
        v.setPadding(dp(8), dp(5), dp(8), dp(5));
        v.setContentDescription((ok ? "Valid token " : "Invalid token ") + label);
        return v;
    }

    private LinearLayout.LayoutParams smallChipLp() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-2, -2);
        lp.setMargins(0, dp(3), dp(5), dp(3));
        return lp;
    }

    private static boolean validTargetToken(String value) {
        if (value == null || value.trim().isEmpty()) return false;
        String v = value.trim();
        if (v.contains("-")) {
            String[] p = v.split("-", 2);
            return p.length == 2 && isIp(p[0]) && isIp(p[1]);
        }
        if (v.contains("/")) {
            String[] p = v.split("/", 2);
            try {
                int prefix = Integer.parseInt(p[1]);
                return p.length == 2 && isIp(p[0]) && prefix >= 0 && prefix <= (p[0].contains(":") ? 128 : 32);
            } catch (Exception ignored) { return false; }
        }
        return isIp(v) || validDomainToken(v);
    }

    private static boolean validDomainToken(String value) {
        return value != null && value.matches("(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$");
    }

    private void scrollTo(View anchor) {
        if (mainScroll == null || anchor == null) return;
        mainScroll.post(() -> mainScroll.smoothScrollTo(0, anchor.getTop()));
    }

    private void selectTab(int tab) {
        activeTab = Math.max(0, Math.min(2, tab));
        styleTab(tabTargetButton, activeTab == 0);
        styleTab(tabLiveButton, activeTab == 1);
        styleTab(tabVaultButton, activeTab == 2);
        if (targetTab != null) targetTab.setVisibility(activeTab == 0 ? View.VISIBLE : View.GONE);
        if (liveTab != null) liveTab.setVisibility(activeTab == 1 ? View.VISIBLE : View.GONE);
        if (vaultTab != null) vaultTab.setVisibility(activeTab == 2 ? View.VISIBLE : View.GONE);
        if (mainScroll != null) mainScroll.post(() -> mainScroll.smoothScrollTo(0, 0));
    }

    private void styleTab(Button button, boolean selected) {
        if (button == null) return;
        button.setTextColor(selected ? Color.rgb(2, 18, 24) : Color.WHITE);
        button.setBackground(glassBg(selected ? BLUE : Color.rgb(21, 45, 62),
                selected ? Color.argb(210, 255, 255, 255) : Color.argb(110, 255, 255, 255)));
    }

    private void maybeShowOnboarding() {
        SharedPreferences prefs = getSharedPreferences("maybeedgescanner", MODE_PRIVATE);
        if (prefs.getBoolean("onboarded_v2", false)) return;
        prefs.edit().putBoolean("onboarded_v2", true).apply();
        ui.postDelayed(() -> new AlertDialog.Builder(this)
                .setTitle("Welcome to MaybeEdgeScanner")
                .setMessage("1. Pick target corpora: Akamai, CloudFront, Fastly, or all bundled presets.\n\n" +
                        "2. Pick SNI hosts: SNI is the hostname used during TLS. Presets include useful defaults, and your custom hosts are merged in.\n\n" +
                        "3. Scan and filter: choose a single profile, Auto multi-step ladder, or Manual selected steps. Live Terminal shows progress; Edge Vault lets you sort by score, filter by SNI/cert/CDN/latency, and copy only visible rows.")
                .setPositiveButton("Start setup", (d, which) -> scrollTo(targetAnchor))
                .setNegativeButton("Guide", (d, which) -> showGuide())
                .show(), 550);
    }

    private void applyAccessibilityLabels() {
        targetsInput.setContentDescription("Targets input. Add domains, IP addresses, or CIDR ranges.");
        snisInput.setContentDescription("SNI hosts input. Add one or more TLS hostnames.");
        startButton.setContentDescription("Start scan with the selected targets, SNI hosts, profile, filters, and performance values.");
        stopButton.setContentDescription("Stop the active scan.");
        copyButton.setContentDescription("Copy filtered results using the selected clipboard format.");
        progress.setContentDescription("Scan progress");
        workflowSpinner.setContentDescription("Scan workflow. Choose single profile, automatic multi-step ladder, or manual selected steps.");
        visualModeSpinner.setContentDescription("Visual mode. Glass comfort is spacious, High contrast increases readability, Compact analyst shows denser result cards.");
    }

    private void showGuide() {
        new AlertDialog.Builder(this)
                .setTitle("MaybeEdgeScanner guide")
                .setMessage(
                        "What to scan\n" +
                        "Targets are IPs, domains, or CIDR ranges. Presets add bundled Akamai, AWS CloudFront, Fastly, other cloud, and community edge corpora.\n\n" +
                        "SNI hosts\n" +
                        "SNI is the hostname sent during TLS. Use preset SNIs or add your own domains. Enable All SNI hosts for deeper matching; leave it off for faster scans.\n\n" +
                        "Profiles\n" +
                        "Quick TCP checks reachability. Standard TLS verifies TLS. Deep HTTP + SNI adds HTTP HEAD checks. Verify CDN edge favors confirmed working CDN-like endpoints.\n\n" +
                        "Workflows\n" +
                        "Single runs one selected profile. Auto multi-step ladder runs TCP, then TLS, then HTTP/SNI, then CDN verification. Manual selected steps runs only the checked stages, useful when you want a focused pass without changing presets.\n\n" +
                        "Visual modes\n" +
                        "Glass comfort is the default card layout. High contrast avoids color-only status cues and increases card opacity. Compact analyst reduces spacing so more edges fit on screen.\n\n" +
                        "Performance parameters\n" +
                        "Total cap limits expanded CIDRs. Batch controls how many targets run per wave. Threads controls parallel sockets. Timeout ms controls how long each connect/TLS/HTTP attempt can wait.\n\n" +
                        "Filtering and sorting\n" +
                        "Use Working only, TLS/HTTP only, HTTP only, Known CDN only, TLS 1.3 only, SNI filter, CDN filter, certificate filter, max latency, and min score. Sort by Score to surface the strongest candidates.\n\n" +
                        "Copy and export\n" +
                        "Copy filtered uses exactly the rows currently visible after filters and sort. Choose line-separated IPs, comma-separated IPs, IP SNI pairs, CSV, or JSON.")
                .setPositiveButton("Got it", null)
                .show();
    }

    private void loadDefaults() {
        LinkedHashSet<String> targets = new LinkedHashSet<>(loadAsset("default_targets.txt"));
        targets.addAll(loadAsset("default_edges_extra.txt"));
        targets.addAll(communityEdgeCorpus("scan-corpora/maybepsiphon-edge-ips.txt", "scan-corpora/community-edge-cidrs-24.txt"));
        targetsInput.setText(joinLines(targets));
        LinkedHashSet<String> snis = new LinkedHashSet<>(loadAsset("default_snis.txt"));
        snis.addAll(loadAsset("scan-corpora/maybepsiphon-sni-hosts.txt"));
        snisInput.setText(joinLines(snis));
    }

    private void applyPreset(boolean append) {
        Preset preset = loadSelectedPreset();
        if (append) {
            LinkedHashSet<String> targets = new LinkedHashSet<>(lines(targetsInput.getText().toString()));
            targets.addAll(preset.targets);
            targetsInput.setText(joinLines(targets));
            LinkedHashSet<String> snis = new LinkedHashSet<>(lines(snisInput.getText().toString()));
            snis.addAll(preset.snis);
            snisInput.setText(joinLines(snis));
        } else {
            targetsInput.setText(joinLines(preset.targets));
            snisInput.setText(joinLines(preset.snis));
        }
        String summary = preset.name + ": " + preset.targets.size() + " target tokens, " + preset.snis.size() +
                " SNI | " + preset.detail + " | Sampling applies when you press Replace/Append; Total cap applies after CIDR expansion.";
        presetSummaryView.setText(summary);
        updateScanPlanPreview();
        toast((append ? "Appended " : "Loaded ") + summary);
    }

    private Preset loadSelectedPreset() {
        int selected = presetSpinner.getSelectedItemPosition();
        Preset p = new Preset(String.valueOf(presetSpinner.getSelectedItem()));
        p.snis.addAll(loadAsset("default_snis.txt"));
        p.snis.addAll(loadAsset("scan-corpora/maybepsiphon-sni-hosts.txt"));
        if (selected == 0 || selected == 6) {
            int count = intValue(communitySampleInput, 0);
            addAll(p, "app defaults", sampleSource(loadAsset("default_targets.txt"), count));
            addAll(p, "extra edges", sampleSource(loadAsset("default_edges_extra.txt"), count));
            addAll(p, "community tested /24s", sampleSource(communityEdgeCorpus("scan-corpora/maybepsiphon-edge-ips.txt", "scan-corpora/community-edge-cidrs-24.txt"), count));
        }
        if (selected == 1 || selected == 6) {
            int count = intValue(akamaiSampleInput, 0);
            addAll(p, "Akamai AS20940", sampleSource(loadAssetTokens("scan-corpora/akamai-AS20940.json"), count));
            addAll(p, "Akamai 184.x hosts", sampleSource(loadAsset("scan-corpora/akamai-hosts-184x.txt"), count));
            addRelevantSni(p.snis, "akamai");
        }
        if (selected == 2 || selected == 6) {
            addAll(p, "AWS CloudFront", sampleSource(loadAssetTokens("scan-corpora/aws-cloudfront-ranges.txt"), intValue(cloudfrontSampleInput, 0)));
            addRelevantSni(p.snis, "aws");
            addRelevantSni(p.snis, "cloudfront");
        }
        if (selected == 3 || selected == 6) {
            addAll(p, "Fastly AS54113", sampleSource(loadAssetTokens("scan-corpora/fastly-AS54113.json"), intValue(fastlySampleInput, 0)));
            addRelevantSni(p.snis, "fastly");
        }
        if (selected == 4 || selected == 6) {
            addAll(p, "Cloudflare", sampleSource(loadAssetTokens("scan-corpora/cloudflare-ranges.txt"), intValue(cloudflareSampleInput, 0)));
            addRelevantSni(p.snis, "cloudflare");
        }
        if (selected == 5 || selected == 6) {
            int count = intValue(otherCdnSampleInput, 0);
            addAll(p, "GitHub Pages", sampleSource(loadAssetTokens("scan-corpora/github-pages-ranges.txt"), count));
            addAll(p, "Azure Front Door", sampleSource(loadAssetTokens("scan-corpora/azure-frontdoor-ranges.txt"), count));
            addAll(p, "Google CDN", sampleSource(loadAssetTokens("scan-corpora/google-cdn-ranges.txt"), count));
            addAll(p, "Bunny CDN", sampleSource(loadAssetTokens("scan-corpora/bunny-ranges.txt"), count));
            addAll(p, "StackPath/Edgio", sampleSource(loadAssetTokens("scan-corpora/stackpath-edgio-ranges.txt"), count));
            addAll(p, "conventional CDN/cloud ranges", sampleSource(loadAssetTokens("scan-corpora/other-cloud-ranges.txt"), count));
            addRelevantSni(p.snis, "cloudflare");
            addRelevantSni(p.snis, "mapbox");
        }
        return p;
    }

    private LinkedHashSet<String> sampleSource(Collection<String> values, int count) {
        ArrayList<String> list = new ArrayList<>(values);
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (count <= 0) {
            out.addAll(list);
            return out;
        }
        if (list.isEmpty()) return out;
        for (int i = 0; i < count; i++) {
            String token = list.get((int) Math.floor(i * (list.size() / (double) count)));
            out.add(sampleOneExpandedTarget(token, i));
        }
        return out;
    }

    private static String sampleOneExpandedTarget(String token, int index) {
        String clean = cleanToken(token);
        if (clean.contains("/")) return sampleCidr(clean, index);
        if (clean.contains("-")) return sampleRange(clean, index);
        return clean;
    }

    private static String sampleCidr(String cidr, int index) {
        try {
            String[] p = cidr.split("/", 2);
            if (p.length != 2 || !isIp(p[0])) return cidr;
            int prefix = Integer.parseInt(p[1]);
            if (p[0].contains(":")) {
                List<String> sample = expandIpv6Cidr(p[0], prefix, Math.max(2, (index % 1024) + 2));
                return sample.isEmpty() ? cidr : sample.get(sample.size() - 1);
            }
            long ip = ipv4ToLong(p[0]);
            if (prefix < 0 || prefix > 32) return cidr;
            long mask = prefix == 0 ? 0 : (0xffffffffL << (32 - prefix)) & 0xffffffffL;
            long start = ip & mask;
            long size = 1L << (32 - prefix);
            long usable = Math.max(1, size - (size > 2 ? 2 : 0));
            long offset = size > 2 ? 1 + Math.floorMod((long) index * 7919L, usable) : Math.floorMod(index, usable);
            return longToIpv4(start + offset);
        } catch (Exception ignored) {
            return cidr;
        }
    }

    private static String sampleRange(String range, int index) {
        try {
            String[] p = range.split("-", 2);
            if (p.length != 2 || !isIp(p[0]) || !isIp(p[1]) || p[0].contains(":") || p[1].contains(":")) return range;
            long start = ipv4ToLong(p[0]);
            long end = ipv4ToLong(p[1]);
            if (end < start) return range;
            long size = end - start + 1;
            return longToIpv4(start + Math.floorMod((long) index * 7919L, size));
        } catch (Exception ignored) {
            return range;
        }
    }

    private LinkedHashSet<String> communityEdgeCorpus(String ipAsset, String cidrAsset) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String value : loadAsset(ipAsset)) out.add(toIpv4Cidr24(value));
        out.addAll(loadAsset(cidrAsset));
        return out;
    }

    private void addAll(Preset preset, String label, Collection<String> values) {
        int before = preset.targets.size();
        preset.targets.addAll(values);
        int added = preset.targets.size() - before;
        int requested = values == null ? 0 : values.size();
        int skipped = Math.max(0, requested - added);
        if (preset.detail.length() > 0) preset.detail += " | ";
        preset.detail += label + " sampled " + requested + ", added " + added;
        if (skipped > 0) preset.detail += ", deduped " + skipped;
    }

    private void addRelevantSni(LinkedHashSet<String> snis, String needle) {
        for (String sni : loadAsset("scan-corpora/maybepsiphon-sni-hosts.txt")) {
            if (sni.toLowerCase(Locale.US).contains(needle)) snis.add(sni);
        }
    }

    private void startScan() {
        if (executor != null && !executor.isShutdown()) return;
        stop.set(false);
        allResults.clear();
        checkedTargets.set(0);
        scanStartedAt = System.currentTimeMillis();
        resultList.removeAllViews();
        logView.setText("");
        bestView.setText("Best result will appear here");

        List<String> targets = cap(expandTargets(lines(targetsInput.getText().toString())), intValue(totalInput, 72000));
        List<String> snis = lines(snisInput.getText().toString());
        List<Integer> ports = parsePorts(portsInput.getText().toString());
        if (targets.isEmpty() || ports.isEmpty()) {
            toast("Targets and ports are required");
            return;
        }
        if (snis.isEmpty()) snis = Collections.singletonList("");
        List<Integer> workflowProfiles = selectedWorkflowProfiles();
        boolean allSniPreference = multiSni.isChecked();
        boolean suppressNoisyLogs = hideNoisyLogs.isChecked();
        String httpPath = pathInput.getText().toString();
        int tlsMode = tlsModeSpinner == null ? 0 : tlsModeSpinner.getSelectedItemPosition();
        totalTargets = estimateAttemptUnits(targets.size(), snis.size(), ports.size(), workflowProfiles, allSniPreference);
        int batch = Math.max(1, intValue(batchInput, 12000));
        int threads = Math.max(1, intValue(threadsInput, 64));
        int timeout = Math.max(1, intValue(timeoutInput, 3000));

        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        status.setText("Running");
        appendLog("Scan started: expanded_targets=" + targets.size() + ", sni_hosts=" + snis.size() +
                ", probe_units=" + totalTargets + ", ports=" + ports + ", batch=" + batch +
                ", threads=" + threads + ", workflow=" + workflowSpinner.getSelectedItem() +
                ", steps=" + workflowLabels(workflowProfiles));
        appendResourceWarnings(threads, batch, timeout, targets.size());
        executor = Executors.newFixedThreadPool(threads);
        List<String> finalSnis = snis;
        new Thread(() -> runWorkflow(targets, finalSnis, ports, batch, timeout, workflowProfiles,
                allSniPreference, httpPath, tlsMode, suppressNoisyLogs), "scan-orchestrator").start();
    }

    private List<Integer> selectedWorkflowProfiles() {
        ArrayList<Integer> profiles = new ArrayList<>();
        int mode = workflowSpinner == null ? 0 : workflowSpinner.getSelectedItemPosition();
        if (mode == 1) {
            profiles.add(0);
            profiles.add(1);
            profiles.add(2);
            profiles.add(3);
        } else if (mode == 2) {
            if (stepTcp != null && stepTcp.isChecked()) profiles.add(0);
            if (stepTls != null && stepTls.isChecked()) profiles.add(1);
            if (stepHttp != null && stepHttp.isChecked()) profiles.add(2);
            if (stepVerify != null && stepVerify.isChecked()) profiles.add(3);
        } else {
            profiles.add(profileSpinner == null ? 1 : profileSpinner.getSelectedItemPosition());
        }
        if (profiles.isEmpty()) profiles.add(profileSpinner == null ? 1 : profileSpinner.getSelectedItemPosition());
        return profiles;
    }

    private String workflowLabels(List<Integer> profiles) {
        ArrayList<String> labels = new ArrayList<>();
        for (int profile : profiles) labels.add(profileName(profile));
        return joinComma(labels);
    }

    private String profileName(int profile) {
        switch (profile) {
            case 0: return "TCP";
            case 1: return "TLS";
            case 2: return "HTTP";
            case 3: return "Verify";
            default: return "Profile " + profile;
        }
    }

    private void runWorkflow(List<String> targets, List<String> snis, List<Integer> ports, int batchSize,
                             int timeout, List<Integer> profiles, boolean allSniPreference,
                             String httpPath, int tlsMode, boolean suppressNoisyLogs) {
        for (int i = 0; i < profiles.size() && !stop.get(); i++) {
            int profile = profiles.get(i);
            boolean allSni = allSniPreference || profile >= 2;
            appendLog("Workflow step " + (i + 1) + "/" + profiles.size() + ": " + profileName(profile) +
                    (allSni ? " with multi-SNI" : " with primary SNI"));
            runBatches(targets, snis, ports, batchSize, timeout, profile, allSni, httpPath, tlsMode, suppressNoisyLogs);
        }
        executor.shutdownNow();
        ui.post(() -> {
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
            status.setText(stop.get() ? "Stopped" : "Ready");
            appendLog((stop.get() ? "Stopped" : "Complete") + " in " + elapsed());
            if (!stop.get()) saveLocalObservationHistory();
            updateProgress();
            renderResults();
        });
    }

    private void runBatches(List<String> targets, List<String> snis, List<Integer> ports, int batchSize,
                            int timeout, int profile, boolean allSni, String httpPath, int tlsMode, boolean suppressNoisyLogs) {
        int batches = (targets.size() + batchSize - 1) / batchSize;
        for (int start = 0, batchNo = 1; start < targets.size() && !stop.get(); start += batchSize, batchNo++) {
            List<String> batch = targets.subList(start, Math.min(targets.size(), start + batchSize));
            appendLog(profileName(profile) + " batch " + batchNo + "/" + batches + ": " + batch.size() + " targets");
            CountDownLatch latch = new CountDownLatch(batch.size());
            for (String target : batch) {
                executor.submit(() -> {
                    try { scanTarget(target, snis, ports, timeout, profile, allSni, httpPath, tlsMode, suppressNoisyLogs); }
                    finally {
                        updateProgress();
                        latch.countDown();
                    }
                });
            }
            try { latch.await(); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
        }
    }

    private void appendResourceWarnings(int threads, int batch, int timeout, int targets) {
        if (threads >= 256 || batch >= 72000 || targets >= 72000) {
            appendLog("Warning: high-volume scan selected. Android may throttle sockets, battery, or thermal performance.");
        }
        if (timeout < 250) {
            appendLog("Warning: very low timeout may miss slow-but-working edges.");
        }
    }

    private void scanTarget(String target, List<String> snis, List<Integer> ports, int timeout, int profile,
                            boolean allSni, String httpPath, int tlsMode, boolean suppressNoisyLogs) {
        if (stop.get()) return;
        List<String> ips = resolve(target);
        if (ips.isEmpty()) {
            addResult(Result.down(target, "", 0, "", "dns_failed"), suppressNoisyLogs);
            return;
        }
        for (String ip : ips) {
            if (stop.get()) return;
            for (int port : ports) {
                Result base = new Result(target, ip, port, "");
                base.tcp(timeout);
                if (profile == 0 || !base.tcpPass) {
                    addResult(base.finish(), suppressNoisyLogs);
                    continue;
                }
                List<String> candidates = allSni ? snis : Collections.singletonList(isIp(target) ? first(snis) : target);
                for (String sni : candidates) {
                    if (stop.get()) return;
                    if (sni == null || sni.trim().isEmpty()) continue;
                    Result r = new Result(target, ip, port, sni.trim());
                    r.tcpPass = base.tcpPass;
                    r.tcpLatencyMs = base.tcpLatencyMs;
                    r.tls(timeout, tlsMode);
                    if (profile >= 2 && r.tlsPass) r.http(timeout, httpPath, tlsMode);
                    addResult(r.finish(), suppressNoisyLogs);
                    if (profile == 3 && r.httpPass) break;
                }
            }
        }
    }

    private void addResult(Result r, boolean suppressNoisyLogs) {
        allResults.add(r);
        checkedTargets.incrementAndGet();
        if (!suppressNoisyLogs && (r.tlsPass || r.httpPass || allResults.size() % 200 == 0)) {
            appendLog("Result " + r.address() + " sni=" + dash(r.sni) + " tcp=" + r.tcpPass +
                    " tls=" + r.tlsPass + " http=" + r.httpPass + " q=" + Math.round(r.quality));
        }
        scheduleRender();
    }

    private void updateProgress() {
        ui.post(() -> {
            progress.setMax(Math.max(1, totalTargets));
            int checked = Math.min(checkedTargets.get(), Math.max(1, totalTargets));
            progress.setProgress(checked);
            Stats s = stats();
            metrics.setText(checked + " / " + totalTargets + " probe units | rows " + allResults.size() + " | TCP " + s.tcp +
                    " | TLS " + s.tls + " | HTTP " + s.http + " | Q " + Math.round(s.bestQuality) + " | " + elapsed());
            countersView.setText("Down " + s.down + " | timeout " + s.timeout + " | reset " + s.reset +
                    " | cert " + s.cert + " | DNS " + s.dns + " | " + resourceLine());
            if (s.best != null) bestView.setText("Best: " + s.best.summary());
        });
    }

    private void scheduleRender() {
        if (!renderQueued.compareAndSet(false, true)) return;
        ui.postDelayed(() -> {
            renderQueued.set(false);
            renderResults();
        }, 900);
    }

    private void renderResults() {
        if (resultList == null) return;
        List<Result> snapshot = filteredResults();
        if (batteryFriendlyMode()) {
            if (analyticsPanel != null) analyticsPanel.setVisibility(View.GONE);
        } else {
            if (analyticsPanel != null) analyticsPanel.setVisibility(View.VISIBLE);
            updateAnalytics(snapshot);
        }
        renderStableHistoryPanel();
        resultList.removeAllViews();
        if (snapshot.isEmpty()) {
            resultList.addView(emptyVaultView());
            return;
        }
        resultList.addView(resultSummaryStrip(snapshot));
        if (!batteryFriendlyMode() && vaultModeSpinner != null && vaultModeSpinner.getSelectedItemPosition() == 1) {
            resultList.addView(heatmapView(snapshot));
            return;
        }
        int limit = Math.min(intValue(resultLimitInput, 250), snapshot.size());
        if (batteryFriendlyMode()) limit = Math.min(limit, 75);
        for (int i = 0; i < limit; i++) resultList.addView(resultView(snapshot.get(i)));
    }

    private View resultSummaryStrip(List<Result> rows) {
        int working = 0;
        long latencySum = 0, best = Long.MAX_VALUE;
        int latencyCount = 0;
        for (Result r : rows) {
            if (r.working()) working++;
            long latency = r.totalLatency();
            if (latency > 0) {
                latencySum += latency;
                latencyCount++;
                best = Math.min(best, latency);
            }
        }
        int success = rows.isEmpty() ? 0 : Math.round(working * 100f / rows.size());
        String line = "Visible results: " + rows.size() +
                " | alive/working " + working +
                " | success " + success + "%" +
                " | best " + (best == Long.MAX_VALUE ? "--" : best + "ms") +
                " | avg " + (latencyCount == 0 ? "--" : Math.round(latencySum / (float) latencyCount) + "ms") +
                " | filter " + (filterWorking.isChecked() ? "alive only" : "all");
        TextView v = panelText(line);
        v.setTypeface(Typeface.MONOSPACE);
        return v;
    }

    private View emptyVaultView() {
        LinearLayout card = column();
        card.setPadding(dp(16), dp(14), dp(16), dp(14));
        card.setBackground(glassBg(Color.rgb(10, 28, 41), Color.argb(130, 255, 255, 255)));
        TextView icon = text("⌕", 34, BLUE, true);
        icon.setGravity(Gravity.CENTER);
        card.addView(icon);
        card.addView(text("No visible edges yet", 16, Color.WHITE, true));
        card.addView(text("Pick provider cards, review the valid target chips, then start the Auto multi-step ladder. If a scan already ran, loosen filters to reveal hidden rows.", 12, Color.rgb(205, 226, 238), false));
        Button cta = button("Go to Target Setup", Color.rgb(22, 54, 72), Color.WHITE);
        cta.setOnClickListener(v -> scrollTo(targetAnchor));
        card.addView(cta);
        return card;
    }

    private void updateAnalytics(List<Result> rows) {
        if (analyticsPanel == null) return;
        analyticsPanel.removeAllViews();
        analyticsPanel.addView(text("Live analytics", 15, Color.WHITE, true));
        if (rows == null || rows.isEmpty()) {
            analyticsPanel.addView(text("Visible-result charts appear here while the scan runs. The dashboard respects your active filters, sort, and best-per-IP setting.", 12, MUTED, false));
            return;
        }
        int total = rows.size(), http = 0, tls = 0, tcp = 0, down = 0;
        int fast = 0, medium = 0, slow = 0, verySlow = 0;
        Map<String, Integer> cdns = new TreeMap<>();
        for (Result r : rows) {
            if (r.httpPass) http++;
            else if (r.tlsPass) tls++;
            else if (r.tcpPass) tcp++;
            else down++;
            long latency = r.totalLatency();
            if (latency > 0 && latency < 120) fast++;
            else if (latency > 0 && latency < 300) medium++;
            else if (latency > 0 && latency < 700) slow++;
            else if (latency > 0) verySlow++;
            String cdn = r.cdn == null || r.cdn.trim().isEmpty() ? "UNKNOWN" : r.cdn.toUpperCase(Locale.US);
            cdns.put(cdn, cdns.containsKey(cdn) ? cdns.get(cdn) + 1 : 1);
        }
        analyticsPanel.addView(text("Status distribution", 12, highContrastMode() ? Color.WHITE : MUTED, true));
        analyticsPanel.addView(metricBar("HTTP", http, total, Color.rgb(66, 230, 170)));
        analyticsPanel.addView(metricBar("TLS", tls, total, Color.rgb(55, 212, 255)));
        analyticsPanel.addView(metricBar("TCP", tcp, total, Color.rgb(255, 204, 100)));
        analyticsPanel.addView(metricBar("Down", down, total, Color.rgb(255, 112, 135)));
        analyticsPanel.addView(text("Latency histogram", 12, highContrastMode() ? Color.WHITE : MUTED, true));
        analyticsPanel.addView(metricBar("<120ms", fast, total, Color.rgb(66, 230, 170)));
        analyticsPanel.addView(metricBar("120-299ms", medium, total, Color.rgb(55, 212, 255)));
        analyticsPanel.addView(metricBar("300-699ms", slow, total, Color.rgb(255, 204, 100)));
        analyticsPanel.addView(metricBar("700ms+", verySlow, total, Color.rgb(255, 112, 135)));
        analyticsPanel.addView(text("CDN mix", 12, highContrastMode() ? Color.WHITE : MUTED, true));
        ArrayList<Map.Entry<String, Integer>> groups = new ArrayList<>(cdns.entrySet());
        groups.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));
        for (int i = 0; i < Math.min(5, groups.size()); i++) {
            Map.Entry<String, Integer> e = groups.get(i);
            analyticsPanel.addView(metricBar(e.getKey(), e.getValue(), total, cdnColor(e.getKey())));
        }
        analyticsPanel.addView(text("Provider health", 12, highContrastMode() ? Color.WHITE : MUTED, true));
        for (ProviderHealth h : providerHealth(rows)) {
            analyticsPanel.addView(text(h.label(), 11, Color.WHITE, false));
        }
    }

    private List<ProviderHealth> providerHealth(List<Result> rows) {
        Map<String, ProviderHealth> map = new TreeMap<>();
        for (Result r : rows) {
            String cdn = r.cdn == null || r.cdn.trim().isEmpty() ? "UNKNOWN" : r.cdn.toUpperCase(Locale.US);
            ProviderHealth h = map.get(cdn);
            if (h == null) {
                h = new ProviderHealth(cdn);
                map.put(cdn, h);
            }
            h.total++;
            if (r.working()) h.working++;
            long latency = r.totalLatency();
            if (latency > 0) {
                h.latencySum += latency;
                h.latencyCount++;
            }
            String reason = r.reason == null ? "" : r.reason.toLowerCase(Locale.US);
            if (reason.contains("timeout")) h.timeout++;
            if (reason.contains("reset")) h.reset++;
        }
        ArrayList<ProviderHealth> out = new ArrayList<>(map.values());
        out.sort((a, b) -> Integer.compare(b.working, a.working));
        return out.subList(0, Math.min(6, out.size()));
    }

    private View metricBar(String label, int value, int total, int color) {
        LinearLayout box = column();
        box.setPadding(0, dp(3), 0, dp(3));
        String textValue = label + "  " + value + "/" + Math.max(1, total) + "  " + Math.round(value * 100f / Math.max(1, total)) + "%";
        box.addView(text(textValue, compactMode() ? 10 : 11, Color.WHITE, false));
        FrameLayout track = new FrameLayout(this);
        track.setBackground(glassBg(Color.rgb(25, 38, 49), Color.argb(60, 255, 255, 255)));
        TextView fill = text("", 1, Color.TRANSPARENT, false);
        fill.setBackground(glassBg(color, Color.argb(140, 255, 255, 255)));
        FrameLayout.LayoutParams fillLp = new FrameLayout.LayoutParams(Math.max(dp(3), Math.round(dp(220) * value / (float)Math.max(1, total))), dp(7));
        track.addView(fill, fillLp);
        box.addView(track, new LinearLayout.LayoutParams(-1, dp(7)));
        box.setContentDescription(textValue);
        return box;
    }

    private int cdnColor(String cdn) {
        String c = cdn == null ? "" : cdn.toLowerCase(Locale.US);
        if (c.contains("cloudflare")) return Color.rgb(255, 156, 67);
        if (c.contains("fastly")) return Color.rgb(226, 74, 94);
        if (c.contains("akamai")) return Color.rgb(54, 166, 255);
        if (c.contains("aws") || c.contains("cloudfront")) return Color.rgb(255, 204, 100);
        return BLUE;
    }

    private View heatmapView(List<Result> rows) {
        LinearLayout panel = column();
        panel.setPadding(dp(12), dp(10), dp(12), dp(12));
        panel.setBackground(glassBg(Color.rgb(8, 24, 36), Color.argb(120, 255, 255, 255)));
        panel.addView(text("CIDR heatmap overview", 15, Color.WHITE, true));
        panel.addView(text("Each tile is a filtered result: green HTTP, cyan TLS, amber TCP, red failed.", 12, MUTED, false));
        int columns = 16;
        LinearLayout row = null;
        int limit = Math.min(rows.size(), 512);
        for (int i = 0; i < limit; i++) {
            if (i % columns == 0) {
                row = row();
                row.setGravity(Gravity.START);
                panel.addView(row);
            }
            Result r = rows.get(i);
            TextView tile = text("", 1, Color.TRANSPARENT, false);
            tile.setMinHeight(dp(15));
            tile.setMinWidth(dp(15));
            tile.setBackground(glassBg(tileColor(r), Color.argb(70, 255, 255, 255)));
            tile.setContentDescription(r.summary());
            tile.setOnClickListener(v -> copyOne(r));
            row.addView(tile, heatTileLp());
        }
        if (rows.size() > limit) panel.addView(text("Showing first " + limit + " of " + rows.size() + " filtered results.", 11, MUTED, false));
        return panel;
    }

    private LinearLayout.LayoutParams heatTileLp() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(dp(16), dp(16));
        lp.setMargins(dp(2), dp(2), dp(2), dp(2));
        return lp;
    }

    private int tileColor(Result r) {
        if (r.httpPass) return Color.rgb(20, 160, 105);
        if (r.tlsPass) return Color.rgb(17, 132, 170);
        if (r.tcpPass) return Color.rgb(156, 119, 26);
        return Color.rgb(112, 39, 52);
    }

    private List<Result> filteredResults() {
        List<Result> snapshot;
        synchronized (allResults) { snapshot = new ArrayList<>(allResults); }
        int maxLatency = intValue(maxLatencyInput, 0);
        String cdn = cdnFilterInput.getText().toString().trim().toLowerCase(Locale.US);
        String cert = certFilterInput.getText().toString().trim().toLowerCase(Locale.US);
        String sni = sniFilterInput.getText().toString().trim().toLowerCase(Locale.US);
        int minQuality = intValue(minQualityInput, 0);
        snapshot.removeIf(r -> (filterWorking.isChecked() && !r.working()) ||
                (filterSni.isChecked() && !(r.tlsPass || r.httpPass)) ||
                (requireHttp.isChecked() && !r.httpPass) ||
                (requireKnownCdn.isChecked() && "UNKNOWN".equalsIgnoreCase(r.cdn)) ||
                (requireTls13.isChecked() && !r.tlsVersion.contains("1.3")) ||
                (maxLatency > 0 && (r.totalLatency() <= 0 || r.totalLatency() > maxLatency)) ||
                (minQuality > 0 && r.quality < minQuality) ||
                (!cdn.isEmpty() && !r.cdn.toLowerCase(Locale.US).contains(cdn)) ||
                (!sni.isEmpty() && !r.sni.toLowerCase(Locale.US).contains(sni)) ||
                (!cert.isEmpty() && !r.tlsCert.toLowerCase(Locale.US).contains(cert)));
        if (bestPerIp.isChecked()) {
            Map<String, Result> best = new LinkedHashMap<>();
            for (Result r : snapshot) {
                String key = r.ip + ":" + r.port;
                Result old = best.get(key);
                if (old == null || r.quality > old.quality) best.put(key, r);
            }
            snapshot = new ArrayList<>(best.values());
        }
        int sort = sortSpinner.getSelectedItemPosition();
        if (sort == 1) snapshot.sort(Comparator.comparingLong(r -> r.totalLatency() > 0 ? r.totalLatency() : Long.MAX_VALUE));
        else if (sort == 2) snapshot.sort((a, b) -> Double.compare(b.quality, a.quality));
        else if (sort == 3) snapshot.sort(Comparator.comparing((Result r) -> r.cdn).thenComparing((a, b) -> Double.compare(b.quality, a.quality)));
        else if (sort == 4) snapshot.sort(Comparator.comparing((Result r) -> r.sni));
        else if (sort == 5) snapshot.sort((a, b) -> Boolean.compare(b.httpPass, a.httpPass) != 0 ? Boolean.compare(b.httpPass, a.httpPass) : Double.compare(b.quality, a.quality));
        else if (sort == 6) snapshot.sort((a, b) -> Boolean.compare(b.tlsPass, a.tlsPass) != 0 ? Boolean.compare(b.tlsPass, a.tlsPass) : Double.compare(b.quality, a.quality));
        else Collections.reverse(snapshot);
        return snapshot;
    }

    private View resultView(Result r) {
        LinearLayout card = column();
        card.setPadding(dp(compactMode() ? 8 : 10), dp(compactMode() ? 5 : 8), dp(compactMode() ? 8 : 10), dp(compactMode() ? 5 : 8));
        int fill = r.httpPass ? Color.rgb(9, 48, 38) : r.tlsPass ? Color.rgb(16, 45, 37) :
                r.tcpPass ? Color.rgb(43, 36, 16) : Color.rgb(37, 20, 28);
        card.setBackground(glassBg(fill, r.working() ? Color.argb(145, 55, 212, 255) : Color.argb(95, 255, 255, 255)));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.setMargins(0, dp(compactMode() ? 4 : 7), 0, 0);
        card.setLayoutParams(lp);
        TextView top = text(r.address() + "  " + dash(r.sni), compactMode() ? 12 : 13, Color.WHITE, true);
        top.setTypeface(Typeface.MONOSPACE);
        LinearLayout signal = row();
        signal.setGravity(Gravity.START);
        signal.addView(statusDot("TCP", r.tcpPass, Color.rgb(54, 166, 255)), smallChipLp());
        signal.addView(statusDot("TLS", r.tlsPass, Color.rgb(66, 230, 170)), smallChipLp());
        signal.addView(statusDot("HTTP", r.httpPass, Color.rgb(255, 204, 100)), smallChipLp());
        signal.addView(statusDot(r.cdn, !"UNKNOWN".equalsIgnoreCase(r.cdn), BLUE), smallChipLp());
        TextView body = text(latencySparkline(r) + "  " + r.totalLatency() + "ms | HTTP " + r.httpStatus +
                " | Q " + Math.round(r.quality), 12, Color.WHITE, false);
        body.setTypeface(Typeface.MONOSPACE);
        card.addView(top);
        card.addView(signal);
        card.addView(body);
        if (!compactMode() && !r.tlsVersion.isEmpty()) card.addView(text(r.tlsVersion + " | " + r.tlsCipher + " | ALPN " + dash(r.alpn) + " | TLS " + dash(r.tlsProfile), 11, highContrastMode() ? Color.WHITE : MUTED, false));
        if (!compactMode() && r.http3Hint) card.addView(text("HTTP/3 advertised via Alt-Svc: " + trim(r.altSvc, 120), 11, Color.rgb(150, 232, 255), false));
        if (!compactMode() && !r.tlsCert.isEmpty()) card.addView(text(trim(r.tlsCert, 120), 11, highContrastMode() ? Color.WHITE : MUTED, false));
        if (!r.reason.isEmpty()) card.addView(text(r.reason, 11, Color.rgb(255, 180, 180), false));
        card.setOnClickListener(v -> copyOne(r));
        card.setContentDescription(r.summary());
        return card;
    }

    private TextView statusDot(String label, boolean on, int color) {
        String prefix = highContrastMode() ? (on ? "[on] " : "[off] ") : (on ? "● " : "○ ");
        TextView v = text(prefix + label, compactMode() ? 10 : 11, on ? Color.WHITE : (highContrastMode() ? Color.rgb(225, 235, 240) : MUTED), false);
        int offFill = highContrastMode() ? Color.rgb(46, 58, 70) : Color.rgb(27, 38, 49);
        int border = on ? Color.argb(210, 255, 255, 255) : Color.argb(highContrastMode() ? 145 : 70, 255, 255, 255);
        v.setBackground(glassBg(on ? color : offFill, border));
        v.setPadding(dp(compactMode() ? 5 : 7), dp(compactMode() ? 3 : 4), dp(compactMode() ? 5 : 7), dp(compactMode() ? 3 : 4));
        v.setContentDescription(label + (on ? " passed" : " not passed"));
        return v;
    }

    private String latencySparkline(Result r) {
        long[] values = {r.tcpLatencyMs, r.tlsLatencyMs, r.httpLatencyMs};
        StringBuilder sb = new StringBuilder();
        for (long value : values) {
            if (value <= 0) sb.append("-");
            else if (value < 120) sb.append("▁");
            else if (value < 300) sb.append("▃");
            else if (value < 700) sb.append("▅");
            else sb.append("█");
        }
        return sb.toString();
    }

    private void copyOne(Result r) {
        copyWithFallback("result", r.address() + " " + r.sni + " q=" + Math.round(r.quality));
    }

    private void copySelectedFormat() {
        List<Result> rows = filteredResults();
        int format = exportSpinner.getSelectedItemPosition();
        StringBuilder sb = new StringBuilder();
        try {
            if (format == 3) {
                sb.append("target,ip,port,sni,tcp,tls,http,http_status,latency_ms,alpn,tls_profile,http3_hint,cdn,quality,reason\n");
            } else if (format == 4) {
                JSONArray arr = new JSONArray();
                for (Result r : rows) if (r.working()) arr.put(r.json());
                copyWithFallback("JSON", arr.toString(2));
                return;
            }
            LinkedHashSet<String> dedupe = new LinkedHashSet<>();
            for (Result r : rows) if (r.working()) {
                if (format == 0) dedupe.add(r.ip);
                else if (format == 1) dedupe.add(r.ip);
                else if (format == 2) dedupe.add(r.address() + " " + r.sni);
                else if (format == 3) sb.append(r.csv()).append('\n');
            }
            if (format == 0) sb.append(joinLines(dedupe));
            else if (format == 1) sb.append(joinComma(dedupe));
            else if (format == 2) sb.append(joinLines(dedupe));
            copyWithFallback(String.valueOf(exportSpinner.getSelectedItem()), sb.toString());
        } catch (Exception e) {
            toast("Copy failed: " + e.getMessage());
        }
    }

    private void copyWorking(boolean csv) {
        List<Result> rows = filteredResults();
        StringBuilder sb = new StringBuilder();
        if (csv) sb.append("target,ip,port,sni,tcp,tls,http,http_status,latency_ms,alpn,tls_profile,http3_hint,cdn,quality,reason\n");
        for (Result r : rows) if (r.working()) {
            if (csv) sb.append(r.csv()).append('\n');
            else sb.append(r.address()).append(' ').append(r.sni).append(" q=").append(Math.round(r.quality))
                    .append(" cdn=").append(r.cdn).append('\n');
        }
        copyWithFallback(csv ? "CSV" : "working results", sb.toString());
    }

    private void copyWithFallback(String label, String content) {
        if (content == null || content.trim().isEmpty()) {
            toast("Nothing to copy");
            return;
        }
        try {
            clip(content);
            if (copyFallbackView != null) {
                copyFallbackView.setText("Manual copy fallback (" + label + ")\n" + content);
            }
            toast("Copied " + label);
        } catch (Exception e) {
            showManualCopyDialog("Manual copy fallback", content);
            toast("Clipboard unavailable; manual copy opened");
        }
    }

    private void showManualCopyDialog(String title, String content) {
        EditText box = new EditText(this);
        box.setText(content == null ? "" : content);
        box.setTextIsSelectable(true);
        box.setSingleLine(false);
        box.setMinLines(6);
        box.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        new AlertDialog.Builder(this)
                .setTitle(title)
                .setView(box)
                .setPositiveButton("Close", null)
                .show();
    }

    private void exportJson() {
        try {
            JSONArray arr = new JSONArray();
            for (Result r : filteredResults()) arr.put(r.json());
            File out = new File(getExternalFilesDir(null), "maybe_edge_scan_" + System.currentTimeMillis() + ".json");
            try (Writer w = new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8)) {
                w.write(arr.toString(2));
            }
            toast("Exported: " + out.getAbsolutePath());
        } catch (Exception e) {
            toast("Export failed: " + e.getMessage());
        }
    }

    private void clearResults() {
        stop.set(true);
        allResults.clear();
        checkedTargets.set(0);
        totalTargets = 0;
        progress.setProgress(0);
        resultList.removeAllViews();
        logView.setText("");
        metrics.setText("0 / 0 | TCP 0 | TLS 0 | HTTP 0 | Q 0");
        countersView.setText("Down 0 | timeout 0 | reset 0 | cert 0 | DNS 0 | " + resourceLine());
        bestView.setText("Best result will appear here");
        renderStableHistoryPanel();
    }

    private void saveLocalObservationHistory() {
        try {
            JSONObject root = new JSONObject(getSharedPreferences("maybeedgescanner", MODE_PRIVATE).getString("stable_history_v1", "{}"));
            synchronized (allResults) {
                LinkedHashSet<String> seenThisRun = new LinkedHashSet<>();
                for (Result r : allResults) if (r.working() && r.ip != null && !r.ip.isEmpty()) seenThisRun.add(r.ip + ":" + r.port);
                for (String key : seenThisRun) root.put(key, root.optInt(key, 0) + 1);
            }
            getSharedPreferences("maybeedgescanner", MODE_PRIVATE).edit().putString("stable_history_v1", root.toString()).apply();
        } catch (Exception ignored) {}
    }

    private void renderStableHistoryPanel() {
        if (stableHistoryPanel == null) return;
        stableHistoryPanel.removeAllViews();
        stableHistoryPanel.addView(text("Local stable observations", 15, Color.WHITE, true));
        stableHistoryPanel.addView(text("Counts are local pass history from this device, not a universal recommendation list.", 11, MUTED, false));
        try {
            JSONObject root = new JSONObject(getSharedPreferences("maybeedgescanner", MODE_PRIVATE).getString("stable_history_v1", "{}"));
            ArrayList<String> keys = new ArrayList<>();
            Iterator<String> it = root.keys();
            while (it.hasNext()) keys.add(it.next());
            keys.sort((a, b) -> Integer.compare(root.optInt(b, 0), root.optInt(a, 0)));
            LinearLayout chips = row();
            chips.setGravity(Gravity.START);
            int shown = 0;
            for (String key : keys) {
                int count = root.optInt(key, 0);
                if (count < 2) continue;
                chips.addView(chip(key + " x" + count, true), smallChipLp());
                if (++shown >= 8) break;
            }
            if (shown == 0) chips.addView(chip("Run scans to build local stability history", true), smallChipLp());
            stableHistoryPanel.addView(chips);
        } catch (Exception e) {
            stableHistoryPanel.addView(text("History unavailable", 11, MUTED, false));
        }
    }

    private Stats stats() {
        Stats s = new Stats();
        synchronized (allResults) {
            for (Result r : allResults) {
                if (r.tcpPass) s.tcp++;
                if (r.tlsPass) s.tls++;
                if (r.httpPass) s.http++;
                if (!r.working()) s.down++;
                String reason = r.reason.toLowerCase(Locale.US);
                if (reason.contains("timeout")) s.timeout++;
                if (reason.contains("reset")) s.reset++;
                if (reason.contains("cert")) s.cert++;
                if (reason.contains("dns")) s.dns++;
                if (r.quality > s.bestQuality) { s.bestQuality = r.quality; s.best = r; }
            }
        }
        return s;
    }

    private static class Stats {
        int tcp, tls, http, down, timeout, reset, cert, dns;
        double bestQuality;
        Result best;
    }

    private static class ProviderHealth {
        final String name;
        int total, working, timeout, reset, latencyCount;
        long latencySum;
        ProviderHealth(String name) { this.name = name; }
        String label() {
            int success = total == 0 ? 0 : Math.round(working * 100f / total);
            String avg = latencyCount == 0 ? "--" : Math.round(latencySum / (float) latencyCount) + "ms";
            return name + ": " + working + "/" + total + " pass, " + success + "%, avg " + avg +
                    ", timeout " + timeout + ", reset " + reset;
        }
    }

    private static class Result {
        final String target, ip, sni;
        final int port;
        boolean tcpPass, tlsPass, httpPass;
        long tcpLatencyMs, tlsLatencyMs, httpLatencyMs;
        int httpStatus;
        String tlsVersion = "", tlsCipher = "", tlsCert = "", certFingerprint = "", alpn = "", tlsProfile = "", altSvc = "", reason = "", cdn = "UNKNOWN";
        boolean http3Hint;
        double quality;

        Result(String target, String ip, int port, String sni) {
            this.target = target; this.ip = ip; this.port = port; this.sni = sni == null ? "" : sni;
        }
        static Result down(String target, String ip, int port, String sni, String reason) {
            Result r = new Result(target, ip, port, sni); r.reason = reason; return r.finish();
        }
        void tcp(int timeout) {
            long t = System.currentTimeMillis();
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(ip, port), timeout);
                tcpPass = true; tcpLatencyMs = System.currentTimeMillis() - t;
            } catch (Exception e) { reason = classify(e); }
        }
        void tls(int timeout, int tlsMode) {
            long t = System.currentTimeMillis();
            try {
                int activeMode = resolveTlsMode(tlsMode);
                tlsProfile = tlsProfileName(activeMode);
                String host = probeHost();
                Socket raw = new Socket();
                raw.connect(new InetSocketAddress(ip, port), timeout);
                raw.setSoTimeout(timeout);
                SSLSocket ssl = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, host, port, true);
                ssl.setSoTimeout(timeout);
                configureTlsSocket(ssl, activeMode, false);
                ssl.startHandshake();
                tlsPass = true; tlsLatencyMs = System.currentTimeMillis() - t;
                tlsVersion = ssl.getSession().getProtocol();
                tlsCipher = ssl.getSession().getCipherSuite();
                alpn = selectedAlpn(ssl);
                Certificate[] certs = ssl.getSession().getPeerCertificates();
                if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                    X509Certificate c = (X509Certificate) certs[0];
                    tlsCert = c.getSubjectX500Principal().getName();
                    certFingerprint = sha256(c.getEncoded());
                }
                ssl.close();
            } catch (Exception e) { reason = classify(e); }
        }
        void http(int timeout, String path, int tlsMode) {
            long t = System.currentTimeMillis();
            try {
                int activeMode = resolveTlsMode(tlsMode);
                if (tlsProfile.isEmpty()) tlsProfile = tlsProfileName(activeMode);
                String host = probeHost();
                Socket raw = new Socket();
                raw.connect(new InetSocketAddress(ip, port), timeout);
                raw.setSoTimeout(timeout);
                SSLSocket ssl = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, host, port, true);
                ssl.setSoTimeout(timeout);
                configureTlsSocket(ssl, activeMode, true);
                ssl.startHandshake();
                alpn = selectedAlpn(ssl);
                String safePath = path == null || path.trim().isEmpty() ? "/" : path.trim();
                if (!safePath.startsWith("/")) safePath = "/" + safePath;
                OutputStream out = ssl.getOutputStream();
                out.write(("HEAD " + safePath + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nUser-Agent: MaybeEdgeScanner/1.1\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                out.flush();
                BufferedReader reader = new BufferedReader(new InputStreamReader(ssl.getInputStream(), StandardCharsets.US_ASCII));
                String line = reader.readLine();
                httpStatus = parseStatus(line);
                String header;
                while ((header = reader.readLine()) != null && !header.isEmpty()) {
                    String lower = header.toLowerCase(Locale.US);
                    if (lower.startsWith("alt-svc:")) {
                        altSvc = header.substring(header.indexOf(':') + 1).trim();
                        http3Hint = altSvc.toLowerCase(Locale.US).contains("h3");
                    }
                }
                httpPass = httpStatus > 0 && httpStatus < 500;
                httpLatencyMs = System.currentTimeMillis() - t;
                ssl.close();
            } catch (Exception e) { reason = classify(e); }
        }
        Result finish() {
            cdn = detectCdn(ip, sni, tlsCert);
            double stage = (tcpPass ? 25 : 0) + (tlsPass ? 35 : 0) + (httpPass ? 25 : 0);
            long latency = totalLatency();
            double latencyScore = latency > 0 ? 10000.0 / (latency + 100.0) : 0;
            quality = stage + latencyScore * 0.25 + (tlsVersion.contains("1.3") ? 8 : 0) +
                    ("h2".equalsIgnoreCase(alpn) ? 5 : 0) + (http3Hint ? 4 : 0) +
                    (!certFingerprint.isEmpty() ? 8 : 0) + (cdn.equals("UNKNOWN") ? 0 : 6) - (reason.isEmpty() ? 0 : 7);
            return this;
        }
        boolean working() { return tcpPass || tlsPass || httpPass; }
        String address() { return ip + ":" + port; }
        long totalLatency() { return (tcpPass ? tcpLatencyMs : 0) + (tlsPass ? tlsLatencyMs : 0) + (httpPass ? httpLatencyMs : 0); }
        String summary() { return address() + " " + sni + " " + cdn + " q=" + Math.round(quality) + " " + totalLatency() + "ms"; }
        JSONObject json() throws Exception {
            JSONObject o = new JSONObject();
            o.put("target", target); o.put("ip", ip); o.put("port", port); o.put("sni", sni);
            o.put("tcpPass", tcpPass); o.put("tlsPass", tlsPass); o.put("httpPass", httpPass);
            o.put("tcpLatencyMs", tcpLatencyMs); o.put("tlsLatencyMs", tlsLatencyMs); o.put("httpLatencyMs", httpLatencyMs);
            o.put("httpStatus", httpStatus); o.put("tlsVersion", tlsVersion); o.put("tlsCipher", tlsCipher);
            o.put("alpn", alpn); o.put("tlsProfile", tlsProfile); o.put("altSvc", altSvc); o.put("http3Hint", http3Hint);
            o.put("tlsCert", tlsCert); o.put("certFingerprint", certFingerprint); o.put("cdn", cdn);
            o.put("quality", quality); o.put("reason", reason); return o;
        }
        String csv() {
            return q(target)+","+q(ip)+","+port+","+q(sni)+","+tcpPass+","+tlsPass+","+httpPass+","+httpStatus+","+
                    totalLatency()+","+q(alpn)+","+q(tlsProfile)+","+http3Hint+","+q(cdn)+","+Math.round(quality)+","+q(reason);
        }
        String probeHost() {
            String host = sni == null ? "" : sni.trim();
            return host.isEmpty() ? ip : host;
        }
    }

    private List<String> loadAsset(String name) {
        List<String> out = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(getAssets().open(name), StandardCharsets.UTF_8))) {
            String line; while ((line = br.readLine()) != null) if (!line.trim().isEmpty() && !line.trim().startsWith("#")) out.add(line.trim());
        } catch (IOException ignored) {}
        return out;
    }
    private LinkedHashSet<String> loadAssetTokens(String name) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String raw : loadAsset(name)) {
            String clean = raw.replace("[", " ").replace("]", " ").replace("\"", " ").replace(",", " ").trim();
            for (String token : clean.split("\\s+")) {
                token = cleanToken(token);
                if (!token.isEmpty() && validTargetToken(token)) out.add(token);
            }
        }
        return out;
    }
    private static List<String> lines(String s) { return unique(Arrays.asList(s.split("[,;\\s\\r\\n]+"))); }
    private static List<String> unique(Collection<String> in) {
        LinkedHashSet<String> set = new LinkedHashSet<>();
        for (String x : in) {
            if (x == null || x.trim().isEmpty()) continue;
            String clean = cleanToken(x);
            if (!clean.isEmpty()) set.add(clean);
        }
        return new ArrayList<>(set);
    }
    private static List<Integer> parsePorts(String s) {
        LinkedHashSet<Integer> ports = new LinkedHashSet<>();
        for (String p : s.split("[,;\\s]+")) {
            try { int v = Integer.parseInt(p.trim()); if (v > 0 && v < 65536) ports.add(v); } catch (Exception ignored) {}
        }
        if (ports.isEmpty()) ports.add(443);
        return new ArrayList<>(ports);
    }
    private static List<String> cap(List<String> in, int n) { return in.subList(0, Math.min(in.size(), Math.max(1, n))); }
    private static String first(List<String> xs) { return xs.isEmpty() ? "" : xs.get(0); }
    private static boolean isIp(String x) {
        if (x == null) return false;
        String v = x.trim();
        if (v.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            String[] parts = v.split("\\.");
            for (String part : parts) {
                try { int n = Integer.parseInt(part); if (n < 0 || n > 255) return false; }
                catch (Exception e) { return false; }
            }
            return true;
        }
        if (!v.contains(":") || !v.matches("(?i)[0-9a-f:.]+")) return false;
        try { return InetAddress.getByName(v) instanceof Inet6Address; }
        catch (Exception e) { return false; }
    }
    private static List<String> resolve(String target) {
        try {
            if (isIp(target)) return Collections.singletonList(target);
            InetAddress[] a = InetAddress.getAllByName(target);
            List<String> out = new ArrayList<>();
            for (InetAddress x : a) if (x instanceof Inet6Address) out.add(x.getHostAddress());
            for (InetAddress x : a) if (x instanceof Inet4Address) out.add(x.getHostAddress());
            return unique(out);
        } catch (Exception e) { return Collections.emptyList(); }
    }
    private static List<String> expandTargets(List<String> raw) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String x : raw) if (x.contains("/")) out.addAll(expandCidr(x, 200000)); else out.add(x);
        return new ArrayList<>(out);
    }
    private static List<String> expandCidr(String cidr, int cap) {
        List<String> out = new ArrayList<>();
        try {
            String[] p = cidr.split("/");
            if (p.length != 2 || !isIp(p[0])) return out;
            if (p[0].contains(":")) return expandIpv6Cidr(p[0], Integer.parseInt(p[1]), cap);
            long ip = ipv4ToLong(p[0]); int prefix = Integer.parseInt(p[1]);
            if (prefix < 0 || prefix > 32) return out;
            long mask = prefix == 0 ? 0 : (0xffffffffL << (32 - prefix)) & 0xffffffffL;
            long start = ip & mask, end = start | (~mask & 0xffffffffL);
            for (long v = start + 1; v < end && out.size() < cap; v++) out.add(longToIpv4(v));
        } catch (Exception ignored) {}
        return out;
    }
    private static List<String> expandIpv6Cidr(String ipText, int prefix, int cap) {
        List<String> out = new ArrayList<>();
        try {
            if (prefix < 0 || prefix > 128 || cap <= 0) return out;
            byte[] bytes = InetAddress.getByName(ipText).getAddress();
            BigInteger ip = new BigInteger(1, bytes);
            BigInteger all = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);
            BigInteger mask = prefix == 0 ? BigInteger.ZERO : all.shiftRight(128 - prefix).shiftLeft(128 - prefix);
            BigInteger start = ip.and(mask);
            BigInteger size = BigInteger.ONE.shiftLeft(128 - prefix);
            BigInteger current = start;
            if (size.compareTo(BigInteger.ONE) > 0) current = current.add(BigInteger.ONE);
            for (int i = 0; i < cap && current.subtract(start).compareTo(size) < 0; i++) {
                out.add(bigToIpv6(current));
                current = current.add(BigInteger.ONE);
            }
        } catch (Exception ignored) {}
        return out;
    }
    private static String bigToIpv6(BigInteger value) throws Exception {
        byte[] raw = value.toByteArray();
        byte[] bytes = new byte[16];
        int src = Math.max(0, raw.length - 16);
        int len = Math.min(16, raw.length);
        System.arraycopy(raw, src, bytes, 16 - len, len);
        return InetAddress.getByAddress(bytes).getHostAddress();
    }
    private static long ipv4ToLong(String ip) { String[] p = ip.split("\\."); long r = 0; for (String s : p) r = (r << 8) | Integer.parseInt(s); return r & 0xffffffffL; }
    private static String longToIpv4(long v) { return ((v>>24)&255)+"."+((v>>16)&255)+"."+((v>>8)&255)+"."+(v&255); }
    private static String toIpv4Cidr24(String value) {
        if (value == null) return "";
        String v = cleanToken(value);
        if (!isIp(v) || v.contains(":")) return v;
        String[] p = v.split("\\.");
        return p[0] + "." + p[1] + "." + p[2] + ".0/24";
    }
    private static int parseStatus(String line) { try { return line != null && line.startsWith("HTTP/") ? Integer.parseInt(line.split(" ")[1]) : 0; } catch (Exception e) { return 0; } }
    private static void configureTlsSocket(SSLSocket ssl, int tlsMode, boolean rawHttpProbe) {
        ArrayList<String> protocols = new ArrayList<>();
        List<String> supportedProtocols = Arrays.asList(ssl.getSupportedProtocols());
        if (supportedProtocols.contains("TLSv1.3")) protocols.add("TLSv1.3");
        if (supportedProtocols.contains("TLSv1.2")) protocols.add("TLSv1.2");
        if (!protocols.isEmpty()) ssl.setEnabledProtocols(protocols.toArray(new String[0]));
        if (Build.VERSION.SDK_INT < 29) return;
        SSLParameters params = ssl.getSSLParameters();
        params.setApplicationProtocols(rawHttpProbe || tlsMode == 3 ? new String[]{"http/1.1"} : new String[]{"h2", "http/1.1"});
        ssl.setSSLParameters(params);
    }
    private static int resolveTlsMode(int tlsMode) {
        if (tlsMode == 4) return Math.abs((int) (System.nanoTime() % 4));
        return Math.max(0, Math.min(3, tlsMode));
    }
    private static String tlsProfileName(int tlsMode) {
        switch (tlsMode) {
            case 1: return "chrome-like";
            case 2: return "firefox-like";
            case 3: return "http1-only";
            default: return "android-default";
        }
    }
    private static String selectedAlpn(SSLSocket ssl) {
        if (Build.VERSION.SDK_INT < 29) return "";
        String protocol = ssl.getApplicationProtocol();
        return protocol == null ? "" : protocol;
    }
    private static String classify(Exception e) {
        String m = String.valueOf(e.getMessage()).toLowerCase(Locale.US);
        if (m.contains("timed")) return "timeout";
        if (m.contains("refused")) return "refused";
        if (m.contains("reset")) return "reset";
        if (m.contains("cert") || m.contains("trust") || m.contains("handshake")) return "cert_or_tls";
        return e.getClass().getSimpleName();
    }
    private static String detectCdn(String ip, String sni, String cert) {
        String hay = (sni + " " + cert).toLowerCase(Locale.US);
        if (hay.contains("cloudflare") || ip.startsWith("104.16.") || ip.startsWith("104.17.") || ip.startsWith("104.18.") || ip.startsWith("172.64.")) return "CLOUDFLARE";
        if (hay.contains("fastly") || ip.startsWith("151.101.")) return "FASTLY";
        if (hay.contains("akamai") || ip.startsWith("23.") || ip.startsWith("2.") || ip.startsWith("92.12") || ip.startsWith("184.") || ip.startsWith("96.")) return "AKAMAI";
        if (hay.contains("amazon") || hay.contains("cloudfront")) return "CLOUDFRONT";
        if (ip.startsWith("95.216.") || ip.startsWith("65.109.")) return "HETZNER";
        return "UNKNOWN";
    }
    private static String sha256(byte[] bytes) throws Exception { byte[] d = MessageDigest.getInstance("SHA-256").digest(bytes); StringBuilder sb = new StringBuilder(); for (byte b : d) sb.append(String.format("%02x", b)); return sb.toString(); }
    private static String joinLines(Collection<String> xs) { StringBuilder sb = new StringBuilder(); for (String x : xs) sb.append(x).append('\n'); return sb.toString().trim(); }
    private static String joinComma(Collection<String> xs) { StringBuilder sb = new StringBuilder(); for (String x : xs) { if (sb.length() > 0) sb.append(','); sb.append(x); } return sb.toString(); }
    private static String q(String s) { return "\"" + String.valueOf(s).replace("\"", "\"\"") + "\""; }
    private static String trim(String s, int n) { return s.length() <= n ? s : s.substring(0, n - 1) + "..."; }
    private static String dash(String s) { return s == null || s.isEmpty() ? "--" : s; }
    private static String cleanToken(String s) { return s.trim().replace("\"", "").replace(",", "").replace("[", "").replace("]", ""); }
    private String yes(boolean b) { return b ? "yes" : "no"; }
    private String elapsed() { long s = Math.max(0, (System.currentTimeMillis() - scanStartedAt) / 1000); return s + "s"; }
    private void clip(String s) { ((ClipboardManager) getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("MaybeEdgeScanner", s)); }
    private String resourceLine() {
        Intent battery = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        int level = battery == null ? -1 : battery.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
        int scale = battery == null ? -1 : battery.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
        int pct = level >= 0 && scale > 0 ? Math.round(level * 100f / scale) : -1;
        Runtime rt = Runtime.getRuntime();
        long usedMb = (rt.totalMemory() - rt.freeMemory()) / (1024 * 1024);
        return "battery " + (pct >= 0 ? pct + "%" : "n/a") + " | heap " + usedMb + "MB";
    }
    private void appendLog(String s) { ui.post(() -> logView.append(new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date()) + "  " + s + "\n")); }
    private int intValue(EditText e, int fallback) { try { String s = e.getText().toString().trim(); return s.isEmpty() ? fallback : Integer.parseInt(s); } catch (Exception ex) { return fallback; } }
    private LinearLayout column() { LinearLayout l = new LinearLayout(this); l.setOrientation(LinearLayout.VERTICAL); return l; }
    private LinearLayout row() { LinearLayout l = new LinearLayout(this); l.setOrientation(LinearLayout.HORIZONTAL); l.setGravity(Gravity.CENTER); return l; }
    private TextView text(String s, int sp, int color, boolean bold) { TextView v = new TextView(this); v.setText(s); v.setTextSize(sp); v.setTextColor(color); if (bold) v.setTypeface(Typeface.DEFAULT_BOLD); v.setPadding(0, dp(4), 0, dp(4)); return v; }
    private TextView panelText(String s) { TextView v = text(s, 12, Color.WHITE, false); v.setBackground(glassBg(PANEL, Color.argb(120, 255, 255, 255))); v.setPadding(dp(12), dp(10), dp(12), dp(10)); setOuterMargin(v, 0, dp(6), 0, dp(6)); return v; }
    private TextView glassText(String s) { TextView v = panelText(s); v.setTextColor(Color.rgb(196, 223, 235)); return v; }
    private TextView infoCard(String title, String body) { TextView v = panelText(title + "\n" + body); v.setTextColor(Color.rgb(220, 238, 248)); return v; }
    private LinearLayout supportFooter() {
        LinearLayout card = column();
        card.setBackground(glassBg(Color.rgb(9, 22, 31), Color.argb(70, 255, 255, 255)));
        card.setPadding(dp(12), dp(10), dp(12), dp(10));
        setOuterMargin(card, 0, dp(14), 0, dp(8));
        TextView title = text("Support development (optional)", 12, Color.rgb(210, 231, 240), true);
        TextView body = text("GitHub: " + SUPPORT_GITHUB + "\nBTC: " + SUPPORT_BTC + "\nEVM/ETH/ERC20/BNB/BEP20: " + SUPPORT_EVM + "\nPlease verify the correct network before sending assets.", 11, MUTED, false);
        body.setTextIsSelectable(true);
        card.addView(title);
        card.addView(body);
        LinearLayout actions = row();
        Button github = button("GitHub", Color.rgb(24, 45, 58), Color.WHITE);
        Button btc = button("Copy BTC", Color.rgb(24, 45, 58), Color.WHITE);
        Button evm = button("Copy EVM", Color.rgb(24, 45, 58), Color.WHITE);
        github.setOnClickListener(v -> openSupportGitHub());
        btc.setOnClickListener(v -> copySupport("BTC", SUPPORT_BTC));
        evm.setOnClickListener(v -> copySupport("EVM", SUPPORT_EVM));
        actions.addView(github, weight());
        actions.addView(btc, weight());
        actions.addView(evm, weight());
        card.addView(actions);
        return card;
    }
    private TextView section(String s) { TextView v = text(s, 12, Color.rgb(180, 215, 230), true); v.setPadding(dp(2), dp(12), 0, dp(4)); v.setLetterSpacing(0.08f); return v; }
    private TextView pill(String s) { TextView v = text(s, 13, BLUE, true); v.setGravity(Gravity.CENTER); v.setBackground(glassBg(Color.rgb(16, 35, 50), BLUE)); v.setPadding(dp(12), dp(8), dp(12), dp(8)); setOuterMargin(v, 0, dp(8), 0, dp(8)); return v; }
    private EditText area(String hint) { EditText e = input("", false); e.setHint(hint); e.setMinLines(4); e.setGravity(Gravity.TOP); return e; }
    private EditText input(String s, boolean number) { EditText e = new EditText(this); e.setText(s); e.setTextColor(Color.WHITE); e.setTextSize(14); e.setHintTextColor(Color.rgb(145, 174, 190)); e.setSingleLine(false); e.setInputType((number ? InputType.TYPE_CLASS_NUMBER : InputType.TYPE_CLASS_TEXT) | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS); e.setBackground(glassBg(FIELD, Color.argb(95, 255, 255, 255))); e.setPadding(dp(12), dp(10), dp(12), dp(10)); return e; }
    private CheckBox check(String s) { CheckBox c = new CheckBox(this); c.setText(s); c.setTextSize(13); c.setTextColor(Color.WHITE); c.setButtonTintList(android.content.res.ColorStateList.valueOf(BLUE)); return c; }
    private Button button(String s, int bg, int fg) { Button b = new Button(this); b.setText(s); b.setTextColor(fg); b.setTextSize(13); b.setAllCaps(false); b.setTypeface(Typeface.DEFAULT_BOLD); b.setBackground(glassBg(bg, Color.argb(135, 255, 255, 255))); b.setPadding(dp(10), dp(8), dp(10), dp(8)); b.setOnTouchListener((v, e) -> { if (e.getAction() == android.view.MotionEvent.ACTION_DOWN) { v.performHapticFeedback(android.view.HapticFeedbackConstants.KEYBOARD_TAP); v.animate().scaleX(0.98f).scaleY(0.98f).setDuration(70).start(); } if (e.getAction() == android.view.MotionEvent.ACTION_UP || e.getAction() == android.view.MotionEvent.ACTION_CANCEL) v.animate().scaleX(1f).scaleY(1f).setDuration(130).setInterpolator(new DecelerateInterpolator()).start(); return false; }); return b; }
    private Spinner spinner(String[] values) { Spinner s = new Spinner(this); ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, values); s.setAdapter(adapter); s.setBackground(glassBg(FIELD, Color.argb(95, 255, 255, 255))); s.setPadding(dp(8), dp(6), dp(8), dp(6)); return s; }
    private LinearLayout box(String label, View child) { LinearLayout l = column(); l.setBackground(glassBg(Color.rgb(11, 26, 37), Color.argb(75, 255, 255, 255))); l.setPadding(dp(8), dp(4), dp(8), dp(8)); l.addView(section(label)); l.addView(child); return l; }
    private LinearLayout.LayoutParams weight() { LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, -2, 1); lp.setMargins(dp(4), dp(4), dp(4), dp(4)); return lp; }
    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density + 0.5f); }
    private void toast(String s) { Toast.makeText(this, s, Toast.LENGTH_LONG).show(); }
    private void copySupport(String label, String address) { clip(address); toast(label + " address copied"); }
    private void openSupportGitHub() {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, android.net.Uri.parse(SUPPORT_GITHUB)));
        } catch (Exception e) {
            clip(SUPPORT_GITHUB);
            toast("GitHub link copied");
        }
    }
    private boolean highContrastMode() { return visualModeSpinner != null && visualModeSpinner.getSelectedItemPosition() == 1; }
    private boolean compactMode() { return visualModeSpinner != null && visualModeSpinner.getSelectedItemPosition() == 2; }
    private GradientDrawable glassBg(int fill, int stroke) {
        int fillAlpha = highContrastMode() ? 245 : 215;
        int shineAlpha = highContrastMode() ? 40 : 120;
        GradientDrawable g = new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{Color.argb(fillAlpha, Color.red(fill), Color.green(fill), Color.blue(fill)), Color.argb(shineAlpha, 255, 255, 255)});
        g.setCornerRadius(dp(compactMode() ? 10 : 16));
        g.setStroke(dp(highContrastMode() ? 2 : 1), stroke);
        return g;
    }
    private void setOuterMargin(View v, int l, int t, int r, int b) { LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2); lp.setMargins(l, t, r, b); v.setLayoutParams(lp); }

    private static class Preset {
        final String name;
        final LinkedHashSet<String> targets = new LinkedHashSet<>();
        final LinkedHashSet<String> snis = new LinkedHashSet<>();
        String detail = "";
        Preset(String name) { this.name = name; }
    }
}
