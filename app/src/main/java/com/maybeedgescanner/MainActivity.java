package com.maybeedgescanner;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.BatteryManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.widget.*;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.lang.reflect.Method;
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

import rikka.shizuku.Shizuku;

public class MainActivity extends Activity {
    public static final String ACTION_QUICK_SCAN = "com.maybeedgescanner.action.QUICK_SCAN";
    private static final int BLUE = Color.rgb(55, 212, 255);
    private static final int PANEL = Color.rgb(13, 28, 39);
    private static final int FIELD = Color.rgb(9, 20, 29);
    private static final int MUTED = Color.rgb(140, 161, 178);
    private static final String SUPPORT_GITHUB = "https://github.com/maybeknott/MaybeEdgeScanner/";
    private static final int SHIZUKU_REQUEST_CODE = 4601;
    private static final String[] RADIO_MODE_KEYS = {
            "preferred_network_mode",
            "preferred_network_mode0",
            "preferred_network_mode1",
            "preferred_network_mode2"
    };
    private static final int PREVIEW_TARGET_LIMIT = 24;
    private static final int MAX_RENDERED_CARDS = 250;
    private static final int MAX_THREADS = 128;
    private static final int MAX_BATCH = 20000;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final AtomicBoolean stop = new AtomicBoolean(false);
    private final AtomicBoolean renderQueued = new AtomicBoolean(false);
    private final AtomicBoolean shizukuCommandRunning = new AtomicBoolean(false);
    private final AtomicInteger checkedTargets = new AtomicInteger(0);
    private final List<Result> allResults = Collections.synchronizedList(new ArrayList<>());
    private final ConcurrentHashMap<String, List<String>> assetLineCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LinkedHashSet<String>> assetTokenCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LinkedHashSet<String>> communityCorpusCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> assetReadLocks = new ConcurrentHashMap<>();
    private final LinkedHashSet<String> selectedSourceTargets = new LinkedHashSet<>();
    private final LinkedHashSet<String> selectedSourceSnis = new LinkedHashSet<>();
    private final ArrayDeque<String> logLines = new ArrayDeque<>();
    private final StringBuilder stableLogBuilder = new StringBuilder();
    private ExecutorService executor;
    private boolean suppressUiRefresh;
    private String cachedResourceLine = "battery n/a | heap 0MB";
    private long cachedResourceLineAt;
    private long stableHistoryRenderedAt;
    private long lastShizukuProbeAt;
    private float swipeDownX, swipeDownY;

    private LinearLayout resultList;
    private LinearLayout targetTab, liveTab, diagnosticsTab;
    private LinearLayout targetChipPreview, sniChipPreview;
    private LinearLayout analyticsPanel;
    private LinearLayout stableHistoryPanel;
    private ScrollView mainScroll;
    private View targetAnchor, liveAnchor, diagnosticsAnchor;
    private ProgressBar progress;
    private TextView status, metrics, bestView, countersView, logView, networkBanner, homeDashboardView;
    private TextView shizukuHealthTileView, shizukuStatusView, shizukuNextStepView, shizukuOutputView;
    private TextView sourceSummaryView, sourceHealthView;
    private TextView scanPlanView;
    private EditText targetsInput, snisInput, totalInput, batchInput, threadsInput, timeoutInput;
    private EditText communitySampleInput, akamaiSampleInput, cloudfrontSampleInput, fastlySampleInput, cloudflareSampleInput, otherCdnSampleInput, customTargetSampleInput, customSniSampleInput;
    private EditText portsInput, pathInput, maxLatencyInput, resultLimitInput, cdnFilterInput, certFilterInput, sniFilterInput, minQualityInput;
    private EditText shizukuKeyInput, shizukuValueInput;
    private CheckBox multiSni, filterWorking, filterTlsHttp, bestPerIp, hideNoisyLogs, requireHttp, requireKnownCdn, requireTls13, batteryFriendlyUi;
    private CheckBox communitySourceEnabled, akamaiSourceEnabled, cloudfrontSourceEnabled, fastlySourceEnabled, cloudflareSourceEnabled, otherCdnSourceEnabled, defaultSniEnabled;
    private CheckBox stepTcp, stepTls, stepHttp, stepVerify;
    private Spinner profileSpinner, workflowSpinner, sortSpinner, exportSpinner, tlsModeSpinner, cdnProviderSpinner;
    private Button startButton, stopButton, copyButton, copyCsvButton, exportButton, clearButton, helpButton;
    private Button tabTargetButton, tabLiveButton, tabDiagnosticsButton;
    private int totalTargets;
    private int activeTab;
    private int visualizationMode;
    private int densityMode;
    private int resultOffset;
    private long scanStartedAt;
    private final ArrayList<Button> visualizationButtons = new ArrayList<>();
    private final ArrayList<Button> densityButtons = new ArrayList<>();
    private final Shizuku.OnRequestPermissionResultListener shizukuPermissionListener = this::onShizukuPermissionResult;
    private final Shizuku.OnBinderReceivedListener shizukuBinderReceivedListener = this::onShizukuBinderReceived;
    private final Shizuku.OnBinderDeadListener shizukuBinderDeadListener = this::onShizukuBinderDead;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        buildUi();
        loadDefaults();
        maybeShowOnboarding();
        addShizukuListener();
        refreshShizukuState();
        if (ACTION_QUICK_SCAN.equals(getIntent().getAction())) {
            ui.postDelayed(this::startScan, 450);
        }
    }

    @Override protected void onDestroy() {
        removeShizukuListener();
        super.onDestroy();
    }

    @Override protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        synchronized (allResults) {
            outState.putSerializable("results", new ArrayList<>(allResults));
        }
        synchronized (logLines) {
            outState.putStringArrayList("logs", new ArrayList<>(logLines));
        }
    }

    @Override protected void onRestoreInstanceState(Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);
        if (savedInstanceState == null) return;
        Object restored = savedInstanceState.getSerializable("results");
        if (restored instanceof ArrayList<?>) {
            synchronized (allResults) {
                allResults.clear();
                for (Object item : (ArrayList<?>) restored) {
                    if (item instanceof Result) allResults.add((Result) item);
                }
            }
        }
        ArrayList<String> logs = savedInstanceState.getStringArrayList("logs");
        if (logs != null) {
            synchronized (logLines) {
                logLines.clear();
                logLines.addAll(logs);
                rebuildStableLogBuilder();
            }
            if (logView != null) logView.setText(stableLogBuilder.toString().trim());
        }
        updateProgress();
        scheduleRender();
    }

    private void buildUi() {
        LinearLayout screen = column();
        screen.setBackground(new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{Color.rgb(5, 14, 23), Color.rgb(8, 28, 38), Color.rgb(15, 18, 34)}));
        ScrollView scroll = new ScrollView(this);
        mainScroll = scroll;
        scroll.setOnTouchListener((v, event) -> handleTabSwipe(event));
        LinearLayout root = column();
        root.setPadding(dp(14), dp(14), dp(14), dp(22));
        scroll.addView(root);

        root.addView(text("MaybeEdgeScanner", 27, Color.WHITE, true));
        root.addView(text("Edge discovery workspace", 13, MUTED, false));
        status = pill("Ready");
        root.addView(status);
        networkBanner = pill(networkContextLine());
        root.addView(networkBanner);
        homeDashboardView = panelText("Network and system\nTransport: checking\nLAN/WAN: checking\nDNS: checking\nPolicy: checking\nCapacity: checking\nDevice: checking\nRuntime: checking");
        root.addView(homeDashboardView);
        root.addView(quietNote("Sources build IP/SNI scan routes. Results show filtered cards, best SNIs, and export actions. Diagnostics keeps logs, radio controls, and network context separate."));
        helpButton = button("Reference", Color.rgb(23, 46, 63), Color.WHITE);
        root.addView(helpButton);
        LinearLayout tabs = row();
        tabTargetButton = button("Sources", Color.rgb(21, 45, 62), Color.WHITE);
        tabLiveButton = button("Results", Color.rgb(21, 45, 62), Color.WHITE);
        tabDiagnosticsButton = button("Diagnostics", Color.rgb(21, 45, 62), Color.WHITE);
        tabs.addView(tabTargetButton, weight());
        tabs.addView(tabLiveButton, weight());
        tabs.addView(tabDiagnosticsButton, weight());
        screen.addView(tabs);

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
        targetAnchor = section("Sources");
        targetTab.addView(targetAnchor);
        targetsInput = area("Custom targets: IPv4, IPv6, domains, CIDR, ranges");
        snisInput = area("Custom SNI hosts");
        LinearLayout providerPanel = column();
        providerPanel.addView(quietNote("Enable only the corpora you want. Sample is compact by design: 0 means all entries from that source; any larger number is clamped to what that corpus actually contains."));
        communitySampleInput = input("256", true);
        akamaiSampleInput = input("128", true);
        cloudfrontSampleInput = input("128", true);
        fastlySampleInput = input("128", true);
        cloudflareSampleInput = input("128", true);
        otherCdnSampleInput = input("128", true);
        communitySourceEnabled = check("Community tested /24s");
        akamaiSourceEnabled = check("Akamai");
        cloudfrontSourceEnabled = check("AWS CloudFront");
        fastlySourceEnabled = check("Fastly");
        cloudflareSourceEnabled = check("Cloudflare");
        otherCdnSourceEnabled = check("GitHub, Azure, Google, Bunny, Edgio");
        communitySourceEnabled.setChecked(true);
        providerPanel.addView(sourceControl(communitySourceEnabled, communitySampleInput, "Default targets, extra edges, and community-tested IPs expanded to /24 CIDR tokens."));
        providerPanel.addView(sourceControl(akamaiSourceEnabled, akamaiSampleInput, "Akamai AS20940 plus known Akamai 184.x host ranges."));
        providerPanel.addView(sourceControl(cloudfrontSourceEnabled, cloudfrontSampleInput, "AWS CloudFront public range corpus."));
        providerPanel.addView(sourceControl(fastlySourceEnabled, fastlySampleInput, "Fastly AS54113 public range corpus."));
        providerPanel.addView(sourceControl(cloudflareSourceEnabled, cloudflareSampleInput, "Cloudflare public range corpus."));
        providerPanel.addView(sourceControl(otherCdnSourceEnabled, otherCdnSampleInput, "Provider corpus for GitHub Pages, Azure Front Door, Google CDN, Bunny, Edgio, and other cloud/CDN ranges."));
        targetTab.addView(collapsibleBox("Managed source sampling", providerPanel, true));

        sourceSummaryView = glassText("Managed sources are driven directly by the checkboxes above. There is no hidden staging list or add/replace state.");
        targetTab.addView(sourceSummaryView);
        sourceHealthView = glassText("Source health will summarize managed corpora, custom additions, SNI routes, expansion size, and phone-load posture before scanning.");
        targetTab.addView(sourceHealthView);
        scanPlanView = glassText("Scan plan will combine managed sources, custom entries, SNI routes, ports, workflow, and caps before scanning.");
        targetTab.addView(scanPlanView);
        targetTab.addView(section("Targets"));
        targetTab.addView(quietNote("Custom targets are for manual additions/removals only. Selected corpora and sampled IPs stay summarized in managed sources instead of being dumped into this text box."));
        customTargetSampleInput = input("0", true);
        targetTab.addView(box("Custom target sample (0 = all typed values)", customTargetSampleInput));
        targetTab.addView(targetsInput);
        targetChipPreview = chipPanel();
        targetTab.addView(targetChipPreview);
        targetTab.addView(section("SNI Hosts"));
        targetTab.addView(quietNote("Custom SNI hosts are explicit TLS/Host routes. Default SNI routes can be enabled or disabled; custom hosts can be sampled separately."));
        defaultSniEnabled = check("Default SNI route corpus");
        defaultSniEnabled.setChecked(true);
        targetTab.addView(defaultSniEnabled);
        customSniSampleInput = input("0", true);
        targetTab.addView(box("Custom SNI sample (0 = all typed hosts)", customSniSampleInput));
        targetTab.addView(snisInput);
        sniChipPreview = chipPanel();
        targetTab.addView(sniChipPreview);

        LinearLayout workflowPanel = column();
        LinearLayout row1 = row();
        profileSpinner = spinner(new String[]{"Quick TCP", "Standard TLS", "Deep HTTP + SNI", "Verify CDN edge"});
        workflowSpinner = spinner(new String[]{"Single selected profile", "Auto multi-step ladder", "Manual selected steps"});
        sortSpinner = spinner(new String[]{"Newest", "Latency", "Score", "CDN", "SNI", "HTTP first", "TLS first"});
        tlsModeSpinner = spinner(new String[]{"Android default", "Chrome-like ALPN", "Firefox-like ALPN", "HTTP/1.1 only", "Rotate per probe"});
        row1.addView(box("Profile", profileSpinner), weight());
        row1.addView(box("Workflow", workflowSpinner), weight());
        workflowPanel.addView(row1);
        workflowPanel.addView(box("TLS ClientHello", tlsModeSpinner));
        workflowPanel.addView(quietNote("Auto ladder runs TCP, TLS, HTTP/SNI, then CDN verification. Manual runs only checked stages."));
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
        workflowPanel.addView(stepRow1);
        LinearLayout stepRow2 = row();
        stepRow2.addView(stepHttp, weight());
        stepRow2.addView(stepVerify, weight());
        workflowPanel.addView(stepRow2);
        targetTab.addView(collapsibleBox("Workflow and probe stages", workflowPanel, true));

        LinearLayout performancePanel = column();
        performancePanel.addView(quietNote("Performance modes tune threads, batch, and timeout. Raise Total cap for full subnet or full-provider runs."));
        LinearLayout modeRow = row();
        modeRow.addView(modeButton("Battery Saver", "12 / 500 / 2500", 12, 500, 2500), weight());
        modeRow.addView(modeButton("Balanced", "32 / 2000 / 3000", 32, 2000, 3000), weight());
        modeRow.addView(modeButton("Aggressive", "96 / 12000 / 5000", 96, 12000, 5000), weight());
        performancePanel.addView(modeRow);

        LinearLayout row2 = row();
        totalInput = input("5000", true);
        batchInput = input("2000", true);
        threadsInput = input("32", true);
        timeoutInput = input("3000", true);
        row2.addView(box("Total cap", totalInput), weight());
        row2.addView(box("Batch", batchInput), weight());
        performancePanel.addView(row2);
        LinearLayout row3 = row();
        row3.addView(box("Threads", threadsInput), weight());
        row3.addView(box("Timeout ms", timeoutInput), weight());
        performancePanel.addView(row3);
        targetTab.addView(collapsibleBox("Performance and limits", performancePanel, true));

        LinearLayout requestPanel = column();
        LinearLayout row4 = row();
        portsInput = input("443", false);
        pathInput = input("/", false);
        row4.addView(box("Ports", portsInput), weight());
        row4.addView(box("HTTP path", pathInput), weight());
        requestPanel.addView(row4);

        multiSni = check("All SNI hosts");
        filterWorking = check("Working only");
        filterTlsHttp = check("TLS/HTTP only");
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
        checks1.addView(hideNoisyLogs, weight());
        requestPanel.addView(checks1);
        LinearLayout sniRouteRow = row();
        Button primarySniButton = button("Primary SNI", Color.rgb(31, 62, 72), Color.WHITE);
        primarySniButton.setOnClickListener(v -> {
            multiSni.setChecked(false);
            renderTokenPreviews();
            toast("Primary SNI route mode");
        });
        Button allSniButton = button("All SNI routes", Color.rgb(72, 55, 34), Color.WHITE);
        allSniButton.setOnClickListener(v -> {
            multiSni.setChecked(true);
            renderTokenPreviews();
            toast("All SNI route mode");
        });
        sniRouteRow.addView(primarySniButton, weight());
        sniRouteRow.addView(allSniButton, weight());
        requestPanel.addView(sniRouteRow);
        LinearLayout checks2 = row();
        checks2.addView(batteryFriendlyUi, weight());
        requestPanel.addView(checks2);
        targetTab.addView(collapsibleBox("Request and display behavior", requestPanel, false));

        liveTab = column();
        root.addView(liveTab);
        liveAnchor = section("Results");
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

        LinearLayout filterPanel = column();
        filterPanel.addView(quietNote("These controls only change visible cards and exports; they never change the scan queue."));
        LinearLayout resultFilterToggles1 = row();
        resultFilterToggles1.addView(filterWorking, weight());
        resultFilterToggles1.addView(filterTlsHttp, weight());
        filterPanel.addView(resultFilterToggles1);
        LinearLayout resultFilterToggles2 = row();
        resultFilterToggles2.addView(requireHttp, weight());
        resultFilterToggles2.addView(requireKnownCdn, weight());
        filterPanel.addView(resultFilterToggles2);
        LinearLayout resultFilterToggles3 = row();
        resultFilterToggles3.addView(requireTls13, weight());
        resultFilterToggles3.addView(bestPerIp, weight());
        filterPanel.addView(resultFilterToggles3);
        cdnProviderSpinner = spinner(new String[]{"Any provider", "Known CDN", "Akamai", "Cloudflare", "CloudFront/AWS", "Fastly", "GitHub", "Google", "Azure", "Bunny", "Unknown"});
        LinearLayout providerFilterRow = row();
        providerFilterRow.addView(box("Sort cards", sortSpinner), weight());
        providerFilterRow.addView(box("Provider filter", cdnProviderSpinner), weight());
        filterPanel.addView(providerFilterRow);
        LinearLayout row5 = row();
        maxLatencyInput = input("", true); maxLatencyInput.setHint("Any");
        resultLimitInput = input("250", true);
        row5.addView(box("Max latency ms", maxLatencyInput), weight());
        row5.addView(box("Visible cards", resultLimitInput), weight());
        filterPanel.addView(row5);
        LinearLayout row6 = row();
        cdnFilterInput = input("", false); cdnFilterInput.setHint("Any CDN");
        certFilterInput = input("", false); certFilterInput.setHint("Certificate contains");
        row6.addView(box("CDN contains", cdnFilterInput), weight());
        row6.addView(box("Cert contains", certFilterInput), weight());
        filterPanel.addView(row6);
        LinearLayout row7 = row();
        sniFilterInput = input("", false); sniFilterInput.setHint("Any SNI");
        minQualityInput = input("", true); minQualityInput.setHint("Any");
        row7.addView(box("SNI contains", sniFilterInput), weight());
        row7.addView(box("Min score", minQualityInput), weight());
        filterPanel.addView(row7);
        Button clearFiltersButton = button("Clear filters", Color.rgb(24, 45, 58), Color.WHITE);
        clearFiltersButton.setOnClickListener(v -> clearResultFilters());
        LinearLayout quickFilterRow = row();
        Button quickWorkingButton = button("Working", Color.rgb(23, 78, 67), Color.WHITE);
        quickWorkingButton.setOnClickListener(v -> {
            filterWorking.setChecked(true);
            filterTlsHttp.setChecked(false);
            requireHttp.setChecked(false);
            requireKnownCdn.setChecked(false);
            renderResultsFromFirstPage();
        });
        Button quickTlsButton = button("TLS/HTTP", Color.rgb(52, 67, 91), Color.WHITE);
        quickTlsButton.setOnClickListener(v -> {
            filterWorking.setChecked(true);
            filterTlsHttp.setChecked(true);
            renderResultsFromFirstPage();
        });
        Button quickBestButton = button("Best routes", Color.rgb(83, 61, 33), Color.WHITE);
        quickBestButton.setOnClickListener(v -> {
            bestPerIp.setChecked(true);
            sortSpinner.setSelection(2);
            renderResultsFromFirstPage();
        });
        quickFilterRow.addView(quickWorkingButton, weight());
        quickFilterRow.addView(quickTlsButton, weight());
        quickFilterRow.addView(quickBestButton, weight());
        filterPanel.addView(quickFilterRow);
        filterPanel.addView(clearFiltersButton);
        liveTab.addView(collapsibleBox("Filter, sort, and page cards", filterPanel, true));

        LinearLayout exportPanel = column();
        exportPanel.addView(quietNote("Copy and save use the current filtered result set. Cards stay visible after export."));
        LinearLayout buttons = row();
        copyButton = button("Copy format", Color.rgb(34, 51, 66), Color.WHITE);
        copyCsvButton = button("Copy CSV", Color.rgb(34, 51, 66), Color.WHITE);
        exportButton = button("Save JSON", Color.rgb(34, 51, 66), Color.WHITE);
        buttons.addView(copyButton, weight());
        buttons.addView(copyCsvButton, weight());
        buttons.addView(exportButton, weight());
        exportPanel.addView(buttons);
        LinearLayout exportRow = row();
        exportSpinner = spinner(new String[]{"Line-separated IPs", "Comma-separated IPs", "IP SNI pairs", "SNI only", "CSV rows", "JSON"});
        exportRow.addView(box("Clipboard format", exportSpinner), weight());
        exportPanel.addView(exportRow);
        liveTab.addView(collapsibleBox("Copy and export", exportPanel, false));
        liveTab.addView(segmentedChoice("Visualization", new String[]{"Cards", "Heatmap"}, visualizationButtons, visualizationMode, index -> {
            visualizationMode = index;
            scheduleRender();
        }));
        liveTab.addView(segmentedChoice("Density", new String[]{"Comfort", "Contrast", "Compact"}, densityButtons, densityMode, index -> {
            densityMode = index;
            scheduleRender();
        }));
        stableHistoryPanel = column();
        stableHistoryPanel.setBackground(glassBg(Color.rgb(9, 23, 34), Color.argb(90, 255, 255, 255)));
        stableHistoryPanel.setPadding(dp(12), dp(10), dp(12), dp(10));
        setOuterMargin(stableHistoryPanel, 0, dp(8), 0, dp(8));
        liveTab.addView(stableHistoryPanel);
        resultList = new LinearLayout(this);
        resultList.setOrientation(LinearLayout.VERTICAL);
        resultList.setLayoutTransition(null);
        liveTab.addView(resultList);

        diagnosticsTab = column();
        root.addView(diagnosticsTab);
        diagnosticsAnchor = section("Diagnostics");
        diagnosticsTab.addView(diagnosticsAnchor);
        diagnosticsTab.addView(quietNote("Logs and support links live here so they do not bury scan setup or result cards."));
        diagnosticsTab.addView(shizukuHealthTile());
        diagnosticsTab.addView(section("Logs"));
        logView = text("", 12, MUTED, false);
        logView.setTypeface(Typeface.MONOSPACE);
        if (Build.VERSION.SDK_INT >= 21) logView.setLetterSpacing(0.06f);
        if (Build.VERSION.SDK_INT >= 28) logView.setLineHeight(dp(18));
        diagnosticsTab.addView(logView);
        diagnosticsTab.addView(collapsibleBox("Radio and network assist", diagnosticsRadioPanel(), false));
        diagnosticsTab.addView(collapsibleBox("Support and project links", diagnosticsSupportPanel(), false));

        startButton.setOnClickListener(v -> startScan());
        stopButton.setOnClickListener(v -> requestStop());
        clearButton.setOnClickListener(v -> clearResults());
        helpButton.setOnClickListener(v -> showGuide());
        tabTargetButton.setOnClickListener(v -> selectTab(0));
        tabLiveButton.setOnClickListener(v -> selectTab(1));
        tabDiagnosticsButton.setOnClickListener(v -> selectTab(2));
        copyButton.setOnClickListener(v -> copySelectedFormat());
        copyCsvButton.setOnClickListener(v -> copyVisibleCsv());
        exportButton.setOnClickListener(v -> exportJson());
        View.OnClickListener refresh = v -> renderResultsFromFirstPage();
        filterWorking.setOnClickListener(refresh);
        filterTlsHttp.setOnClickListener(refresh);
        bestPerIp.setOnClickListener(refresh);
        requireHttp.setOnClickListener(refresh);
        requireKnownCdn.setOnClickListener(refresh);
        requireTls13.setOnClickListener(refresh);
        View.OnClickListener planClick = v -> updateScanPlanPreview();
        stepTcp.setOnClickListener(planClick);
        stepTls.setOnClickListener(planClick);
        stepHttp.setOnClickListener(planClick);
        stepVerify.setOnClickListener(planClick);
        batteryFriendlyUi.setOnClickListener(v -> applyBatteryFriendlyUi());
        multiSni.setOnClickListener(v -> {
            scheduleRender();
            updateScanPlanPreview();
        });
        sortSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) { renderResultsFromFirstPage(); }
            @Override public void onNothingSelected(AdapterView<?> p) {}
        });
        cdnProviderSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) { renderResultsFromFirstPage(); }
            @Override public void onNothingSelected(AdapterView<?> p) {}
        });
        AdapterView.OnItemSelectedListener planRefresh = new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) { updateScanPlanPreview(); }
            @Override public void onNothingSelected(AdapterView<?> p) {}
        };
        profileSpinner.setOnItemSelectedListener(planRefresh);
        workflowSpinner.setOnItemSelectedListener(planRefresh);
        tlsModeSpinner.setOnItemSelectedListener(planRefresh);
        targetsInput.addTextChangedListener(simpleWatcher(this::renderTokenPreviews));
        snisInput.addTextChangedListener(simpleWatcher(this::renderTokenPreviews));
        totalInput.addTextChangedListener(simpleWatcher(this::renderTokenPreviews));
        customTargetSampleInput.addTextChangedListener(simpleWatcher(this::renderTokenPreviews));
        customSniSampleInput.addTextChangedListener(simpleWatcher(this::renderTokenPreviews));
        defaultSniEnabled.setOnClickListener(v -> renderTokenPreviews());
        batchInput.addTextChangedListener(simpleWatcher(this::updateScanPlanPreview));
        threadsInput.addTextChangedListener(simpleWatcher(this::updateScanPlanPreview));
        timeoutInput.addTextChangedListener(simpleWatcher(this::updateScanPlanPreview));
        portsInput.addTextChangedListener(simpleWatcher(this::updateScanPlanPreview));
        pathInput.addTextChangedListener(simpleWatcher(this::updateScanPlanPreview));
        maxLatencyInput.addTextChangedListener(simpleWatcher(this::renderResultsFromFirstPage));
        resultLimitInput.addTextChangedListener(simpleWatcher(this::renderResultsFromFirstPage));
        cdnFilterInput.addTextChangedListener(simpleWatcher(this::renderResultsFromFirstPage));
        certFilterInput.addTextChangedListener(simpleWatcher(this::renderResultsFromFirstPage));
        sniFilterInput.addTextChangedListener(simpleWatcher(this::renderResultsFromFirstPage));
        minQualityInput.addTextChangedListener(simpleWatcher(this::renderResultsFromFirstPage));
        screen.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(screen);
        applyAccessibilityLabels();
        updateHomeDashboard();
        updateAnalytics(Collections.emptyList());
        renderTokenPreviews();
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
            String transport = transportName(caps);
            String metered = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) ? "unmetered" : "metered";
            String internet = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ? "validated" : "unverified";
            String roaming = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING) ? "not roaming" : "roaming/unknown";
            return "Connected via " + transport + " | " + metered + " | " + internet + " | " + roaming;
        } catch (Exception ignored) {
            return "Network context unavailable";
        }
    }

    private void updateHomeDashboard() {
        if (homeDashboardView == null) return;
        homeDashboardView.setText(homeDashboardText("checking..."));
        new Thread(() -> {
            String publicIp = fetchPublicIp();
            ui.post(() -> {
                if (homeDashboardView != null) homeDashboardView.setText(homeDashboardText(publicIp));
            });
        }, "public-ip-lookup").start();
    }

    private String homeDashboardText(String publicIp) {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (cm == null) return "Network\nContext unavailable";
            Network network = cm.getActiveNetwork();
            if (network == null) return "Network\nOffline";
            NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            LinkProperties lp = cm.getLinkProperties(network);
            String transport = transportName(caps);
            String privateIp = privateIps(lp);
            String dns = dnsServers(lp);
            String dnsProvider = dnsProvider(dns);
            String dnsStatus = dnsStatus(caps, lp);
            String proxyVpn = proxyVpnStatus(cm, caps);
            String providerStatus = providerStatus(caps);
            String capacity = capacityStatus(caps);
            return "Network and system\n" +
                    "Transport: " + transport + "\n" +
                    "LAN/WAN: " + privateIp + " -> " + publicIp + "\n" +
                    "DNS: " + dnsProvider + " (" + dns + ")\n" +
                    "Policy: " + proxyVpn + "\n" +
                    "State: " + dnsStatus + " | " + providerStatus + "\n" +
                    "Capacity: " + capacity + "\n" +
                    "Device: " + deviceLine() + "\n" +
                    "Runtime: " + resourceLine();
        } catch (Exception e) {
            return "Network\nDetails unavailable";
        }
    }

    private String fetchPublicIp() {
        String[] endpoints = {
                "https://api.ipify.org",
                "https://ifconfig.me/ip",
                "https://icanhazip.com"
        };
        for (String endpoint : endpoints) {
            HttpURLConnection conn = null;
            try {
                conn = (HttpURLConnection) new URL(endpoint).openConnection();
                conn.setConnectTimeout(2500);
                conn.setReadTimeout(2500);
                conn.setRequestProperty("User-Agent", "MaybeEdgeScanner/1.1");
                try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.US_ASCII))) {
                    String line = br.readLine();
                    if (line != null && !line.trim().isEmpty()) return line.trim();
                }
            } catch (Exception ignored) {
            } finally {
                if (conn != null) conn.disconnect();
            }
        }
        return "unavailable";
    }

    private String privateIps(LinkProperties lp) {
        ArrayList<String> ips = new ArrayList<>();
        if (lp != null) {
            for (LinkAddress address : lp.getLinkAddresses()) addPrivateAddress(ips, address == null ? null : address.getAddress());
        }
        if (ips.isEmpty()) {
            try {
                Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
                while (interfaces != null && interfaces.hasMoreElements()) {
                    NetworkInterface ni = interfaces.nextElement();
                    if (ni == null || !ni.isUp() || ni.isLoopback() || ni.isVirtual()) continue;
                    Enumeration<InetAddress> addresses = ni.getInetAddresses();
                    while (addresses.hasMoreElements()) addPrivateAddress(ips, addresses.nextElement());
                }
            } catch (Exception ignored) {}
        }
        return ips.isEmpty() ? "unavailable" : joinComma(ips);
    }

    private void addPrivateAddress(ArrayList<String> ips, InetAddress inet) {
        if (inet == null || inet.isLoopbackAddress() || inet.isLinkLocalAddress() || inet.isMulticastAddress()) return;
        String host = inet.getHostAddress();
        if (host == null || host.trim().isEmpty()) return;
        int zone = host.indexOf('%');
        if (zone >= 0) host = host.substring(0, zone);
        boolean privateV4 = inet instanceof Inet4Address && (inet.isSiteLocalAddress() || host.startsWith("100.64.") || host.startsWith("169.254."));
        boolean usableV6 = inet instanceof Inet6Address && !host.equals("::1");
        if ((privateV4 || usableV6) && !ips.contains(host)) ips.add(host);
    }

    private String dnsServers(LinkProperties lp) {
        if (lp == null || lp.getDnsServers().isEmpty()) return "unavailable";
        ArrayList<String> servers = new ArrayList<>();
        for (InetAddress dns : lp.getDnsServers()) servers.add(dns.getHostAddress());
        return joinComma(servers);
    }

    private String dnsProvider(String dns) {
        String d = dns == null ? "" : dns;
        if (d.contains("1.1.1.1") || d.contains("1.0.0.1") || d.contains("2606:4700")) return "Cloudflare";
        if (d.contains("8.8.8.8") || d.contains("8.8.4.4") || d.contains("2001:4860:4860")) return "Google";
        if (d.contains("9.9.9.9") || d.contains("149.112.112.112") || d.contains("2620:fe")) return "Quad9";
        if (d.contains("208.67.222.222") || d.contains("208.67.220.220")) return "Cisco OpenDNS";
        if (d.contains("94.140.14.") || d.contains("2a10:50c0")) return "AdGuard";
        return d == null || d.equals("unavailable") ? "unavailable" : "network provided";
    }

    private String dnsStatus(NetworkCapabilities caps, LinkProperties lp) {
        ArrayList<String> status = new ArrayList<>();
        status.add(caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ? "internet ok" : "internet unverified");
        if (Build.VERSION.SDK_INT >= 28 && lp != null) {
            status.add(lp.isPrivateDnsActive() ? "Private DNS active" : "Private DNS off");
            String name = lp.getPrivateDnsServerName();
            if (name != null && !name.trim().isEmpty()) status.add(name);
        }
        return joinComma(status);
    }

    private String proxyVpnStatus(ConnectivityManager cm, NetworkCapabilities caps) {
        ArrayList<String> out = new ArrayList<>();
        out.add(caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ? "VPN active" : "VPN not detected");
        try {
            ProxyInfo proxy = cm == null ? null : cm.getDefaultProxy();
            if (proxy != null && proxy.getHost() != null) out.add("proxy " + proxy.getHost() + ":" + proxy.getPort());
        } catch (Exception ignored) {}
        String sysProxy = System.getProperty("http.proxyHost");
        if (sysProxy != null && !sysProxy.trim().isEmpty()) out.add("system proxy " + sysProxy);
        return joinComma(out);
    }

    private String transportName(NetworkCapabilities caps) {
        if (caps == null) return "network unknown";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "Wi-Fi";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return "Cellular";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return "Ethernet";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return "VPN";
        return "Network";
    }

    private String providerStatus(NetworkCapabilities caps) {
        if (caps == null) return "capabilities unknown";
        ArrayList<String> status = new ArrayList<>();
        status.add(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) ? "unmetered" : "metered");
        status.add(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ? "internet capable" : "no internet capability");
        status.add(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING) ? "not roaming" : "roaming/unknown");
        if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)) status.add("captive portal");
        return joinComma(status);
    }

    private String capacityStatus(NetworkCapabilities caps) {
        if (caps == null) return "unknown";
        int down = caps.getLinkDownstreamBandwidthKbps();
        int up = caps.getLinkUpstreamBandwidthKbps();
        ArrayList<String> parts = new ArrayList<>();
        if (down > 0) parts.add("down " + down + " kbps");
        if (up > 0) parts.add("up " + up + " kbps");
        return parts.isEmpty() ? "not reported by Android" : joinComma(parts);
    }

    private LinearLayout sourceControl(CheckBox enabled, EditText input, String detail) {
        LinearLayout panel = column();
        panel.setBackground(glassBg(Color.rgb(10, 24, 34), Color.argb(60, 255, 255, 255)));
        panel.setPadding(dp(7), dp(2), dp(7), dp(7));
        LinearLayout controls = row();
        input.setEms(7);
        input.setMinWidth(dp(76));
        input.setMaxWidth(dp(112));
        SeekBar scrubber = new SeekBar(this);
        scrubber.setMax(999999);
        scrubber.setProgress(clampInt(intValue(input, 0), 0, 999999));
        scrubber.setContentDescription(enabled.getText() + " horizontal sample scrubber. Zero means all available entries.");
        scrubber.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
                if (!fromUser) return;
                suppressUiRefresh = true;
                input.setText(String.valueOf(progress));
                input.setSelection(input.getText().length());
                suppressUiRefresh = false;
                renderTokenPreviews();
            }
            @Override public void onStartTrackingTouch(SeekBar seekBar) {}
            @Override public void onStopTrackingTouch(SeekBar seekBar) {}
        });
        input.addTextChangedListener(simpleWatcher(() -> {
            int value = clampInt(intValue(input, 0), 0, 999999);
            if (scrubber.getProgress() != value) scrubber.setProgress(value);
            renderTokenPreviews();
        }));
        enabled.setOnClickListener(v -> renderTokenPreviews());
        controls.addView(enabled, new LinearLayout.LayoutParams(0, -2, 1));
        controls.addView(input, fixedWidth(94));
        panel.addView(controls);
        panel.addView(scrubber, new LinearLayout.LayoutParams(-1, -2));
        TextView hint = text(detail + "\n0 = all available; type exact large counts or scrub horizontally for coarse sampling.", 10, Color.rgb(155, 184, 198), false);
        panel.addView(hint);
        return panel;
    }

    private void clearManagedSources() {
        selectedSourceTargets.clear();
        selectedSourceSnis.clear();
        if (communitySourceEnabled != null) communitySourceEnabled.setChecked(false);
        if (akamaiSourceEnabled != null) akamaiSourceEnabled.setChecked(false);
        if (cloudfrontSourceEnabled != null) cloudfrontSourceEnabled.setChecked(false);
        if (fastlySourceEnabled != null) fastlySourceEnabled.setChecked(false);
        if (cloudflareSourceEnabled != null) cloudflareSourceEnabled.setChecked(false);
        if (otherCdnSourceEnabled != null) otherCdnSourceEnabled.setChecked(false);
        if (defaultSniEnabled != null) defaultSniEnabled.setChecked(false);
        if (sourceSummaryView != null) sourceSummaryView.setText("Managed sources disabled. Custom targets and custom SNI routes remain untouched.");
        renderTokenPreviews();
        toast("Managed sources cleared");
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
            updateScanPlanPreview();
            toast(title + " values applied. You can still edit them.");
        });
        b.setContentDescription(title + " performance mode: threads, batch, timeout " + subtitle);
        return b;
    }

    private void applyBatteryFriendlyUi() {
        boolean on = batteryFriendlyUi != null && batteryFriendlyUi.isChecked();
        if (hideNoisyLogs != null) hideNoisyLogs.setChecked(on || hideNoisyLogs.isChecked());
        if (resultLimitInput != null && on) resultLimitInput.setText("75");
        if (on) {
            densityMode = 2;
            refreshSegmentButtons(densityButtons, densityMode);
        }
        if (analyticsPanel != null) analyticsPanel.setVisibility(on ? View.GONE : View.VISIBLE);
        if (logView != null) logView.setVisibility(on ? View.GONE : View.VISIBLE);
        scheduleRender();
        toast(on ? "Battery-friendly UI enabled" : "Battery-friendly UI disabled");
    }

    private boolean batteryFriendlyMode() {
        return batteryFriendlyUi != null && batteryFriendlyUi.isChecked();
    }

    private android.text.TextWatcher simpleWatcher(Runnable afterChange) {
        final Runnable runner = () -> {
            if (!suppressUiRefresh && afterChange != null) afterChange.run();
        };
        return new android.text.TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(android.text.Editable s) {
                if (suppressUiRefresh) return;
                ui.removeCallbacks(runner);
                ui.postDelayed(runner, 650);
            }
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
        rebuildManagedSources();
        List<String> targetTokens = combinedTargetTokens();
        int targetCap = Math.max(1, intValue(totalInput, 72000));
        int estimatedTargets = estimateExpandedTargetCount(targetTokens, 200000);
        List<String> previewTargets = previewExpandedTargets(targetTokens, Math.min(targetCap, PREVIEW_TARGET_LIMIT));
        renderChips(targetChipPreview, "Source preview (" + selectedSourceTargets.size() + " managed tokens + " + sampledCustomTargets().size() + " custom -> " + Math.min(estimatedTargets, targetCap) + " endpoints, " + previewTargets.size() + " previewed)", previewTargets, true);
        if (sniPairingEnabled()) renderChips(sniChipPreview, "SNI routes (" + selectedSourceSnis.size() + " default + " + sampledCustomSnis().size() + " custom)", combinedSniTokens(), false);
        else renderChips(sniChipPreview, "SNI pairing disabled", Collections.emptyList(), false);
        updateSourceHealth(targetTokens, estimatedTargets, targetCap);
        updateScanPlanPreview();
    }

    private void updateSourceHealth(List<String> targetTokens, int estimatedTargets, int targetCap) {
        if (sourceHealthView == null || targetsInput == null || snisInput == null) return;
        int customTargets = lines(targetsInput.getText().toString()).size();
        int managedTargets = selectedSourceTargets.size();
        int customRoutes = lines(snisInput.getText().toString()).size();
        int cappedTargets = Math.min(estimatedTargets, targetCap);
        String composition = targetTokens.isEmpty()
                ? "No target sources selected yet."
                : managedTargets + " managed target tokens + " + customTargets + " custom target tokens, deduped before expansion.";
        String routeScope = sniPairingEnabled()
                ? selectedSourceSnis.size() + " managed SNI routes + " + customRoutes + " custom SNI routes; route mode is " + ((multiSni != null && multiSni.isChecked()) ? "all SNI hosts." : "primary SNI first.")
                : "IP-only scope; SNI/host names are extracted from TLS and HTTP results, not paired as scan input.";
        sourceHealthView.setText("Source health\n" +
                composition + "\n" +
                "Expanded estimate: " + estimatedTargets + " endpoints; Total cap keeps " + cappedTargets + " for this run.\n" +
                routeScope + "\n" +
                sourceLoadPosture(estimatedTargets, targetCap));
    }

    private String sourceLoadPosture(int estimatedTargets, int targetCap) {
        int threads = clampInt(intValue(threadsInput, 32), 1, MAX_THREADS);
        int batch = clampInt(intValue(batchInput, 2000), 1, MAX_BATCH);
        int capped = Math.min(estimatedTargets, targetCap);
        if (capped == 0) return "Posture: idle; add or select IP targets before scanning.";
        if (capped > 12000 || threads > 64 || batch > 8000) return "Posture: wide/high-load; better for plugged-in devices or the sidecar.";
        if (capped < 500 || threads <= 16) return "Posture: light route validation; good for tuning SNI choices and unstable mobile links.";
        return "Posture: balanced phone scan; suitable for normal interactive use.";
    }

    private List<String> combinedTargetTokens() {
        LinkedHashSet<String> merged = new LinkedHashSet<>(selectedSourceTargets);
        merged.addAll(sampledCustomTargets());
        return new ArrayList<>(merged);
    }

    private List<String> combinedSniTokens() {
        LinkedHashSet<String> merged = new LinkedHashSet<>(selectedSourceSnis);
        merged.addAll(sampledCustomSnis());
        return new ArrayList<>(merged);
    }

    private LinkedHashSet<String> sampledCustomTargets() {
        return sampleSource(lines(targetsInput == null ? "" : targetsInput.getText().toString()), customTargetSampleInput == null ? 0 : intValue(customTargetSampleInput, 0));
    }

    private LinkedHashSet<String> sampledCustomSnis() {
        return sampleSource(lines(snisInput == null ? "" : snisInput.getText().toString()), customSniSampleInput == null ? 0 : intValue(customSniSampleInput, 0));
    }

    private void updateScanPlanPreview() {
        if (scanPlanView == null || targetsInput == null || snisInput == null || portsInput == null || totalInput == null) return;
        List<String> rawTargets = combinedTargetTokens();
        int cap = Math.max(1, intValue(totalInput, 72000));
        int estimatedTargets = estimateExpandedTargetCount(rawTargets, 200000);
        int cappedTargets = Math.min(estimatedTargets, cap);
        int sniCount = sniPairingEnabled() ? Math.max(1, combinedSniTokens().size()) : 1;
        List<Integer> ports = parsePorts(portsInput.getText().toString());
        List<Integer> profiles = selectedWorkflowProfiles();
        boolean allSni = sniPairingEnabled() && multiSni != null && multiSni.isChecked();
        int units = estimateAttemptUnits(cappedTargets, sniCount, ports.size(), profiles, allSni);
        int batch = clampInt(intValue(batchInput, 2000), 1, MAX_BATCH);
        int threads = clampInt(intValue(threadsInput, 32), 1, MAX_THREADS);
        int timeout = clampInt(intValue(timeoutInput, 3000), 250, 15000);
        String path = pathInput == null ? "/" : pathInput.getText().toString().trim();
        if (path.isEmpty()) path = "/";
        if (!path.startsWith("/")) path = "/" + path;
        scanPlanView.setText("Scan plan\n" +
                selectedSourceTargets.size() + " managed source tokens + " + lines(targetsInput.getText().toString()).size() + " custom tokens -> " + estimatedTargets + " estimated endpoints -> " + cappedTargets + " after Total cap " + cap + "\n" +
                (sniPairingEnabled() ? sniCount + " SNI host" + (sniCount == 1 ? "" : "s") + " kept separate for TLS/Host routing; " : "IP-only TLS/HTTP probing; ") + "ports " + ports + "\n" +
                "Runtime: batch " + batch + ", threads " + threads + ", timeout " + timeout + "ms, HTTP path " + path + "\n" +
                "TLS ClientHello mode: " + (tlsModeSpinner == null ? "Android default" : tlsModeSpinner.getSelectedItem()) + "\n" +
                workflowLabels(profiles) + " -> " + (profiles.isEmpty() ? "select at least one manual step." : "about " + units + " probe units. Preset overlaps are deduped, not overridden."));
    }

    private int estimateAttemptUnits(int targets, int snis, int ports, List<Integer> profiles, boolean allSni) {
        long units = 0;
        int portCount = Math.max(1, ports);
        int routeCount = Math.max(1, snis);
        for (int profile : profiles) {
            int sniMultiplier = profile == 0 ? 1 : ((profile >= 2 || allSni) ? routeCount : 1);
            units += (long) Math.max(0, targets) * portCount * Math.max(1, sniMultiplier);
        }
        if (units <= 0) return 0;
        return units > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) units;
    }

    private boolean sniPairingEnabled() {
        return true;
    }

    private static List<String> previewExpandedTargets(List<String> raw, int limit) {
        ArrayList<String> out = new ArrayList<>();
        int cap = Math.max(1, limit);
        int index = 0;
        for (String token : raw) {
            if (out.size() >= cap) break;
            String clean = cleanToken(token);
            if (clean.isEmpty()) continue;
            out.add((clean.contains("/") || clean.contains("-")) ? sampleOneExpandedTarget(clean, index++) : clean);
        }
        return out;
    }

    private void renderChips(LinearLayout panel, String title, List<String> values, boolean targets) {
        panel.removeAllViews();
        int valid = 0;
        for (String value : values) if (targets ? validTargetToken(value) : validDomainToken(value)) valid++;
        panel.addView(text(title + ": " + valid + "/" + values.size() + " ready", 11, MUTED, true));
        int shown = Math.min(values.size(), 8);
        LinearLayout row = null;
        for (int i = 0; i < shown; i++) {
            if (i % 2 == 0) {
                row = row();
                row.setGravity(Gravity.START);
                panel.addView(row);
            }
            String token = values.get(i);
            boolean ok = targets ? validTargetToken(token) : validDomainToken(token);
            row.addView(chip(token, ok), smallChipLp());
        }
        if (row == null) {
            row = row();
            row.setGravity(Gravity.START);
            panel.addView(row);
        }
        if (values.size() > shown) row.addView(chip("+" + (values.size() - shown) + " more", true), smallChipLp());
        if (values.isEmpty()) row.addView(chip(targets ? "Paste IPs, CIDRs, ranges, domains" : "Paste hostnames for TLS SNI", true), smallChipLp());
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
            return p.length == 2 && isIpv4(p[0]) && isIpv4(p[1]);
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
        styleTab(tabDiagnosticsButton, activeTab == 2);
        setTabVisible(targetTab, activeTab == 0);
        setTabVisible(liveTab, activeTab == 1);
        setTabVisible(diagnosticsTab, activeTab == 2);
        if (mainScroll != null) mainScroll.post(() -> mainScroll.smoothScrollTo(0, 0));
    }

    private void setTabVisible(View tab, boolean visible) {
        if (tab == null) return;
        tab.animate().cancel();
        if (visible) {
            if (tab.getVisibility() != View.VISIBLE) {
                tab.setAlpha(0f);
                tab.setVisibility(View.VISIBLE);
            }
            tab.animate().alpha(1f).setDuration(150).start();
        } else {
            if (tab.getVisibility() == View.VISIBLE) {
                tab.animate().alpha(0f).setDuration(120).withEndAction(() -> {
                    if (tab.getAlpha() == 0f) tab.setVisibility(View.GONE);
                }).start();
            } else {
                tab.setAlpha(0f);
                tab.setVisibility(View.GONE);
            }
        }
    }

    private boolean handleTabSwipe(android.view.MotionEvent event) {
        if (event == null) return false;
        if (event.getAction() == android.view.MotionEvent.ACTION_DOWN) {
            swipeDownX = event.getX();
            swipeDownY = event.getY();
        } else if (event.getAction() == android.view.MotionEvent.ACTION_UP) {
            float dx = event.getX() - swipeDownX;
            float dy = event.getY() - swipeDownY;
            if (Math.abs(dx) > dp(72) && Math.abs(dx) > Math.abs(dy) * 1.6f) {
                selectTab(activeTab + (dx < 0 ? 1 : -1));
            }
        }
        return false;
    }

    private void styleTab(Button button, boolean selected) {
        if (button == null) return;
        button.setTextColor(selected ? Color.rgb(2, 18, 24) : Color.WHITE);
        button.setBackground(glassBg(selected ? BLUE : Color.rgb(21, 45, 62),
                selected ? Color.argb(210, 255, 255, 255) : Color.argb(110, 255, 255, 255)));
    }

    private void maybeShowOnboarding() {
        SharedPreferences prefs = getSharedPreferences("maybeedgescanner", MODE_PRIVATE);
        if (prefs.getBoolean("onboarded_v3", false)) return;
        prefs.edit().putBoolean("onboarded_v3", true).apply();
        ui.postDelayed(() -> new AlertDialog.Builder(this)
                .setTitle("Welcome to MaybeEdgeScanner")
                .setMessage("1. Pick target corpora: Akamai, CloudFront, Fastly, or all bundled presets.\n\n" +
                        "2. Pick SNI hosts: SNI is the hostname used during TLS. Presets include useful defaults, and your custom hosts are merged in.\n\n" +
                        "3. Scan and filter: choose a single profile, Auto multi-step ladder, or Manual selected steps. Results show progress, cards, provider filters, sorting, visual density, and export. Diagnostics keeps logs and support out of the way.")
                .setPositiveButton("Start setup", (d, which) -> scrollTo(targetAnchor))
                .setNegativeButton("Guide", (d, which) -> showGuide())
                .show(), 550);
    }

    private void applyAccessibilityLabels() {
        targetsInput.setContentDescription("Targets input. Add domains, IP addresses, or CIDR ranges.");
        snisInput.setContentDescription("SNI hosts input. Add one or more TLS hostnames.");
        startButton.setContentDescription("Start scan with the selected targets, SNI hosts, workflow, and performance values.");
        stopButton.setContentDescription("Stop the active scan.");
        copyButton.setContentDescription("Copy filtered results using the selected clipboard format.");
        progress.setContentDescription("Scan progress");
        workflowSpinner.setContentDescription("Scan workflow. Choose single profile, automatic multi-step ladder, or manual selected steps.");
    }

    private void showGuide() {
        new AlertDialog.Builder(this)
                .setTitle("MaybeEdgeScanner guide")
                .setMessage(
                        "What to scan\n" +
                        "Targets are IPs, domains, or CIDR ranges. Source checkboxes enable bundled Akamai, AWS CloudFront, Fastly, other cloud, and community edge corpora. Use 0 for a full corpus or type an exact sample count.\n\n" +
                        "SNI hosts\n" +
                        "SNI is the hostname sent during TLS. Toggle the default SNI corpus, let enabled providers add relevant host routes, or add your own domains. Enable All SNI hosts for deeper matching; leave it off for faster scans.\n\n" +
                        "Profiles\n" +
                        "Quick TCP checks reachability. Standard TLS verifies TLS. Deep HTTP + SNI adds HTTP HEAD checks. Verify CDN edge favors confirmed working CDN-like endpoints.\n\n" +
                        "Workflows\n" +
                        "Single runs one selected profile. Auto multi-step ladder runs TCP, then TLS, then HTTP/SNI, then CDN verification. Manual selected steps runs only the checked stages, useful when you want a focused pass without changing source selections.\n\n" +
                        "Visual modes\n" +
                        "Comfort is the default card layout. Contrast avoids color-only status cues and increases card opacity. Compact reduces spacing so more edges fit on screen.\n\n" +
                        "Performance parameters\n" +
                        "Total cap is the run limit after CIDR/range expansion; raise it when you intentionally want full subnets or very large provider corpora. Batch controls how many targets run per wave. Threads controls parallel sockets. Timeout ms controls how long each connect/TLS/HTTP attempt can wait.\n\n" +
                        "Filtering and sorting\n" +
                        "Results owns all browsing controls: Working only, TLS/HTTP only, HTTP only, Known CDN only, TLS 1.3 only, provider filter, SNI filter, CDN text filter, certificate filter, max latency, visible card limit, and min score. Sort by Score to surface the strongest candidates.\n\n" +
                        "Copy and export\n" +
                        "Copy filtered uses exactly the rows currently visible after filters and sort. Choose line-separated IPs, comma-separated IPs, IP SNI pairs, SNI only, CSV, or JSON. Copy never replaces the card surface; it only reports status.")
                .setPositiveButton("Got it", null)
                .show();
    }

    private void loadDefaults() {
        status.setText("Loading sources");
        new Thread(() -> {
            warmSourceCaches();
            ui.post(() -> {
                suppressUiRefresh = true;
                if (communitySourceEnabled != null) communitySourceEnabled.setChecked(true);
                if (defaultSniEnabled != null) defaultSniEnabled.setChecked(true);
                targetsInput.setText("");
                snisInput.setText("");
                suppressUiRefresh = false;
                status.setText("Ready");
                renderTokenPreviews();
            });
        }, "source-loader").start();
    }

    private void warmSourceCaches() {
        loadAsset("default_targets.txt");
        loadAsset("default_edges_extra.txt");
        communityEdgeCorpus("scan-corpora/maybepsiphon-edge-ips.txt", "scan-corpora/community-edge-cidrs-24.txt");
        loadAsset("default_snis.txt");
        loadAsset("scan-corpora/maybepsiphon-sni-hosts.txt");
        loadAssetTokens("scan-corpora/akamai-AS20940.json");
        loadAsset("scan-corpora/akamai-hosts-184x.txt");
        loadAssetTokens("scan-corpora/aws-cloudfront-ranges.txt");
        loadAssetTokens("scan-corpora/fastly-AS54113.json");
        loadAssetTokens("scan-corpora/cloudflare-ranges.txt");
        loadAssetTokens("scan-corpora/github-pages-ranges.txt");
        loadAssetTokens("scan-corpora/azure-frontdoor-ranges.txt");
        loadAssetTokens("scan-corpora/google-cdn-ranges.txt");
        loadAssetTokens("scan-corpora/bunny-ranges.txt");
        loadAssetTokens("scan-corpora/stackpath-edgio-ranges.txt");
        loadAssetTokens("scan-corpora/other-cloud-ranges.txt");
    }

    private void rebuildManagedSources() {
        selectedSourceTargets.clear();
        selectedSourceSnis.clear();
        ArrayList<String> enabled = new ArrayList<>();
        if (checked(defaultSniEnabled)) {
            selectedSourceSnis.addAll(loadAsset("default_snis.txt"));
            selectedSourceSnis.addAll(loadAsset("scan-corpora/maybepsiphon-sni-hosts.txt"));
        }
        if (checked(communitySourceEnabled)) {
            int count = intValue(communitySampleInput, 0);
            selectedSourceTargets.addAll(sampleSource(loadAsset("default_targets.txt"), count));
            selectedSourceTargets.addAll(sampleSource(loadAsset("default_edges_extra.txt"), count));
            selectedSourceTargets.addAll(sampleSource(communityEdgeCorpus("scan-corpora/maybepsiphon-edge-ips.txt", "scan-corpora/community-edge-cidrs-24.txt"), count));
            enabled.add("Community");
        }
        if (checked(akamaiSourceEnabled)) {
            int count = intValue(akamaiSampleInput, 0);
            selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/akamai-AS20940.json"), count));
            selectedSourceTargets.addAll(sampleSource(loadAsset("scan-corpora/akamai-hosts-184x.txt"), count));
            addRelevantSni(selectedSourceSnis, "akamai");
            enabled.add("Akamai");
        }
        if (checked(cloudfrontSourceEnabled)) {
            selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/aws-cloudfront-ranges.txt"), intValue(cloudfrontSampleInput, 0)));
            addRelevantSni(selectedSourceSnis, "aws");
            addRelevantSni(selectedSourceSnis, "cloudfront");
            enabled.add("CloudFront");
        }
        if (checked(fastlySourceEnabled)) {
            selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/fastly-AS54113.json"), intValue(fastlySampleInput, 0)));
            addRelevantSni(selectedSourceSnis, "fastly");
            enabled.add("Fastly");
        }
        if (checked(cloudflareSourceEnabled)) {
            selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/cloudflare-ranges.txt"), intValue(cloudflareSampleInput, 0)));
            addRelevantSni(selectedSourceSnis, "cloudflare");
            enabled.add("Cloudflare");
        }
        if (checked(otherCdnSourceEnabled)) {
            int count = intValue(otherCdnSampleInput, 0);
            selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/github-pages-ranges.txt"), count));
            selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/azure-frontdoor-ranges.txt"), count));
            selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/google-cdn-ranges.txt"), count));
            selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/bunny-ranges.txt"), count));
            selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/stackpath-edgio-ranges.txt"), count));
            selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/other-cloud-ranges.txt"), count));
            addRelevantSni(selectedSourceSnis, "cloudflare");
            addRelevantSni(selectedSourceSnis, "mapbox");
            enabled.add("Other providers");
        }
        if (sourceSummaryView != null) {
            int estimated = estimateExpandedTargetCount(new ArrayList<>(selectedSourceTargets), 200000);
            sourceSummaryView.setText("Managed sources\n" +
                    (enabled.isEmpty() ? "No target corpus enabled" : joinComma(enabled)) + "\n" +
                    selectedSourceTargets.size() + " target tokens -> about " + estimated + " expanded endpoints before Total cap.\n" +
                    selectedSourceSnis.size() + " default/provider SNI routes " + (checked(defaultSniEnabled) ? "enabled" : "disabled") + "; custom typed targets and SNIs are sampled separately.");
        }
    }

    private boolean checked(CheckBox box) {
        return box != null && box.isChecked();
    }

    private LinkedHashSet<String> sampleSource(Collection<String> values, int count) {
        ArrayList<String> list = new ArrayList<>(values);
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (count <= 0) {
            out.addAll(list);
            return out;
        }
        if (list.isEmpty()) return out;
        int sampleCount = Math.min(count, list.size());
        for (int i = 0; i < sampleCount; i++) {
            String token = list.get((int) Math.floor(i * (list.size() / (double) sampleCount)));
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
        String key = ipAsset + "|" + cidrAsset;
        LinkedHashSet<String> cached = communityCorpusCache.get(key);
        if (cached != null) return new LinkedHashSet<>(cached);
        synchronized (assetReadLocks.computeIfAbsent("community:" + key, ignored -> new Object())) {
            cached = communityCorpusCache.get(key);
            if (cached != null) return new LinkedHashSet<>(cached);
            LinkedHashSet<String> out = new LinkedHashSet<>();
            for (String value : loadAsset(ipAsset)) out.add(toIpv4Cidr24(value));
            out.addAll(loadAsset(cidrAsset));
            communityCorpusCache.put(key, new LinkedHashSet<>(out));
            return out;
        }
    }

    private void addRelevantSni(LinkedHashSet<String> snis, String needle) {
        for (String sni : loadAsset("scan-corpora/maybepsiphon-sni-hosts.txt")) {
            if (sni.toLowerCase(Locale.US).contains(needle)) snis.add(sni);
        }
    }

    private void startScan() {
        if (executor != null && !executor.isShutdown()) {
            toast("Scan is already running");
            selectTab(1);
            return;
        }
        rebuildManagedSources();
        List<String> targets = expandTargets(combinedTargetTokens(), Math.max(1, intValue(totalInput, 5000)));
        List<String> snis = sniPairingEnabled() ? combinedSniTokens() : Collections.singletonList("");
        List<Integer> ports = parsePorts(portsInput.getText().toString());
        if (targets.isEmpty() || ports.isEmpty()) {
            toast("Targets and ports are required");
            return;
        }
        stop.set(false);
        synchronized (allResults) {
            allResults.clear();
        }
        checkedTargets.set(0);
        scanStartedAt = System.currentTimeMillis();
        resultList.removeAllViews();
        synchronized (logLines) {
            logLines.clear();
            stableLogBuilder.setLength(0);
        }
        logView.setText("");
        bestView.setText("Best result will appear here");
        if (snis.isEmpty()) snis = Collections.singletonList("");
        List<Integer> workflowProfiles = selectedWorkflowProfiles();
        if (workflowProfiles.isEmpty()) {
            toast("Select at least one manual workflow step");
            selectTab(0);
            updateScanPlanPreview();
            return;
        }
        boolean allSniPreference = sniPairingEnabled() && multiSni.isChecked();
        boolean suppressNoisyLogs = hideNoisyLogs.isChecked();
        String httpPath = pathInput.getText().toString();
        int tlsMode = tlsModeSpinner == null ? 0 : tlsModeSpinner.getSelectedItemPosition();
        totalTargets = estimateAttemptUnits(targets.size(), snis.size(), ports.size(), workflowProfiles, allSniPreference);
        int batch = clampInt(intValue(batchInput, 2000), 1, MAX_BATCH);
        int threads = clampInt(intValue(threadsInput, 32), 1, MAX_THREADS);
        int timeout = clampInt(intValue(timeoutInput, 3000), 250, 15000);

        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        status.setText("Running");
        selectTab(1);
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

    private void requestStop() {
        stop.set(true);
        status.setText("Stopping");
        stopButton.setEnabled(false);
        appendLog("Stop requested. Current sockets will finish or time out.");
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
        return profiles;
    }

    private String workflowLabels(List<Integer> profiles) {
        if (profiles.isEmpty()) return "No manual steps selected";
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
            boolean allSni = sniPairingEnabled() && (allSniPreference || profile >= 2);
            appendLog("Workflow step " + (i + 1) + "/" + profiles.size() + ": " + profileName(profile) +
                    (sniPairingEnabled() ? (allSni ? " with multi-SNI" : " with primary SNI") : " with IP-only probing"));
            runBatches(targets, snis, ports, batchSize, timeout, profile, allSni, httpPath, tlsMode, suppressNoisyLogs);
        }
        executor.shutdownNow();
        ui.post(() -> {
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
            status.setText(stop.get() ? "Stopped" : "Ready");
            appendLog((stop.get() ? "Stopped" : "Complete") + " in " + elapsed());
            if (!stop.get()) checkedTargets.set(totalTargets);
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
                List<String> candidates = sniPairingEnabled()
                        ? (allSni ? snis : Collections.singletonList(isIp(target) ? first(snis) : target))
                        : Collections.singletonList("");
                for (String sni : candidates) {
                    if (stop.get()) return;
                    String routeSni = sni == null ? "" : sni.trim();
                    Result r = new Result(target, ip, port, routeSni);
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
        int resultCount;
        synchronized (allResults) {
            allResults.add(r);
            resultCount = allResults.size();
        }
        checkedTargets.incrementAndGet();
        if (!suppressNoisyLogs && (r.tlsPass || r.httpPass || resultCount % 200 == 0)) {
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
            metrics.setText(checked + " / " + totalTargets + " probe units | rows " + s.rows + " | TCP " + s.tcp +
                    " | TLS " + s.tls + " | HTTP " + s.http + " | Q " + Math.round(s.bestQuality) + " | " + elapsed());
            countersView.setText("Down " + s.down + " | timeout " + s.timeout + " | reset " + s.reset +
                    " | cert " + s.cert + " | DNS " + s.dns + " | " + resourceLine());
            if (s.best != null) bestView.setText("Best: " + s.best.summary());
        });
    }

    private void scheduleRender() {
        if (!renderQueued.compareAndSet(false, true)) return;
        ui.removeCallbacks(renderBufferRunnable);
        ui.postDelayed(renderBufferRunnable, 500);
    }

    private final Runnable renderBufferRunnable = () -> {
        renderQueued.set(false);
        renderResults();
    };

    private void renderResults() {
        if (resultList == null) return;
        List<Result> snapshot = filteredResults();
        if (batteryFriendlyMode() || compactMode()) {
            if (analyticsPanel != null) analyticsPanel.setVisibility(View.GONE);
        } else {
            if (analyticsPanel != null) analyticsPanel.setVisibility(View.VISIBLE);
            updateAnalytics(snapshot);
        }
        renderStableHistoryPanel();
        resultList.removeAllViews();
        if (snapshot.isEmpty()) {
            resultList.addView(emptyResultsView());
            return;
        }
        Result bestVisible = bestVisibleResult(snapshot);
        bestView.setText((bestVisible == null ? "Best result unavailable" : "Best: " + bestVisible.summary()) + "\n" + bestSniLine(snapshot));
        resultList.addView(resultSummaryStrip(snapshot));
        if (!batteryFriendlyMode() && !compactMode() && visualizationMode == 1) {
            resultList.addView(heatmapView(snapshot));
        }
        int limit = Math.min(clampInt(intValue(resultLimitInput, 250), 1, MAX_RENDERED_CARDS), snapshot.size());
        if (batteryFriendlyMode()) limit = Math.min(limit, 75);
        if (compactMode()) limit = Math.min(limit, 90);
        int maxStart = Math.max(0, snapshot.size() - limit);
        resultOffset = Math.min(Math.max(0, resultOffset), maxStart);
        int end = Math.min(snapshot.size(), resultOffset + limit);
        for (int i = resultOffset; i < end; i++) resultList.addView(resultView(snapshot.get(i)));
        if (limit < snapshot.size()) {
            resultList.addView(resultPager(resultOffset, end, snapshot.size(), limit));
        }
    }

    private void renderResultsFromFirstPage() {
        resultOffset = 0;
        scheduleRender();
    }

    private View resultPager(int start, int end, int total, int pageSize) {
        LinearLayout panel = column();
        panel.setBackground(glassBg(Color.rgb(8, 20, 29), Color.argb(60, 255, 255, 255)));
        panel.setPadding(dp(9), dp(6), dp(9), dp(8));
        setOuterMargin(panel, 0, dp(6), 0, dp(8));
        panel.addView(text("Showing cards " + (start + 1) + "-" + end + " of " + total, 11, Color.rgb(185, 210, 222), false));
        LinearLayout controls = row();
        Button prev = button("Previous", Color.rgb(24, 45, 58), Color.WHITE);
        Button next = button("Next", Color.rgb(24, 45, 58), Color.WHITE);
        prev.setEnabled(start > 0);
        next.setEnabled(end < total);
        prev.setOnClickListener(v -> {
            resultOffset = Math.max(0, resultOffset - pageSize);
            renderResults();
        });
        next.setOnClickListener(v -> {
            resultOffset = Math.min(Math.max(0, total - pageSize), resultOffset + pageSize);
            renderResults();
        });
        controls.addView(prev, weight());
        controls.addView(next, weight());
        panel.addView(controls);
        return panel;
    }

    private View resultSummaryStrip(List<Result> rows) {
        int working = 0;
        long latencySum = 0, best = Long.MAX_VALUE;
        int latencyCount = 0;
        int rawCount;
        synchronized (allResults) {
            rawCount = allResults.size();
        }
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
        String line = "Visible results: " + rows.size() + " of " + rawCount +
                " | alive/working " + working +
                " | success " + success + "%" +
                " | best " + (best == Long.MAX_VALUE ? "--" : best + "ms") +
                " | avg " + (latencyCount == 0 ? "--" : Math.round(latencySum / (float) latencyCount) + "ms") +
                " | " + bestSniLine(rows) +
                " | filters " + filterSummary();
        TextView v = panelText(line);
        v.setTypeface(Typeface.MONOSPACE);
        return v;
    }

    private String bestSniLine(List<Result> rows) {
        LinkedHashMap<String, Double> scores = new LinkedHashMap<>();
        for (Result r : rows) {
            for (String host : sniCandidates(r)) {
                Double old = scores.get(host);
                double score = r.quality + (r.httpPass ? 12 : 0) + (r.tlsPass ? 8 : 0) - Math.max(0, r.totalLatency()) / 1000.0;
                if (old == null || score > old) scores.put(host, score);
            }
        }
        if (scores.isEmpty()) return "Best SNIs: none visible";
        ArrayList<Map.Entry<String, Double>> ordered = new ArrayList<>(scores.entrySet());
        ordered.sort((a, b) -> Double.compare(b.getValue(), a.getValue()));
        ArrayList<String> top = new ArrayList<>();
        for (int i = 0; i < Math.min(5, ordered.size()); i++) {
            Map.Entry<String, Double> e = ordered.get(i);
            top.add(e.getKey() + " q" + Math.round(e.getValue()));
        }
        return "Best SNIs: " + joinComma(top);
    }

    private Result bestVisibleResult(List<Result> rows) {
        Result best = null;
        for (Result r : rows) {
            if (best == null || r.quality > best.quality || (r.quality == best.quality && r.totalLatency() < best.totalLatency())) best = r;
        }
        return best;
    }

    private List<String> sniCandidates(Result r) {
        LinkedHashSet<String> hosts = new LinkedHashSet<>();
        addHostCandidate(hosts, r.sni);
        addHostCandidate(hosts, r.target);
        if (r.tlsCert != null && !r.tlsCert.isEmpty()) {
            String[] parts = r.tlsCert.split(",");
            for (String part : parts) {
                String value = part.trim();
                if (value.regionMatches(true, 0, "CN=", 0, 3)) addHostCandidate(hosts, value.substring(3));
            }
        }
        return new ArrayList<>(hosts);
    }

    private void addHostCandidate(LinkedHashSet<String> hosts, String value) {
        if (value == null) return;
        String host = value.trim().toLowerCase(Locale.US);
        if (host.startsWith("*.")) host = host.substring(2);
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if (isHostCandidate(host)) hosts.add(host);
    }

    private boolean isHostCandidate(String host) {
        if (host == null || host.length() < 4 || host.length() > 253 || !host.contains(".")) return false;
        if (host.matches("[0-9a-f:.]+") || host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) return false;
        return host.matches("[a-z0-9][a-z0-9.-]*[a-z0-9]");
    }

    private View emptyResultsView() {
        LinearLayout card = column();
        card.setPadding(dp(16), dp(14), dp(16), dp(14));
        card.setBackground(glassBg(Color.rgb(10, 28, 41), Color.argb(130, 255, 255, 255)));
        TextView icon = text("⌕", 34, BLUE, true);
        icon.setGravity(Gravity.CENTER);
        card.addView(icon);
        boolean hasRows;
        synchronized (allResults) { hasRows = !allResults.isEmpty(); }
        card.addView(text(hasRows ? "Filters hid every row" : "No visible edges yet", 16, Color.WHITE, true));
        card.addView(text(hasRows ? "Loosen provider, score, latency, SNI, certificate, or status filters to reveal existing scan rows." :
                "Start a scan from Sources. Result cards will stay here; copy and export never replace them.", 12, Color.rgb(205, 226, 238), false));
        Button cta = button(hasRows ? "Clear filters" : "Open Sources", Color.rgb(22, 54, 72), Color.WHITE);
        cta.setOnClickListener(v -> {
            if (hasRows) clearResultFilters();
            else selectTab(0);
        });
        card.addView(cta);
        return card;
    }

    private void clearResultFilters() {
        resultOffset = 0;
        suppressUiRefresh = true;
        if (filterWorking != null) filterWorking.setChecked(false);
        if (filterTlsHttp != null) filterTlsHttp.setChecked(false);
        if (requireHttp != null) requireHttp.setChecked(false);
        if (requireKnownCdn != null) requireKnownCdn.setChecked(false);
        if (requireTls13 != null) requireTls13.setChecked(false);
        if (bestPerIp != null) bestPerIp.setChecked(false);
        if (cdnProviderSpinner != null) cdnProviderSpinner.setSelection(0);
        if (maxLatencyInput != null) maxLatencyInput.setText("");
        if (cdnFilterInput != null) cdnFilterInput.setText("");
        if (certFilterInput != null) certFilterInput.setText("");
        if (sniFilterInput != null) sniFilterInput.setText("");
        if (minQualityInput != null) minQualityInput.setText("");
        suppressUiRefresh = false;
        scheduleRender();
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
        panel.addView(text("Heatmap overview", 15, Color.WHITE, true));
        int http = 0, tls = 0, tcp = 0, down = 0;
        for (Result r : rows) {
            if (r.httpPass) http++;
            else if (r.tlsPass) tls++;
            else if (r.tcpPass) tcp++;
            else down++;
        }
        panel.addView(text("Filtered mix: " + http + " HTTP, " + tls + " TLS, " + tcp + " TCP, " + down + " failed. Tap any tile to copy that result.", 12, MUTED, false));
        panel.addView(text("Colors: green HTTP, cyan TLS, amber TCP, red failed.", 11, MUTED, false));
        int columns = 12;
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
        String cdnPreset = cdnProviderSpinner == null || cdnProviderSpinner.getSelectedItem() == null ? "Any provider" : cdnProviderSpinner.getSelectedItem().toString();
        String cdn = cdnFilterInput == null ? "" : cdnFilterInput.getText().toString().trim().toLowerCase(Locale.US);
        String cert = certFilterInput == null ? "" : certFilterInput.getText().toString().trim().toLowerCase(Locale.US);
        String sni = sniFilterInput == null ? "" : sniFilterInput.getText().toString().trim().toLowerCase(Locale.US);
        int minQuality = intValue(minQualityInput, 0);
        snapshot.removeIf(r -> (filterWorking.isChecked() && !r.working()) ||
                (filterTlsHttp.isChecked() && !(r.tlsPass || r.httpPass)) ||
                (requireHttp.isChecked() && !r.httpPass) ||
                (requireKnownCdn.isChecked() && "UNKNOWN".equalsIgnoreCase(r.cdn)) ||
                (!providerMatches(cdnPreset, r.cdn)) ||
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

    private boolean providerMatches(String preset, String provider) {
        String choice = preset == null ? "" : preset.toLowerCase(Locale.US);
        String cdn = provider == null ? "" : provider.toLowerCase(Locale.US);
        if (choice.isEmpty() || choice.startsWith("any")) return true;
        if (choice.startsWith("known")) return !cdn.isEmpty() && !"unknown".equals(cdn);
        if (choice.startsWith("unknown")) return cdn.isEmpty() || "unknown".equals(cdn);
        if (choice.contains("cloudfront") || choice.contains("aws")) return cdn.contains("cloudfront") || cdn.contains("aws") || cdn.contains("amazon");
        if (choice.contains("cloudflare")) return cdn.contains("cloudflare");
        if (choice.contains("akamai")) return cdn.contains("akamai");
        if (choice.contains("fastly")) return cdn.contains("fastly");
        if (choice.contains("github")) return cdn.contains("github");
        if (choice.contains("google")) return cdn.contains("google") || cdn.contains("gcp");
        if (choice.contains("azure")) return cdn.contains("azure") || cdn.contains("microsoft");
        if (choice.contains("bunny")) return cdn.contains("bunny");
        return cdn.contains(choice);
    }

    private String filterSummary() {
        ArrayList<String> active = new ArrayList<>();
        if (filterWorking != null && filterWorking.isChecked()) active.add("working");
        if (filterTlsHttp != null && filterTlsHttp.isChecked()) active.add("TLS/HTTP");
        if (requireHttp != null && requireHttp.isChecked()) active.add("HTTP");
        if (requireKnownCdn != null && requireKnownCdn.isChecked()) active.add("known CDN");
        if (requireTls13 != null && requireTls13.isChecked()) active.add("TLS 1.3");
        if (bestPerIp != null && bestPerIp.isChecked()) active.add("best/IP");
        if (cdnProviderSpinner != null && cdnProviderSpinner.getSelectedItemPosition() > 0) active.add(String.valueOf(cdnProviderSpinner.getSelectedItem()));
        if (maxLatencyInput != null && !maxLatencyInput.getText().toString().trim().isEmpty()) active.add("latency");
        if (minQualityInput != null && !minQualityInput.getText().toString().trim().isEmpty()) active.add("score");
        if (cdnFilterInput != null && !cdnFilterInput.getText().toString().trim().isEmpty()) active.add("CDN text");
        if (certFilterInput != null && !certFilterInput.getText().toString().trim().isEmpty()) active.add("cert");
        if (sniFilterInput != null && !sniFilterInput.getText().toString().trim().isEmpty()) active.add("SNI");
        return active.isEmpty() ? "none" : joinHuman(active);
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
        TextView top = text(r.address(), compactMode() ? 13 : 15, Color.WHITE, true);
        top.setTypeface(Typeface.MONOSPACE);
        TextView route = text("SNI " + dash(r.sni), compactMode() ? 11 : 12, highContrastMode() ? Color.WHITE : Color.rgb(190, 218, 232), false);
        route.setSingleLine(false);
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
        card.addView(route);
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
        String route = r.sni == null || r.sni.isEmpty() ? "" : " " + r.sni;
        copyToClipboardOrDialog("result", r.address() + route + " q=" + Math.round(r.quality));
    }

    private void copySelectedFormat() {
        List<Result> rows = filteredResults();
        int format = exportSpinner.getSelectedItemPosition();
        StringBuilder sb = new StringBuilder();
        try {
            if (format == 4) {
                sb.append("target,ip,port,sni,tcp,tls,http,http_status,latency_ms,alpn,tls_profile,http3_hint,cdn,quality,reason\n");
            } else if (format == 5) {
                JSONArray arr = new JSONArray();
                for (Result r : rows) arr.put(r.json());
                copyToClipboardOrDialog("JSON", arr.toString(2));
                return;
            }
            LinkedHashSet<String> dedupe = new LinkedHashSet<>();
            for (Result r : rows) if (r.ip != null && !r.ip.isEmpty()) {
                if (format == 0) dedupe.add(r.ip);
                else if (format == 1) dedupe.add(r.ip);
                else if (format == 2) dedupe.add(r.address() + " " + r.sni);
                else if (format == 3 && r.sni != null && !r.sni.isEmpty()) dedupe.add(r.sni);
                else if (format == 4) sb.append(r.csv()).append('\n');
            }
            if (format == 0) sb.append(joinLines(dedupe));
            else if (format == 1) sb.append(joinComma(dedupe));
            else if (format == 2) sb.append(joinLines(dedupe));
            else if (format == 3) sb.append(joinLines(dedupe));
            copyToClipboardOrDialog(String.valueOf(exportSpinner.getSelectedItem()), sb.toString());
        } catch (Exception e) {
            toast("Copy failed: " + e.getMessage());
        }
    }

    private void copyVisibleCsv() {
        List<Result> rows = filteredResults();
        StringBuilder sb = new StringBuilder();
        sb.append("target,ip,port,sni,tcp,tls,http,http_status,latency_ms,alpn,tls_profile,http3_hint,cdn,quality,reason\n");
        for (Result r : rows) sb.append(r.csv()).append('\n');
        copyToClipboardOrDialog("visible CSV", sb.toString());
    }

    private void copyToClipboardOrDialog(String label, String content) {
        if (content == null || content.trim().isEmpty()) {
            toast("Nothing to copy");
            return;
        }
        try {
            clip(content);
            if (status != null) status.setText("Copied " + label + " | " + content.length() + " chars");
            toast("Copied " + label);
        } catch (Exception e) {
            showClipboardDialog("Clipboard unavailable", content);
            toast("Clipboard unavailable; copy manually");
        }
    }

    private void showClipboardDialog(String title, String content) {
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
            File out = new File(getExternalFilesDir(null), "maybeedgescanner_scan_" + System.currentTimeMillis() + ".json");
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
        synchronized (allResults) {
            allResults.clear();
        }
        checkedTargets.set(0);
        totalTargets = 0;
        stableHistoryRenderedAt = 0;
        progress.setProgress(0);
        resultList.removeAllViews();
        synchronized (logLines) {
            logLines.clear();
            stableLogBuilder.setLength(0);
        }
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
            stableHistoryRenderedAt = 0;
        } catch (Exception ignored) {}
    }

    private void renderStableHistoryPanel() {
        if (stableHistoryPanel == null) return;
        long now = System.currentTimeMillis();
        if (now - stableHistoryRenderedAt < 5000 && stableHistoryPanel.getChildCount() > 0) return;
        stableHistoryRenderedAt = now;
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
            s.rows = allResults.size();
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
        int rows, tcp, tls, http, down, timeout, reset, cert, dns;
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

    private static class Result implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
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
        String address() { return ip == null || ip.isEmpty() ? target : ip + ":" + port; }
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
        List<String> cached = assetLineCache.get(name);
        if (cached != null) return new ArrayList<>(cached);
        synchronized (assetReadLocks.computeIfAbsent("lines:" + name, ignored -> new Object())) {
            cached = assetLineCache.get(name);
            if (cached != null) return new ArrayList<>(cached);
            List<String> out = new ArrayList<>();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(getAssets().open(name), StandardCharsets.UTF_8))) {
                String line; while ((line = br.readLine()) != null) if (!line.trim().isEmpty() && !line.trim().startsWith("#")) out.add(line.trim());
            } catch (IOException ignored) {}
            assetLineCache.put(name, Collections.unmodifiableList(new ArrayList<>(out)));
            return out;
        }
    }
    private LinkedHashSet<String> loadAssetTokens(String name) {
        LinkedHashSet<String> cached = assetTokenCache.get(name);
        if (cached != null) return new LinkedHashSet<>(cached);
        synchronized (assetReadLocks.computeIfAbsent("tokens:" + name, ignored -> new Object())) {
            cached = assetTokenCache.get(name);
            if (cached != null) return new LinkedHashSet<>(cached);
            LinkedHashSet<String> out = new LinkedHashSet<>();
            for (String raw : loadAsset(name)) {
                String clean = raw.replace("[", " ").replace("]", " ").replace("\"", " ").replace(",", " ").trim();
                for (String token : clean.split("\\s+")) {
                    token = cleanToken(token);
                    if (!token.isEmpty() && validTargetToken(token)) out.add(token);
                }
            }
            assetTokenCache.put(name, new LinkedHashSet<>(out));
            return out;
        }
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
        for (String p : String.valueOf(s == null ? "" : s).split("[,;\\s]+")) {
            try { int v = Integer.parseInt(p.trim()); if (v > 0 && v < 65536) ports.add(v); } catch (Exception ignored) {}
        }
        if (ports.isEmpty()) ports.add(443);
        return new ArrayList<>(ports);
    }
    private static List<String> cap(List<String> in, int n) { return new ArrayList<>(in.subList(0, Math.min(in.size(), Math.max(1, n)))); }
    private static String first(List<String> xs) { return xs.isEmpty() ? "" : xs.get(0); }
    private static boolean isIpv4(String x) {
        if (x == null) return false;
        String v = x.trim();
        if (!v.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) return false;
        String[] parts = v.split("\\.");
        for (String part : parts) {
            try { int n = Integer.parseInt(part); if (n < 0 || n > 255) return false; }
            catch (Exception e) { return false; }
        }
        return true;
    }
    private static boolean isIp(String x) {
        if (x == null) return false;
        String v = x.trim();
        if (isIpv4(v)) return true;
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
        return expandTargets(raw, Integer.MAX_VALUE);
    }

    private static List<String> expandTargets(List<String> raw, int totalCap) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        int cap = Math.max(1, totalCap);
        for (String x : raw) {
            if (out.size() >= cap) break;
            int remaining = Math.min(200000, cap - out.size());
            if (x.contains("/")) out.addAll(expandCidr(x, remaining));
            else if (x.contains("-")) out.addAll(expandRange(x, remaining));
            else out.add(x);
        }
        return new ArrayList<>(out);
    }
    private static int estimateExpandedTargetCount(Collection<String> raw, int perTokenCap) {
        long total = 0;
        for (String x : raw) {
            if (x == null || x.trim().isEmpty()) continue;
            if (x.contains("/")) total += estimateCidrCount(x, perTokenCap);
            else if (x.contains("-")) total += estimateRangeCount(x, perTokenCap);
            else total++;
            if (total > Integer.MAX_VALUE) return Integer.MAX_VALUE;
        }
        return (int) total;
    }
    private static int estimateCidrCount(String cidr, int cap) {
        try {
            String[] p = cidr.split("/", 2);
            if (p.length != 2 || !isIp(p[0]) || cap <= 0) return 0;
            int prefix = Integer.parseInt(p[1]);
            if (p[0].contains(":")) {
                if (prefix < 0 || prefix > 128) return 0;
                return cap;
            }
            if (prefix < 0 || prefix > 32) return 0;
            long size = 1L << (32 - prefix);
            long usable = size > 2 ? size - 2 : size;
            return (int) Math.min(Math.max(0, usable), cap);
        } catch (Exception ignored) { return 0; }
    }
    private static int estimateRangeCount(String range, int cap) {
        try {
            String[] p = range.split("-", 2);
            if (p.length != 2 || !isIpv4(p[0]) || !isIpv4(p[1]) || cap <= 0) return 0;
            long start = ipv4ToLong(p[0]);
            long end = ipv4ToLong(p[1]);
            if (end < start) return 0;
            return (int) Math.min(end - start + 1, cap);
        } catch (Exception ignored) { return 0; }
    }
    private static List<String> expandRange(String range, int cap) {
        List<String> out = new ArrayList<>();
        try {
            String[] p = range.split("-", 2);
            if (p.length != 2 || !isIpv4(p[0]) || !isIpv4(p[1]) || cap <= 0) return out;
            long start = ipv4ToLong(p[0]);
            long end = ipv4ToLong(p[1]);
            if (end < start) return out;
            for (long v = start; v <= end && out.size() < cap; v++) out.add(longToIpv4(v));
        } catch (Exception ignored) {}
        return out;
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
            long first = end - start + 1 <= 2 ? start : start + 1;
            long last = end - start + 1 <= 2 ? end : end - 1;
            for (long v = first; v <= last && out.size() < cap; v++) out.add(longToIpv4(v));
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
        if (hay.contains("cloudflare") || inCidrV4(ip, "104.16.0.0", 12) || inCidrV4(ip, "172.64.0.0", 13)) return "CLOUDFLARE";
        if (hay.contains("fastly") || inCidrV4(ip, "151.101.0.0", 16)) return "FASTLY";
        if (hay.contains("akamai") || inCidrV4(ip, "23.32.0.0", 11) || inCidrV4(ip, "23.192.0.0", 11) || inCidrV4(ip, "184.24.0.0", 13)) return "AKAMAI";
        if (hay.contains("amazon") || hay.contains("cloudfront") || inCidrV4(ip, "13.32.0.0", 15) || inCidrV4(ip, "13.224.0.0", 14) || inCidrV4(ip, "18.64.0.0", 14) || inCidrV4(ip, "54.230.0.0", 16)) return "CLOUDFRONT";
        if (ip.startsWith("95.216.") || ip.startsWith("65.109.")) return "HETZNER";
        return "UNKNOWN";
    }
    private static boolean inCidrV4(String ip, String network, int bits) {
        try {
            byte[] addr = InetAddress.getByName(ip).getAddress();
            byte[] net = InetAddress.getByName(network).getAddress();
            if (addr.length != 4 || net.length != 4) return false;
            int a = ((addr[0] & 255) << 24) | ((addr[1] & 255) << 16) | ((addr[2] & 255) << 8) | (addr[3] & 255);
            int n = ((net[0] & 255) << 24) | ((net[1] & 255) << 16) | ((net[2] & 255) << 8) | (net[3] & 255);
            int mask = bits == 0 ? 0 : -1 << (32 - bits);
            return (a & mask) == (n & mask);
        } catch (Exception ignored) { return false; }
    }
    private static String sha256(byte[] bytes) throws Exception { byte[] d = MessageDigest.getInstance("SHA-256").digest(bytes); StringBuilder sb = new StringBuilder(); for (byte b : d) sb.append(String.format("%02x", b)); return sb.toString(); }
    private static String joinLines(Collection<String> xs) { StringBuilder sb = new StringBuilder(); for (String x : xs) sb.append(x).append('\n'); return sb.toString().trim(); }
    private static String joinComma(Collection<String> xs) { StringBuilder sb = new StringBuilder(); for (String x : xs) { if (sb.length() > 0) sb.append(','); sb.append(x); } return sb.toString(); }
    private static String joinHuman(Collection<String> xs) { StringBuilder sb = new StringBuilder(); for (String x : xs) { if (sb.length() > 0) sb.append(", "); sb.append(x); } return sb.toString(); }
    private static String q(String s) { return "\"" + String.valueOf(s).replace("\"", "\"\"") + "\""; }
    private static String trim(String s, int n) { return s.length() <= n ? s : s.substring(0, n - 1) + "..."; }
    private static String dash(String s) { return s == null || s.isEmpty() ? "--" : s; }
    private static String cleanToken(String s) { return s.trim().replace("\"", "").replace(",", "").replace("[", "").replace("]", ""); }
    private String elapsed() { long s = Math.max(0, (System.currentTimeMillis() - scanStartedAt) / 1000); return s + "s"; }
    private void clip(String s) { ((ClipboardManager) getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("MaybeEdgeScanner", s)); }
    private String resourceLine() {
        long now = System.currentTimeMillis();
        if (now - cachedResourceLineAt < 5000) return cachedResourceLine;
        Intent battery = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        int level = battery == null ? -1 : battery.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
        int scale = battery == null ? -1 : battery.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
        int status = battery == null ? -1 : battery.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
        int plugged = battery == null ? 0 : battery.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0);
        int pct = level >= 0 && scale > 0 ? Math.round(level * 100f / scale) : -1;
        boolean charging = status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL;
        String plug = plugged == BatteryManager.BATTERY_PLUGGED_USB ? "usb" :
                plugged == BatteryManager.BATTERY_PLUGGED_AC ? "ac" :
                plugged == BatteryManager.BATTERY_PLUGGED_WIRELESS ? "wireless" : "unplugged";
        Runtime rt = Runtime.getRuntime();
        long usedMb = (rt.totalMemory() - rt.freeMemory()) / (1024 * 1024);
        long maxMb = rt.maxMemory() / (1024 * 1024);
        cachedResourceLine = "power " + (pct >= 0 ? pct + "%" : "n/a") + " " +
                (charging ? "charging" : "battery") + "/" + plug +
                " | heap " + usedMb + "/" + maxMb + "MB" +
                " | cores " + rt.availableProcessors();
        cachedResourceLineAt = now;
        return cachedResourceLine;
    }

    private String deviceLine() {
        String model = (Build.MANUFACTURER + " " + Build.MODEL).trim();
        String abi = Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "unknown ABI";
        return model + " | Android " + Build.VERSION.RELEASE + " API " + Build.VERSION.SDK_INT + " | " + abi;
    }
    private void appendLog(String s) {
        ui.post(() -> {
            String line = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date()) + "  " + s;
            synchronized (logLines) {
                logLines.addLast(line);
                if (logLines.size() > 250) {
                    logLines.removeFirst();
                    rebuildStableLogBuilder();
                } else {
                    stableLogBuilder.append(line).append('\n');
                }
            }
            if (logView != null) logView.setText(stableLogBuilder.toString().trim());
        });
    }
    private void rebuildStableLogBuilder() { stableLogBuilder.setLength(0); for (String x : logLines) stableLogBuilder.append(x).append('\n'); }
    private int intValue(EditText e, int defaultValue) { try { String s = e.getText().toString().trim(); return s.isEmpty() ? defaultValue : Integer.parseInt(s); } catch (Exception ex) { return defaultValue; } }
    private static int clampInt(int value, int min, int max) { return Math.max(min, Math.min(max, value)); }
    private LinearLayout column() { LinearLayout l = new LinearLayout(this); l.setOrientation(LinearLayout.VERTICAL); return l; }
    private LinearLayout row() { LinearLayout l = new LinearLayout(this); l.setOrientation(LinearLayout.HORIZONTAL); l.setGravity(Gravity.CENTER); return l; }
    private TextView text(String s, int sp, int color, boolean bold) { TextView v = new TextView(this); v.setText(s); v.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp); v.setTextColor(color); if (bold) v.setTypeface(Typeface.DEFAULT_BOLD); v.setPadding(0, dp(4), 0, dp(4)); if (Build.VERSION.SDK_INT >= 21) v.setLetterSpacing(0.02f); if (Build.VERSION.SDK_INT >= 23) v.setBreakStrategy(android.text.Layout.BREAK_STRATEGY_HIGH_QUALITY); return v; }
    private TextView panelText(String s) { TextView v = text(s, 12, Color.WHITE, false); v.setBackground(glassBg(PANEL, Color.argb(95, 255, 255, 255))); v.setPadding(dp(10), dp(8), dp(10), dp(8)); setOuterMargin(v, 0, dp(5), 0, dp(5)); return v; }
    private TextView glassText(String s) { TextView v = panelText(s); v.setTextColor(Color.rgb(196, 223, 235)); return v; }
    private TextView quietNote(String body) { TextView v = text(body, 11, Color.rgb(185, 210, 222), false); v.setBackground(glassBg(Color.rgb(8, 20, 29), Color.argb(45, 255, 255, 255))); v.setPadding(dp(9), dp(6), dp(9), dp(6)); setOuterMargin(v, 0, dp(4), 0, dp(6)); return v; }
    private LinearLayout segmentedChoice(String label, String[] names, ArrayList<Button> buttons, int selectedIndex, SegmentHandler afterChange) {
        LinearLayout group = column();
        group.setBackground(glassBg(Color.rgb(10, 24, 34), Color.argb(60, 255, 255, 255)));
        group.setPadding(dp(7), dp(2), dp(7), dp(7));
        setOuterMargin(group, 0, dp(4), 0, dp(4));
        group.addView(section(label));
        LinearLayout controls = row();
        buttons.clear();
        for (int i = 0; i < names.length; i++) {
            final int index = i;
            Button b = button(names[i], Color.rgb(24, 45, 58), Color.WHITE);
            b.setContentDescription(label + ": " + names[i]);
            b.setOnClickListener(v -> {
                if (afterChange != null) afterChange.onSelect(index);
                refreshSegmentButtons(buttons, index);
            });
            buttons.add(b);
            controls.addView(b, weight());
        }
        group.addView(controls);
        refreshSegmentButtons(buttons, selectedIndex);
        return group;
    }

    private void refreshSegmentButtons(ArrayList<Button> buttons, int selectedIndex) {
        for (int i = 0; i < buttons.size(); i++) styleSegmentButton(buttons.get(i), i == selectedIndex);
    }

    private interface SegmentHandler { void onSelect(int index); }

    private void styleSegmentButton(Button button, boolean selected) {
        button.setTextColor(selected ? Color.rgb(2, 18, 24) : Color.WHITE);
        button.setBackground(glassBg(selected ? BLUE : Color.rgb(24, 45, 58),
                selected ? Color.argb(210, 255, 255, 255) : Color.argb(95, 255, 255, 255)));
    }

    private LinearLayout collapsibleBox(String title, View body, boolean open) {
        LinearLayout group = column();
        setOuterMargin(group, 0, dp(8), 0, dp(8));
        Button header = button((open ? "- " : "+ ") + title, Color.rgb(16, 38, 52), Color.WHITE);
        body.setVisibility(open ? View.VISIBLE : View.GONE);
        header.setContentDescription(title + (open ? " expanded" : " collapsed"));
        header.setOnClickListener(v -> {
            boolean show = body.getVisibility() != View.VISIBLE;
            body.setVisibility(show ? View.VISIBLE : View.GONE);
            header.setText((show ? "- " : "+ ") + title);
            header.setContentDescription(title + (show ? " expanded" : " collapsed"));
        });
        group.addView(header);
        group.addView(body);
        return group;
    }

    private LinearLayout diagnosticsRadioPanel() {
        LinearLayout card = column();
        card.setBackground(glassBg(Color.rgb(9, 22, 31), Color.argb(70, 255, 255, 255)));
        card.setPadding(dp(12), dp(10), dp(12), dp(10));
        setOuterMargin(card, 0, dp(8), 0, dp(8));
        card.addView(text("Mobile radio control is device-specific", 12, Color.rgb(210, 231, 240), true));
        card.addView(text("A normal APK cannot bundle its own Shizuku-like privileged bridge. Radio writes require a running Shizuku/Sui/root/system context; without that, this panel stays useful as read/status guidance plus direct Android settings shortcuts.", 11, MUTED, false));

        shizukuStatusView = panelText("Shizuku: checking");
        card.addView(shizukuStatusView);
        shizukuNextStepView = quietNote(shizukuUnavailableNextStep());
        card.addView(shizukuNextStepView);

        LinearLayout statusRow = row();
        Button check = button("Check service", Color.rgb(24, 45, 58), Color.WHITE);
        Button request = button("Request access", Color.rgb(24, 45, 58), Color.WHITE);
        check.setOnClickListener(v -> refreshShizukuState());
        request.setOnClickListener(v -> requestShizukuPermission());
        statusRow.addView(check, weight());
        statusRow.addView(request, weight());
        card.addView(statusRow);

        LinearLayout probeRow = row();
        Button probe = button("Bridge probe", Color.rgb(24, 45, 58), Color.WHITE);
        Button read = button("Read current", Color.rgb(24, 45, 58), Color.WHITE);
        probe.setOnClickListener(v -> runShizukuRadioCommand("Bridge capability probe", buildBridgeProbeCommand(), false));
        read.setOnClickListener(v -> runShizukuRadioCommand("Read radio modes", buildReadModesCommand(), false));
        probeRow.addView(probe, weight());
        probeRow.addView(read, weight());
        card.addView(probeRow);

        LinearLayout shizukuAppRow = row();
        Button openShizuku = button("Open manager", Color.rgb(24, 45, 58), Color.WHITE);
        Button shizukuGuide = button("Setup guide", Color.rgb(24, 45, 58), Color.WHITE);
        openShizuku.setOnClickListener(v -> openShizukuManager());
        shizukuGuide.setOnClickListener(v -> openUrl("https://shizuku.rikka.app/guide/setup/"));
        shizukuAppRow.addView(openShizuku, weight());
        shizukuAppRow.addView(shizukuGuide, weight());
        card.addView(shizukuAppRow);

        LinearLayout installRow = row();
        Button shizukuRelease = button("GitHub APK", Color.rgb(24, 45, 58), Color.WHITE);
        Button developer = button("Developer options", Color.rgb(24, 45, 58), Color.WHITE);
        shizukuRelease.setOnClickListener(v -> openUrl("https://github.com/RikkaApps/Shizuku/releases/latest"));
        developer.setOnClickListener(v -> openAndroidSettings(android.provider.Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS, "Developer options unavailable"));
        installRow.addView(shizukuRelease, weight());
        installRow.addView(developer, weight());
        card.addView(installRow);
        card.addView(collapsibleBox("Shizuku setup notes", shizukuSetupNotesPanel(), false));

        LinearLayout modeRow = row();
        Button lteOnly = button("Prefer LTE", Color.rgb(24, 45, 58), Color.WHITE);
        Button nrLte = button("Prefer 5G/LTE", Color.rgb(24, 45, 58), Color.WHITE);
        Button auto = button("Reset Auto", Color.rgb(24, 45, 58), Color.WHITE);
        lteOnly.setOnClickListener(v -> confirmRadioMode("LTE only", "11", "LTE-only can remove service where LTE is weak or unavailable. Use Auto to undo it."));
        nrLte.setOnClickListener(v -> confirmRadioMode("5G/LTE preferred", "33", "5G/LTE values are especially OEM-dependent. If the readback looks wrong, use Auto or the phone settings panel."));
        auto.setOnClickListener(v -> confirmRadioMode("Auto network", "9", "Auto restores a broad LTE/GSM/WCDMA preference on many Android devices. Some devices may use a different default."));
        modeRow.addView(lteOnly, weight());
        modeRow.addView(nrLte, weight());
        modeRow.addView(auto, weight());
        card.addView(modeRow);
        card.addView(quietNote("Writes are explicit, confirmed, and read back immediately. LTE/5G constants vary by OEM and SIM slot; if service drops or readback differs, use Reset Auto or Android network settings."));

        LinearLayout settingsRow = row();
        Button mobile = button("Mobile settings", Color.rgb(24, 45, 58), Color.WHITE);
        Button wireless = button("Network settings", Color.rgb(24, 45, 58), Color.WHITE);
        mobile.setOnClickListener(v -> openAndroidSettings(android.provider.Settings.ACTION_NETWORK_OPERATOR_SETTINGS, "Mobile network settings unavailable"));
        wireless.setOnClickListener(v -> openAndroidSettings(android.provider.Settings.ACTION_WIRELESS_SETTINGS, "Network settings unavailable"));
        settingsRow.addView(mobile, weight());
        settingsRow.addView(wireless, weight());
        card.addView(settingsRow);

        LinearLayout custom = column();
        custom.addView(quietNote("Advanced override is limited to a settings key and numeric value. It is for SIM-slot/OEM variants, not arbitrary shell commands."));
        LinearLayout customRow = row();
        shizukuKeyInput = input("preferred_network_mode", false);
        shizukuValueInput = input("11", true);
        customRow.addView(box("Settings key", shizukuKeyInput), weight());
        customRow.addView(box("Value", shizukuValueInput), weight());
        custom.addView(customRow);
        Button applyCustom = button("Apply custom", Color.rgb(24, 45, 58), Color.WHITE);
        applyCustom.setOnClickListener(v -> confirmCustomRadioMode());
        custom.addView(applyCustom);
        card.addView(collapsibleBox("Advanced radio key", custom, false));

        shizukuOutputView = panelText("No privileged action has run in this session. Use Bridge probe to verify UID, Android version, and command reach before writing radio settings.");
        shizukuOutputView.setTypeface(Typeface.MONOSPACE);
        shizukuOutputView.setTextIsSelectable(true);
        card.addView(shizukuOutputView);
        Button copyOutput = button("Copy output", Color.rgb(24, 45, 58), Color.WHITE);
        copyOutput.setOnClickListener(v -> copyShizukuOutput());
        card.addView(copyOutput);
        return card;
    }

    private LinearLayout shizukuHealthTile() {
        LinearLayout card = column();
        card.setBackground(glassBg(Color.rgb(9, 23, 34), Color.argb(85, 255, 255, 255)));
        card.setPadding(dp(12), dp(10), dp(12), dp(10));
        setOuterMargin(card, 0, dp(8), 0, dp(8));
        card.addView(text("Shizuku health", 12, Color.rgb(210, 231, 240), true));
        shizukuHealthTileView = panelText(buildShizukuHealthText());
        card.addView(shizukuHealthTileView);
        LinearLayout row = row();
        Button refresh = button("Refresh health", Color.rgb(24, 45, 58), Color.WHITE);
        Button open = button("Open Shizuku", Color.rgb(24, 45, 58), Color.WHITE);
        refresh.setOnClickListener(v -> refreshShizukuState());
        open.setOnClickListener(v -> openShizukuManager());
        row.addView(refresh, weight());
        row.addView(open, weight());
        card.addView(row);
        return card;
    }

    private LinearLayout shizukuSetupNotesPanel() {
        LinearLayout panel = column();
        panel.addView(quietNote("Android 11 and newer: Shizuku can usually be started entirely on-device through Wireless debugging in Developer options. Some OEMs move or rename that page, so the Developer options button is kept beside the setup links."));
        panel.addView(quietNote("Android 10 and older: Shizuku still works, but starting it normally requires computer ADB after boot. Rooted devices can use root-backed Shizuku or Sui instead."));
        panel.addView(quietNote("ADB shell is not root. It is UID 2000 and receives many Android shell permissions, but vendor SELinux policy, hidden APIs, modem firmware, and carrier overlays can still block radio changes."));
        panel.addView(quietNote("Root/Sui is UID 0 and can reach more, but the app still keeps all write operations behind confirmations and immediate readback."));
        panel.addView(quietNote("Prefer the official GitHub release for direct APK install/update checks; the official Shizuku download page remains useful when users want Play Store or F-Droid options."));
        panel.addView(quietNote("Long-term deeper integration should use Shizuku UserService/AIDL for rich privileged APIs. This panel intentionally keeps radio actions narrow and auditable."));
        return panel;
    }

    private void addShizukuListener() {
        try {
            Shizuku.addRequestPermissionResultListener(shizukuPermissionListener);
            Shizuku.addBinderReceivedListenerSticky(shizukuBinderReceivedListener);
            Shizuku.addBinderDeadListener(shizukuBinderDeadListener);
        } catch (Throwable ignored) {
        }
    }

    private void removeShizukuListener() {
        try {
            Shizuku.removeRequestPermissionResultListener(shizukuPermissionListener);
            Shizuku.removeBinderReceivedListener(shizukuBinderReceivedListener);
            Shizuku.removeBinderDeadListener(shizukuBinderDeadListener);
        } catch (Throwable ignored) {
        }
    }

    private void onShizukuBinderReceived() {
        ui.post(() -> {
            refreshShizukuState();
            if (shizukuOutputView != null && shizukuOutputView.getText().toString().startsWith("Privileged service disconnected")) {
                setShizukuOutput("Privileged service connected. Run Bridge probe before writing radio settings.");
            }
        });
    }

    private void onShizukuBinderDead() {
        shizukuCommandRunning.set(false);
        ui.post(() -> {
            refreshShizukuState();
            setShizukuOutput("Privileged service disconnected. Radio diagnostics are paused until Shizuku is available again.");
            toast("Shizuku disconnected");
        });
    }

    private void onShizukuPermissionResult(int requestCode, int grantResult) {
        if (requestCode != SHIZUKU_REQUEST_CODE) return;
        ui.post(() -> {
            refreshShizukuState();
            setShizukuOutput(grantResult == PackageManager.PERMISSION_GRANTED
                    ? "Shizuku access granted. Run Bridge probe next, then Read current."
                    : "Shizuku access denied. Open Shizuku, allow this app under authorized apps, then tap Check service.");
            toast(grantResult == PackageManager.PERMISSION_GRANTED ? "Shizuku access granted" : "Shizuku access denied");
        });
    }

    private boolean shizukuAvailable() {
        try {
            return Shizuku.pingBinder();
        } catch (Throwable ignored) {
            return false;
        }
    }

    private boolean shizukuPermissionGranted() {
        try {
            return shizukuAvailable() && !Shizuku.isPreV11() && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private void refreshShizukuState() {
        updateShizukuHealthTile();
        if (shizukuStatusView == null) return;
        if (!shizukuAvailable()) {
            shizukuStatusView.setText("Privileged bridge: unavailable\nBinder: not alive\n" + shizukuSetupPathLine() + "\nRadio writes cannot be self-contained in a regular APK. Start Shizuku, Sui, root, or a local ADB bridge; Android settings shortcuts still work.");
            setShizukuNextStep(shizukuUnavailableNextStep());
            return;
        }
        try {
            if (Shizuku.isPreV11()) {
                shizukuStatusView.setText("Shizuku: unsupported server\nThis app needs Shizuku v11+ permission APIs.");
                setShizukuNextStep("Next: update Shizuku from the official GitHub APK, reopen it, then tap Check service.");
                return;
            }
        } catch (Throwable ignored) {
        }
        boolean granted = shizukuPermissionGranted();
        StringBuilder sb = new StringBuilder();
        int uid = -1;
        sb.append("Privileged bridge: ").append(granted ? "ready" : "permission needed");
        sb.append("\nBinder: alive");
        try { sb.append("\nServer: Shizuku v").append(Shizuku.getVersion()); } catch (Throwable ignored) {}
        try {
            uid = Shizuku.getUid();
            sb.append('\n').append(shizukuIdentityLine(uid));
        } catch (Throwable ignored) {
            sb.append("\nPrivilege: unknown UID");
        }
        sb.append("\nPermission API: v11+ runtime grant");
        sb.append('\n').append(shizukuSetupPathLine());
        sb.append('\n').append(shizukuCapabilityHint(uid));
        sb.append("\nRadio writes: confirmed action with readback");
        shizukuStatusView.setText(sb.toString());
        setShizukuNextStep(granted
                ? "Next: run Bridge probe, then Read current. Use radio writes only after the readback looks sane for this device and SIM."
                : "Next: tap Request access, approve this app in Shizuku, then run Bridge probe.");
        updateShizukuHealthTile();
    }

    private void updateShizukuHealthTile() {
        if (shizukuHealthTileView != null) shizukuHealthTileView.setText(buildShizukuHealthText());
    }

    private String buildShizukuHealthText() {
        boolean alive = shizukuAvailable();
        if (!alive) {
            return "Bridge: offline | Permission: not available | Backend: none\n"
                    + shizukuSetupPathLine() + "\n"
                    + "Last probe: " + shizukuLastProbeLine();
        }
        boolean preV11 = false;
        boolean granted = false;
        String version = "unknown";
        int uid = -1;
        try { preV11 = Shizuku.isPreV11(); } catch (Throwable ignored) {}
        try { version = "v" + Shizuku.getVersion(); } catch (Throwable ignored) {}
        if (!preV11) granted = shizukuPermissionGranted();
        try { uid = Shizuku.getUid(); } catch (Throwable ignored) {}
        String backend = uid == 0 ? "root UID 0" : (uid == 2000 ? "ADB shell UID 2000" : "UID " + (uid < 0 ? "unknown" : uid));
        String permission = preV11 ? "unsupported server" : (granted ? "granted" : "needed");
        return "Bridge: online | Permission: " + permission + " | Backend: " + backend + "\n"
                + "Server: " + version + " | Last probe: " + shizukuLastProbeLine() + "\n"
                + shizukuSetupPathLine();
    }

    private String shizukuLastProbeLine() {
        if (lastShizukuProbeAt <= 0) return "not run";
        long seconds = Math.max(0, (System.currentTimeMillis() - lastShizukuProbeAt) / 1000);
        return seconds < 60 ? seconds + "s ago" : (seconds / 60) + "m ago";
    }

    private String shizukuSetupPathLine() {
        if (Build.VERSION.SDK_INT >= 30) {
            return "Setup path: Wireless debugging on-device (Android " + Build.VERSION.RELEASE + ")";
        }
        return "Setup path: computer ADB after reboot on Android " + Build.VERSION.RELEASE + ", unless root/Sui is available";
    }

    private String shizukuUnavailableNextStep() {
        if (Build.VERSION.SDK_INT >= 30) {
            return "Next: open Shizuku, start it with Wireless debugging, return here, then tap Check service.";
        }
        return "Next: start Shizuku with computer ADB after boot, or use root/Sui, then return and tap Check service.";
    }

    private void setShizukuNextStep(String text) {
        if (shizukuNextStepView != null) shizukuNextStepView.setText(text);
    }

    private String shizukuIdentityLine(int uid) {
        if (uid == 0) return "Privilege: root backend (UID 0)";
        if (uid == 2000) return "Privilege: ADB shell backend (UID 2000)";
        return "Privilege: backend UID " + uid;
    }

    private String shizukuCapabilityHint(int uid) {
        if (uid == 0) return "Capability: root can reach more system APIs; commands still require confirmation here.";
        if (uid == 2000) return "Capability: ADB shell can use many system permissions, but OEM and Android-version limits still apply.";
        return "Capability: backend permissions vary; use Bridge probe before any write.";
    }

    private void requestShizukuPermission() {
        if (!shizukuAvailable()) {
            refreshShizukuState();
            setShizukuOutput(shizukuUnavailableNextStep() + "\n\nUse GitHub APK if Shizuku is not installed or needs a direct update.");
            toast("Start Shizuku first");
            return;
        }
        if (shizukuPermissionGranted()) {
            refreshShizukuState();
            setShizukuOutput("Shizuku is already allowed. Run Bridge probe next, then Read current.");
            toast("Shizuku is already allowed");
            return;
        }
        try {
            if (Shizuku.isPreV11()) {
                setShizukuOutput("This device is running an unsupported Shizuku server. Update Shizuku, then try again.");
                setShizukuNextStep("Next: update Shizuku from the official GitHub APK, reopen it, then tap Check service.");
                return;
            }
            if (Shizuku.shouldShowRequestPermissionRationale()) {
                setShizukuOutput("Shizuku permission was denied with rationale required. Open Shizuku, allow this app, then tap Check.");
                setShizukuNextStep("Next: open Shizuku, allow this app under authorized apps, then tap Check service.");
                toast("Allow this app inside Shizuku");
                return;
            }
        } catch (Throwable ignored) {
        }
        try {
            setShizukuNextStep("Next: approve the Shizuku permission dialog for this app.");
            Shizuku.requestPermission(SHIZUKU_REQUEST_CODE);
        } catch (Throwable e) {
            setShizukuOutput("Permission request failed: " + e.getClass().getSimpleName() + ": " + safeMessage(e));
        }
    }

    private void openShizukuManager() {
        try {
            Intent intent = getPackageManager().getLaunchIntentForPackage("moe.shizuku.privileged.api");
            if (intent == null) throw new IllegalStateException("Shizuku manager is not installed");
            startActivity(intent);
        } catch (Throwable e) {
            setShizukuOutput("Could not open Shizuku manager: " + safeMessage(e));
            openUrl("https://github.com/RikkaApps/Shizuku/releases/latest");
        }
    }

    private void openUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)));
        } catch (Exception e) {
            clip(url);
            toast("Link copied");
        }
    }

    private void confirmRadioMode(String label, String value, String warning) {
        new AlertDialog.Builder(this)
                .setTitle("Apply " + label + "?")
                .setMessage(warning + "\n\nThe app will write value " + value + " to common preferred_network_mode keys and then read them back.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Apply", (d, which) -> runShizukuSettingsWrite(label, RADIO_MODE_KEYS, value))
                .show();
    }

    private void confirmCustomRadioMode() {
        String key = shizukuKeyInput == null ? "" : shizukuKeyInput.getText().toString().trim();
        String value = shizukuValueInput == null ? "" : shizukuValueInput.getText().toString().trim();
        if (!key.matches("[A-Za-z0-9_.-]{3,80}") || !value.matches("[0-9]{1,4}")) {
            toast("Use a simple settings key and numeric value");
            return;
        }
        if (!Arrays.asList(RADIO_MODE_KEYS).contains(key)) {
            toast("Custom radio key is not in the approved preferred network mode list");
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Apply custom radio value?")
                .setMessage("Key: " + key + "\nValue: " + value + "\n\nThis is for OEM or SIM-slot variants only. Keep a reset path available.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Apply", (d, which) -> runShizukuSettingsWrite("Custom radio value", new String[]{key}, value))
                .show();
    }

    private String buildReadModesCommand() {
        StringBuilder cmd = new StringBuilder("echo radio-preferred-network-modes; ");
        for (String key : RADIO_MODE_KEYS) {
            cmd.append("echo ").append(key).append("=$(settings get global ").append(key).append(" 2>/dev/null); ");
        }
        return cmd.toString();
    }

    private String buildBridgeProbeCommand() {
        return "echo shizuku-bridge-probe; "
                + "id; "
                + "echo uid=$(id -u 2>/dev/null); "
                + "echo sdk=$(getprop ro.build.version.sdk 2>/dev/null); "
                + "echo release=$(getprop ro.build.version.release 2>/dev/null); "
                + "echo device=$(getprop ro.product.manufacturer 2>/dev/null) $(getprop ro.product.model 2>/dev/null); "
                + "echo airplane=$(settings get global airplane_mode_on 2>/dev/null); "
                + "cmd connectivity help >/dev/null 2>&1 && echo connectivity-cmd=available || echo connectivity-cmd=limited; "
                + buildReadModesCommand();
    }

    private void runShizukuSettingsWrite(String label, String[] keys, String value) {
        if (!shizukuPermissionGranted()) {
            refreshShizukuState();
            requestShizukuPermission();
            return;
        }
        if (!value.matches("[0-9]{1,4}")) {
            toast("Use a numeric radio mode value");
            return;
        }
        for (String key : keys) {
            if (!Arrays.asList(RADIO_MODE_KEYS).contains(key)) {
                toast("Rejected non-approved radio key");
                return;
            }
        }
        if (!shizukuCommandRunning.compareAndSet(false, true)) {
            setShizukuOutput("Another Shizuku radio action is still running. Wait for the readback before starting a new one.");
            toast("Shizuku action already running");
            return;
        }
        setShizukuOutput(label + " running...");
        new Thread(() -> {
            StringBuilder output = new StringBuilder("Action: ").append(label).append('\n');
            boolean allWritesStarted = true;
            boolean allVerified = true;
            try {
                output.append("Write value: ").append(value).append("\n\n");
                for (String key : keys) {
                    CommandResult put = runShizukuProcessCapture(new String[]{"/system/bin/settings", "put", "global", key, value}, 5);
                    output.append("put ").append(key).append(" exit=").append(put.exitCode).append('\n');
                    if (!put.stdout.trim().isEmpty()) output.append(put.stdout.trim()).append('\n');
                    if (!put.stderr.trim().isEmpty()) output.append("stderr: ").append(put.stderr.trim()).append('\n');
                    if (put.exitCode != 0) allWritesStarted = false;
                }
                output.append("\nradio-preferred-network-modes\n");
                for (String key : keys) {
                    CommandResult get = runShizukuProcessCapture(new String[]{"/system/bin/settings", "get", "global", key}, 5);
                    String actual = get.stdout.trim();
                    output.append(key).append("=").append(actual).append('\n');
                    if (!value.equals(actual)) allVerified = false;
                    if (!get.stderr.trim().isEmpty()) output.append("stderr: ").append(get.stderr.trim()).append('\n');
                }
            } catch (Throwable e) {
                allWritesStarted = false;
                allVerified = false;
                output.append("\nFailed: ").append(e.getClass().getSimpleName()).append(": ").append(safeMessage(e));
            }
            final String finalOutput = output.toString();
            final boolean finalWritesStarted = allWritesStarted;
            final boolean finalVerified = allVerified;
            ui.post(() -> {
                shizukuCommandRunning.set(false);
                refreshShizukuState();
                setShizukuOutput(finalOutput);
                toast(finalWritesStarted && finalVerified ? "Radio mode verified" : "Radio write not verified");
            });
        }, "shizuku-settings-write").start();
    }

    private void runShizukuRadioCommand(String label, String command, boolean writeAction) {
        runShizukuRadioCommand(label, command, writeAction, null);
    }

    private void runShizukuRadioCommand(String label, String command, boolean writeAction, String expectedValue) {
        if (!shizukuPermissionGranted()) {
            refreshShizukuState();
            requestShizukuPermission();
            return;
        }
        if (!shizukuCommandRunning.compareAndSet(false, true)) {
            setShizukuOutput("Another Shizuku radio action is still running. Wait for the readback before starting a new one.");
            toast("Shizuku action already running");
            return;
        }
        setShizukuOutput(label + " running...");
        new Thread(() -> {
            String output;
            int exitCode = -1;
            try {
                Process process = startShizukuShellProcess(command);
                StringBuilder stdout = new StringBuilder();
                StringBuilder stderr = new StringBuilder();
                Thread stdoutThread = collectProcessStream(process.getInputStream(), stdout);
                Thread stderrThread = collectProcessStream(process.getErrorStream(), stderr);
                boolean finished = process.waitFor(9, java.util.concurrent.TimeUnit.SECONDS);
                if (!finished) {
                    process.destroy();
                    exitCode = -2;
                    output = "Action: " + label + "\nExit: timeout\n\nThe privileged command did not finish within 9 seconds. No follow-up command was queued.";
                } else {
                    exitCode = process.exitValue();
                    joinQuietly(stdoutThread);
                    joinQuietly(stderrThread);
                    String stdoutText = bufferedText(stdout).trim();
                    String stderrText = bufferedText(stderr).trim();
                    output = "Action: " + label + "\nExit: " + exitCode + "\n\n" + stdoutText;
                    if (!stderrText.isEmpty()) output += "\n\nstderr:\n" + stderrText;
                }
                joinQuietly(stdoutThread);
                joinQuietly(stderrThread);
            } catch (Throwable e) {
                output = "Action: " + label + "\nFailed: " + e.getClass().getSimpleName() + ": " + safeMessage(e);
            }
            final String finalOutput = output;
            final int finalExitCode = exitCode;
            final boolean verifiedWrite = !writeAction || shizukuWriteVerified(output, expectedValue);
            ui.post(() -> {
                shizukuCommandRunning.set(false);
                if (finalExitCode == 0 && label.toLowerCase(Locale.US).contains("bridge capability")) {
                    lastShizukuProbeAt = System.currentTimeMillis();
                }
                refreshShizukuState();
                setShizukuOutput(finalOutput);
                toast(finalExitCode == 0 ? (writeAction ? (verifiedWrite ? "Radio mode verified" : "Radio write not verified") : "Radio modes read") : "Shizuku command failed");
            });
        }, "shizuku-radio").start();
    }

    private boolean shizukuWriteVerified(String output, String expectedValue) {
        if (expectedValue == null || expectedValue.trim().isEmpty() || output == null) return false;
        String expected = expectedValue.trim();
        for (String line : output.split("\\R")) {
            String trimmed = line.trim();
            for (String key : RADIO_MODE_KEYS) {
                if (trimmed.equals(key + "=" + expected)) return true;
            }
        }
        return false;
    }

    private void setShizukuOutput(String text) {
        if (shizukuOutputView != null) shizukuOutputView.setText(text);
    }

    private void copyShizukuOutput() {
        String text = shizukuOutputView == null ? "" : shizukuOutputView.getText().toString();
        if (text.trim().isEmpty()) {
            toast("No Shizuku output yet");
            return;
        }
        clip(text);
        toast("Shizuku output copied");
    }

    private Process startShizukuShellProcess(String command) throws Exception {
        return startShizukuProcess(new String[]{"/system/bin/sh", "-c", command});
    }

    private Process startShizukuProcess(String[] command) throws Exception {
        Method newProcess = Shizuku.class.getDeclaredMethod("newProcess", String[].class, String[].class, String.class);
        newProcess.setAccessible(true);
        return (Process) newProcess.invoke(null, (Object) command, null, null);
    }

    private CommandResult runShizukuProcessCapture(String[] command, int timeoutSeconds) throws Exception {
        Process process = startShizukuProcess(command);
        StringBuilder stdout = new StringBuilder();
        StringBuilder stderr = new StringBuilder();
        Thread stdoutThread = collectProcessStream(process.getInputStream(), stdout);
        Thread stderrThread = collectProcessStream(process.getErrorStream(), stderr);
        boolean finished = process.waitFor(timeoutSeconds, java.util.concurrent.TimeUnit.SECONDS);
        if (!finished) {
            process.destroy();
            joinQuietly(stdoutThread);
            joinQuietly(stderrThread);
            return new CommandResult(-2, bufferedText(stdout), bufferedText(stderr));
        }
        int exitCode = process.exitValue();
        joinQuietly(stdoutThread);
        joinQuietly(stderrThread);
        return new CommandResult(exitCode, bufferedText(stdout), bufferedText(stderr));
    }

    private static class CommandResult {
        final int exitCode;
        final String stdout;
        final String stderr;

        CommandResult(int exitCode, String stdout, String stderr) {
            this.exitCode = exitCode;
            this.stdout = stdout == null ? "" : stdout;
            this.stderr = stderr == null ? "" : stderr;
        }
    }

    private Thread collectProcessStream(InputStream in, StringBuilder out) {
        Thread thread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                int lines = 0;
                while (lines < 500 && (line = reader.readLine()) != null) {
                    synchronized (out) {
                        out.append(line).append('\n');
                    }
                    lines++;
                }
                if (lines >= 500) {
                    synchronized (out) {
                        out.append("[stream] truncated after 500 lines\n");
                    }
                }
            } catch (IOException e) {
                synchronized (out) {
                    out.append("[stream] ").append(e.getClass().getSimpleName()).append(": ").append(safeMessage(e)).append('\n');
                }
            }
        }, "shizuku-stream");
        thread.start();
        return thread;
    }

    private void joinQuietly(Thread thread) {
        try {
            thread.join(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private String bufferedText(StringBuilder sb) {
        synchronized (sb) {
            return sb.toString();
        }
    }

    private String safeMessage(Throwable e) {
        return e.getMessage() == null ? "no message" : e.getMessage();
    }

    private LinearLayout diagnosticsSupportPanel() {
        LinearLayout card = column();
        card.setBackground(glassBg(Color.rgb(9, 22, 31), Color.argb(70, 255, 255, 255)));
        card.setPadding(dp(12), dp(10), dp(12), dp(10));
        setOuterMargin(card, 0, dp(14), 0, dp(8));
        TextView title = text("Support", 12, Color.rgb(210, 231, 240), true);
        TextView body = text("Project link and donation addresses are kept here so they never interrupt setup or results.", 11, MUTED, false);
        body.setTextIsSelectable(true);
        card.addView(title);
        card.addView(body);
        LinearLayout actions = row();
        Button github = button("GitHub", Color.rgb(24, 45, 58), Color.WHITE);
        Button btc = button("Copy BTC", Color.rgb(24, 45, 58), Color.WHITE);
        Button evm = button("Copy EVM", Color.rgb(24, 45, 58), Color.WHITE);
        github.setOnClickListener(v -> openSupportGitHub());
        btc.setOnClickListener(v -> copySupport("BTC", supportBtc()));
        evm.setOnClickListener(v -> copySupport("EVM", supportEvm()));
        actions.addView(github, weight());
        actions.addView(btc, weight());
        actions.addView(evm, weight());
        card.addView(actions);
        return card;
    }
    private TextView section(String s) { TextView v = text(s, 12, Color.rgb(180, 215, 230), true); v.setPadding(dp(2), dp(10), 0, dp(4)); v.setLetterSpacing(0f); return v; }
    private TextView pill(String s) { TextView v = text(s, 13, BLUE, true); v.setGravity(Gravity.CENTER); v.setBackground(glassBg(Color.rgb(16, 35, 50), BLUE)); v.setPadding(dp(12), dp(8), dp(12), dp(8)); setOuterMargin(v, 0, dp(8), 0, dp(8)); return v; }
    private EditText area(String hint) { EditText e = input("", false); e.setHint(hint); e.setMinLines(3); e.setMaxLines(7); e.setGravity(Gravity.TOP); return e; }
    private EditText input(String s, boolean number) { EditText e = new EditText(this); e.setText(s); e.setTextColor(Color.WHITE); e.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13); e.setHintTextColor(Color.rgb(145, 174, 190)); e.setSingleLine(false); e.setMaxLines(number ? 1 : 4); e.setHorizontallyScrolling(false); int type = number ? InputType.TYPE_CLASS_NUMBER : (InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE); e.setInputType(type | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS); e.setBackground(glassBg(FIELD, Color.argb(85, 255, 255, 255))); e.setPadding(dp(10), dp(8), dp(10), dp(8)); return e; }
    private CheckBox check(String s) { CheckBox c = new CheckBox(this); c.setText(s); c.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12); c.setTextColor(Color.WHITE); c.setMinHeight(dp(40)); c.setContentDescription(s); c.setButtonTintList(android.content.res.ColorStateList.valueOf(BLUE)); return c; }
    private Button button(String s, int bg, int fg) { Button b = new Button(this); b.setText(s); b.setTextColor(fg); b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12); b.setMinHeight(dp(42)); b.setAllCaps(false); b.setContentDescription(s.replace('\n', ' ')); b.setTypeface(Typeface.DEFAULT_BOLD); b.setBackground(glassBg(bg, Color.argb(125, 255, 255, 255))); b.setPadding(dp(9), dp(7), dp(9), dp(7)); b.setOnTouchListener((v, e) -> { if (e.getAction() == android.view.MotionEvent.ACTION_DOWN) { v.performHapticFeedback(android.view.HapticFeedbackConstants.KEYBOARD_TAP); v.animate().scaleX(0.98f).scaleY(0.98f).setDuration(70).start(); } if (e.getAction() == android.view.MotionEvent.ACTION_UP || e.getAction() == android.view.MotionEvent.ACTION_CANCEL) v.animate().scaleX(1f).scaleY(1f).setDuration(130).setInterpolator(new DecelerateInterpolator()).start(); return false; }); return b; }
    private Spinner spinner(String[] values) {
        Spinner s = new Spinner(this);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, values);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        s.setAdapter(adapter);
        s.setBackground(glassBg(FIELD, Color.argb(85, 255, 255, 255)));
        s.setPadding(dp(8), dp(5), dp(8), dp(5));
        return s;
    }
    private LinearLayout box(String label, View child) { LinearLayout l = column(); l.setBackground(glassBg(Color.rgb(10, 24, 34), Color.argb(60, 255, 255, 255))); l.setPadding(dp(7), dp(2), dp(7), dp(7)); l.addView(section(label)); l.addView(child); return l; }
    private LinearLayout.LayoutParams weight() { LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, -2, 1); lp.setMargins(dp(4), dp(4), dp(4), dp(4)); return lp; }
    private LinearLayout.LayoutParams fixedWidth(int widthDp) { LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(dp(widthDp), -2); lp.setMargins(dp(3), dp(3), dp(3), dp(3)); return lp; }
    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density + 0.5f); }
    private void toast(String s) { Toast.makeText(this, s, Toast.LENGTH_LONG).show(); }
    private void copySupport(String label, String address) { clip(address); toast(label + " address copied"); }
    private String supportEvm() { return new String(new char[]{'0','x','8','9','8','8','e','d','0','9','D','A','2','1','8','7','9','9','e','9','9','F','b','1','E','9','4','2','4','3','c','C','1','C','1','c','B','4','1','A','4','0'}); }
    private String supportBtc() { return new String(new char[]{'b','c','1','q','t','2','m','x','z','m','l','c','v','3','r','e','4','p','j','e','m','s','h','e','j','z','q','0','h','j','3','c','8','d','g','p','0','e','5','t','v','x'}); }
    private void openSupportGitHub() {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, android.net.Uri.parse(SUPPORT_GITHUB)));
        } catch (Exception e) {
            clip(SUPPORT_GITHUB);
            toast("GitHub link copied");
        }
    }
    private void openAndroidSettings(String action, String fallbackMessage) {
        try {
            startActivity(new Intent(action));
        } catch (Exception e) {
            toast(fallbackMessage);
        }
    }
    private boolean highContrastMode() { return densityMode == 1; }
    private boolean compactMode() { return densityMode == 2; }
    private GradientDrawable glassBg(int fill, int stroke) {
        int fillAlpha = highContrastMode() ? 245 : 215;
        int shineAlpha = highContrastMode() ? 40 : 120;
        GradientDrawable g = new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{Color.argb(fillAlpha, Color.red(fill), Color.green(fill), Color.blue(fill)), Color.argb(shineAlpha, 255, 255, 255)});
        g.setCornerRadius(dp(compactMode() ? 7 : 10));
        g.setStroke(highContrastMode() ? dp(2) : dp(1), stroke);
        return g;
    }
    private void setOuterMargin(View v, int l, int t, int r, int b) { LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2); lp.setMargins(l, t, r, b); v.setLayoutParams(lp); }

}
