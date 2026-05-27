package com.maybeedgescanner;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
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
import android.text.Layout;
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
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLParameters;

import rikka.shizuku.Shizuku;
import com.maybeedgescanner.diagnostics.PrivilegedTelephonyBasebandManager;

import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.DiffUtil;
import android.view.ViewGroup;
import android.transition.TransitionManager;

public class MainActivity extends Activity {
    public static final String ACTION_QUICK_SCAN = "com.maybeedgescanner.action.QUICK_SCAN";
    public static final String ACTION_SERVICE_STOP_SCAN = "com.maybeedgescanner.action.SERVICE_STOP_SCAN";
    private static final int BLUE = Color.rgb(23, 192, 235);
    private static final int PANEL = Color.rgb(13, 28, 39);
    private static final int FIELD = Color.rgb(9, 20, 29);
    private static final int MUTED = Color.rgb(140, 161, 178);
    private static final String SUPPORT_GITHUB = "https://github.com/maybeknott/MaybeEdgeScanner/";
    private static final int SHIZUKU_REQUEST_CODE = 4601;
    private static final int NOTIFICATION_REQUEST_CODE = 4602;
    private static final String[] RADIO_MODE_KEYS = {
            "preferred_network_mode",
            "preferred_network_mode0",
            "preferred_network_mode1",
            "preferred_network_mode2"
    };
    private static final int PREVIEW_TARGET_LIMIT = 12;
    private static final int RESULT_QUEUE_CAPACITY = 8192;
    private static final int RESULT_DRAIN_BATCH = 512;
    private static final int PREVIEW_CHIP_LIMIT = 12;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final AtomicBoolean stop = new AtomicBoolean(false);
    private final AtomicBoolean renderQueued = new AtomicBoolean(false);
    private final AtomicBoolean resultDrainQueued = new AtomicBoolean(false);
    private final AtomicBoolean progressQueued = new AtomicBoolean(false);
    private final AtomicBoolean shizukuCommandRunning = new AtomicBoolean(false);
    private PrivilegedTelephonyBasebandManager basebandManager;
    private final AtomicInteger checkedTargets = new AtomicInteger(0);
    private final AtomicLong resultSequence = new AtomicLong(0);
    private final AtomicLong scanGeneration = new AtomicLong(0);
    private final AtomicLong shizukuActionSequence = new AtomicLong(0);
    private final ResultSessionStore<Result> resultStore = new ResultSessionStore<>();
    private final BlockingQueue<ResultEvent> pendingResults = new ArrayBlockingQueue<>(RESULT_QUEUE_CAPACITY);
    private final ConcurrentHashMap<String, List<String>> assetLineCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LinkedHashSet<String>> assetTokenCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LinkedHashSet<String>> communityCorpusCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> assetReadLocks = new ConcurrentHashMap<>();
    private final LinkedHashSet<String> selectedSourceTargets = new LinkedHashSet<>();
    private final LinkedHashSet<String> selectedSourceSnis = new LinkedHashSet<>();
    private final ArrayDeque<String> logLines = new ArrayDeque<>();
    private final StringBuilder stableLogBuilder = new StringBuilder();
    private final ExecutorService previewExecutor = Executors.newSingleThreadExecutor();
    private ExecutorService executor;
    private boolean suppressUiRefresh;
    private String cachedResourceLine = "battery n/a | heap 0MB";
    private long cachedResourceLineAt;
    private long stableHistoryRenderedAt;
    private long analyticsRenderedAt;
    private long heatmapRenderedAt;
    private long logRenderedAt;
    private String lastRenderedLogText = "";
    private long lastShizukuProbeAt;
    private float swipeDownX, swipeDownY;

    private RecyclerView resultList;
    private ResultsAdapter resultsAdapter;
    private LinearLayout resultSummaryContainer;
    private LinearLayout heatmapContainer;
    private LinearLayout pagerContainer;
    private TextView resultSummaryText;
    private LinearLayout pagerPanel;
    private TextView pagerText;
    private Button pagerPrevButton;
    private Button pagerNextButton;
    private LinearLayout targetTab, liveTab, diagnosticsTab;
    private LinearLayout targetChipPreview, sniChipPreview;
    private LinearLayout analyticsPanel;
    private LinearLayout stableHistoryPanel;
    private ScrollView targetScroll, liveScroll, diagnosticsScroll;
    private View targetAnchor, liveAnchor, diagnosticsAnchor;
    private ProgressBar progress;
    private TextView status, metrics, bestView, countersView, logView, networkBanner, homeDashboardView;
    private TextView shizukuHealthTileView, shizukuStatusView, shizukuNextStepView, shizukuOutputView;
    private TextView sourceSummaryView, sourceHealthView;
    private TextView scanPlanView;
    private EditText targetsInput, snisInput, totalInput, batchInput, threadsInput, timeoutInput;
    private EditText communitySampleInput, akamaiSampleInput, cloudfrontSampleInput, fastlySampleInput, cloudflareSampleInput, otherCdnSampleInput, customTargetSampleInput, customSniSampleInput;
    private EditText portsInput, pathInput, maxLatencyInput, resultLimitInput, cdnFilterInput, certFilterInput, sniFilterInput, minQualityInput;
    private EditText shizukuKeyInput, shizukuValueInput, logFilterInput;
    private TextView diagnosticOutputView;
    private Button runDiagnosticsButton;
    private CheckBox multiSni, filterWorking, filterTlsHttp, bestPerIp, hideNoisyLogs, requireHttp, requireKnownCdn, requireTls13, batteryFriendlyUi;
    private CheckBox diagnosticsOfflineMode, diagnosticsIncludePublicIp, exportPrivacyMode;
    private CheckBox communitySourceEnabled, akamaiSourceEnabled, cloudfrontSourceEnabled, fastlySourceEnabled, cloudflareSourceEnabled, otherCdnSourceEnabled, defaultSniEnabled;
    private CheckBox stepTcp, stepTls, stepHttp, stepVerify;
    private Spinner profileSpinner, workflowSpinner, sortSpinner, exportSpinner, fileExportSpinner, tlsModeSpinner, cdnProviderSpinner;
    private Spinner routeProviderSpinner, routeProtocolSpinner, routeAuthSpinner, routeDnsSpinner, routeSplitSpinner, routeUpstreamSpinner, routeDownstreamSpinner, routeGatewaySpinner;
    private Spinner routeStrategySpinner, routeConduitModeSpinner, routeProviderChainSpinner;
    private EditText routeProfileRefInput, routeCredentialRefInput, routeConfigRefInput, routeEndpointInput, routePackageInput;
    private EditText routeFrontingIpRefInput, routeFrontingSniInput, routeChainUpstreamRefInput, routeGatewayAuthRefInput, routeLanSocksPortInput, routeLanHttpPortInput;
    private CheckBox routeShareLanCheck, routeBeastModeCheck;
    private TextView routeReadinessView;
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
    private final BroadcastReceiver scanControlReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            if (intent == null) return;
            String action = intent.getAction();
            if (ACTION_SERVICE_STOP_SCAN.equals(action)) {
                requestStop();
            } else if (ScanForegroundService.ACTION_STATE_CHANGED.equals(action)) {
                ScanForegroundService.ScanLifecycleSnapshot snapshot = ScanForegroundService.snapshot();
                if (status != null && !"idle".equals(snapshot.state)) {
                    status.setText(snapshot.state + ": " + snapshot.detail);
                }
            }
        }
    };

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        buildUi();
        loadDefaults();
        maybeShowOnboarding();
        addShizukuListener();
        registerScanControlReceiver();
        ensureScanNotificationPermission();
        refreshShizukuState();
        if (ACTION_QUICK_SCAN.equals(getIntent().getAction())) {
            ui.postDelayed(this::handleQuickScanIntent, 450);
        }
    }

    @Override protected void onDestroy() {
        stop.set(true);
        if (executor != null) {
            executor.shutdownNow();
        }
        if (previewExecutor != null) {
            previewExecutor.shutdownNow();
        }
        removeShizukuListener();
        try {
            unregisterReceiver(scanControlReceiver);
        } catch (IllegalArgumentException ignored) {
        }
        super.onDestroy();
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (ACTION_QUICK_SCAN.equals(intent.getAction())) {
            ui.postDelayed(this::handleQuickScanIntent, 450);
        }
    }

    @Override protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putString("result_session_id", resultStore.sessionId());
        outState.putInt("result_count", resultStore.size());
        synchronized (logLines) {
            outState.putInt("log_count", logLines.size());
        }
    }

    @Override protected void onRestoreInstanceState(Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);
        if (savedInstanceState == null) return;
        // Full scan rows/logs intentionally stay out of Activity bundles. A later
        // foreground-service session store will provide process-death recovery.
        updateProgress();
        scheduleRender();
    }

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    private void registerScanControlReceiver() {
        IntentFilter filter = new IntentFilter();
        filter.addAction(ACTION_SERVICE_STOP_SCAN);
        filter.addAction(ScanForegroundService.ACTION_STATE_CHANGED);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(scanControlReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(scanControlReceiver, filter);
        }
    }

    private void handleQuickScanIntent() {
        selectTab(0);
        Toast.makeText(this, "Quick scan preset loaded. Review the plan, then press Start.", Toast.LENGTH_LONG).show();
        updateScanPlanPreview();
        ScanForegroundService.update(this, "waiting_for_confirmation",
                "Quick scan request opened for review", 0);
    }

    private void ensureScanNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return;
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return;
        requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, NOTIFICATION_REQUEST_CODE);
    }

    private void buildUi() {
        RelativeLayout screen = new RelativeLayout(this);
        screen.setBackground(new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{Color.rgb(5, 14, 23), Color.rgb(8, 28, 38), Color.rgb(15, 18, 34)}));
        screen.setLayoutParams(new RelativeLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        LinearLayout tabs = row();
        tabs.setId(View.generateViewId());
        tabTargetButton = button("Sources", Color.rgb(21, 45, 62), Color.WHITE);
        tabLiveButton = button("Results", Color.rgb(21, 45, 62), Color.WHITE);
        tabDiagnosticsButton = button("Diagnostics", Color.rgb(21, 45, 62), Color.WHITE);
        tabs.addView(tabTargetButton, weight());
        tabs.addView(tabLiveButton, weight());
        tabs.addView(tabDiagnosticsButton, weight());
        RelativeLayout.LayoutParams tabsParams = new RelativeLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        tabsParams.addRule(RelativeLayout.ALIGN_PARENT_BOTTOM);
        tabs.setLayoutParams(tabsParams);

        // Pinned App Header: System Status
        LinearLayout headerContainer = column();
        headerContainer.setId(View.generateViewId());
        headerContainer.setPadding(dp(14), dp(12), dp(14), dp(8));
        headerContainer.setBackground(new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{Color.rgb(10, 24, 40), Color.rgb(8, 20, 32)}));

        LinearLayout titleRow = row();
        titleRow.setGravity(Gravity.CENTER_VERTICAL);
        TextView titleText = text("MaybeEdgeScanner", 22, Color.WHITE, true);
        if (Build.VERSION.SDK_INT >= 21) titleText.setLetterSpacing(0.04f);
        titleRow.addView(titleText, weight());
        status = pill("Ready");
        status.setPadding(dp(10), dp(4), dp(10), dp(4));
        titleRow.addView(status);
        headerContainer.addView(titleRow);

        TextView subtitleText = text("Edge discovery workspace", 12, MUTED, false);
        subtitleText.setPadding(0, 0, 0, dp(4));
        headerContainer.addView(subtitleText);

        networkBanner = pill(networkContextLine());
        networkBanner.setPadding(dp(10), dp(4), dp(10), dp(4));
        headerContainer.addView(networkBanner);

        LinearLayout quick = row();
        startButton = button("Start", BLUE, Color.rgb(2, 18, 24));
        stopButton = button("Stop", Color.rgb(255, 102, 122), Color.WHITE);
        clearButton = button("Clear", Color.rgb(34, 51, 66), Color.WHITE);
        stopButton.setEnabled(false);
        quick.addView(startButton, weight());
        quick.addView(stopButton, weight());
        quick.addView(clearButton, weight());
        headerContainer.addView(quick);

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setMax(100);
        LinearLayout.LayoutParams progressLp = new LinearLayout.LayoutParams(-1, dp(4));
        progressLp.setMargins(0, dp(6), 0, 0);
        progress.setLayoutParams(progressLp);
        headerContainer.addView(progress);

        RelativeLayout.LayoutParams headerParams = new RelativeLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        headerParams.addRule(RelativeLayout.ALIGN_PARENT_TOP);
        headerContainer.setLayoutParams(headerParams);

        // Central FrameLayout content view container
        FrameLayout contentContainer = new FrameLayout(this);
        contentContainer.setId(View.generateViewId());
        RelativeLayout.LayoutParams contentParams = new RelativeLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT);
        contentParams.addRule(RelativeLayout.BELOW, headerContainer.getId());
        contentParams.addRule(RelativeLayout.ABOVE, tabs.getId());
        contentContainer.setLayoutParams(contentParams);

        // Tab 1: Sources scroll container
        targetScroll = new ScrollView(this);
        targetScroll.setOnTouchListener((v, event) -> handleTabSwipe(event));
        targetTab = column();
        targetTab.setPadding(dp(14), dp(10), dp(14), dp(22));
        targetScroll.addView(targetTab);
        contentContainer.addView(targetScroll);

        // Tab 2: Results scroll container
        liveScroll = new ScrollView(this);
        liveScroll.setOnTouchListener((v, event) -> handleTabSwipe(event));
        liveTab = column();
        liveTab.setPadding(dp(14), dp(10), dp(14), dp(22));
        liveScroll.addView(liveTab);
        contentContainer.addView(liveScroll);

        // Tab 3: Diagnostics scroll container
        diagnosticsScroll = new ScrollView(this);
        diagnosticsScroll.setOnTouchListener((v, event) -> handleTabSwipe(event));
        diagnosticsTab = column();
        diagnosticsTab.setPadding(dp(14), dp(10), dp(14), dp(22));
        diagnosticsScroll.addView(diagnosticsTab);
        contentContainer.addView(diagnosticsScroll);

        // Populate Sources Tab
        homeDashboardView = panelText("Network and system\nTransport: checking\nLAN/WAN: checking\nDNS: checking\nPolicy: checking\nCapacity: checking\nDevice: checking\nRuntime: checking");
        targetTab.addView(homeDashboardView);
        targetTab.addView(quietNote("Sources build IP/SNI scan routes. Results show filtered cards, best SNIs, and export actions. Diagnostics keeps logs, radio controls, and network context separate."));
        helpButton = button("Reference", Color.rgb(23, 46, 63), Color.WHITE);
        targetTab.addView(helpButton);

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

        // Modernized Unified Configuration Dashboard Container
        LinearLayout metricsDashboardCard = column();
        metricsDashboardCard.setBackground(glassBg(PANEL, Color.argb(120, 255, 255, 255)));
        metricsDashboardCard.setPadding(dp(12), dp(12), dp(12), dp(12));
        setOuterMargin(metricsDashboardCard, 0, dp(6), 0, dp(8));

        sourceSummaryView = text("Managed sources: initializing", 12, Color.rgb(196, 223, 235), false);
        sourceHealthView = text("Source health: checking", 11, Color.rgb(160, 195, 215), false);
        scanPlanView = text("Scan plan: mapping", 11, Color.WHITE, false);
        formatMonospace(scanPlanView, 11);

        metricsDashboardCard.addView(text("Pre-Flight Invalidation Metrics", 13, BLUE, true));
        metricsDashboardCard.addView(sourceSummaryView);
        metricsDashboardCard.addView(sourceHealthView);
        metricsDashboardCard.addView(scanPlanView);
        targetTab.addView(metricsDashboardCard);
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
        performancePanel.addView(quietNote("Performance modes tune threads, batch, and timeout. Raise Run budget for full subnet or full-provider runs."));
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
        row2.addView(box("Run budget", totalInput), weight());
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

        LinearLayout routePanel = column();
        routePanel.addView(quietNote("Edge routing profiles attach provider route identity to scans without storing raw provider credentials in the sidecar. Windscribe login/session ownership stays Android-side; Psiphon uses config/profile references and readiness observation."));
        routeProviderSpinner = spinner(new String[]{"Direct / no provider route", "Windscribe", "Psiphon", "Generic local proxy"});
        routeProtocolSpinner = spinner(new String[]{"external_vpn", "local_proxy", "wireguard", "openvpn_udp", "openvpn_tcp", "tcp", "stealth", "wstunnel", "ikev2", "tunnel_core_supervised", "external_vpn_apk"});
        routeAuthSpinner = spinner(new String[]{"none", "external_app", "profile_ref", "credential_ref", "auth_token_ref", "sso_external", "wsnet_session_ref", "config_ref"});
        routeDnsSpinner = spinner(new String[]{"system_or_route_default", "remote_dns", "route_dns", "ctrld", "control_d", "robert", "doh", "dot", "custom_dns_ref", "no_dns"});
        routeSplitSpinner = spinner(new String[]{"scanner_app_only", "include_targets", "exclude_targets", "external_vpn_policy", "disabled"});
        routeUpstreamSpinner = spinner(new String[]{"none", "system_proxy", "proxy_ref", "direct", "provider_default"});
        routeDownstreamSpinner = spinner(new String[]{"scanner_to_route", "local_proxy_gateway", "vpn_interface", "provider_default"});
        routeGatewaySpinner = spinner(new String[]{"loopback_only", "lan_shared"});
        routeStrategySpinner = spinner(new String[]{"provider_default", "auto", "conduit_first", "conduit", "cdn_fronting", "direct", "profile_default"});
        routeConduitModeSpinner = spinner(new String[]{"auto", "shirokhorshid", "public"});
        routeProviderChainSpinner = spinner(new String[]{"none", "psiphon_over_windscribe", "windscribe_over_psiphon", "generic_proxy_over_windscribe", "windscribe_over_generic_proxy"});
        routeProfileRefInput = input("", false); routeProfileRefInput.setHint("ref:windscribe-profile or ref:user-connected-vpn");
        routeCredentialRefInput = input("", false); routeCredentialRefInput.setHint("ref:stored-session/auth-token only");
        routeConfigRefInput = input("", false); routeConfigRefInput.setHint("ref:psiphon-config");
        routeEndpointInput = input("", false); routeEndpointInput.setHint("socks5://127.0.0.1:1080 or http://127.0.0.1:8080");
        routePackageInput = input("", false); routePackageInput.setHint("com.psiphon3 for external APK observation");
        routeFrontingIpRefInput = input("", false); routeFrontingIpRefInput.setHint("ref:fronting-ip-list");
        routeFrontingSniInput = input("", false); routeFrontingSniInput.setHint("front.example.com");
        routeChainUpstreamRefInput = input("", false); routeChainUpstreamRefInput.setHint("ref:upstream-route");
        routeGatewayAuthRefInput = input("", false); routeGatewayAuthRefInput.setHint("ref:lan-gateway-auth");
        routeLanSocksPortInput = input("", true); routeLanSocksPortInput.setHint("optional");
        routeLanHttpPortInput = input("", true); routeLanHttpPortInput.setHint("optional");
        routeShareLanCheck = check("Share route gateway on LAN");
        routeBeastModeCheck = check("Beast establishment");
        LinearLayout routeRow1 = row();
        routeRow1.addView(box("Provider", routeProviderSpinner), weight());
        routeRow1.addView(box("Protocol", routeProtocolSpinner), weight());
        routePanel.addView(routeRow1);
        LinearLayout routeRow2 = row();
        routeRow2.addView(box("Auth", routeAuthSpinner), weight());
        routeRow2.addView(box("DNS policy", routeDnsSpinner), weight());
        routePanel.addView(routeRow2);
        LinearLayout routeRow3 = row();
        routeRow3.addView(box("Split tunnel", routeSplitSpinner), weight());
        routeRow3.addView(box("Downstream", routeDownstreamSpinner), weight());
        routePanel.addView(routeRow3);
        LinearLayout routeRow4 = row();
        routeRow4.addView(box("Upstream", routeUpstreamSpinner), weight());
        routeRow4.addView(box("Gateway", routeGatewaySpinner), weight());
        routePanel.addView(routeRow4);
        LinearLayout routeRow5 = row();
        routeRow5.addView(box("Strategy", routeStrategySpinner), weight());
        routeRow5.addView(box("Conduit", routeConduitModeSpinner), weight());
        routePanel.addView(routeRow5);
        routePanel.addView(box("Provider chain", routeProviderChainSpinner));
        routePanel.addView(box("Profile ref", routeProfileRefInput));
        routePanel.addView(box("Credential/session ref", routeCredentialRefInput));
        routePanel.addView(box("Config ref", routeConfigRefInput));
        routePanel.addView(box("Local proxy endpoint", routeEndpointInput));
        routePanel.addView(box("External package", routePackageInput));
        routePanel.addView(box("CDN/fronting IP ref", routeFrontingIpRefInput));
        routePanel.addView(box("CDN/fronting SNI", routeFrontingSniInput));
        routePanel.addView(box("Chain upstream route ref", routeChainUpstreamRefInput));
        routePanel.addView(box("LAN gateway auth ref", routeGatewayAuthRefInput));
        LinearLayout lanPorts = row();
        lanPorts.addView(box("LAN SOCKS port", routeLanSocksPortInput), weight());
        lanPorts.addView(box("LAN HTTP port", routeLanHttpPortInput), weight());
        routePanel.addView(lanPorts);
        LinearLayout routeFlags = row();
        routeFlags.addView(routeShareLanCheck, weight());
        routeFlags.addView(routeBeastModeCheck, weight());
        routePanel.addView(routeFlags);
        LinearLayout routeActions = row();
        Button routeDefaults = button("Route defaults", Color.rgb(24, 45, 58), Color.WHITE);
        Button routeObserve = button("Observe route", Color.rgb(24, 45, 58), Color.WHITE);
        routeDefaults.setOnClickListener(v -> applyRouteProviderDefaults());
        routeObserve.setOnClickListener(v -> updateRouteReadinessPreview());
        routeActions.addView(routeDefaults, weight());
        routeActions.addView(routeObserve, weight());
        routePanel.addView(routeActions);
        routeReadinessView = panelText("Route readiness: direct scan path");
        formatMonospace(routeReadinessView, 11);
        routePanel.addView(routeReadinessView);
        targetTab.addView(collapsibleBox("Edge routing profile", routePanel, false));

        // Populate Results Tab
        liveAnchor = section("Results");
        liveTab.addView(liveAnchor);
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
        filterPanel.addView(quietNote("These controls only change visible rows and exports; they never change the scan queue."));
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
        resultLimitInput = input("1000", true);
        row5.addView(box("Max latency ms", maxLatencyInput), weight());
        row5.addView(box("Visible rows", resultLimitInput), weight());
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
        exportPanel.addView(quietNote("Clipboard uses filtered cards. File export streams full session results with schema + redaction metadata."));
        LinearLayout buttons = row();
        copyButton = button("Copy format", Color.rgb(34, 51, 66), Color.WHITE);
        copyCsvButton = button("Copy CSV", Color.rgb(34, 51, 66), Color.WHITE);
        exportButton = button("Save Export", Color.rgb(34, 51, 66), Color.WHITE);
        buttons.addView(copyButton, weight());
        buttons.addView(copyCsvButton, weight());
        buttons.addView(exportButton, weight());
        exportPanel.addView(buttons);
        LinearLayout exportRow = row();
        exportSpinner = spinner(new String[]{"Line-separated IPs", "Comma-separated IPs", "IP SNI pairs", "SNI only", "CSV rows", "JSON"});
        exportRow.addView(box("Clipboard format", exportSpinner), weight());
        exportPanel.addView(exportRow);
        fileExportSpinner = spinner(new String[]{"JSONL session export", "CSV session export", "Markdown report", "Nmap-like XML"});
        exportPanel.addView(box("File export format", fileExportSpinner));
        exportPrivacyMode = check("Privacy redaction for exports");
        exportPrivacyMode.setChecked(true);
        exportPanel.addView(exportPrivacyMode);
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
        resultSummaryContainer = new LinearLayout(this);
        resultSummaryContainer.setOrientation(LinearLayout.VERTICAL);
        liveTab.addView(resultSummaryContainer);

        heatmapContainer = new LinearLayout(this);
        heatmapContainer.setOrientation(LinearLayout.VERTICAL);
        liveTab.addView(heatmapContainer);

        resultList = new RecyclerView(this);
        resultList.setLayoutManager(new LinearLayoutManager(this));
        resultList.setNestedScrollingEnabled(false);
        liveTab.addView(resultList);

        resultsAdapter = new ResultsAdapter();
        resultList.setAdapter(resultsAdapter);

        pagerContainer = new LinearLayout(this);
        pagerContainer.setOrientation(LinearLayout.VERTICAL);
        liveTab.addView(pagerContainer);

        // Populate Diagnostics Tab
        diagnosticsAnchor = section("Diagnostics");
        diagnosticsTab.addView(diagnosticsAnchor);
        diagnosticsTab.addView(quietNote("Logs and support links live here so they do not bury scan setup or result cards."));
        diagnosticsTab.addView(shizukuHealthTile());

        // Automated Diagnostic Checks Card
        diagnosticsTab.addView(section("Network Diagnostic Checks"));
        LinearLayout diagCard = column();
        diagCard.setBackground(glassBg(PANEL, Color.argb(120, 255, 255, 255)));
        diagCard.setPadding(dp(12), dp(12), dp(12), dp(12));
        setOuterMargin(diagCard, 0, dp(6), 0, dp(8));

        diagCard.addView(text("Automated Diagnostic Suite", 13, BLUE, true));
        diagCard.addView(text("Check DNS query latency, raw TCP connection, and secure HTTPS handshakes in a non-blocking background thread.", 11, MUTED, false));

        runDiagnosticsButton = button("Run Diagnostics", Color.rgb(24, 45, 58), Color.WHITE);
        runDiagnosticsButton.setOnClickListener(v -> runNetworkDiagnostics());
        diagCard.addView(runDiagnosticsButton);
        diagnosticsOfflineMode = check("Offline diagnostics mode (no external probes)");
        diagnosticsOfflineMode.setChecked(false);
        diagCard.addView(diagnosticsOfflineMode);
        diagnosticsIncludePublicIp = check("Include public IP probe (api.ipify.org)");
        diagnosticsIncludePublicIp.setChecked(false);
        diagCard.addView(diagnosticsIncludePublicIp);

        diagnosticOutputView = panelText("Ready to run network diagnostics.");
        formatMonospace(diagnosticOutputView, 11);
        diagnosticOutputView.setTextIsSelectable(true);
        diagCard.addView(diagnosticOutputView);
        diagnosticsTab.addView(diagCard);

        diagnosticsTab.addView(section("Logs"));
        logFilterInput = input("", false);
        logFilterInput.setHint("Search logs...");
        diagnosticsTab.addView(box("Search logs", logFilterInput));

        logView = text("", 12, MUTED, false);
        formatMonospace(logView, 12);
        diagnosticsTab.addView(logView);
        diagnosticsTab.addView(collapsibleBox("Radio and network assist", diagnosticsRadioPanel(), false));
        diagnosticsTab.addView(collapsibleBox("Support and project links", diagnosticsSupportPanel(), false));

        // Setup layouts inside screen Relativelayout
        screen.addView(headerContainer);
        screen.addView(contentContainer);
        screen.addView(tabs);

        startButton.setOnClickListener(v -> startScan());
        stopButton.setOnClickListener(v -> requestStop());
        clearButton.setOnClickListener(v -> clearResults());
        helpButton.setOnClickListener(v -> showGuide());
        routeProviderSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                applyRouteProviderDefaults();
            }
            @Override public void onNothingSelected(AdapterView<?> parent) {
                updateRouteReadinessPreview();
            }
        });
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
        logFilterInput.addTextChangedListener(simpleWatcher(this::refreshLogView));
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
        synchronized (selectedSourceTargets) {
            selectedSourceTargets.clear();
        }
        synchronized (selectedSourceSnis) {
            selectedSourceSnis.clear();
        }
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
            if (!suppressUiRefresh && afterChange != null) {
                android.os.AsyncTask.THREAD_POOL_EXECUTOR.execute(afterChange);
            }
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
        
        final String rawTargetsText = targetsInput.getText().toString();
        final String rawSnisText = snisInput.getText().toString();
        final int targetCap = Math.max(1, intValue(totalInput, 72000));
        
        final boolean defaultSni = checked(defaultSniEnabled);
        final boolean community = checked(communitySourceEnabled);
        final int communityCount = intValue(communitySampleInput, 0);
        final boolean akamai = checked(akamaiSourceEnabled);
        final int akamaiCount = intValue(akamaiSampleInput, 0);
        final boolean cloudfront = checked(cloudfrontSourceEnabled);
        final int cloudfrontCount = intValue(cloudfrontSampleInput, 0);
        final boolean fastly = checked(fastlySourceEnabled);
        final int fastlyCount = intValue(fastlySampleInput, 0);
        final boolean cloudflare = checked(cloudflareSourceEnabled);
        final int cloudflareCount = intValue(cloudflareSampleInput, 0);
        final boolean otherCdn = checked(otherCdnSourceEnabled);
        final int otherCdnCount = intValue(otherCdnSampleInput, 0);
        
        final int threads = Math.max(1, intValue(threadsInput, 32));
        final int batch = Math.max(1, intValue(batchInput, 2000));
        final int timeout = Math.max(1, intValue(timeoutInput, 3000));
        final String pathText = pathInput == null ? "/" : pathInput.getText().toString();
        final String tlsMode = tlsModeSpinner == null ? "Android default" : String.valueOf(tlsModeSpinner.getSelectedItem());
        final List<Integer> profiles = selectedWorkflowProfiles();
        final boolean allSni = sniPairingEnabled() && multiSni != null && multiSni.isChecked();
        final String portsText = portsInput == null ? "443" : portsInput.getText().toString();
        
        previewExecutor.execute(() -> {
            rebuildManagedSourcesBg(defaultSni, community, communityCount, akamai, akamaiCount, cloudfront, cloudfrontCount, fastly, fastlyCount, cloudflare, cloudflareCount, otherCdn, otherCdnCount);
            
            final List<String> targetTokens = combinedTargetTokens(rawTargetsText);
            final int estimatedTargets = estimateExpandedTargetCount(targetTokens, Integer.MAX_VALUE);
            final List<String> previewTargets = previewExpandedTargets(targetTokens, Math.min(targetCap, PREVIEW_TARGET_LIMIT));
            
            final boolean sniPairing = sniPairingEnabled();
            final List<String> combinedSniTokens = sniPairing ? combinedSniTokens(rawSnisText) : Collections.emptyList();
            
            final String summaryText = getSummaryText(defaultSni, community, akamai, cloudfront, fastly, cloudflare, otherCdn);
            final String healthText = getHealthText(rawTargetsText, rawSnisText, targetTokens, estimatedTargets, targetCap, threads, batch, allSni);
            final String planText = getPlanText(rawTargetsText, rawSnisText, targetTokens, targetCap, batch, threads, timeout, pathText, tlsMode, profiles, allSni, portsText);
            
            ui.post(() -> {
                if (targetChipPreview == null || sniChipPreview == null) return;
                
                int managedSize;
                int customSize;
                synchronized (selectedSourceTargets) {
                    managedSize = selectedSourceTargets.size();
                    customSize = sampleSource(lines(rawTargetsText), customTargetSampleInput == null ? 0 : intValue(customTargetSampleInput, 0)).size();
                }
                
                renderChips(targetChipPreview, "Source preview (" + managedSize + " managed tokens + " + customSize + " custom -> " + Math.min(estimatedTargets, targetCap) + " endpoints, " + previewTargets.size() + " previewed)", previewTargets, true);
                
                if (sniPairing) {
                    int managedSnis;
                    int customSnis;
                    synchronized (selectedSourceSnis) {
                        managedSnis = selectedSourceSnis.size();
                        customSnis = sampleSource(lines(rawSnisText), customSniSampleInput == null ? 0 : intValue(customSniSampleInput, 0)).size();
                    }
                    renderChips(sniChipPreview, "SNI routes (" + managedSnis + " default + " + customSnis + " custom)", combinedSniTokens, false);
                } else {
                    renderChips(sniChipPreview, "SNI pairing disabled", Collections.emptyList(), false);
                }
                
                if (sourceSummaryView != null) sourceSummaryView.setText(summaryText);
                if (sourceHealthView != null) sourceHealthView.setText(healthText);
                if (scanPlanView != null) scanPlanView.setText(planText);
            });
        });
    }


    private String sourceLoadPosture(int estimatedTargets, int targetCap) {
        return sourceLoadPostureBg(estimatedTargets, targetCap, 32, 2000);
    }

    private List<String> combinedTargetTokens() {
        return combinedTargetTokens(targetsInput == null ? "" : targetsInput.getText().toString());
    }

    private List<String> combinedTargetTokens(String customTargetsText) {
        synchronized (selectedSourceTargets) {
            LinkedHashSet<String> merged = new LinkedHashSet<>(selectedSourceTargets);
            merged.addAll(sampledCustomTargets(customTargetsText));
            return new ArrayList<>(merged);
        }
    }

    private List<String> combinedSniTokens() {
        return combinedSniTokens(snisInput == null ? "" : snisInput.getText().toString());
    }

    private List<String> combinedSniTokens(String customSnisText) {
        synchronized (selectedSourceSnis) {
            LinkedHashSet<String> merged = new LinkedHashSet<>(selectedSourceSnis);
            merged.addAll(sampledCustomSnis(customSnisText));
            return new ArrayList<>(merged);
        }
    }

    private LinkedHashSet<String> sampledCustomTargets() {
        return sampledCustomTargets(targetsInput == null ? "" : targetsInput.getText().toString());
    }

    private LinkedHashSet<String> sampledCustomTargets(String customTargetsText) {
        return sampleSource(lines(customTargetsText), customTargetSampleInput == null ? 0 : intValue(customTargetSampleInput, 0));
    }

    private LinkedHashSet<String> sampledCustomSnis() {
        return sampledCustomSnis(snisInput == null ? "" : snisInput.getText().toString());
    }

    private LinkedHashSet<String> sampledCustomSnis(String customSnisText) {
        return sampleSource(lines(customSnisText), customSniSampleInput == null ? 0 : intValue(customSniSampleInput, 0));
    }

    private void updateScanPlanPreview() {}

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
        PreviewPanelState state = previewPanelState(panel);
        int valid = 0;
        for (String value : values) if (targets ? validTargetToken(value) : validDomainToken(value)) valid++;
        state.title.setText(title + ": " + valid + "/" + values.size() + " ready");
        int shown = Math.min(values.size(), PREVIEW_CHIP_LIMIT);
        for (int i = 0; i < shown; i++) {
            String token = values.get(i);
            boolean ok = targets ? validTargetToken(token) : validDomainToken(token);
            bindPreviewChip(state.chips.get(i), token, ok);
            state.chips.get(i).setVisibility(View.VISIBLE);
        }
        for (int i = shown; i < state.chips.size(); i++) {
            state.chips.get(i).setVisibility(View.GONE);
        }
        if (values.size() > shown) {
            bindPreviewChip(state.overflowChip, "+" + (values.size() - shown) + " more", true);
            state.overflowChip.setVisibility(View.VISIBLE);
        } else {
            state.overflowChip.setVisibility(View.GONE);
        }
        if (values.isEmpty()) {
            bindPreviewChip(state.emptyChip, targets ? "Paste IPs, CIDRs, ranges, domains" : "Paste hostnames for TLS SNI", true);
            state.emptyChip.setVisibility(View.VISIBLE);
        } else {
            state.emptyChip.setVisibility(View.GONE);
        }
    }

    private PreviewPanelState previewPanelState(LinearLayout panel) {
        Object tag = panel.getTag();
        if (tag instanceof PreviewPanelState) return (PreviewPanelState) tag;
        panel.removeAllViews();
        PreviewPanelState state = new PreviewPanelState();
        state.title = text("", 11, MUTED, true);
        panel.addView(state.title);
        LinearLayout row = null;
        for (int i = 0; i < PREVIEW_CHIP_LIMIT; i++) {
            if (i % 2 == 0) {
                row = row();
                row.setGravity(Gravity.START);
                panel.addView(row);
            }
            TextView chip = chip("", true);
            chip.setVisibility(View.GONE);
            state.chips.add(chip);
            row.addView(chip, smallChipLp());
        }
        LinearLayout metaRow = row();
        metaRow.setGravity(Gravity.START);
        state.overflowChip = chip("", true);
        state.emptyChip = chip("", true);
        state.overflowChip.setVisibility(View.GONE);
        state.emptyChip.setVisibility(View.GONE);
        metaRow.addView(state.overflowChip, smallChipLp());
        metaRow.addView(state.emptyChip, smallChipLp());
        panel.addView(metaRow);
        panel.setTag(state);
        return state;
    }

    private void bindPreviewChip(TextView v, String label, boolean ok) {
        v.setText(trim(label, 22));
        int fill = ok ? Color.rgb(11, 58, 46) : Color.rgb(74, 26, 37);
        int stroke = ok ? Color.argb(150, 66, 230, 170) : Color.argb(170, 255, 120, 140);
        v.setBackground(glassBg(fill, stroke));
        v.setContentDescription((ok ? "Valid token " : "Invalid token ") + label);
    }

    private static class PreviewPanelState {
        TextView title;
        final ArrayList<TextView> chips = new ArrayList<>();
        TextView overflowChip;
        TextView emptyChip;
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
        if (anchor == null) return;
        View parent = (View) anchor.getParent();
        int top = anchor.getTop();
        ScrollView scrollView = null;
        while (parent != null) {
            if (parent instanceof ScrollView) {
                scrollView = (ScrollView) parent;
                break;
            }
            top += parent.getTop();
            if (parent.getParent() instanceof View) {
                parent = (View) parent.getParent();
            } else {
                break;
            }
        }
        if (scrollView != null) {
            final ScrollView finalScroll = scrollView;
            final int finalTop = top;
            finalScroll.post(() -> finalScroll.smoothScrollTo(0, finalTop));
        }
    }

    private void selectTab(int tab) {
        activeTab = Math.max(0, Math.min(2, tab));
        styleTab(tabTargetButton, activeTab == 0);
        styleTab(tabLiveButton, activeTab == 1);
        styleTab(tabDiagnosticsButton, activeTab == 2);
        setTabVisible(targetScroll, activeTab == 0);
        setTabVisible(liveScroll, activeTab == 1);
        setTabVisible(diagnosticsScroll, activeTab == 2);
        ScrollView activeScroll = (activeTab == 0) ? targetScroll : (activeTab == 1 ? liveScroll : diagnosticsScroll);
        if (activeScroll != null) {
            activeScroll.post(() -> activeScroll.smoothScrollTo(0, 0));
        }
        if (activeTab == 1) {
            analyticsRenderedAt = 0;
            renderResults();
        }
        if (activeTab == 2) {
            logRenderedAt = 0;
            refreshLogView();
        }
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
                        "Run budget is the requested execution budget after CIDR/range expansion; raise it when you intentionally want full subnets or very large provider corpora. Batch controls how many targets run per wave. Threads controls parallel sockets. Timeout ms controls how long each connect/TLS/HTTP attempt can wait.\n\n" +
                        "Filtering and sorting\n" +
                        "Results owns all browsing controls: Working only, TLS/HTTP only, HTTP only, Known CDN only, TLS 1.3 only, provider filter, SNI filter, CDN text filter, certificate filter, max latency, visible row budget, and min score. Sort by Score to surface the strongest candidates.\n\n" +
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
        rebuildManagedSourcesBg(
            checked(defaultSniEnabled),
            checked(communitySourceEnabled), intValue(communitySampleInput, 0),
            checked(akamaiSourceEnabled), intValue(akamaiSampleInput, 0),
            checked(cloudfrontSourceEnabled), intValue(cloudfrontSampleInput, 0),
            checked(fastlySourceEnabled), intValue(fastlySampleInput, 0),
            checked(cloudflareSourceEnabled), intValue(cloudflareSampleInput, 0),
            checked(otherCdnSourceEnabled), intValue(otherCdnSampleInput, 0)
        );
        if (sourceSummaryView != null) {
            sourceSummaryView.setText(getSummaryText(
                checked(defaultSniEnabled),
                checked(communitySourceEnabled),
                checked(akamaiSourceEnabled),
                checked(cloudfrontSourceEnabled),
                checked(fastlySourceEnabled),
                checked(cloudflareSourceEnabled),
                checked(otherCdnSourceEnabled)
            ));
        }
    }

    private void rebuildManagedSourcesBg(
            boolean defaultSni,
            boolean community, int communityCount,
            boolean akamai, int akamaiCount,
            boolean cloudfront, int cloudfrontCount,
            boolean fastly, int fastlyCount,
            boolean cloudflare, int cloudflareCount,
            boolean otherCdn, int otherCdnCount) {
        synchronized (selectedSourceTargets) {
            selectedSourceTargets.clear();
        }
        synchronized (selectedSourceSnis) {
            selectedSourceSnis.clear();
        }
        if (defaultSni) {
            synchronized (selectedSourceSnis) {
                selectedSourceSnis.addAll(loadAsset("default_snis.txt"));
                selectedSourceSnis.addAll(loadAsset("scan-corpora/maybepsiphon-sni-hosts.txt"));
            }
        }
        if (community) {
            synchronized (selectedSourceTargets) {
                selectedSourceTargets.addAll(sampleSource(loadAsset("default_targets.txt"), communityCount));
                selectedSourceTargets.addAll(sampleSource(loadAsset("default_edges_extra.txt"), communityCount));
                selectedSourceTargets.addAll(sampleSource(communityEdgeCorpus("scan-corpora/maybepsiphon-edge-ips.txt", "scan-corpora/community-edge-cidrs-24.txt"), communityCount));
            }
        }
        if (akamai) {
            synchronized (selectedSourceTargets) {
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/akamai-AS20940.json"), akamaiCount));
                selectedSourceTargets.addAll(sampleSource(loadAsset("scan-corpora/akamai-hosts-184x.txt"), akamaiCount));
            }
            synchronized (selectedSourceSnis) {
                addRelevantSni(selectedSourceSnis, "akamai");
            }
        }
        if (cloudfront) {
            synchronized (selectedSourceTargets) {
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/aws-cloudfront-ranges.txt"), cloudfrontCount));
            }
            synchronized (selectedSourceSnis) {
                addRelevantSni(selectedSourceSnis, "aws");
                addRelevantSni(selectedSourceSnis, "cloudfront");
            }
        }
        if (fastly) {
            synchronized (selectedSourceTargets) {
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/fastly-AS54113.json"), fastlyCount));
            }
            synchronized (selectedSourceSnis) {
                addRelevantSni(selectedSourceSnis, "fastly");
            }
        }
        if (cloudflare) {
            synchronized (selectedSourceTargets) {
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/cloudflare-ranges.txt"), cloudflareCount));
            }
            synchronized (selectedSourceSnis) {
                addRelevantSni(selectedSourceSnis, "cloudflare");
            }
        }
        if (otherCdn) {
            synchronized (selectedSourceTargets) {
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/github-pages-ranges.txt"), otherCdnCount));
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/azure-frontdoor-ranges.txt"), otherCdnCount));
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/google-cdn-ranges.txt"), otherCdnCount));
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/bunny-ranges.txt"), otherCdnCount));
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/stackpath-edgio-ranges.txt"), otherCdnCount));
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens("scan-corpora/other-cloud-ranges.txt"), otherCdnCount));
            }
            synchronized (selectedSourceSnis) {
                addRelevantSni(selectedSourceSnis, "cloudflare");
                addRelevantSni(selectedSourceSnis, "mapbox");
            }
        }
    }

    private String getSummaryText(boolean defaultSni, boolean community, boolean akamai, boolean cloudfront, boolean fastly, boolean cloudflare, boolean otherCdn) {
        ArrayList<String> enabled = new ArrayList<>();
        if (community) enabled.add("Community");
        if (akamai) enabled.add("Akamai");
        if (cloudfront) enabled.add("CloudFront");
        if (fastly) enabled.add("Fastly");
        if (cloudflare) enabled.add("Cloudflare");
        if (otherCdn) enabled.add("Other providers");

        int estimated;
        int targetSize;
        synchronized (selectedSourceTargets) {
            estimated = estimateExpandedTargetCount(new ArrayList<>(selectedSourceTargets), Integer.MAX_VALUE);
            targetSize = selectedSourceTargets.size();
        }

        int sniSize;
        synchronized (selectedSourceSnis) {
            sniSize = selectedSourceSnis.size();
        }

        return "Managed sources\n" +
                (enabled.isEmpty() ? "No target corpus enabled" : joinComma(enabled)) + "\n" +
                targetSize + " target tokens -> about " + estimated + " expanded endpoints before Run budget.\n" +
                sniSize + " default/provider SNI routes " + (defaultSni ? "enabled" : "disabled") + "; custom typed targets and SNIs are sampled separately.";
    }

    private String getHealthText(
            String rawTargetsText, String rawSnisText,
            List<String> targetTokens, int estimatedTargets, int targetCap,
            int threads, int batch, boolean isMultiSni) {
        int customTargets = lines(rawTargetsText).size();
        
        int managedTargets;
        synchronized (selectedSourceTargets) {
            managedTargets = selectedSourceTargets.size();
        }

        int customRoutes = lines(rawSnisText).size();
        int cappedTargets = Math.min(estimatedTargets, targetCap);

        String composition = targetTokens.isEmpty()
                ? "No target sources selected yet."
                : managedTargets + " managed target tokens + " + customTargets + " custom target tokens, deduped before expansion.";

        int sniSize;
        synchronized (selectedSourceSnis) {
            sniSize = selectedSourceSnis.size();
        }

        String routeScope = sniPairingEnabled()
                ? sniSize + " managed SNI routes + " + customRoutes + " custom SNI routes; route mode is " + (isMultiSni ? "all SNI hosts." : "primary SNI first.")
                : "IP-only scope; SNI/host names are extracted from TLS and HTTP results, not paired as scan input.";

        return "Source health\n" +
                composition + "\n" +
                "Expanded estimate: " + estimatedTargets + " endpoints; Run budget requests " + cappedTargets + " for this run.\n" +
                routeScope + "\n" +
                sourceLoadPostureBg(estimatedTargets, targetCap, threads, batch);
    }

    private String sourceLoadPostureBg(int estimatedTargets, int targetCap, int threads, int batch) {
        int capped = Math.min(estimatedTargets, targetCap);
        if (capped == 0) return "Posture: idle; add or select IP targets before scanning.";
        if (capped > 12000 || threads > 64 || batch > 8000) return "Posture: wide/high-load; better for plugged-in devices or the sidecar.";
        if (capped < 500 || threads <= 16) return "Posture: light route validation; good for tuning SNI choices and unstable mobile links.";
        return "Posture: balanced phone scan; suitable for normal interactive use.";
    }

    private String getPlanText(
            String rawTargetsText, String rawSnisText,
            List<String> targetTokens, int targetCap, int batch, int threads, int timeout,
            String pathText, String tlsMode, List<Integer> profiles, boolean allSni, String portsText) {
        int estimatedTargets = estimateExpandedTargetCount(targetTokens, Integer.MAX_VALUE);
        int cappedTargets = Math.min(estimatedTargets, targetCap);
        int sniCount = sniPairingEnabled() ? Math.max(1, combinedSniTokens(rawSnisText).size()) : 1;
        List<Integer> ports = parsePorts(portsText);
        int units = estimateAttemptUnits(cappedTargets, sniCount, ports.size(), profiles, allSni);
        
        int managedTargets;
        synchronized (selectedSourceTargets) {
            managedTargets = selectedSourceTargets.size();
        }

        String path = pathText.trim();
        if (path.isEmpty()) path = "/";
        if (!path.startsWith("/")) path = "/" + path;

        return "Scan plan\n" +
                managedTargets + " managed source tokens + " + lines(rawTargetsText).size() + " custom tokens -> " + estimatedTargets + " estimated endpoints -> " + cappedTargets + " requested by Run budget " + targetCap + "\n" +
                (sniPairingEnabled() ? sniCount + " SNI host" + (sniCount == 1 ? "" : "s") + " kept separate for TLS/Host routing; " : "IP-only TLS/HTTP probing; ") + "ports " + ports + "\n" +
                "Runtime: batch " + batch + ", threads " + threads + ", timeout " + timeout + "ms, HTTP path " + path + "\n" +
                "TLS ClientHello mode: " + tlsMode + "\n" +
                workflowLabels(profiles) + " -> " + (profiles.isEmpty() ? "select at least one manual step." : "about " + units + " probe units. Preset overlaps are deduped, not overridden.");
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

    private void applyRouteProviderDefaults() {
        int provider = routeProviderSpinner == null ? 0 : routeProviderSpinner.getSelectedItemPosition();
        if (provider == 1) {
            routeProtocolSpinner.setSelection(indexOf(routeProtocolSpinner, "wireguard"));
            routeAuthSpinner.setSelection(indexOf(routeAuthSpinner, "wsnet_session_ref"));
            routeDnsSpinner.setSelection(indexOf(routeDnsSpinner, "ctrld"));
            routeDownstreamSpinner.setSelection(indexOf(routeDownstreamSpinner, "vpn_interface"));
            routeStrategySpinner.setSelection(indexOf(routeStrategySpinner, "provider_default"));
            routeProviderChainSpinner.setSelection(indexOf(routeProviderChainSpinner, "none"));
            routeBeastModeCheck.setChecked(false);
            routeShareLanCheck.setChecked(false);
            if (routeProfileRefInput.getText().toString().trim().isEmpty()) routeProfileRefInput.setText("ref:windscribe-profile");
            if (routeCredentialRefInput.getText().toString().trim().isEmpty()) routeCredentialRefInput.setText("ref:windscribe-session");
        } else if (provider == 2) {
            routeProtocolSpinner.setSelection(indexOf(routeProtocolSpinner, "tunnel_core_supervised"));
            routeAuthSpinner.setSelection(indexOf(routeAuthSpinner, "config_ref"));
            routeDnsSpinner.setSelection(indexOf(routeDnsSpinner, "remote_dns"));
            routeDownstreamSpinner.setSelection(indexOf(routeDownstreamSpinner, "local_proxy_gateway"));
            routeStrategySpinner.setSelection(indexOf(routeStrategySpinner, "conduit_first"));
            routeConduitModeSpinner.setSelection(indexOf(routeConduitModeSpinner, "auto"));
            routeProviderChainSpinner.setSelection(indexOf(routeProviderChainSpinner, "none"));
            routeBeastModeCheck.setChecked(true);
            if (routeConfigRefInput.getText().toString().trim().isEmpty()) routeConfigRefInput.setText("ref:psiphon-config");
        } else if (provider == 3) {
            routeProtocolSpinner.setSelection(indexOf(routeProtocolSpinner, "local_proxy"));
            routeAuthSpinner.setSelection(indexOf(routeAuthSpinner, "credential_ref"));
            routeDownstreamSpinner.setSelection(indexOf(routeDownstreamSpinner, "local_proxy_gateway"));
            routeStrategySpinner.setSelection(indexOf(routeStrategySpinner, "direct"));
            routeProviderChainSpinner.setSelection(indexOf(routeProviderChainSpinner, "none"));
            routeBeastModeCheck.setChecked(false);
            routeShareLanCheck.setChecked(false);
            if (routeEndpointInput.getText().toString().trim().isEmpty()) routeEndpointInput.setText("socks5://127.0.0.1:1080");
        }
        updateRouteReadinessPreview();
    }

    private int indexOf(Spinner spinner, String value) {
        if (spinner == null || spinner.getAdapter() == null) return 0;
        for (int i = 0; i < spinner.getAdapter().getCount(); i++) {
            if (value.equals(String.valueOf(spinner.getAdapter().getItem(i)))) return i;
        }
        return 0;
    }

    private EdgeRouteProfile buildSelectedRouteProfile() {
        int provider = routeProviderSpinner == null ? 0 : routeProviderSpinner.getSelectedItemPosition();
        if (provider == 0) return EdgeRouteProfile.direct();
        String plugin = provider == 1 ? "windscribe" : provider == 2 ? "psiphon" : "generic-proxy";
        EdgeRouteProfile profile = new EdgeRouteProfile();
        profile.enabled = true;
        profile.providerId = plugin.equals("generic-proxy") ? "" : plugin;
        profile.pluginId = plugin;
        profile.routeId = "route-" + plugin + "-android";
        profile.protocolMode = spinnerText(routeProtocolSpinner);
        profile.authMode = spinnerText(routeAuthSpinner);
        profile.dnsPolicy = spinnerText(routeDnsSpinner);
        profile.splitTunnel = spinnerText(routeSplitSpinner);
        profile.upstreamMode = spinnerText(routeUpstreamSpinner);
        profile.downstreamMode = spinnerText(routeDownstreamSpinner);
        profile.gatewayMode = spinnerText(routeGatewaySpinner);
        profile.routeStrategy = spinnerText(routeStrategySpinner);
        profile.conduitMode = spinnerText(routeConduitModeSpinner);
        profile.providerChain = spinnerText(routeProviderChainSpinner);
        profile.profileRef = safeRouteField(routeProfileRefInput);
        profile.credentialRef = safeRouteField(routeCredentialRefInput);
        profile.configRef = safeRouteField(routeConfigRefInput);
        profile.endpoint = safeRouteField(routeEndpointInput);
        profile.packageName = safeRouteField(routePackageInput);
        profile.frontingIpRef = safeRouteField(routeFrontingIpRefInput);
        profile.frontingSni = safeRouteField(routeFrontingSniInput);
        profile.chainUpstreamRef = safeRouteField(routeChainUpstreamRefInput);
        profile.gatewayAuthRef = safeRouteField(routeGatewayAuthRefInput);
        profile.lanSocksPort = safeRouteField(routeLanSocksPortInput);
        profile.lanHttpPort = safeRouteField(routeLanHttpPortInput);
        profile.shareProxyOnLan = routeShareLanCheck != null && routeShareLanCheck.isChecked();
        profile.beastMode = routeBeastModeCheck != null && routeBeastModeCheck.isChecked();
        profile.routeBinding = routeBindingFor(profile);
        return profile;
    }

    private String routeBindingFor(EdgeRouteProfile profile) {
        if (!profile.enabled) return "direct";
        if ("psiphon".equals(profile.pluginId)) {
            return ("external_vpn_apk".equals(profile.protocolMode) || "external_vpn".equals(profile.protocolMode))
                    ? "external_vpn_observation" : "tunnel_core_local_proxy";
        }
        if ("windscribe".equals(profile.pluginId)) {
            if ("local_proxy".equals(profile.protocolMode)) return "local_proxy_gateway";
            if (Arrays.asList("wireguard", "openvpn_udp", "openvpn_tcp", "tcp", "stealth", "wstunnel", "ikev2").contains(profile.protocolMode)) {
                return "profile_backed_vpn_or_proxy";
            }
            return "external_vpn_observation";
        }
        return "generic_local_proxy";
    }

    private void updateRouteReadinessPreview() {
        if (routeReadinessView == null) return;
        EdgeRouteProfile profile = buildSelectedRouteProfile();
        String text;
        if (!profile.enabled) {
            text = "Route readiness: direct scan path\nNo provider route metadata will be attached.";
        } else if ("windscribe".equals(profile.pluginId)) {
            WindscribeAuthSession session = WindscribeAuthSession.fromRefs(profile.credentialRef, profile.profileRef);
            WindscribeRouteObserver.RouteObservation observation = WindscribeRouteObserver.observe(this, profile, session);
            text = observation.summary();
        } else if ("psiphon".equals(profile.pluginId)) {
            PsiphonTunnelSupervisor.Readiness readiness = PsiphonTunnelSupervisor.preview(profile);
            text = readiness.summary();
        } else {
            text = "Route readiness: generic local proxy\nendpoint=" + redactedValue(profile.endpoint) +
                    "\nstate=" + (profile.endpoint.isEmpty() ? "needs endpoint" : "ready for local proxy probe");
        }
        routeReadinessView.setText(text);
    }

    private String spinnerText(Spinner spinner) {
        return spinner == null || spinner.getSelectedItem() == null ? "" : String.valueOf(spinner.getSelectedItem()).trim();
    }

    private String safeRouteField(EditText field) {
        if (field == null) return "";
        return field.getText().toString().replace('\r', ' ').replace('\n', ' ').trim();
    }

    private static String redactedValue(String value) {
        if (value == null || value.isEmpty()) return "--";
        if (value.startsWith("ref:")) return value;
        return value.replaceAll("(?i)(token|secret|password|auth)[^@/\\s]*", "[redacted]");
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
        resultStore.clear();
        pendingResults.clear();
        resultDrainQueued.set(false);
        ui.removeCallbacks(progressRunnable);
        progressQueued.set(false);
        resultSequence.set(0);
        long generation = scanGeneration.incrementAndGet();
        checkedTargets.set(0);
        scanStartedAt = System.currentTimeMillis();
        resultSummaryContainer.removeAllViews();
        heatmapContainer.removeAllViews();
        pagerContainer.removeAllViews();
        resultSummaryText = null;
        pagerPanel = null;
        pagerText = null;
        pagerPrevButton = null;
        pagerNextButton = null;
        heatmapRenderedAt = 0;
        resultsAdapter.setResults(Collections.emptyList());
        synchronized (logLines) {
            logLines.clear();
            stableLogBuilder.setLength(0);
        }
        logView.setText("");
        lastRenderedLogText = "";
        logRenderedAt = 0;
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
        int batch = Math.max(1, intValue(batchInput, 2000));
        int threads = Math.max(1, intValue(threadsInput, 32));
        int timeout = Math.max(1, intValue(timeoutInput, 3000));
        EdgeRouteProfile routeProfile = buildSelectedRouteProfile();
        updateRouteReadinessPreview();

        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        status.setText("Running");
        selectTab(1);
        appendLog("Scan started: expanded_targets=" + targets.size() + ", sni_hosts=" + snis.size() +
                ", probe_units=" + totalTargets + ", ports=" + ports + ", batch=" + batch +
                ", threads=" + threads + ", workflow=" + workflowSpinner.getSelectedItem() +
                ", steps=" + workflowLabels(workflowProfiles) + ", route=" + routeProfile.summary());
        ScanForegroundService.start(this, "running",
                "0 / " + totalTargets + " probe units", 0);
        appendResourceWarnings(threads, batch, timeout, targets.size());
        ExecutorService scanExecutor = Executors.newFixedThreadPool(threads);
        executor = scanExecutor;
        List<String> finalSnis = snis;
        new Thread(() -> runWorkflow(generation, scanExecutor, targets, finalSnis, ports, batch, timeout, workflowProfiles,
                allSniPreference, httpPath, tlsMode, suppressNoisyLogs, routeProfile), "scan-orchestrator").start();
    }

    private void requestStop() {
        stop.set(true);
        status.setText("Stopping");
        stopButton.setEnabled(false);
        appendLog("Stop requested. Current sockets will finish or time out.");
        ScanForegroundService.update(this, "cancelling",
                checkedTargets.get() + " / " + totalTargets + " probe units", progressPercent());
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

    private void runWorkflow(long generation, ExecutorService scanExecutor, List<String> targets, List<String> snis, List<Integer> ports, int batchSize,
                             int timeout, List<Integer> profiles, boolean allSniPreference,
                             String httpPath, int tlsMode, boolean suppressNoisyLogs, EdgeRouteProfile routeProfile) {
        for (int i = 0; i < profiles.size() && !stop.get() && generation == scanGeneration.get(); i++) {
            int profile = profiles.get(i);
            boolean allSni = sniPairingEnabled() && (allSniPreference || profile >= 2);
            appendLog("Workflow step " + (i + 1) + "/" + profiles.size() + ": " + profileName(profile) +
                    (sniPairingEnabled() ? (allSni ? " with multi-SNI" : " with primary SNI") : " with IP-only probing"));
            runBatches(generation, scanExecutor, targets, snis, ports, batchSize, timeout, profile, allSni, httpPath, tlsMode, suppressNoisyLogs, routeProfile);
        }
        scanExecutor.shutdownNow();
        ui.post(() -> {
            if (generation != scanGeneration.get()) return;
            if (executor == scanExecutor) executor = null;
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
            status.setText(stop.get() ? "Stopped" : "Ready");
            appendLog((stop.get() ? "Stopped" : "Complete") + " in " + elapsed());
            if (!stop.get()) checkedTargets.set(totalTargets);
            if (!stop.get()) saveLocalObservationHistory();
            renderProgressDirect();
            ScanForegroundService.stop(this, stop.get() ? "Scan stopped" : "Scan completed");
            renderResults();
        });
    }

    private void runBatches(long generation, ExecutorService scanExecutor, List<String> targets, List<String> snis, List<Integer> ports, int batchSize,
                            int timeout, int profile, boolean allSni, String httpPath, int tlsMode, boolean suppressNoisyLogs, EdgeRouteProfile routeProfile) {
        int batches = (targets.size() + batchSize - 1) / batchSize;
        for (int start = 0, batchNo = 1; start < targets.size() && !stop.get() && generation == scanGeneration.get(); start += batchSize, batchNo++) {
            List<String> batch = targets.subList(start, Math.min(targets.size(), start + batchSize));
            appendLog(profileName(profile) + " batch " + batchNo + "/" + batches + ": " + batch.size() + " targets");
            CountDownLatch latch = new CountDownLatch(batch.size());
            for (String target : batch) {
                if (stop.get() || generation != scanGeneration.get()) {
                    latch.countDown();
                    continue;
                }
                try {
                    scanExecutor.submit(() -> {
                            try { scanTarget(generation, target, snis, ports, timeout, profile, allSni, httpPath, tlsMode, suppressNoisyLogs, routeProfile); }
                        finally {
                            updateProgress();
                            latch.countDown();
                        }
                    });
                } catch (RejectedExecutionException ignored) {
                    latch.countDown();
                }
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

    private void scanTarget(long generation, String target, List<String> snis, List<Integer> ports, int timeout, int profile,
                            boolean allSni, String httpPath, int tlsMode, boolean suppressNoisyLogs, EdgeRouteProfile routeProfile) {
        if (stop.get() || generation != scanGeneration.get()) return;
        List<String> ips = resolve(target);
        if (ips.isEmpty()) {
            addResult(generation, Result.down(target, "", 0, "", "dns_failed").withRoute(routeProfile), suppressNoisyLogs);
            return;
        }
        for (String ip : ips) {
            if (stop.get() || generation != scanGeneration.get()) return;
            for (int port : ports) {
                if (profile == 0) {
                    Result base = new Result(target, ip, port, "");
                    base.tcp(timeout);
                    addResult(generation, base.withRoute(routeProfile).finish(), suppressNoisyLogs);
                    continue;
                }
                List<String> candidates = sniPairingEnabled()
                        ? (allSni ? snis : Collections.singletonList(isIp(target) ? first(snis) : target))
                        : Collections.singletonList("");
                for (String sni : candidates) {
                    if (stop.get() || generation != scanGeneration.get()) return;
                    String routeSni = sni == null ? "" : sni.trim();
                    Result r = new Result(target, ip, port, routeSni);
                    r.tls(timeout, tlsMode);
                    if (profile >= 2 && r.tlsPass) r.http(timeout, httpPath, tlsMode);
                    addResult(generation, r.withRoute(routeProfile).finish(), suppressNoisyLogs);
                    if (profile == 3 && r.httpPass) break;
                }
            }
        }
    }

    private void addResult(long generation, Result r, boolean suppressNoisyLogs) {
        if (generation != scanGeneration.get()) return;
        r.rowId = resultSequence.incrementAndGet();
        checkedTargets.incrementAndGet();
        ResultEvent event = new ResultEvent(r, suppressNoisyLogs, generation);
        boolean queued = false;
        while (!queued && !stop.get() && generation == scanGeneration.get()) {
            try {
                queued = pendingResults.offer(event, 250, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (!queued) {
                scheduleResultDrain();
            }
        }
        if (queued && generation == scanGeneration.get()) scheduleResultDrain();
    }

    private void updateProgress() {
        if (!progressQueued.compareAndSet(false, true)) return;
        ui.postDelayed(progressRunnable, 120);
    }

    private final Runnable progressRunnable = () -> {
        progressQueued.set(false);
        renderProgressDirect();
    };

    private int progressPercent() {
        int total = Math.max(1, totalTargets);
        int checked = Math.max(0, Math.min(checkedTargets.get(), total));
        return (int) Math.min(100, Math.max(0, Math.round((checked * 100.0) / total)));
    }

    private void renderProgressDirect() {
        progress.setMax(Math.max(1, totalTargets));
        int checked = Math.min(checkedTargets.get(), Math.max(1, totalTargets));
        progress.setProgress(checked);
        Stats s = stats();
        metrics.setText(checked + " / " + totalTargets + " probe units | rows " + s.rows + " | TCP " + s.tcp +
                " | TLS " + s.tls + " | HTTP " + s.http + " | Q " + Math.round(s.bestQuality) +
                " | queued " + pendingResults.size() + " | " + elapsed());
        countersView.setText("Down " + s.down + " | timeout " + s.timeout + " | reset " + s.reset +
                " | cert " + s.cert + " | DNS " + s.dns + " | " + resourceLine());
        if (s.best != null) bestView.setText("Best: " + s.best.summary());
        if (executor != null && !executor.isShutdown()) {
            ScanForegroundService.update(this, "running",
                    checked + " / " + totalTargets + " probe units", progressPercent());
        }
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

    private final Runnable resultDrainRunnable = () -> {
        resultDrainQueued.set(false);
        int drained = 0;
        ResultEvent event;
        while (drained < RESULT_DRAIN_BATCH && (event = pendingResults.poll()) != null) {
            if (event.generation != scanGeneration.get()) {
                drained++;
                continue;
            }
            int resultCount = resultStore.append(event.result);
            Result r = event.result;
            if (!event.suppressNoisyLogs && (r.tlsPass || r.httpPass || resultCount % 200 == 0)) {
                appendLog("Result " + r.address() + " sni=" + dash(r.sni) + " tcp=" + r.tcpPass +
                        " tls=" + r.tlsPass + " http=" + r.httpPass + " q=" + Math.round(r.quality));
            }
            drained++;
        }
        if (drained > 0) {
            updateProgress();
            scheduleRender();
        }
        if (!pendingResults.isEmpty()) {
            scheduleResultDrain();
        }
    };

    private void scheduleResultDrain() {
        if (!resultDrainQueued.compareAndSet(false, true)) return;
        ui.post(resultDrainRunnable);
    }

    private void renderResults() {
        if (resultList == null) return;
        List<Result> snapshot = filteredResults();
        long now = System.currentTimeMillis();
        boolean analyticsDue = activeTab == 1 && now - analyticsRenderedAt >= (batteryFriendlyMode() ? 5000 : 2500);
        if (batteryFriendlyMode() || compactMode()) {
            if (analyticsPanel != null) analyticsPanel.setVisibility(View.GONE);
        } else if (analyticsDue) {
            if (analyticsPanel != null) analyticsPanel.setVisibility(View.VISIBLE);
            updateAnalytics(snapshot);
            analyticsRenderedAt = now;
        }
        renderStableHistoryPanel();

        if (snapshot.isEmpty()) {
            updateResultSummary(snapshot);
            updateHeatmapPanel(snapshot, now);
            updatePagerPanel(0, 0, 0, 1, false);
            bestView.setText("Best result unavailable\n");
            resultsAdapter.setResults(Collections.emptyList());
            return;
        }
        Result bestVisible = bestVisibleResult(snapshot);
        bestView.setText((bestVisible == null ? "Best result unavailable" : "Best: " + bestVisible.summary()) + "\n" + bestSniLine(snapshot));
        
        updateResultSummary(snapshot);
        updateHeatmapPanel(snapshot, now);
        int limit = Math.min(Math.max(1, intValue(resultLimitInput, 1000)), snapshot.size());
        int maxStart = Math.max(0, snapshot.size() - limit);
        resultOffset = Math.min(Math.max(0, resultOffset), maxStart);
        int end = Math.min(snapshot.size(), resultOffset + limit);
        
        List<Result> sliced = new ArrayList<>();
        for (int i = resultOffset; i < end; i++) {
            sliced.add(snapshot.get(i));
        }
        resultsAdapter.setResults(sliced);

        updatePagerPanel(resultOffset, end, snapshot.size(), limit, limit < snapshot.size());
    }

    private void renderResultsFromFirstPage() {
        resultOffset = 0;
        scheduleRender();
    }

    private void updateResultSummary(List<Result> rows) {
        if (resultSummaryContainer == null) return;
        if (rows == null || rows.isEmpty()) {
            resultSummaryContainer.setVisibility(View.GONE);
            return;
        }
        if (resultSummaryText == null) {
            resultSummaryText = panelText("");
            formatMonospace(resultSummaryText, 11);
            resultSummaryContainer.addView(resultSummaryText);
        }
        resultSummaryContainer.setVisibility(View.VISIBLE);
        resultSummaryText.setText(resultSummaryLine(rows));
    }

    private void updateHeatmapPanel(List<Result> rows, long now) {
        if (heatmapContainer == null) return;
        boolean visible = rows != null && !rows.isEmpty() && activeTab == 1 && !batteryFriendlyMode() && !compactMode() && visualizationMode == 1;
        if (!visible) {
            heatmapContainer.setVisibility(View.GONE);
            return;
        }
        long cadence = batteryFriendlyMode() ? 5000 : 2500;
        if (heatmapContainer.getChildCount() > 0 && now - heatmapRenderedAt < cadence) {
            heatmapContainer.setVisibility(View.VISIBLE);
            return;
        }
        heatmapRenderedAt = now;
        heatmapContainer.removeAllViews();
        heatmapContainer.addView(heatmapView(rows));
        heatmapContainer.setVisibility(View.VISIBLE);
    }

    private void updatePagerPanel(int start, int end, int total, int pageSize, boolean visible) {
        if (pagerContainer == null) return;
        if (!visible) {
            pagerContainer.setVisibility(View.GONE);
            return;
        }
        ensurePagerPanel();
        pagerContainer.setVisibility(View.VISIBLE);
        pagerText.setText("Showing cards " + (start + 1) + "-" + end + " of " + total);
        pagerPrevButton.setEnabled(start > 0);
        pagerNextButton.setEnabled(end < total);
        pagerPrevButton.setOnClickListener(v -> {
            resultOffset = Math.max(0, resultOffset - pageSize);
            renderResults();
        });
        pagerNextButton.setOnClickListener(v -> {
            resultOffset = Math.min(Math.max(0, total - pageSize), resultOffset + pageSize);
            renderResults();
        });
    }

    private void ensurePagerPanel() {
        if (pagerPanel != null) return;
        pagerPanel = column();
        pagerPanel.setBackground(glassBg(Color.rgb(8, 20, 29), Color.argb(60, 255, 255, 255)));
        pagerPanel.setPadding(dp(9), dp(6), dp(9), dp(8));
        setOuterMargin(pagerPanel, 0, dp(6), 0, dp(8));
        pagerText = text("", 11, Color.rgb(185, 210, 222), false);
        pagerPanel.addView(pagerText);
        LinearLayout controls = row();
        pagerPrevButton = button("Previous", Color.rgb(24, 45, 58), Color.WHITE);
        pagerNextButton = button("Next", Color.rgb(24, 45, 58), Color.WHITE);
        controls.addView(pagerPrevButton, weight());
        controls.addView(pagerNextButton, weight());
        pagerPanel.addView(controls);
        pagerContainer.addView(pagerPanel);
    }

    private String resultSummaryLine(List<Result> rows) {
        int working = 0;
        long latencySum = 0, best = Long.MAX_VALUE;
        int latencyCount = 0;
        int rawCount;
        rawCount = resultStore.size();
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
        return "Visible results: " + rows.size() + " of " + rawCount +
                " | alive/working " + working +
                " | success " + success + "%" +
                " | best " + (best == Long.MAX_VALUE ? "--" : best + "ms") +
                " | avg " + (latencyCount == 0 ? "--" : Math.round(latencySum / (float) latencyCount) + "ms") +
                " | " + bestSniLine(rows) +
                " | filters " + filterSummary();
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
        hasRows = !resultStore.isEmpty();
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
        int limit = rows.size();
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
        boolean fWorking = filterWorking.isChecked();
        boolean fTlsHttp = filterTlsHttp.isChecked();
        boolean rHttp = requireHttp.isChecked();
        boolean rKnownCdn = requireKnownCdn.isChecked();
        boolean rTls13 = requireTls13.isChecked();
        boolean bPerIp = bestPerIp.isChecked();
        int maxLatency = intValue(maxLatencyInput, 0);
        int minQuality = intValue(minQualityInput, 0);
        String cdnPreset = cdnProviderSpinner == null || cdnProviderSpinner.getSelectedItem() == null ? "Any provider" : cdnProviderSpinner.getSelectedItem().toString();
        String cdn = cdnFilterInput == null ? "" : cdnFilterInput.getText().toString().trim().toLowerCase(Locale.US);
        String cert = certFilterInput == null ? "" : certFilterInput.getText().toString().trim().toLowerCase(Locale.US);
        String sni = sniFilterInput == null ? "" : sniFilterInput.getText().toString().trim().toLowerCase(Locale.US);
        int sort = sortSpinner.getSelectedItemPosition();

        List<Result> snapshot = new ArrayList<>();
        for (Result r : resultStore.snapshot()) {
                if (fWorking && !r.working()) continue;
                if (fTlsHttp && !(r.tlsPass || r.httpPass)) continue;
                if (rHttp && !r.httpPass) continue;
                if (rKnownCdn && "UNKNOWN".equalsIgnoreCase(r.cdn)) continue;
                if (!providerMatches(cdnPreset, r.cdn)) continue;
                if (rTls13 && !r.tlsVersion.contains("1.3")) continue;
                if (maxLatency > 0 && (r.totalLatency() <= 0 || r.totalLatency() > maxLatency)) continue;
                if (minQuality > 0 && r.quality < minQuality) continue;
                if (!cdn.isEmpty() && !r.cdn.toLowerCase(Locale.US).contains(cdn)) continue;
                if (!sni.isEmpty() && !r.sni.toLowerCase(Locale.US).contains(sni)) continue;
                if (!cert.isEmpty() && !r.tlsCert.toLowerCase(Locale.US).contains(cert)) continue;
                snapshot.add(r);
        }
        if (bPerIp) {
            Map<String, Result> best = new LinkedHashMap<>();
            for (Result r : snapshot) {
                String key = r.ip + ":" + r.port;
                Result old = best.get(key);
                if (old == null || r.quality > old.quality) best.put(key, r);
            }
            snapshot = new ArrayList<>(best.values());
        }
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
        formatMonospace(top, compactMode() ? 13 : 15);
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
        formatMonospace(body, 12);
        card.addView(top);
        card.addView(route);
        card.addView(signal);
        card.addView(body);
        if (!compactMode() && !r.tlsVersion.isEmpty()) card.addView(text(r.tlsVersion + " | " + r.tlsCipher + " | ALPN " + dash(r.alpn) + " | TLS " + dash(r.tlsProfile), 11, highContrastMode() ? Color.WHITE : MUTED, false));
        if (!compactMode() && !r.routeProviderId.isEmpty()) card.addView(text("Route " + r.routeProviderId + " | " + r.routeBinding + " | " + r.routeProtocolMode + " | DNS " + r.routeDnsPolicy, 11, Color.rgb(175, 230, 215), false));
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
            List<Result> rows = exportRowsForFile();
            String redactionMode = exportRedactionMode();
            int format = fileExportSpinner == null ? 0 : fileExportSpinner.getSelectedItemPosition();
            String base = "maybeedgescanner_export_" + System.currentTimeMillis();
            String extension = format == 0 ? ".jsonl" : format == 1 ? ".csv" : format == 2 ? ".md" : ".xml";
            File out = new File(getExternalFilesDir(null), base + extension);
            JSONObject meta = buildExportMeta(formatLabelForFileExport(format), redactionMode, rows.size());
            try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8))) {
                if (format == 0) {
                    JSONObject metaLine = new JSONObject(meta.toString());
                    metaLine.put("record_type", "export_meta");
                    w.write(metaLine.toString());
                    w.newLine();
                    for (Result row : rows) {
                        JSONObject item = exportResultJson(row, redactionMode);
                        item.put("record_type", "scan_result");
                        w.write(item.toString());
                        w.newLine();
                    }
                } else if (format == 1) {
                    w.write("# schema_version: " + meta.optInt("schema_version"));
                    w.newLine();
                    w.write("# app_version: " + meta.optString("app_version"));
                    w.newLine();
                    w.write("# scan_session_id: " + meta.optString("scan_session_id"));
                    w.newLine();
                    w.write("# product_mode: " + meta.optString("product_mode"));
                    w.newLine();
                    w.write("# redaction_mode: " + meta.optString("redaction_mode"));
                    w.newLine();
                    w.write("target,ip,port,sni,tcp,tls,http,http_status,latency_ms,alpn,tls_profile,http3_hint,cdn,route_provider,route_dns_policy,quality,reason");
                    w.newLine();
                    for (Result row : rows) {
                        JSONObject item = exportResultJson(row, redactionMode);
                        w.write(csvCell(item.optString("target")) + "," + csvCell(item.optString("ip")) + "," + item.optInt("port") + "," +
                                csvCell(item.optString("sni")) + "," + item.optBoolean("tcpPass") + "," + item.optBoolean("tlsPass") + "," +
                                item.optBoolean("httpPass") + "," + item.optInt("httpStatus") + "," + item.optLong("totalLatencyMs") + "," +
                                csvCell(item.optString("alpn")) + "," + csvCell(item.optString("tlsProfile")) + "," + item.optBoolean("http3Hint") + "," +
                                csvCell(item.optString("cdn")) + "," + csvCell(item.optString("routeProviderId")) + "," +
                                csvCell(item.optString("routeDnsPolicy")) + "," + item.optLong("qualityRounded") + "," + csvCell(item.optString("reason")));
                        w.newLine();
                    }
                } else if (format == 2) {
                    w.write("# MaybeEdgeScanner Report");
                    w.newLine();
                    w.newLine();
                    w.write("- schema_version: " + meta.optInt("schema_version"));
                    w.newLine();
                    w.write("- app_version: " + meta.optString("app_version"));
                    w.newLine();
                    w.write("- scan_session_id: " + meta.optString("scan_session_id"));
                    w.newLine();
                    w.write("- product_mode: " + meta.optString("product_mode"));
                    w.newLine();
                    w.write("- redaction_mode: " + meta.optString("redaction_mode"));
                    w.newLine();
                    w.write("- result_count: " + meta.optInt("result_count"));
                    w.newLine();
                    w.newLine();
                    w.write("| target | ip | sni | tcp/tls/http | cdn | route | ms |");
                    w.newLine();
                    w.write("| --- | --- | --- | --- | --- | --- | --- |");
                    w.newLine();
                    for (Result row : rows) {
                        JSONObject item = exportResultJson(row, redactionMode);
                        String checks = (item.optBoolean("tcpPass") ? "T" : "-") + "/" + (item.optBoolean("tlsPass") ? "L" : "-") + "/" + (item.optBoolean("httpPass") ? "H" : "-");
                        String route = item.optString("routeProviderId");
                        if (route.isEmpty()) route = "--";
                        w.write("| " + safeMd(item.optString("target")) + " | " + safeMd(item.optString("ip")) + " | " + safeMd(item.optString("sni")) + " | " + checks + " | " + safeMd(item.optString("cdn")) + " | " + safeMd(route) + " | " + item.optLong("totalLatencyMs") + " |");
                        w.newLine();
                    }
                } else {
                    w.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                    w.newLine();
                    w.write("<nmaprun scanner=\"MaybeEdgeScanner\" args=\"edge scan export\" product_mode=\"" + xmlEscape(meta.optString("product_mode")) + "\" redaction_mode=\"" + xmlEscape(meta.optString("redaction_mode")) + "\" scan_session_id=\"" + xmlEscape(meta.optString("scan_session_id")) + "\">");
                    w.newLine();
                    for (Result row : rows) {
                        JSONObject item = exportResultJson(row, redactionMode);
                        String ip = item.optString("ip");
                        int port = item.optInt("port");
                        if (ip.isEmpty() || port <= 0) continue;
                        String state = (item.optBoolean("tcpPass") || item.optBoolean("tlsPass") || item.optBoolean("httpPass")) ? "open" : "closed";
                        String addrType = ip.contains(":") ? "ipv6" : "ipv4";
                        w.write("<host><status state=\"up\"/><address addr=\"" + xmlEscape(ip) + "\" addrtype=\"" + addrType + "\"/><ports><port protocol=\"tcp\" portid=\"" + port + "\"><state state=\"" + state + "\"/><service name=\"" + xmlEscape(item.optString("sni")) + "\" product=\"" + xmlEscape(item.optString("cdn")) + "\"/></port></ports></host>");
                        w.newLine();
                    }
                    w.write("</nmaprun>");
                    w.newLine();
                }
            }
            toast("Exported: " + out.getAbsolutePath());
        } catch (Exception e) {
            toast("Export failed: " + e.getMessage());
        }
    }

    private List<Result> exportRowsForFile() {
        return new ArrayList<>(resultStore.snapshot());
    }

    private String exportRedactionMode() {
        return exportPrivacyMode != null && exportPrivacyMode.isChecked() ? "privacy" : "none";
    }

    private String formatLabelForFileExport(int format) {
        if (format == 1) return "csv";
        if (format == 2) return "markdown_report";
        if (format == 3) return "nmap_xml_like";
        return "jsonl";
    }

    private JSONObject buildExportMeta(String format, String redactionMode, int resultCount) throws Exception {
        JSONObject meta = new JSONObject();
        meta.put("schema_version", 1);
        meta.put("app_version", appVersionName());
        meta.put("scan_session_id", resultStore.sessionId());
        meta.put("product_mode", "route_pairing");
        meta.put("format", format);
        meta.put("redaction_mode", redactionMode);
        meta.put("result_count", resultCount);
        meta.put("generated_at_ms", System.currentTimeMillis());
        meta.put("scan_started_at_ms", scanStartedAt);
        return meta;
    }

    private String appVersionName() {
        try {
            return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception e) {
            return "unknown";
        }
    }

    private JSONObject exportResultJson(Result row, String redactionMode) throws Exception {
        JSONObject item = row.json();
        item.put("totalLatencyMs", row.totalLatency());
        item.put("qualityRounded", Math.round(row.quality));
        item.put("redaction_mode", redactionMode);
        if ("privacy".equals(redactionMode)) {
            item.put("ip", redactIp(item.optString("ip")));
            item.put("tlsCert", "[REDACTED]");
            item.put("certFingerprint", "[REDACTED]");
            redactRouteField(item, "routeId");
            redactRouteField(item, "routeProviderId");
            redactRouteField(item, "routeBinding");
            redactRouteField(item, "routeProtocolMode");
            redactRouteField(item, "routeAuthMode");
            redactRouteField(item, "routeDnsPolicy");
            redactRouteField(item, "routeReadiness");
        }
        return item;
    }

    private void redactRouteField(JSONObject item, String key) throws Exception {
        if (item.has(key) && !item.optString(key).isEmpty()) {
            item.put(key, "[REDACTED]");
        }
    }

    private String redactIp(String ip) {
        if (ip == null || ip.isEmpty()) return ip;
        if (ip.contains(".")) {
            String[] parts = ip.split("\\.");
            if (parts.length == 4) return parts[0] + "." + parts[1] + "." + parts[2] + ".x";
        }
        if (ip.contains(":")) {
            int idx = ip.indexOf("::");
            if (idx >= 0) return ip.substring(0, idx + 2) + "xxxx";
            String[] parts = ip.split(":");
            if (parts.length > 2) return parts[0] + ":" + parts[1] + ":xxxx::";
        }
        return "[REDACTED]";
    }

    private static String csvCell(String value) {
        if (value == null) value = "";
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private static String safeMd(String value) {
        if (value == null) return "";
        return value.replace("|", "\\|").replace("\n", " ");
    }

    private static String xmlEscape(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&apos;");
    }

    private void clearResults() {
        stop.set(true);
        ScanForegroundService.stop(this, "Scan cleared");
        resultStore.clear();
        pendingResults.clear();
        resultDrainQueued.set(false);
        ui.removeCallbacks(progressRunnable);
        progressQueued.set(false);
        resultSequence.set(0);
        scanGeneration.incrementAndGet();
        checkedTargets.set(0);
        totalTargets = 0;
        stableHistoryRenderedAt = 0;
        progress.setProgress(0);
        resultSummaryContainer.removeAllViews();
        heatmapContainer.removeAllViews();
        pagerContainer.removeAllViews();
        resultSummaryText = null;
        pagerPanel = null;
        pagerText = null;
        pagerPrevButton = null;
        pagerNextButton = null;
        heatmapRenderedAt = 0;
        resultsAdapter.setResults(Collections.emptyList());
        synchronized (logLines) {
            logLines.clear();
            stableLogBuilder.setLength(0);
        }
        logView.setText("");
        lastRenderedLogText = "";
        logRenderedAt = 0;
        metrics.setText("0 / 0 | TCP 0 | TLS 0 | HTTP 0 | Q 0");
        countersView.setText("Down 0 | timeout 0 | reset 0 | cert 0 | DNS 0 | " + resourceLine());
        bestView.setText("Best result will appear here");
        renderStableHistoryPanel();
    }

    private void saveLocalObservationHistory() {
        try {
            JSONObject root = new JSONObject(getSharedPreferences("maybeedgescanner", MODE_PRIVATE).getString("stable_history_v1", "{}"));
            LinkedHashSet<String> seenThisRun = new LinkedHashSet<>();
            for (Result r : resultStore.snapshot()) if (r.working() && r.ip != null && !r.ip.isEmpty()) seenThisRun.add(r.ip + ":" + r.port);
            for (String key : seenThisRun) root.put(key, root.optInt(key, 0) + 1);
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
        List<Result> snapshot = resultStore.snapshot();
        s.rows = snapshot.size();
        for (Result r : snapshot) {
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
        return s;
    }

    private static class Stats {
        int rows, tcp, tls, http, down, timeout, reset, cert, dns;
        double bestQuality;
        Result best;
    }

    private static class ResultEvent {
        final Result result;
        final boolean suppressNoisyLogs;
        final long generation;

        ResultEvent(Result result, boolean suppressNoisyLogs, long generation) {
            this.result = result;
            this.suppressNoisyLogs = suppressNoisyLogs;
            this.generation = generation;
        }
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
        long rowId;
        boolean tcpPass, tlsPass, httpPass;
        long tcpLatencyMs, tlsLatencyMs, httpLatencyMs;
        int httpStatus;
        String tlsVersion = "", tlsCipher = "", tlsCert = "", certFingerprint = "", alpn = "", tlsProfile = "", altSvc = "", reason = "", cdn = "UNKNOWN";
        String routeId = "", routeProviderId = "", routeBinding = "", routeProtocolMode = "", routeAuthMode = "", routeDnsPolicy = "", routeReadiness = "";
        boolean http3Hint;
        double quality;

        Result(String target, String ip, int port, String sni) {
            this.target = target; this.ip = ip; this.port = port; this.sni = sni == null ? "" : sni;
        }
        static Result down(String target, String ip, int port, String sni, String reason) {
            Result r = new Result(target, ip, port, sni); r.reason = reason; return r.finish();
        }
        Result withRoute(EdgeRouteProfile route) {
            if (route == null || !route.enabled) return this;
            routeId = route.routeId;
            routeProviderId = route.providerId;
            routeBinding = route.routeBinding;
            routeProtocolMode = route.protocolMode;
            routeAuthMode = route.authMode;
            routeDnsPolicy = route.dnsPolicy;
            routeReadiness = "not_checked";
            return this;
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
            int activeMode = resolveTlsMode(tlsMode);
            tlsProfile = tlsProfileName(activeMode);
            String host = probeHost();
            try (Socket raw = new Socket()) {
                long connectStart = System.currentTimeMillis();
                raw.connect(new InetSocketAddress(ip, port), timeout);
                tcpPass = true;
                tcpLatencyMs = System.currentTimeMillis() - connectStart;
                raw.setSoTimeout(timeout);
                try (SSLSocket ssl = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, host, port, true)) {
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
                }
            } catch (Exception e) { reason = classify(e); }
        }
        void http(int timeout, String path, int tlsMode) {
            long t = System.currentTimeMillis();
            int activeMode = resolveTlsMode(tlsMode);
            if (tlsProfile.isEmpty()) tlsProfile = tlsProfileName(activeMode);
            String host = probeHost();
            try (Socket raw = new Socket()) {
                long connectStart = System.currentTimeMillis();
                raw.connect(new InetSocketAddress(ip, port), timeout);
                tcpPass = true;
                if (tcpLatencyMs <= 0) tcpLatencyMs = System.currentTimeMillis() - connectStart;
                raw.setSoTimeout(timeout);
                try (SSLSocket ssl = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, host, port, true)) {
                    ssl.setSoTimeout(timeout);
                    configureTlsSocket(ssl, activeMode, true);
                    ssl.startHandshake();
                    tlsPass = true;
                    alpn = selectedAlpn(ssl);
                    String safePath = path == null || path.trim().isEmpty() ? "/" : path.trim();
                    if (!safePath.startsWith("/")) safePath = "/" + safePath;
                    OutputStream out = ssl.getOutputStream();
                    out.write(("HEAD " + safePath + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nUser-Agent: MaybeEdgeScanner/1.1\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                    InputStream in = ssl.getInputStream();
                    String line = readAsciiLineLimited(in, 4096);
                    httpStatus = parseStatus(line);
                    String header;
                    for (int i = 0; i < 48 && (header = readAsciiLineLimited(in, 4096)) != null && !header.isEmpty(); i++) {
                        String lower = header.toLowerCase(Locale.US);
                        if (lower.startsWith("alt-svc:")) {
                            altSvc = header.substring(header.indexOf(':') + 1).trim();
                            http3Hint = altSvc.toLowerCase(Locale.US).contains("h3");
                        }
                    }
                    httpPass = httpStatus > 0 && httpStatus < 500;
                    httpLatencyMs = System.currentTimeMillis() - t;
                }
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
        String summary() { return address() + " " + sni + " " + cdn + routeSummarySuffix() + " q=" + Math.round(quality) + " " + totalLatency() + "ms"; }
        String routeSummarySuffix() { return routeProviderId == null || routeProviderId.isEmpty() ? "" : " route=" + routeProviderId + "/" + routeProtocolMode; }
        JSONObject json() throws Exception {
            JSONObject o = new JSONObject();
            o.put("target", target); o.put("ip", ip); o.put("port", port); o.put("sni", sni);
            o.put("tcpPass", tcpPass); o.put("tlsPass", tlsPass); o.put("httpPass", httpPass);
            o.put("tcpLatencyMs", tcpLatencyMs); o.put("tlsLatencyMs", tlsLatencyMs); o.put("httpLatencyMs", httpLatencyMs);
            o.put("httpStatus", httpStatus); o.put("tlsVersion", tlsVersion); o.put("tlsCipher", tlsCipher);
            o.put("alpn", alpn); o.put("tlsProfile", tlsProfile); o.put("altSvc", altSvc); o.put("http3Hint", http3Hint);
            o.put("tlsCert", tlsCert); o.put("certFingerprint", certFingerprint); o.put("cdn", cdn);
            o.put("routeId", routeId); o.put("routeProviderId", routeProviderId); o.put("routeBinding", routeBinding);
            o.put("routeProtocolMode", routeProtocolMode); o.put("routeAuthMode", routeAuthMode);
            o.put("routeDnsPolicy", routeDnsPolicy); o.put("routeReadiness", routeReadiness);
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
            int remaining = cap - out.size();
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

    private static String readAsciiLineLimited(InputStream in, int maxBytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(maxBytes, 512));
        for (int i = 0; i < maxBytes; i++) {
            int ch = in.read();
            if (ch == -1) return out.size() == 0 ? null : out.toString(StandardCharsets.US_ASCII.name());
            if (ch == '\n') break;
            if (ch != '\r') out.write(ch);
        }
        return out.toString(StandardCharsets.US_ASCII.name());
    }
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
            refreshLogView();
        });
    }
    private void refreshLogView() {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            refreshLogViewDirect();
        } else {
            ui.post(this::refreshLogViewDirect);
        }
    }
    private void refreshLogViewDirect() {
        if (logView == null) return;
        if (activeTab != 2) return;
        long now = System.currentTimeMillis();
        if (now - logRenderedAt < 250) return;
        String filter = "";
        if (logFilterInput != null) {
            filter = logFilterInput.getText().toString().trim().toLowerCase(Locale.US);
        }
        String nextText;
        if (filter.isEmpty()) {
            nextText = stableLogBuilder.toString().trim();
        } else {
            StringBuilder sb = new StringBuilder();
            synchronized (logLines) {
                for (String x : logLines) {
                    if (x.toLowerCase(Locale.US).contains(filter)) {
                        sb.append(x).append('\n');
                    }
                }
            }
            nextText = sb.toString().trim();
        }
        if (!nextText.equals(lastRenderedLogText)) {
            logView.setText(nextText);
            lastRenderedLogText = nextText;
        }
        logRenderedAt = now;
    }
    private void runNetworkDiagnostics() {
        if (diagnosticOutputView == null || runDiagnosticsButton == null) return;
        runDiagnosticsButton.setEnabled(false);
        diagnosticOutputView.setText("Running diagnostic suite...\n");
        appendLog("Network diagnostics: starting...");

        new Thread(() -> {
            StringBuilder sb = new StringBuilder();
            ArrayList<String> externalServices = new ArrayList<>();
            boolean offlineMode = diagnosticsOfflineMode != null && diagnosticsOfflineMode.isChecked();
            boolean includePublicIp = diagnosticsIncludePublicIp != null && diagnosticsIncludePublicIp.isChecked() && !offlineMode;
            sb.append("=== NETWORK DIAGNOSTIC REPORT ===\n");
            sb.append("Timestamp: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date())).append("\n\n");
            sb.append("[0] Diagnostic mode:\n");
            sb.append(" - Offline mode: ").append(offlineMode ? "ON" : "OFF").append('\n');
            sb.append(" - Public IP probe: ").append(includePublicIp ? "ON" : "OFF").append('\n');
            sb.append('\n');

            // 1. VPN / Proxy Check
            sb.append("[1] Checking proxy & VPN posture:\n");
            try {
                ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
                if (cm != null) {
                    Network network = cm.getActiveNetwork();
                    if (network != null) {
                        NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                        if (caps != null) {
                            boolean isVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                            sb.append(" - VPN active: ").append(isVpn ? "YES (Traffic routed via VPN tunnel)" : "NO").append("\n");
                        }
                    }
                    ProxyInfo proxy = cm.getDefaultProxy();
                    if (proxy != null && proxy.getHost() != null) {
                        sb.append(" - System proxy: ").append(proxy.getHost()).append(":").append(proxy.getPort()).append("\n");
                    } else {
                        sb.append(" - System proxy: none detected\n");
                    }
                }
            } catch (Exception e) {
                sb.append(" - Error querying connection managers: ").append(e.getMessage()).append("\n");
            }
            sb.append("\n");

            if (offlineMode) {
                sb.append("[2] DNS/TCP/HTTPS probes:\n");
                sb.append(" - Skipped in offline diagnostics mode\n\n");
            } else {
                // 2. DNS latency test
                sb.append("[2] Testing DNS resolution latency:\n");
                String[] dnsHosts = {"one.one.one.one", "dns.google", "aparat.com"};
                for (String host : dnsHosts) {
                    long start = System.currentTimeMillis();
                    try {
                        InetAddress[] addrs = InetAddress.getAllByName(host);
                        long elapsed = System.currentTimeMillis() - start;
                        sb.append(" - Resolved ").append(host).append(" in ").append(elapsed).append("ms -> [");
                        for (int i = 0; i < addrs.length; i++) {
                            sb.append(addrs[i].getHostAddress());
                            if (i < addrs.length - 1) sb.append(", ");
                        }
                        sb.append("]\n");
                    } catch (Exception e) {
                        sb.append(" - Resolution failed for ").append(host).append(": ").append(e.toString()).append("\n");
                    }
                }
                sb.append("\n");

                // 3. Raw TCP Latency
                sb.append("[3] Testing raw TCP connection latency (Port 443):\n");
                String[][] tcpHosts = {
                    {"Cloudflare", "1.1.1.1"},
                    {"Google DNS", "8.8.8.8"},
                    {"Akamai DNS", "184.26.160.25"},
                };
                for (String[] pair : tcpHosts) {
                    String name = pair[0];
                    String ip = pair[1];
                    long start = System.currentTimeMillis();
                    try (Socket s = new Socket()) {
                        s.connect(new InetSocketAddress(ip, 443), 2000);
                        long elapsed = System.currentTimeMillis() - start;
                        sb.append(" - Connected to ").append(name).append(" (").append(ip).append(") in ").append(elapsed).append("ms\n");
                    } catch (Exception e) {
                        sb.append(" - Connection failed to ").append(name).append(" (").append(ip).append("): ").append(e.getMessage()).append("\n");
                    }
                }
                sb.append("\n");

                // 4. HTTPS Protocol & Secure Negotiation Handshake
                sb.append("[4] Testing secure HTTPS negotiation handshake:\n");
                String[] httpsTargets = {"https://1.1.1.1", "https://8.8.8.8", "https://www.google.com"};
                for (String target : httpsTargets) {
                    long start = System.currentTimeMillis();
                    HttpURLConnection conn = null;
                    try {
                        conn = (HttpURLConnection) new URL(target).openConnection();
                        conn.setConnectTimeout(2500);
                        conn.setReadTimeout(2500);
                        conn.setRequestMethod("GET");
                        int code = conn.getResponseCode();
                        long elapsed = System.currentTimeMillis() - start;
                        sb.append(" - GET ").append(target).append(" status ").append(code).append(" in ").append(elapsed).append("ms\n");
                        externalServices.add(target);
                    } catch (Exception e) {
                        sb.append(" - HTTPS negotiation failed for ").append(target).append(": ").append(e.toString()).append("\n");
                    } finally {
                        if (conn != null) conn.disconnect();
                    }
                }
                sb.append("\n");
                if (includePublicIp) {
                    sb.append("[5] Public IP probe:\n");
                    String publicIpURL = "https://api.ipify.org?format=json";
                    try {
                        JSONObject publicIp = fetchJson(publicIpURL, 2500);
                        sb.append(" - api.ipify.org response: ").append(publicIp.optString("ip", "unknown")).append('\n');
                        externalServices.add(publicIpURL);
                    } catch (Exception e) {
                        sb.append(" - Public IP probe failed: ").append(e.getMessage()).append('\n');
                    }
                    sb.append('\n');
                }
            }

            sb.append("[6] Local sidecar state:\n");
            try {
                JSONObject heartbeat = fetchJson("http://127.0.0.1:10808/api/heartbeat", 1200);
                sb.append(" - heartbeat version=").append(heartbeat.optInt("version"))
                        .append(" state=").append(heartbeat.optString("state", "unknown"))
                        .append(" uptime_ms=").append(heartbeat.optLong("uptime_ms")).append('\n');
                String licenseId = heartbeat.optString("license_id", "");
                if (!licenseId.isEmpty()) {
                    sb.append(" - sidecar license=").append(licenseId).append('\n');
                }
                String sourceOffer = heartbeat.optString("source_offer_url", "");
                if (!sourceOffer.isEmpty()) {
                    sb.append(" - source offer=").append(sourceOffer).append('\n');
                }
            } catch (Exception e) {
                sb.append(" - heartbeat unavailable: ").append(e.getMessage()).append('\n');
            }
            try {
                JSONObject corpus = fetchJson("http://127.0.0.1:10808/api/provider-corpus", 1200);
                sb.append(" - provider corpus id=").append(corpus.optString("corpus_id", "unknown"))
                        .append(" stale=").append(corpus.optBoolean("stale", false))
                        .append(" stale_after=").append(corpus.optString("stale_after", "unknown")).append('\n');
            } catch (Exception e) {
                sb.append(" - provider corpus status unavailable: ").append(e.getMessage()).append('\n');
            }
            sb.append('\n');

            // 7. System stats
            sb.append("[7] Local routing environments:\n");
            sb.append(" - Device: ").append(Build.MANUFACTURER).append(" ").append(Build.MODEL).append("\n");
            sb.append(" - Android version: ").append(Build.VERSION.RELEASE).append(" (API ").append(Build.VERSION.SDK_INT).append(")\n");
            Runtime rt = Runtime.getRuntime();
            long freeHeap = rt.freeMemory() / (1024 * 1024);
            long totalHeap = rt.totalMemory() / (1024 * 1024);
            sb.append(" - JVM Heap memory: total ").append(totalHeap).append("MB, free ").append(freeHeap).append("MB\n");
            sb.append('\n');

            sb.append("[8] External services contacted:\n");
            if (externalServices.isEmpty()) {
                sb.append(" - none\n");
            } else {
                LinkedHashSet<String> unique = new LinkedHashSet<>(externalServices);
                for (String service : unique) sb.append(" - ").append(service).append('\n');
            }

            String report = sb.toString();
            appendLog("Network diagnostics: completed.");
            ui.post(() -> {
                if (diagnosticOutputView != null) {
                    diagnosticOutputView.setText(report);
                }
                if (runDiagnosticsButton != null) {
                    runDiagnosticsButton.setEnabled(true);
                }
            });
        }, "network-diagnostic-thread").start();
    }

    private JSONObject fetchJson(String endpoint, int timeoutMs) throws Exception {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(endpoint).openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            int statusCode = conn.getResponseCode();
            InputStream stream = statusCode >= 200 && statusCode < 300 ? conn.getInputStream() : conn.getErrorStream();
            if (stream == null) throw new IOException("HTTP " + statusCode);
            String text;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) sb.append(line);
                text = sb.toString();
            }
            if (statusCode < 200 || statusCode >= 300) throw new IOException("HTTP " + statusCode + ": " + text);
            return new JSONObject(text);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }
    private void rebuildStableLogBuilder() { stableLogBuilder.setLength(0); for (String x : logLines) stableLogBuilder.append(x).append('\n'); }
    private int intValue(EditText e, int defaultValue) { try { String s = e.getText().toString().trim(); return s.isEmpty() ? defaultValue : Integer.parseInt(s); } catch (Exception ex) { return defaultValue; } }
    private static int clampInt(int value, int min, int max) { return Math.max(min, Math.min(max, value)); }
    private LinearLayout column() { LinearLayout l = new LinearLayout(this); l.setOrientation(LinearLayout.VERTICAL); return l; }
    private LinearLayout row() { LinearLayout l = new LinearLayout(this); l.setOrientation(LinearLayout.HORIZONTAL); l.setGravity(Gravity.CENTER); return l; }
    @SuppressLint("WrongConstant")
    private TextView text(String s, int sp, int color, boolean bold) { TextView v = new TextView(this); v.setText(s); v.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp); v.setTextColor(color); if (bold) v.setTypeface(Typeface.DEFAULT_BOLD); v.setPadding(0, dp(4), 0, dp(4)); v.setLetterSpacing(0.02f); v.setBreakStrategy(Layout.BREAK_STRATEGY_HIGH_QUALITY); return v; }
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
        final LinearLayout group = column();
        setOuterMargin(group, 0, dp(8), 0, dp(8));

        final LinearLayout header = row();
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setBackground(glassBg(Color.rgb(16, 38, 52), Color.argb(125, 255, 255, 255)));
        header.setPadding(dp(12), dp(10), dp(12), dp(10));
        header.setClickable(true);
        header.setFocusable(true);

        final TextView titleText = text(title, 12, Color.WHITE, true);
        titleText.setTypeface(Typeface.DEFAULT_BOLD);
        
        final TextView arrowText = text("▼", 12, MUTED, false);
        arrowText.setGravity(Gravity.CENTER);
        if (open) {
            arrowText.setRotation(180f);
        } else {
            arrowText.setRotation(0f);
        }

        header.addView(titleText, weight());
        header.addView(arrowText);

        body.setVisibility(open ? View.VISIBLE : View.GONE);
        header.setContentDescription(title + (open ? " expanded" : " collapsed"));

        header.setOnTouchListener((v, e) -> {
            if (e.getAction() == android.view.MotionEvent.ACTION_DOWN) {
                v.performHapticFeedback(android.view.HapticFeedbackConstants.KEYBOARD_TAP);
                v.animate().scaleX(0.98f).scaleY(0.98f).setDuration(70).start();
            } else if (e.getAction() == android.view.MotionEvent.ACTION_UP || e.getAction() == android.view.MotionEvent.ACTION_CANCEL) {
                v.animate().scaleX(1f).scaleY(1f).setDuration(130).setInterpolator(new DecelerateInterpolator()).start();
            }
            return false;
        });

        header.setOnClickListener(v -> {
            boolean show = body.getVisibility() != View.VISIBLE;
            if (group.getParent() instanceof ViewGroup) {
                TransitionManager.beginDelayedTransition((ViewGroup) group.getParent());
            }
            body.setVisibility(show ? View.VISIBLE : View.GONE);
            header.setContentDescription(title + (show ? " expanded" : " collapsed"));
            arrowText.animate().cancel();
            arrowText.animate().rotation(show ? 180f : 0f).setDuration(200).start();
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
        formatMonospace(shizukuOutputView, 11);
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
        if (basebandManager == null) {
            basebandManager = new PrivilegedTelephonyBasebandManager();
            basebandManager.initializePrivilegeContext(this, new PrivilegedTelephonyBasebandManager.TelephonyLifecycleCallback() {
                @Override
                public void onServiceConnectionStateChanged(boolean isConnectedActive) {
                    ui.post(() -> {
                        if (isConnectedActive) {
                            setShizukuOutput("Privileged Binder proxy online. Type-safe binder transactions active.");
                        }
                    });
                }
                @Override
                public void onOperationComplete(boolean success, String response) {
                    ui.post(() -> {
                        setShizukuOutput(response);
                        toast(success ? "Radio mode verified" : "Radio write not verified");
                    });
                }

                @Override
                public void onCapabilityReportUpdated(PrivilegedTelephonyBasebandManager.PrivilegedCapabilityReport report) {
                    ui.post(() -> {
                        updateShizukuHealthTile();
                        if (shizukuStatusView != null) refreshShizukuState();
                    });
                }
            });
        }
    }

    private void removeShizukuListener() {
        try {
            Shizuku.removeRequestPermissionResultListener(shizukuPermissionListener);
            Shizuku.removeBinderReceivedListener(shizukuBinderReceivedListener);
            Shizuku.removeBinderDeadListener(shizukuBinderDeadListener);
        } catch (Throwable ignored) {
        }
        if (basebandManager != null) {
            basebandManager.terminatePrivilegeContext();
            basebandManager = null;
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
        if (basebandManager != null) {
            sb.append("\n\nCapability report:\n").append(basebandManager.capabilityReport().toDisplayText());
        }
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
                + shizukuSetupPathLine()
                + (basebandManager == null ? "" : "\n\n" + basebandManager.capabilityReport().toDisplayText());
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
        android.os.AsyncTask.THREAD_POOL_EXECUTOR.execute(() -> {
            long operationId = shizukuActionSequence.incrementAndGet();
            StringBuilder output = new StringBuilder("Action: ").append(label).append('\n');
            output.append("operation_id=").append(operationId).append('\n');
            boolean allWritesStarted = true;
            boolean allVerified = true;
            try {
                output.append("Write value: ").append(value).append("\n\n");
                
                // Bundle setting writes into a single shell command script to minimize process forks
                StringBuilder script = new StringBuilder();
                for (String key : keys) {
                    script.append("/system/bin/settings put global ").append(key).append(" ").append(value).append(" ; ");
                }
                
                CommandResult put = runShizukuProcessCapture(new String[]{"/system/bin/sh", "-c", script.toString()}, 8);
                output.append("Batch settings put finished\n");
                if (!put.stdout.trim().isEmpty()) output.append(put.stdout.trim()).append('\n');
                if (!put.stderr.trim().isEmpty()) output.append("stderr: ").append(put.stderr.trim()).append('\n');
                if (put.exitCode != 0) allWritesStarted = false;
                
                // Symmetrically invoke type-safe binder mutation if basebandManager is active
                int valInt = Integer.parseInt(value);
                for (String key : keys) {
                    int slotId = 0;
                    if (key.endsWith("1")) slotId = 1;
                    else if (key.endsWith("2")) slotId = 2;
                    if (basebandManager != null) {
                        basebandManager.invokeBasebandRadioMutation(slotId, valInt);
                    }
                }

                output.append("\nradio-preferred-network-modes verification:\n");
                StringBuilder readScript = new StringBuilder();
                for (String key : keys) {
                    readScript.append("echo -n ").append(key).append("= ; /system/bin/settings get global ").append(key).append(" ; ");
                }
                CommandResult get = runShizukuProcessCapture(new String[]{"/system/bin/sh", "-c", readScript.toString()}, 8);
                output.append("readback_initial:\n").append(get.stdout.trim()).append('\n');
                if (!get.stderr.trim().isEmpty()) output.append("stderr: ").append(get.stderr.trim()).append('\n');
                try { Thread.sleep(1500L); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                CommandResult settled = runShizukuProcessCapture(new String[]{"/system/bin/sh", "-c", readScript.toString()}, 8);
                output.append("readback_after_settle_1500ms:\n").append(settled.stdout.trim()).append('\n');
                if (!settled.stderr.trim().isEmpty()) output.append("settled_stderr: ").append(settled.stderr.trim()).append('\n');
                
                // Verify all keys
                for (String key : keys) {
                    if (!get.stdout.contains(key + "=" + value) || !settled.stdout.contains(key + "=" + value)) {
                        allVerified = false;
                    }
                }
                output.append("classification=").append(allWritesStarted && allVerified ? "verified" : "readback_mismatch_or_rejected").append('\n');
            } catch (Throwable e) {
                allWritesStarted = false;
                allVerified = false;
                output.append("\nclassification=ipc_or_shell_fault\nFailed: ").append(e.getClass().getSimpleName()).append(": ").append(safeMessage(e));
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
        });
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
            Process process = null;
            Thread stdoutThread = null;
            Thread stderrThread = null;
            try {
                process = startShizukuShellProcess(command);
                StringBuilder stdout = new StringBuilder();
                StringBuilder stderr = new StringBuilder();
                stdoutThread = collectProcessStream(process.getInputStream(), stdout);
                stderrThread = collectProcessStream(process.getErrorStream(), stderr);
                boolean finished = waitForProcess(process, 9);
                if (!finished) {
                    terminateProcess(process);
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
            } finally {
                if (process != null) {
                    try { process.getInputStream().close(); } catch (Throwable ignored) {}
                    try { process.getErrorStream().close(); } catch (Throwable ignored) {}
                    try { process.getOutputStream().close(); } catch (Throwable ignored) {}
                    process.destroy();
                }
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
        if (!buildBridgeProbeCommand().equals(command) && !buildReadModesCommand().equals(command)) {
            throw new SecurityException("Command execution rejected: Unsafe shell command input.");
        }
        return startShizukuProcess(new String[]{"/system/bin/sh", "-c", command});
    }

    private Process startShizukuProcess(String[] command) throws Exception {
        try {
            java.lang.reflect.Method method = Shizuku.class.getDeclaredMethod("newProcess", String[].class, String[].class, String.class);
            method.setAccessible(true);
            return (Process) method.invoke(null, (Object) command, null, null);
        } catch (Exception e) {
            throw new RuntimeException("Shizuku process invocation failed via reflection", e);
        }
    }

    private CommandResult runShizukuProcessCapture(String[] command, int timeoutSeconds) throws Exception {
        Process process = null;
        Thread stdoutThread = null;
        Thread stderrThread = null;
        StringBuilder stdout = new StringBuilder();
        StringBuilder stderr = new StringBuilder();
        try {
            process = startShizukuProcess(command);
            stdoutThread = collectProcessStream(process.getInputStream(), stdout);
            stderrThread = collectProcessStream(process.getErrorStream(), stderr);
            boolean finished = waitForProcess(process, timeoutSeconds);
            if (!finished) {
                terminateProcess(process);
                joinQuietly(stdoutThread);
                joinQuietly(stderrThread);
                return new CommandResult(-2, bufferedText(stdout), bufferedText(stderr));
            }
            int exitCode = process.exitValue();
            joinQuietly(stdoutThread);
            joinQuietly(stderrThread);
            return new CommandResult(exitCode, bufferedText(stdout), bufferedText(stderr));
        } finally {
            if (process != null) {
                try { process.getInputStream().close(); } catch (Throwable ignored) {}
                try { process.getErrorStream().close(); } catch (Throwable ignored) {}
                try { process.getOutputStream().close(); } catch (Throwable ignored) {}
                process.destroy();
            }
        }
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
        if (thread == null) return;
        try {
            thread.join(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private boolean waitForProcess(Process process, int timeoutSeconds) throws InterruptedException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        }
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(timeoutSeconds);
        while (System.currentTimeMillis() < deadline) {
            try {
                process.exitValue();
                return true;
            } catch (IllegalThreadStateException ignored) {
                Thread.sleep(50);
            }
        }
        return false;
    }

    private void terminateProcess(Process process) {
        if (process == null) return;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            process.destroyForcibly();
        } else {
            process.destroy();
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
    private void formatMonospace(TextView v, int sp) {
        if (v == null) return;
        v.setTypeface(Typeface.MONOSPACE);
        v.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        if (Build.VERSION.SDK_INT >= 21) {
            v.setLetterSpacing(0.08f);
        }
        if (Build.VERSION.SDK_INT >= 28) {
            v.setLineHeight(dp(sp + 6));
        }
    }
    private GradientDrawable glassBg(int fill, int stroke) {
        int fillAlpha = highContrastMode() ? 245 : 215;
        int shineAlpha = highContrastMode() ? 40 : 120;
        GradientDrawable g = new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{Color.argb(fillAlpha, Color.red(fill), Color.green(fill), Color.blue(fill)), Color.argb(shineAlpha, 255, 255, 255)});
        g.setCornerRadius(dp(compactMode() ? 7 : 10));
        g.setStroke(highContrastMode() ? dp(2) : 1, stroke);
        return g;
    }
    private void setOuterMargin(View v, int l, int t, int r, int b) { LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2); lp.setMargins(l, t, r, b); v.setLayoutParams(lp); }

    private class ResultsAdapter extends RecyclerView.Adapter<ResultsAdapter.ViewHolder> {
        private final List<Result> mItems = new ArrayList<>();
        private boolean mIsEmptyState = false;

        ResultsAdapter() {
            setHasStableIds(true);
        }

        public void setResults(List<Result> items) {
            final ArrayList<Result> oldItems = new ArrayList<>(mItems);
            final boolean oldEmptyState = mIsEmptyState;
            final ArrayList<Result> newItems = new ArrayList<>(items);
            final boolean newEmptyState = newItems.isEmpty();
            DiffUtil.DiffResult diff = DiffUtil.calculateDiff(new DiffUtil.Callback() {
                @Override public int getOldListSize() { return oldEmptyState ? 1 : oldItems.size(); }
                @Override public int getNewListSize() { return newEmptyState ? 1 : newItems.size(); }
                @Override public boolean areItemsTheSame(int oldPosition, int newPosition) {
                    if (oldEmptyState || newEmptyState) return oldEmptyState == newEmptyState;
                    return oldItems.get(oldPosition).rowId == newItems.get(newPosition).rowId;
                }
                @Override public boolean areContentsTheSame(int oldPosition, int newPosition) {
                    if (oldEmptyState || newEmptyState) return oldEmptyState == newEmptyState;
                    return resultContentKey(oldItems.get(oldPosition)).equals(resultContentKey(newItems.get(newPosition)));
                }
            });
            mItems.clear();
            mIsEmptyState = newEmptyState;
            if (!newEmptyState) mItems.addAll(newItems);
            diff.dispatchUpdatesTo(this);
        }

        @Override
        public long getItemId(int position) {
            return mIsEmptyState ? RecyclerView.NO_ID : mItems.get(position).rowId;
        }

        @Override
        public int getItemViewType(int position) {
            return mIsEmptyState ? 0 : 1;
        }

        @Override
        public ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            if (viewType == 0) {
                FrameLayout container = new FrameLayout(parent.getContext());
                container.setLayoutParams(new RecyclerView.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT));
                return new ViewHolder(container);
            }
            return new ResultViewHolder(createResultRowView(parent));
        }

        @Override
        public void onBindViewHolder(ViewHolder holder, int position) {
            if (mIsEmptyState) {
                FrameLayout container = (FrameLayout) holder.itemView;
                if (container.getChildCount() == 0) {
                    container.addView(emptyResultsView());
                }
            } else {
                ((ResultViewHolder) holder).bind(mItems.get(position));
            }
        }

        @Override
        public int getItemCount() {
            return mIsEmptyState ? 1 : mItems.size();
        }

        class ViewHolder extends RecyclerView.ViewHolder {
            ViewHolder(View itemView) {
                super(itemView);
            }
        }

        class ResultViewHolder extends ViewHolder {
            final LinearLayout card;
            final TextView top;
            final TextView route;
            final TextView tcpChip;
            final TextView tlsChip;
            final TextView httpChip;
            final TextView cdnChip;
            final TextView body;
            final TextView tlsLine;
            final TextView http3Line;
            final TextView certLine;
            final TextView reasonLine;

            ResultViewHolder(View itemView) {
                super(itemView);
                card = (LinearLayout) itemView;
                top = (TextView) card.getChildAt(0);
                route = (TextView) card.getChildAt(1);
                LinearLayout signal = (LinearLayout) card.getChildAt(2);
                tcpChip = (TextView) signal.getChildAt(0);
                tlsChip = (TextView) signal.getChildAt(1);
                httpChip = (TextView) signal.getChildAt(2);
                cdnChip = (TextView) signal.getChildAt(3);
                body = (TextView) card.getChildAt(3);
                tlsLine = (TextView) card.getChildAt(4);
                http3Line = (TextView) card.getChildAt(5);
                certLine = (TextView) card.getChildAt(6);
                reasonLine = (TextView) card.getChildAt(7);
            }

            void bind(Result r) {
                card.setPadding(dp(compactMode() ? 8 : 10), dp(compactMode() ? 5 : 8), dp(compactMode() ? 8 : 10), dp(compactMode() ? 5 : 8));
                card.setBackground(glassBg(resultFillColor(r), r.working() ? Color.argb(145, 55, 212, 255) : Color.argb(95, 255, 255, 255)));
                top.setText(r.address());
                top.setTextSize(TypedValue.COMPLEX_UNIT_SP, compactMode() ? 13 : 15);
                route.setText("Host hint " + dash(r.sni));
                route.setTextSize(TypedValue.COMPLEX_UNIT_SP, compactMode() ? 11 : 12);
                route.setTextColor(highContrastMode() ? Color.WHITE : Color.rgb(190, 218, 232));
                bindStatusChip(tcpChip, "TCP", r.tcpPass, Color.rgb(54, 166, 255));
                bindStatusChip(tlsChip, "TLS", r.tlsPass, Color.rgb(66, 230, 170));
                bindStatusChip(httpChip, "HTTP", r.httpPass, Color.rgb(255, 204, 100));
                bindStatusChip(cdnChip, r.cdn, !"UNKNOWN".equalsIgnoreCase(r.cdn), BLUE);
                body.setText(latencySparkline(r) + "  " + r.totalLatency() + "ms | HTTP " + r.httpStatus + " | Q " + Math.round(r.quality));
                bindOptionalLine(tlsLine, !compactMode() && !r.tlsVersion.isEmpty(), r.tlsVersion + " | " + r.tlsCipher + " | ALPN " + dash(r.alpn) + " | TLS " + dash(r.tlsProfile), highContrastMode() ? Color.WHITE : MUTED);
                bindOptionalLine(http3Line, !compactMode() && r.http3Hint, "HTTP/3 advertised via Alt-Svc: " + trim(r.altSvc, 120), Color.rgb(150, 232, 255));
                bindOptionalLine(certLine, !compactMode() && !r.tlsCert.isEmpty(), trim(r.tlsCert, 120), highContrastMode() ? Color.WHITE : MUTED);
                bindOptionalLine(reasonLine, !r.reason.isEmpty(), r.reason, Color.rgb(255, 180, 180));
                card.setOnClickListener(v -> copyOne(r));
                card.setContentDescription(r.summary());
            }
        }
    }

    private LinearLayout createResultRowView(ViewGroup parent) {
        LinearLayout card = column();
        card.setPadding(dp(compactMode() ? 8 : 10), dp(compactMode() ? 5 : 8), dp(compactMode() ? 8 : 10), dp(compactMode() ? 5 : 8));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.setMargins(0, dp(compactMode() ? 4 : 7), 0, 0);
        card.setLayoutParams(lp);
        TextView top = text("", compactMode() ? 13 : 15, Color.WHITE, true);
        formatMonospace(top, compactMode() ? 13 : 15);
        TextView route = text("", compactMode() ? 11 : 12, highContrastMode() ? Color.WHITE : Color.rgb(190, 218, 232), false);
        route.setSingleLine(false);
        LinearLayout signal = row();
        signal.setGravity(Gravity.START);
        signal.addView(statusDot("TCP", false, Color.rgb(54, 166, 255)), smallChipLp());
        signal.addView(statusDot("TLS", false, Color.rgb(66, 230, 170)), smallChipLp());
        signal.addView(statusDot("HTTP", false, Color.rgb(255, 204, 100)), smallChipLp());
        signal.addView(statusDot("UNKNOWN", false, BLUE), smallChipLp());
        TextView body = text("", 12, Color.WHITE, false);
        formatMonospace(body, 12);
        card.addView(top);
        card.addView(route);
        card.addView(signal);
        card.addView(body);
        card.addView(text("", 11, MUTED, false));
        card.addView(text("", 11, Color.rgb(150, 232, 255), false));
        card.addView(text("", 11, MUTED, false));
        card.addView(text("", 11, Color.rgb(255, 180, 180), false));
        return card;
    }

    private int resultFillColor(Result r) {
        return r.httpPass ? Color.rgb(9, 48, 38) : r.tlsPass ? Color.rgb(16, 45, 37) :
                r.tcpPass ? Color.rgb(43, 36, 16) : Color.rgb(37, 20, 28);
    }

    private void bindStatusChip(TextView v, String label, boolean on, int color) {
        String safeLabel = label == null || label.trim().isEmpty() ? "UNKNOWN" : label;
        String prefix = on ? "[on] " : "[off] ";
        v.setText(prefix + safeLabel);
        v.setTextSize(TypedValue.COMPLEX_UNIT_SP, compactMode() ? 10 : 11);
        v.setTextColor(on ? Color.WHITE : (highContrastMode() ? Color.rgb(225, 235, 240) : MUTED));
        int offFill = highContrastMode() ? Color.rgb(46, 58, 70) : Color.rgb(27, 38, 49);
        int border = on ? Color.argb(210, 255, 255, 255) : Color.argb(highContrastMode() ? 145 : 70, 255, 255, 255);
        v.setBackground(glassBg(on ? color : offFill, border));
        v.setPadding(dp(compactMode() ? 5 : 7), dp(compactMode() ? 3 : 4), dp(compactMode() ? 5 : 7), dp(compactMode() ? 3 : 4));
        v.setContentDescription(safeLabel + (on ? " passed" : " not passed"));
    }

    private void bindOptionalLine(TextView v, boolean visible, String value, int color) {
        v.setVisibility(visible ? View.VISIBLE : View.GONE);
        if (!visible) {
            v.setText("");
            return;
        }
        v.setText(value == null ? "" : value);
        v.setTextColor(color);
    }

    private String resultContentKey(Result r) {
        return r.target + "|" + r.ip + "|" + r.port + "|" + r.sni + "|" +
                r.tcpPass + "|" + r.tlsPass + "|" + r.httpPass + "|" + r.httpStatus + "|" +
                r.tcpLatencyMs + "|" + r.tlsLatencyMs + "|" + r.httpLatencyMs + "|" +
                r.tlsVersion + "|" + r.tlsCipher + "|" + r.tlsCert + "|" + r.certFingerprint + "|" +
                r.alpn + "|" + r.tlsProfile + "|" + r.altSvc + "|" + r.http3Hint + "|" +
                r.reason + "|" + r.cdn + "|" + Math.round(r.quality * 100.0);
    }

}
