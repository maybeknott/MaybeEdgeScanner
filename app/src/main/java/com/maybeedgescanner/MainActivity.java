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
import android.net.Uri;
import android.graphics.Insets;
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
import android.view.WindowInsets;
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
    private static final int IMPORT_TARGETS_REQUEST_CODE = 4603;
    private static final int IMPORT_SNIS_REQUEST_CODE = 4604;
    private static final String[] RADIO_MODE_KEYS = {
            "preferred_network_mode",
            "preferred_network_mode0",
            "preferred_network_mode1",
            "preferred_network_mode2"
    };
    private static final int PREVIEW_TARGET_LIMIT = 12;
    private static final int PREVIEW_CHIP_LIMIT = 12;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ScanSessionController scanSession = ScanSessionController.get();
    private final Runnable hideFeedbackRunnable = this::hideFeedback;
    private final AtomicBoolean renderQueued = new AtomicBoolean(false);
    private final AtomicBoolean progressQueued = new AtomicBoolean(false);
    private final AtomicBoolean shizukuCommandRunning = new AtomicBoolean(false);
    private PrivilegedTelephonyBasebandManager basebandManager;
    private final AtomicLong previewGeneration = new AtomicLong(0);
    private final AtomicLong shizukuActionSequence = new AtomicLong(0);
    private final ConcurrentHashMap<String, List<String>> assetLineCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LinkedHashSet<String>> assetTokenCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LinkedHashSet<String>> communityCorpusCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> assetReadLocks = new ConcurrentHashMap<>();
    private final LinkedHashSet<String> selectedSourceTargets = new LinkedHashSet<>();
    private final LinkedHashSet<String> selectedSourceSnis = new LinkedHashSet<>();
    private final ArrayDeque<String> logLines = new ArrayDeque<>();
    private final StringBuilder stableLogBuilder = new StringBuilder();
    private final ExecutorService previewExecutor = Executors.newSingleThreadExecutor();
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
    private TextView status, metrics, bestView, countersView, logView, networkBanner, homeDashboardView, feedbackView;
    private TextView shizukuHealthTileView, shizukuStatusView, shizukuNextStepView, shizukuOutputView;
    private TextView sourceSummaryView, sourceHealthView;
    private TextView scanPlanView;
    private TextView targetInputStatsView, sniInputStatsView;
    private EditText targetsInput, snisInput, totalInput, batchInput, threadsInput, timeoutInput;
    private EditText communitySampleInput, akamaiSampleInput, cloudfrontSampleInput, fastlySampleInput, cloudflareSampleInput, otherNetworkSampleInput, customTargetSampleInput, customSniSampleInput;
    private EditText portsInput, pathInput, maxLatencyInput, resultLimitInput, networkFilterInput, certFilterInput, sniFilterInput, minQualityInput;
    private EditText shizukuKeyInput, shizukuValueInput, logFilterInput;
    private TextView diagnosticOutputView;
    private Button runDiagnosticsButton, diagnosticsCopyRedactedButton, diagnosticsCopyFullButton;
    private CheckBox multiSni, filterWorking, filterTlsHttp, bestPerIp, hideNoisyLogs, requireHttp, requireKnownNetwork, requireTls13, batteryFriendlyUi;
    private CheckBox diagnosticsOfflineMode, diagnosticsIncludePublicIp, exportPrivacyMode;
    private CheckBox communitySourceEnabled, akamaiSourceEnabled, cloudfrontSourceEnabled, fastlySourceEnabled, cloudflareSourceEnabled, otherNetworkSourceEnabled, defaultSniEnabled;
    private CheckBox stepTcp, stepTls, stepHttp, stepVerify;
    private Spinner profileSpinner, workflowSpinner, sortSpinner, exportSpinner, fileExportSpinner, tlsModeSpinner, networkProviderSpinner;
    private Spinner routeProviderSpinner, routeProtocolSpinner, routeAuthSpinner, routeDnsSpinner, routeSplitSpinner, routeUpstreamSpinner, routeDownstreamSpinner, routeGatewaySpinner;
    private Spinner routeStrategySpinner, routeConduitModeSpinner, routeProviderChainSpinner;
    private EditText routeProfileRefInput, routeCredentialRefInput, routeConfigRefInput, routeEndpointInput, routePackageInput;
    private EditText routeFrontingIpRefInput, routeFrontingSniInput, routeChainUpstreamRefInput, routeGatewayAuthRefInput, routeLanSocksPortInput, routeLanHttpPortInput;
    private CheckBox routeShareLanCheck, routeBeastModeCheck;
    private TextView routeReadinessView;
    private Button startButton, stopButton, copyButton, copyCsvButton, exportButton, clearButton, helpButton;
    private Button tabTargetButton, tabLiveButton, tabDiagnosticsButton;
    private int activeTab;
    private int visualizationMode;
    private int densityMode;
    private int resultOffset;
    private final ArrayList<Button> visualizationButtons = new ArrayList<>();
    private final ArrayList<Button> densityButtons = new ArrayList<>();

    private void hideFeedback() {
        if (feedbackView != null) feedbackView.setVisibility(View.GONE);
    }

    private final Shizuku.OnRequestPermissionResultListener shizukuPermissionListener = this::onShizukuPermissionResult;
    private final Shizuku.OnBinderReceivedListener shizukuBinderReceivedListener = this::onShizukuBinderReceived;
    private final Shizuku.OnBinderDeadListener shizukuBinderDeadListener = this::onShizukuBinderDead;
    private final BroadcastReceiver scanControlReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            if (intent == null) return;
            String action = intent.getAction();
            if (ACTION_SERVICE_STOP_SCAN.equals(action)) {
                ScanCommandBus.submit(context, ScanCommand.cancelScan("legacy_broadcast",
                        ScanSessionController.get().currentGeneration()));
            } else if (ScanCommandBus.ACTION_SCAN_COMMAND.equals(action)) {
                onScanCommand(readScanCommand(intent));
            } else if (ScanForegroundService.ACTION_STATE_CHANGED.equals(action)) {
                ScanForegroundService.ScanLifecycleSnapshot snapshot = ScanForegroundService.snapshot();
                if (status != null && !"idle".equals(snapshot.state)) {
                    status.setText(displayLifecycleState(snapshot));
                    refreshActionButtons();
                    renderProgressDirect();
                }
            } else if (ScanForegroundService.ACTION_ROUTE_CHANGED.equals(action)) {
                renderRouteSnapshot(ScanForegroundService.routeSnapshot());
            } else if (ScanSessionUiSnapshot.ACTION_SNAPSHOT.equals(action)) {
                applySessionSnapshot();
            } else if (ScanExportBus.ACTION_EXPORT_COMPLETED.equals(action)) {
                onExportCompleted(intent);
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
        scanSession.attachUi(this);
        refreshShizukuState();
        if (ACTION_QUICK_SCAN.equals(getIntent().getAction())) {
            ui.postDelayed(this::handleQuickScanIntent, 450);
        }
    }

    @Override protected void onResume() {
        super.onResume();
        scanSession.attachUi(this);
        applySessionSnapshot();
    }

    @Override protected void onDestroy() {
        scanSession.onActivityDestroy(this, isChangingConfigurations(), isFinishing());
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
        outState.putString("result_session_id", scanSession.results().sessionId());
        outState.putInt("result_count", scanSession.results().size());
        synchronized (logLines) {
            outState.putInt("log_count", logLines.size());
        }
    }

    @Override protected void onRestoreInstanceState(Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);
        if (savedInstanceState == null) return;
        // Full scan rows/logs intentionally stay out of Activity bundles. A later
        // foreground-service session store will provide process-death recovery.
        scheduleProgressUpdate();
        scheduleRender();
    }

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    private void registerScanControlReceiver() {
        IntentFilter filter = new IntentFilter();
        filter.addAction(ACTION_SERVICE_STOP_SCAN);
        filter.addAction(ScanCommandBus.ACTION_SCAN_COMMAND);
        filter.addAction(ScanForegroundService.ACTION_STATE_CHANGED);
        filter.addAction(ScanForegroundService.ACTION_ROUTE_CHANGED);
        filter.addAction(ScanSessionUiSnapshot.ACTION_SNAPSHOT);
        filter.addAction(ScanExportBus.ACTION_EXPORT_COMPLETED);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(scanControlReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(scanControlReceiver, filter);
        }
    }

    private void handleQuickScanIntent() {
        selectTab(0);
        toast("Quick scan preset loaded. Review the IP and SNI plan, then press Start.");
        updateScanPlanPreview();
        ScanForegroundService.enterPlanReview(this, "Quick scan request opened for review");
    }

    private void ensureScanNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return;
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return;
        requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, NOTIFICATION_REQUEST_CODE);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) return;
        try {
            if (requestCode == IMPORT_TARGETS_REQUEST_CODE) {
                appendToInput(targetsInput, readTextFromUri(data.getData(), 2 * 1024 * 1024));
                renderScanPlanPreviews();
                toast("Imported custom IP list");
            } else if (requestCode == IMPORT_SNIS_REQUEST_CODE) {
                appendToInput(snisInput, readTextFromUri(data.getData(), 2 * 1024 * 1024));
                renderScanPlanPreviews();
                toast("Imported custom SNI list");
            }
        } catch (IOException e) {
            toast("Import failed: " + e.getMessage());
        }
    }

    private void buildUi() {
        RelativeLayout screen = new RelativeLayout(this);
        screen.setBackground(new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{Color.rgb(5, 14, 23), Color.rgb(8, 28, 38), Color.rgb(15, 18, 34)}));
        screen.setLayoutParams(new RelativeLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        LinearLayout tabs = row();
        tabs.setId(View.generateViewId());
        tabs.setGravity(Gravity.CENTER);
        tabs.setMinimumHeight(dp(62));
        tabs.setBackground(new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{Color.rgb(8, 18, 29), Color.rgb(5, 12, 20)}));
        tabTargetButton = button("Routes", Color.rgb(21, 45, 62), Color.WHITE);
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
        headerContainer.setPadding(dp(14), dp(6), dp(14), dp(6));
        headerContainer.setBackground(new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{Color.rgb(10, 24, 40), Color.rgb(8, 20, 32)}));

        LinearLayout titleRow = row();
        titleRow.setGravity(Gravity.CENTER_VERTICAL);
        TextView titleText = text("MaybeEdgeScanner", 17, Color.WHITE, true);
        titleRow.addView(titleText, weight());
        status = pill("Ready");
        status.setPadding(dp(10), dp(3), dp(10), dp(3));
        titleRow.addView(status);
        headerContainer.addView(titleRow);

        TextView subtitleText = text("Route pairing workspace", 12, MUTED, false);
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
        targetScroll.setFillViewport(true);
        targetScroll.setClipToPadding(false);
        targetScroll.setOverScrollMode(View.OVER_SCROLL_IF_CONTENT_SCROLLS);
        targetScroll.setOnTouchListener((v, event) -> handleTabSwipe(event));
        targetTab = column();
        targetTab.setPadding(dp(14), dp(10), dp(14), dp(96));
        targetScroll.addView(targetTab);
        contentContainer.addView(targetScroll);

        // Tab 2: Results scroll container
        liveScroll = new ScrollView(this);
        liveScroll.setFillViewport(true);
        liveScroll.setClipToPadding(false);
        liveScroll.setOverScrollMode(View.OVER_SCROLL_IF_CONTENT_SCROLLS);
        liveScroll.setOnTouchListener((v, event) -> handleTabSwipe(event));
        liveTab = column();
        liveTab.setPadding(dp(14), dp(10), dp(14), dp(96));
        liveScroll.addView(liveTab);
        contentContainer.addView(liveScroll);

        // Tab 3: Diagnostics scroll container
        diagnosticsScroll = new ScrollView(this);
        diagnosticsScroll.setFillViewport(true);
        diagnosticsScroll.setClipToPadding(false);
        diagnosticsScroll.setOverScrollMode(View.OVER_SCROLL_IF_CONTENT_SCROLLS);
        diagnosticsScroll.setOnTouchListener((v, event) -> handleTabSwipe(event));
        diagnosticsTab = column();
        diagnosticsTab.setPadding(dp(14), dp(10), dp(14), dp(96));
        diagnosticsScroll.addView(diagnosticsTab);
        contentContainer.addView(diagnosticsScroll);

        // Populate Routes tab
        homeDashboardView = panelText("Network and system\nTransport: checking\nAddresses: hidden by default\nDNS: checking\nPolicy: checking\nCapacity: checking\nDevice: checking\nRuntime: checking");
        targetTab.addView(homeDashboardView);
        targetTab.addView(quietNote("Build IP/SNI route candidates, choose the route provider, then scan. Results show route evidence, best candidates, filters, and exports. Diagnostics keeps logs and radio controls separate."));
        helpButton = button("Reference", Color.rgb(23, 46, 63), Color.WHITE);
        targetTab.addView(helpButton);

        targetAnchor = section("Route Sources");
        targetTab.addView(targetAnchor);
        targetsInput = area("Custom targets: IPv4, IPv6, domains, CIDR, ranges");
        snisInput = area("Custom SNI hosts");
        LinearLayout providerPanel = column();
        providerPanel.addView(quietNote("Choose IP route sources and bounded sample sizes. Counts show estimated expanded IPs, so CIDR ranges read as their real scan size instead of a tiny line/token count."));
        communitySampleInput = input("256", true);
        akamaiSampleInput = input("128", true);
        cloudfrontSampleInput = input("128", true);
        fastlySampleInput = input("128", true);
        cloudflareSampleInput = input("128", true);
        otherNetworkSampleInput = input("128", true);
        communitySourceEnabled = check("Community tested /24s");
        akamaiSourceEnabled = check("Akamai");
        cloudfrontSourceEnabled = check("AWS CloudFront");
        fastlySourceEnabled = check("Fastly");
        cloudflareSourceEnabled = check("Cloudflare");
        otherNetworkSourceEnabled = check("GitHub, Azure, Google, Bunny, Edgio");
        communitySourceEnabled.setChecked(true);
        providerPanel.addView(sourceControl(communitySourceEnabled, communitySampleInput, "Default route IPs, extra edge IPs, and community-tested /24 ranges.", communitySourceTotal()));
        providerPanel.addView(sourceControl(akamaiSourceEnabled, akamaiSampleInput, "Akamai AS20940 plus known Akamai 184.x IP ranges.", akamaiSourceTotal()));
        providerPanel.addView(sourceControl(cloudfrontSourceEnabled, cloudfrontSampleInput, "AWS CloudFront public IP ranges.", cloudfrontSourceTotal()));
        providerPanel.addView(sourceControl(fastlySourceEnabled, fastlySampleInput, "Fastly AS54113 public IP ranges.", fastlySourceTotal()));
        providerPanel.addView(sourceControl(cloudflareSourceEnabled, cloudflareSampleInput, "Cloudflare public IP ranges.", cloudflareSourceTotal()));
        providerPanel.addView(sourceControl(otherNetworkSourceEnabled, otherNetworkSampleInput, "GitHub Pages, Azure Front Door, Google edge ranges, Bunny, Edgio, and other cloud/provider IP ranges.", otherNetworkSourceTotal()));
        targetTab.addView(collapsibleBox("IP route source selection", providerPanel, true));
        targetTab.addView(collapsibleBox("Route: Current network / Windscribe app / Psiphon app", routeQuickPanel(), true));

        // Modernized Unified Configuration Dashboard Container
        LinearLayout metricsDashboardCard = column();
        metricsDashboardCard.setBackground(glassBg(PANEL, Color.argb(120, 255, 255, 255)));
        metricsDashboardCard.setPadding(dp(12), dp(12), dp(12), dp(12));
        setOuterMargin(metricsDashboardCard, 0, dp(6), 0, dp(8));

        sourceSummaryView = text("Route sources: initializing", 12, Color.rgb(196, 223, 235), false);
        sourceHealthView = text("Route source health: checking", 11, Color.rgb(160, 195, 215), false);
        scanPlanView = text("Scan plan: mapping", 11, Color.WHITE, false);
        formatMonospace(scanPlanView, 11);

        metricsDashboardCard.addView(text("Scan plan", 13, BLUE, true));
        metricsDashboardCard.addView(sourceSummaryView);
        metricsDashboardCard.addView(sourceHealthView);
        metricsDashboardCard.addView(scanPlanView);
        targetTab.addView(metricsDashboardCard);
        targetTab.addView(section("Targets"));
        targetTab.addView(quietNote("Add custom IPs, domains, CIDR blocks, or ranges here. Small lists are previewed below; large pastes stay summarized so the screen does not flood with raw input."));
        customTargetSampleInput = input("0", true);
        customTargetSampleInput.setVisibility(View.GONE);
        targetTab.addView(customInputActions(targetsInput, IMPORT_TARGETS_REQUEST_CODE, true));
        targetTab.addView(targetsInput);
        targetInputStatsView = quietNote("Custom IPs: none");
        targetTab.addView(targetInputStatsView);
        targetChipPreview = chipPanel();
        targetTab.addView(targetChipPreview);
        targetTab.addView(section("SNI Hosts"));
        targetTab.addView(quietNote("Custom SNI hosts are explicit TLS/Host routes. Default SNI routes can be enabled or disabled; large SNI pastes are summarized."));
        defaultSniEnabled = check("Default SNI route corpus");
        defaultSniEnabled.setChecked(true);
        targetTab.addView(defaultSniEnabled);
        customSniSampleInput = input("0", true);
        customSniSampleInput.setVisibility(View.GONE);
        targetTab.addView(sniRouteControls());
        targetTab.addView(customInputActions(snisInput, IMPORT_SNIS_REQUEST_CODE, false));
        targetTab.addView(snisInput);
        sniInputStatsView = quietNote("Custom SNI hosts: none");
        targetTab.addView(sniInputStatsView);
        sniChipPreview = chipPanel();
        targetTab.addView(sniChipPreview);

        LinearLayout workflowPanel = column();
        LinearLayout row1 = row();
        profileSpinner = spinner(new String[]{"Quick TCP", "Standard TLS", "Deep HTTP + SNI", "Verify provider edge"});
        workflowSpinner = spinner(new String[]{"Single selected profile", "Auto multi-step ladder", "Manual selected steps"});
        sortSpinner = spinner(new String[]{"Newest", "Latency", "Score", "Network", "SNI", "HTTP first", "TLS first"});
        tlsModeSpinner = spinner(new String[]{"Android default", "Chrome-like ALPN", "Firefox-like ALPN", "HTTP/1.1 only", "Rotate per probe"});
        row1.addView(box("Profile", profileSpinner), weight());
        row1.addView(box("Workflow", workflowSpinner), weight());
        workflowPanel.addView(row1);
        workflowPanel.addView(box("TLS ClientHello", tlsModeSpinner));
        workflowPanel.addView(quietNote("Auto ladder runs TCP, TLS, HTTP/SNI, then provider-route verification. Manual runs only checked stages."));
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
        targetTab.addView(collapsibleBox("Workflow and checks", workflowPanel, true));

        LinearLayout performancePanel = column();
        performancePanel.addView(quietNote("Presets set the total IP limit, batch size, threads, and timeout together so the batch can never exceed the run limit."));
        LinearLayout modeRow = row();
        modeRow.addView(modeButton("Conservative", "25k IPs / 2.5k batch / 16 threads", 25000, 2500, 16, 2500), weight());
        modeRow.addView(modeButton("Balanced", "120k IPs / 10k batch / 48 threads", 120000, 10000, 48, 3000), weight());
        modeRow.addView(modeButton("Aggressive", "500k IPs / 50k batch / 128 threads", 500000, 50000, 128, 5000), weight());
        performancePanel.addView(modeRow);

        LinearLayout row2 = row();
        totalInput = input("0", true);
        batchInput = input("2000", true);
        threadsInput = input("32", true);
        timeoutInput = input("3000", true);
        row2.addView(box("IP scan limit (0 = unlimited)", totalInput), weight());
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
        filterWorking = check("Successful only");
        filterTlsHttp = check("Has TLS or HTTP");
        bestPerIp = check("Best per IP");
        hideNoisyLogs = check("Quiet logs");
        requireHttp = check("Has HTTP");
        requireKnownNetwork = check("Known provider only");
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
            renderScanPlanPreviews();
            toast("Primary SNI route mode");
        });
        Button allSniButton = button("All SNI routes", Color.rgb(72, 55, 34), Color.WHITE);
        allSniButton.setOnClickListener(v -> {
            multiSni.setChecked(true);
            renderScanPlanPreviews();
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
        routePanel.addView(quietNote("Windscribe and Psiphon are installed-app route options. Open the provider app, connect there, then return and observe Android's active route before scanning."));
        routeProviderSpinner = spinner(new String[]{"Current network", "Use Windscribe app", "Use Psiphon app", "Local proxy"});
        routeProtocolSpinner = routeOptionSpinner(RouteOptions.PROTOCOLS);
        routeAuthSpinner = routeOptionSpinner(RouteOptions.AUTH);
        routeDnsSpinner = routeOptionSpinner(RouteOptions.DNS);
        routeSplitSpinner = routeOptionSpinner(RouteOptions.SPLIT);
        routeUpstreamSpinner = routeOptionSpinner(RouteOptions.UPSTREAM);
        routeDownstreamSpinner = routeOptionSpinner(RouteOptions.DOWNSTREAM);
        routeGatewaySpinner = routeOptionSpinner(RouteOptions.GATEWAY);
        routeStrategySpinner = routeOptionSpinner(RouteOptions.STRATEGY);
        routeConduitModeSpinner = routeOptionSpinner(RouteOptions.CONDUIT);
        routeProviderChainSpinner = routeOptionSpinner(RouteOptions.CHAIN);
        routeProfileRefInput = input("", false); routeProfileRefInput.setHint("ref:windscribe-profile or ref:user-connected-vpn");
        routeCredentialRefInput = input("", false); routeCredentialRefInput.setHint("ref:stored-session/auth-token only");
        routeConfigRefInput = input("", false); routeConfigRefInput.setHint("ref:psiphon-config");
        routeEndpointInput = input("", false); routeEndpointInput.setHint("socks5://127.0.0.1:1080 or http://127.0.0.1:8080");
        routePackageInput = input("", false); routePackageInput.setHint("Detected app package, for example com.windscribe.vpn or com.psiphon3");
        routeFrontingIpRefInput = input("", false); routeFrontingIpRefInput.setHint("ref:fronting-ip-list");
        routeFrontingSniInput = input("", false); routeFrontingSniInput.setHint("front.example.com");
        routeChainUpstreamRefInput = input("", false); routeChainUpstreamRefInput.setHint("ref:upstream-route");
        routeGatewayAuthRefInput = input("", false); routeGatewayAuthRefInput.setHint("ref:lan-gateway-auth");
        routeLanSocksPortInput = input("", true); routeLanSocksPortInput.setHint("optional");
        routeLanHttpPortInput = input("", true); routeLanHttpPortInput.setHint("optional");
        routeShareLanCheck = check("Share route gateway on LAN");
        routeBeastModeCheck = check("Beast establishment");
        LinearLayout routeRow1 = row();
        routeRow1.addView(box("Route provider", routeProviderSpinner), weight());
        routeRow1.addView(box("Route mode", routeProtocolSpinner), weight());
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
        routePanel.addView(box("Provider profile ref", routeProfileRefInput));
        routePanel.addView(box("Session reference", routeCredentialRefInput));
        routePanel.addView(box("Psiphon config ref", routeConfigRefInput));
        routePanel.addView(box("Local proxy address", routeEndpointInput));
        routePanel.addView(box("Provider app package", routePackageInput));
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
        LinearLayout providerLaunchActions = row();
        Button openWindscribe = button("Open Windscribe", Color.rgb(19, 68, 74), Color.WHITE);
        Button openPsiphon = button("Open Psiphon", Color.rgb(54, 58, 84), Color.WHITE);
        openWindscribe.setOnClickListener(v -> openFirstInstalledRouteApp("Windscribe", "com.windscribe.vpn"));
        openPsiphon.setOnClickListener(v -> openFirstInstalledRouteApp("Psiphon", "com.psiphon3", "com.psiphon3.subscription"));
        providerLaunchActions.addView(openWindscribe, weight());
        providerLaunchActions.addView(openPsiphon, weight());
        routePanel.addView(providerLaunchActions);
        routeReadinessView = panelText("Route status: current network path");
        formatMonospace(routeReadinessView, 11);
        routePanel.addView(routeReadinessView);
        targetTab.addView(collapsibleBox("Windscribe / Psiphon routes", routePanel, true));

        // Populate Results Tab
        liveAnchor = section("Results");
        liveTab.addView(liveAnchor);
        metrics = text("No scan yet | TCP 0 | TLS 0 | HTTP 0 | Score 0", 13, Color.WHITE, false);
        countersView = text("Failed 0 | timed out 0 | reset 0 | cert 0 | DNS 0 | " + resourceLine(), 12, MUTED, false);
        bestView = panelText(stableBestPlaceholder());
        bestView.setMinLines(3);
        bestView.setGravity(Gravity.CENTER_VERTICAL);
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
        resultFilterToggles2.addView(requireKnownNetwork, weight());
        filterPanel.addView(resultFilterToggles2);
        LinearLayout resultFilterToggles3 = row();
        resultFilterToggles3.addView(requireTls13, weight());
        resultFilterToggles3.addView(bestPerIp, weight());
        filterPanel.addView(resultFilterToggles3);
        networkProviderSpinner = spinner(new String[]{"Any provider", "Known provider", "Akamai", "Cloudflare", "CloudFront/AWS", "Fastly", "GitHub", "Google", "Azure", "Bunny", "Unknown"});
        LinearLayout providerFilterRow = row();
        providerFilterRow.addView(box("Sort cards", sortSpinner), weight());
        providerFilterRow.addView(box("Provider filter", networkProviderSpinner), weight());
        filterPanel.addView(providerFilterRow);
        LinearLayout row5 = row();
        maxLatencyInput = input("", true); maxLatencyInput.setHint("Any");
        resultLimitInput = input("1000", true);
        row5.addView(box("Max latency ms", maxLatencyInput), weight());
        row5.addView(box("Visible rows", resultLimitInput), weight());
        filterPanel.addView(row5);
        LinearLayout row6 = row();
        networkFilterInput = input("", false); networkFilterInput.setHint("Any network");
        certFilterInput = input("", false); certFilterInput.setHint("Certificate contains");
        row6.addView(box("Network contains", networkFilterInput), weight());
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
        Button quickWorkingButton = button("Successful", Color.rgb(23, 78, 67), Color.WHITE);
        quickWorkingButton.setOnClickListener(v -> {
            filterWorking.setChecked(true);
            filterTlsHttp.setChecked(false);
            requireHttp.setChecked(false);
            requireKnownNetwork.setChecked(false);
            renderResultsFromFirstPage();
        });
        Button quickTlsButton = button("TLS or HTTP", Color.rgb(52, 67, 91), Color.WHITE);
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
        filterPanel.addView(compactResultViewControls());
        filterPanel.addView(clearFiltersButton);
        liveTab.addView(collapsibleBox("Filter, sort, and page cards", filterPanel, true));

        LinearLayout exportPanel = column();
        exportPanel.addView(quietNote("Clipboard uses filtered cards. File export streams full session results with schema and redaction details."));
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
        diagnosticsOfflineMode = check("Offline diagnostics mode (no external checks)");
        diagnosticsOfflineMode.setChecked(false);
        diagCard.addView(diagnosticsOfflineMode);
        diagnosticsIncludePublicIp = check("Include public IP lookup (api.ipify.org)");
        diagnosticsIncludePublicIp.setChecked(false);
        diagCard.addView(diagnosticsIncludePublicIp);

        diagnosticOutputView = panelText("Ready to run network diagnostics.");
        formatMonospace(diagnosticOutputView, 11);
        diagnosticOutputView.setTextIsSelectable(true);
        diagCard.addView(diagnosticOutputView);
        LinearLayout diagnosticsCopyRow = row();
        diagnosticsCopyRedactedButton = button("Copy redacted", Color.rgb(34, 51, 66), Color.WHITE);
        diagnosticsCopyFullButton = button("Copy full", Color.rgb(34, 51, 66), Color.WHITE);
        diagnosticsCopyRedactedButton.setOnClickListener(v -> copyDiagnosticsRedacted());
        diagnosticsCopyFullButton.setOnClickListener(v -> copyDiagnosticsFullWithConfirmation());
        diagnosticsCopyRow.addView(diagnosticsCopyRedactedButton, weight());
        diagnosticsCopyRow.addView(diagnosticsCopyFullButton, weight());
        diagCard.addView(diagnosticsCopyRow);
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

        feedbackView = text("", 13, Color.WHITE, false);
        feedbackView.setGravity(Gravity.CENTER_VERTICAL);
        feedbackView.setBackground(glassBg(Color.rgb(34, 42, 50), Color.argb(170, 255, 255, 255)));
        feedbackView.setPadding(dp(14), dp(10), dp(14), dp(10));
        feedbackView.setVisibility(View.GONE);
        RelativeLayout.LayoutParams feedbackParams = new RelativeLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        feedbackParams.addRule(RelativeLayout.ABOVE, tabs.getId());
        feedbackParams.setMargins(dp(24), 0, dp(24), dp(8));
        feedbackView.setLayoutParams(feedbackParams);

        // Setup layouts inside screen Relativelayout
        screen.addView(headerContainer);
        screen.addView(contentContainer);
        screen.addView(feedbackView);
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
        exportButton.setOnClickListener(v -> submitExportCommand());
        View.OnClickListener refresh = v -> renderResultsFromFirstPage();
        filterWorking.setOnClickListener(refresh);
        filterTlsHttp.setOnClickListener(refresh);
        bestPerIp.setOnClickListener(refresh);
        requireHttp.setOnClickListener(refresh);
        requireKnownNetwork.setOnClickListener(refresh);
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
        networkProviderSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
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
        targetsInput.addTextChangedListener(simpleWatcher(this::renderScanPlanPreviews));
        snisInput.addTextChangedListener(simpleWatcher(this::renderScanPlanPreviews));
        totalInput.addTextChangedListener(simpleWatcher(this::renderScanPlanPreviews));
        customTargetSampleInput.addTextChangedListener(simpleWatcher(this::renderScanPlanPreviews));
        customSniSampleInput.addTextChangedListener(simpleWatcher(this::renderScanPlanPreviews));
        defaultSniEnabled.setOnClickListener(v -> renderScanPlanPreviews());
        batchInput.addTextChangedListener(simpleWatcher(this::updateScanPlanPreview));
        threadsInput.addTextChangedListener(simpleWatcher(this::updateScanPlanPreview));
        timeoutInput.addTextChangedListener(simpleWatcher(this::updateScanPlanPreview));
        portsInput.addTextChangedListener(simpleWatcher(this::updateScanPlanPreview));
        pathInput.addTextChangedListener(simpleWatcher(this::updateScanPlanPreview));
        maxLatencyInput.addTextChangedListener(simpleWatcher(this::renderResultsFromFirstPage));
        resultLimitInput.addTextChangedListener(simpleWatcher(this::renderResultsFromFirstPage));
        networkFilterInput.addTextChangedListener(simpleWatcher(this::renderResultsFromFirstPage));
        certFilterInput.addTextChangedListener(simpleWatcher(this::renderResultsFromFirstPage));
        sniFilterInput.addTextChangedListener(simpleWatcher(this::renderResultsFromFirstPage));
        minQualityInput.addTextChangedListener(simpleWatcher(this::renderResultsFromFirstPage));
        logFilterInput.addTextChangedListener(simpleWatcher(this::refreshLogView));
        setContentView(screen);
        applyEdgeInsets(screen, headerContainer, tabs);
        applyAccessibilityLabels();
        updateHomeDashboard();
        updateAnalytics(Collections.emptyList());
        renderScanPlanPreviews();
        refreshActionButtons();
        selectTab(0);
        updateRouteReadinessPreview();
    }

    private void applyEdgeInsets(View screen, LinearLayout headerContainer, LinearLayout tabs) {
        if (screen == null || headerContainer == null || tabs == null) return;
        screen.setOnApplyWindowInsetsListener((v, insets) -> {
            int top, bottom, left, right;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
                top = bars.top;
                bottom = bars.bottom;
                left = bars.left;
                right = bars.right;
            } else {
                top = insets.getSystemWindowInsetTop();
                bottom = insets.getSystemWindowInsetBottom();
                left = insets.getSystemWindowInsetLeft();
                right = insets.getSystemWindowInsetRight();
            }
            headerContainer.setPadding(dp(14) + left, dp(6) + top, dp(14) + right, dp(6));
            int safeBottom = Math.max(bottom, dp(10));
            tabs.setPadding(dp(6) + left, dp(4), dp(6) + right, safeBottom);
            applyScrollContentInsets(left, right, bottom, tabs);
            return insets;
        });
        tabs.post(() -> applyScrollContentInsets(0, 0, 0, tabs));
        screen.requestApplyInsets();
    }

    private void applyScrollContentInsets(int left, int right, int bottom, LinearLayout tabs) {
        int tabHeight = tabs == null || tabs.getHeight() <= 0 ? dp(72) : tabs.getHeight();
        int contentBottom = tabHeight + bottom + dp(28);
        if (targetTab != null) targetTab.setPadding(dp(14) + left, dp(8), dp(14) + right, contentBottom);
        if (liveTab != null) liveTab.setPadding(dp(14) + left, dp(8), dp(14) + right, contentBottom);
        if (diagnosticsTab != null) diagnosticsTab.setPadding(dp(14) + left, dp(8), dp(14) + right, contentBottom);
    }

    private String displayLifecycleState(ScanForegroundService.ScanLifecycleSnapshot snapshot) {
        if (snapshot == null || snapshot.state == null || "idle".equals(snapshot.state)) {
            return hasRunnableTargets() ? "Ready" : "No targets selected";
        }
        String state = snapshot.state.trim().toLowerCase(Locale.US);
        String detail = snapshot.detail == null ? "" : snapshot.detail.trim();
        if (("running".equals(state) || "planning".equals(state) || "cancelling".equals(state))
                && (detail.isEmpty() || detail.startsWith("0 / 0"))) {
            return hasRunnableTargets() ? humanState(state) : "No targets selected";
        }
        if ("waiting_for_confirmation".equals(state)) return "Review scan plan";
        return detail.isEmpty() ? humanState(state) : humanState(state) + ": " + detail;
    }

    private String humanState(String state) {
        if (state == null || state.isEmpty()) return "Ready";
        if ("running".equals(state)) return "Running";
        if ("planning".equals(state)) return "Planning";
        if ("cancelling".equals(state)) return "Stopping";
        if ("waiting_for_confirmation".equals(state)) return "Review scan plan";
        return Character.toUpperCase(state.charAt(0)) + state.substring(1).replace('_', ' ');
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
        homeDashboardView.setText(homeDashboardText("hidden"));
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
            String dns = dnsServers(lp);
            String dnsProvider = dnsProvider(dns);
            String dnsStatus = dnsStatus(caps, lp);
            String proxyVpn = proxyVpnStatus(cm, caps);
            String providerStatus = providerStatus(caps);
            String capacity = capacityStatus(caps);
            return "Network and system\n" +
                    "Transport: " + transport + "\n" +
                    "Addresses: hidden by default\n" +
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

    private int communitySourceTotal() {
        return SourceCatalog.communityTotal(sourceCatalogLoader());
    }

    private int akamaiSourceTotal() {
        return SourceCatalog.akamaiTotal(sourceCatalogLoader());
    }

    private int cloudfrontSourceTotal() {
        return SourceCatalog.cloudfrontTotal(sourceCatalogLoader());
    }

    private int fastlySourceTotal() {
        return SourceCatalog.fastlyTotal(sourceCatalogLoader());
    }

    private int cloudflareSourceTotal() {
        return SourceCatalog.cloudflareTotal(sourceCatalogLoader());
    }

    private int otherNetworkSourceTotal() {
        return SourceCatalog.otherNetworkTotal(sourceCatalogLoader());
    }

    private SourceCatalog.Loader sourceCatalogLoader() {
        return new SourceCatalog.Loader() {
            @Override public List<String> lines(String asset) {
                return loadAsset(asset);
            }

            @Override public Set<String> tokens(String asset) {
                return loadAssetTokens(asset);
            }

            @Override public Set<String> communityEdges(String ipAsset, String cidrAsset) {
                return communityEdgeCorpus(ipAsset, cidrAsset);
            }

            @Override public int estimatedIps(Collection<String> entries) {
                return estimateExpandedTargetCount(entries, Integer.MAX_VALUE);
            }
        };
    }

    private static String countLabel(int count) {
        if (count <= 0) return "unknown";
        return String.format(Locale.US, "%,d", count);
    }

    private static String countLabel(long count) {
        if (count <= 0) return "unknown";
        return String.format(Locale.US, "%,d", count);
    }

    private static int[] samplePresetValues(int availableIps) {
        if (availableIps <= 512) return new int[]{128, 512};
        if (availableIps <= 2048) return new int[]{256, 1024};
        if (availableIps <= 8192) return new int[]{512, 2048};
        return new int[]{1024, 8192};
    }

    private LinearLayout routeQuickPanel() {
        LinearLayout panel = column();
        panel.addView(quietNote("Choose the network path before starting. Current network uses Android's active connection as-is. Windscribe and Psiphon launch the installed app; they are external route providers, not embedded scanner clients."));
        LinearLayout row = row();
        Button direct = button("Current network", Color.rgb(18, 41, 54), Color.WHITE);
        Button windscribe = button("Windscribe app", Color.rgb(19, 68, 74), Color.WHITE);
        Button psiphon = button("Psiphon app", Color.rgb(54, 58, 84), Color.WHITE);
        direct.setOnClickListener(v -> selectRouteProvider(0, false));
        windscribe.setOnClickListener(v -> selectRouteProvider(1, true));
        psiphon.setOnClickListener(v -> selectRouteProvider(2, true));
        row.addView(direct, weight());
        row.addView(windscribe, weight());
        row.addView(psiphon, weight());
        panel.addView(row);
        return panel;
    }

    private void selectRouteProvider(int index, boolean launchApp) {
        if (routeProviderSpinner != null && index >= 0 && index < routeProviderSpinner.getCount()) {
            routeProviderSpinner.setSelection(index);
            applyRouteProviderDefaults();
            updateRouteReadinessPreview();
        }
        if (launchApp && index == 1) {
            openFirstInstalledRouteApp("Windscribe", "com.windscribe.vpn");
        } else if (launchApp && index == 2) {
            openFirstInstalledRouteApp("Psiphon", "com.psiphon3", "com.psiphon3.subscription");
        } else {
            toast("Current network selected");
        }
    }

    private LinearLayout sourceControl(CheckBox enabled, EditText input, String detail, int availableIps) {
        LinearLayout panel = column();
        panel.setBackground(glassBg(Color.rgb(10, 24, 34), Color.argb(60, 255, 255, 255)));
        panel.setPadding(dp(7), dp(2), dp(7), dp(7));
        LinearLayout controls = row();
        input.setVisibility(View.GONE);
        int[] presetValues = samplePresetValues(availableIps);
        int current = intValue(input, 0);
        if (current == 128 || current == 256 || current == 512) input.setText(String.valueOf(presetValues[0]));
        input.addTextChangedListener(simpleWatcher(this::renderScanPlanPreviews));
        enabled.setOnClickListener(v -> renderScanPlanPreviews());
        controls.addView(enabled, new LinearLayout.LayoutParams(0, -2, 1));
        panel.addView(controls);
        LinearLayout presets = row();
        presets.addView(samplePresetButton(input, String.valueOf(presetValues[0]), presetValues[0]), weight());
        presets.addView(samplePresetButton(input, String.valueOf(presetValues[1]), presetValues[1]), weight());
        panel.addView(presets);
        TextView hint = text(detail + "\nEstimated corpus: " + countLabel(availableIps) + " IPs. Use bounded samples for interactive route checks and add one-off custom IPs below.", 10, Color.rgb(155, 184, 198), false);
        panel.addView(hint);
        return panel;
    }

    private Button samplePresetButton(EditText input, String label, int value) {
        Button b = button(label, Color.rgb(18, 41, 54), Color.WHITE);
        b.setOnClickListener(v -> {
            suppressUiRefresh = true;
            input.setText(String.valueOf(value));
            input.setSelection(input.getText().length());
            suppressUiRefresh = false;
            renderScanPlanPreviews();
        });
        b.setContentDescription("Use a sample of " + label + " IPs from this source");
        return b;
    }

    private LinearLayout customInputActions(EditText input, int importRequestCode, boolean includeBest) {
        LinearLayout actions = row();
        Button paste = button("Paste", Color.rgb(24, 45, 58), Color.WHITE);
        Button importFile = button("Import file", Color.rgb(24, 45, 58), Color.WHITE);
        Button clear = button("Clear custom", Color.rgb(52, 35, 42), Color.WHITE);
        paste.setOnClickListener(v -> pasteIntoInput(input));
        importFile.setOnClickListener(v -> importTextFile(importRequestCode));
        clear.setOnClickListener(v -> {
            input.setText("");
            renderScanPlanPreviews();
        });
        actions.addView(paste, weight());
        actions.addView(importFile, weight());
        if (includeBest) {
            Button addBest = button("Add best IP", Color.rgb(18, 55, 50), Color.WHITE);
            addBest.setOnClickListener(v -> addBestResultIp(input));
            actions.addView(addBest, weight());
        }
        actions.addView(clear, weight());
        return actions;
    }

    private LinearLayout sniRouteControls() {
        LinearLayout panel = column();
        panel.setBackground(glassBg(Color.rgb(9, 23, 34), Color.argb(70, 255, 255, 255)));
        panel.setPadding(dp(8), dp(7), dp(8), dp(8));
        setOuterMargin(panel, 0, dp(4), 0, dp(7));

        panel.addView(quietNote("Choose the SNI route set directly. Use the bundled corpus, switch to custom-only, or add common route hosts without editing the text box by hand."));

        LinearLayout corpusRow = row();
        Button enableDefaults = button("Use defaults", Color.rgb(18, 55, 50), Color.WHITE);
        Button customOnly = button("Custom only", Color.rgb(52, 35, 42), Color.WHITE);
        enableDefaults.setOnClickListener(v -> {
            if (defaultSniEnabled != null) defaultSniEnabled.setChecked(true);
            updateScanPlanPreview();
            toast("Default SNI route corpus enabled");
        });
        customOnly.setOnClickListener(v -> {
            if (defaultSniEnabled != null) defaultSniEnabled.setChecked(false);
            updateScanPlanPreview();
            toast("Custom SNI route hosts only");
        });
        corpusRow.addView(enableDefaults, weight());
        corpusRow.addView(customOnly, weight());
        panel.addView(corpusRow);

        LinearLayout presetRow1 = row();
        presetRow1.addView(sniPresetButton("GitHub assets", "github.githubassets.com"), weight());
        presetRow1.addView(sniPresetButton("PyPI", "pypi.org"), weight());
        panel.addView(presetRow1);

        LinearLayout presetRow2 = row();
        presetRow2.addView(sniPresetButton("Mapbox docs", "docs.mapbox.com"), weight());
        presetRow2.addView(sniPresetButton("Akamai edge", "ak.net.akamaized.net"), weight());
        panel.addView(presetRow2);

        return panel;
    }

    private Button sniPresetButton(String label, String host) {
        Button b = button(label, Color.rgb(24, 45, 58), Color.WHITE);
        b.setOnClickListener(v -> {
            appendUniqueLine(snisInput, host);
            updateScanPlanPreview();
            toast(label + " SNI route host added");
        });
        b.setContentDescription("Add SNI route host " + host);
        return b;
    }

    private void pasteIntoInput(EditText input) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        ClipData data = clipboard == null ? null : clipboard.getPrimaryClip();
        if (data == null || data.getItemCount() == 0) {
            toast("Clipboard is empty");
            return;
        }
        CharSequence text = data.getItemAt(0).coerceToText(this);
        if (text == null || text.toString().trim().isEmpty()) {
            toast("Clipboard has no text");
            return;
        }
        appendToInput(input, text.toString());
        renderScanPlanPreviews();
        toast("Pasted custom entries");
    }

    private void importTextFile(int requestCode) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/*");
        startActivityForResult(intent, requestCode);
    }

    private String readTextFromUri(Uri uri, int maxBytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(maxBytes, 8192));
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            if (in == null) throw new IOException("file could not be opened");
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1 && out.size() < maxBytes) {
                out.write(buffer, 0, Math.min(read, maxBytes - out.size()));
            }
        }
        return out.toString(StandardCharsets.UTF_8.name());
    }

    private void appendToInput(EditText input, String addition) {
        if (input == null || addition == null) return;
        String existing = input.getText().toString().trim();
        String incoming = addition.trim();
        if (incoming.isEmpty()) return;
        input.setText(existing.isEmpty() ? incoming : existing + "\n" + incoming);
        input.setSelection(input.getText().length());
    }

    private void addBestResultIp(EditText input) {
        Result best = bestVisibleResult(scanSession.results().snapshot());
        if (best == null || best.ip == null || best.ip.trim().isEmpty()) {
            toast("No best IP yet");
            return;
        }
        appendUniqueLine(input, best.ip.trim());
        renderScanPlanPreviews();
        toast("Best IP added to custom list");
    }

    private void appendUniqueLine(EditText input, String value) {
        if (input == null || value == null || value.trim().isEmpty()) return;
        LinkedHashSet<String> values = new LinkedHashSet<>(lines(input.getText().toString()));
        values.add(value.trim());
        input.setText(String.join("\n", values));
        input.setSelection(input.getText().length());
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
        if (otherNetworkSourceEnabled != null) otherNetworkSourceEnabled.setChecked(false);
        if (defaultSniEnabled != null) defaultSniEnabled.setChecked(false);
        if (sourceSummaryView != null) sourceSummaryView.setText("Managed sources disabled. Custom targets and custom SNI routes remain untouched.");
        renderScanPlanPreviews();
        toast("Managed sources cleared");
    }

    private Button modeButton(String title, String subtitle, int totalLimit, int batch, int threads, int timeout) {
        Button b = button(title + "\n" + subtitle, Color.rgb(16, 38, 52), Color.WHITE);
        b.setOnClickListener(v -> {
            totalInput.setText(String.valueOf(Math.max(totalLimit, batch)));
            threadsInput.setText(String.valueOf(threads));
            batchInput.setText(String.valueOf(batch));
            timeoutInput.setText(String.valueOf(timeout));
            if (title.toLowerCase(Locale.US).contains("conservative")) {
                batteryFriendlyUi.setChecked(true);
                applyBatteryFriendlyUi();
            }
            updateScanPlanPreview();
            toast(title + " values applied. You can still edit them.");
        });
        b.setContentDescription(title + " performance mode: IP limit, batch size, threads, timeout " + subtitle);
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

    private void renderScanPlanPreviews() {
        if (targetChipPreview == null || sniChipPreview == null || targetsInput == null || snisInput == null) return;
        final long generation = previewGeneration.incrementAndGet();
        
        final String rawTargetsText = targetsInput.getText().toString();
        final String rawSnisText = snisInput.getText().toString();
        final String targetStatsText = customTargetStatsText(rawTargetsText);
        final String sniStatsText = customSniStatsText(rawSnisText);
        final int targetCap = intValue(totalInput, 0);
        
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
        final boolean otherNetwork = checked(otherNetworkSourceEnabled);
        final int otherNetworkCount = intValue(otherNetworkSampleInput, 0);
        
        final int threads = Math.max(1, intValue(threadsInput, 32));
        final int batch = Math.max(1, intValue(batchInput, 2000));
        final int timeout = Math.max(1, intValue(timeoutInput, 3000));
        final String pathText = pathInput == null ? "/" : pathInput.getText().toString();
        final String tlsMode = tlsModeSpinner == null ? "Android default" : String.valueOf(tlsModeSpinner.getSelectedItem());
        final List<Integer> profiles = selectedWorkflowProfiles();
        final boolean allSni = sniPairingEnabled() && multiSni != null && multiSni.isChecked();
        final String portsText = portsInput == null ? "443" : portsInput.getText().toString();
        
        previewExecutor.execute(() -> {
            rebuildManagedSourcesBg(defaultSni, community, communityCount, akamai, akamaiCount, cloudfront, cloudfrontCount, fastly, fastlyCount, cloudflare, cloudflareCount, otherNetwork, otherNetworkCount);
            
            final List<String> targetTokens = combinedTargetTokens(rawTargetsText);
            final int estimatedTargets = estimateExpandedTargetCount(targetTokens, Integer.MAX_VALUE);
            final List<String> previewTargets = previewExpandedTargets(targetTokens, targetCap <= 0 ? PREVIEW_TARGET_LIMIT : Math.min(targetCap, PREVIEW_TARGET_LIMIT));
            
            final boolean sniPairing = sniPairingEnabled();
            final List<String> combinedSniTokens = sniPairing ? combinedSniTokens(rawSnisText) : Collections.emptyList();
            
            final String summaryText = getSummaryText(defaultSni, community, akamai, cloudfront, fastly, cloudflare, otherNetwork);
            final String healthText = getHealthText(rawTargetsText, rawSnisText, targetTokens, estimatedTargets, targetCap, threads, batch, allSni);
            final String planText = getPlanText(rawTargetsText, rawSnisText, targetTokens, targetCap, batch, threads, timeout, pathText, tlsMode, profiles, allSni, portsText);
            
            ui.post(() -> {
                if (generation != previewGeneration.get()) return;
                if (targetChipPreview == null || sniChipPreview == null) return;
                
                int managedSize;
                int customSize;
                synchronized (selectedSourceTargets) {
                    managedSize = selectedSourceTargets.size();
                    customSize = sampleSource(lines(rawTargetsText), customTargetSampleInput == null ? 0 : intValue(customTargetSampleInput, 0)).size();
                }
                
                renderChips(targetChipPreview, "Target preview (" + countLabel(ScanTargetPlanner.effectiveScanCap(targetCap, estimatedTargets)) + " IPs planned, " + previewTargets.size() + " shown)", previewTargets, true);
                
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
                if (targetInputStatsView != null) targetInputStatsView.setText(targetStatsText);
                if (sniInputStatsView != null) sniInputStatsView.setText(sniStatsText);
                refreshActionButtons();
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

    private void updateScanPlanPreview() {
        renderScanPlanPreviews();
        refreshActionButtons();
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
        return ScanInputAnalyzer.previewExpandedTargets(raw, limit, MainActivity::sampleOneExpandedTarget);
    }

    private void renderChips(LinearLayout panel, String title, List<String> values, boolean targets) {
        PreviewChipRenderer.render(panel, title, values, targets, PREVIEW_CHIP_LIMIT, new PreviewChipRenderer.Ui() {
            @Override public TextView titleText() { return text("", 11, MUTED, true); }
            @Override public LinearLayout row() {
                LinearLayout row = MainActivity.this.row();
                row.setGravity(Gravity.START);
                return row;
            }
            @Override public TextView chip() { return MainActivity.this.chip("", true); }
            @Override public LinearLayout.LayoutParams chipLayoutParams() { return smallChipLp(); }
            @Override public void bindChip(TextView view, String label, boolean ok) { bindPreviewChip(view, label, ok); }
        });
    }

    private static String customTargetStatsText(String raw) {
        return ScanInputAnalyzer.customTargetStatsText(
                raw,
                list -> estimateExpandedTargetCount(list, Integer.MAX_VALUE),
                MainActivity::estimateCidrCount,
                MainActivity::estimateRangeCount
        );
    }

    private static String customSniStatsText(String raw) {
        return ScanInputAnalyzer.customSniStatsText(raw);
    }

    private void bindPreviewChip(TextView v, String label, boolean ok) {
        v.setText(trim(label, 22));
        int fill = ok ? Color.rgb(11, 58, 46) : Color.rgb(74, 26, 37);
        int stroke = ok ? Color.argb(150, 66, 230, 170) : Color.argb(170, 255, 120, 140);
        v.setBackground(glassBg(fill, stroke));
        v.setContentDescription((ok ? "Valid IP or SNI entry " : "Invalid IP or SNI entry ") + label);
    }

    private TextView chip(String label, boolean ok) {
        TextView v = text(trim(label, 22), 11, Color.WHITE, false);
        int fill = ok ? Color.rgb(11, 58, 46) : Color.rgb(74, 26, 37);
        int stroke = ok ? Color.argb(150, 66, 230, 170) : Color.argb(170, 255, 120, 140);
        v.setBackground(glassBg(fill, stroke));
        v.setPadding(dp(8), dp(5), dp(8), dp(5));
        v.setContentDescription((ok ? "Valid IP or SNI entry " : "Invalid IP or SNI entry ") + label);
        return v;
    }

    private LinearLayout.LayoutParams smallChipLp() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-2, -2);
        lp.setMargins(0, dp(3), dp(5), dp(3));
        return lp;
    }

    private static boolean validTargetToken(String value) {
        return ScanInputAnalyzer.validTargetToken(value);
    }

    private static boolean validDomainToken(String value) {
        return ScanInputAnalyzer.validDomainToken(value);
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
                .setMessage("1. Pick route sources: choose bounded IP samples, custom targets, or both.\n\n" +
                        "2. Pick SNI hosts: SNI is the hostname used during TLS. Presets and custom hosts are kept visible in the scan plan.\n\n" +
                        "3. Pick route evidence: current network, Windscribe app, Psiphon app, or a local proxy. Results show progress, cards, provider filters, sorting, visual density, and export. Diagnostics keeps logs and support out of the way.")
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
                        "Targets are IPs, domains, or CIDR ranges. Route-source checkboxes enable bounded provider/community samples. Use the sample buttons for interactive checks; custom targets remain the precise route-plan input.\n\n" +
                        "SNI hosts\n" +
                        "SNI is the hostname sent during TLS. Toggle the default SNI corpus, let enabled providers add relevant host routes, or add your own domains. Enable All SNI hosts for deeper matching; leave it off for faster scans.\n\n" +
                        "Profiles\n" +
                        "Quick TCP checks reachability. Standard TLS verifies TLS. Deep HTTP + SNI adds HTTP HEAD checks. Verify provider edge favors confirmed working provider IP routes.\n\n" +
                        "Workflows\n" +
                        "Single runs one selected profile. Auto multi-step ladder runs TCP, then TLS, then HTTP/SNI, then provider-route verification. Manual selected steps runs only the checked stages, useful when you want a focused pass without changing source selections.\n\n" +
                        "Visual modes\n" +
                        "Comfort is the default card layout. Contrast avoids color-only status cues and increases card opacity. Compact reduces spacing so more route candidates fit on screen.\n\n" +
                        "Performance parameters\n" +
                        "IP scan limit is the number of expanded IPs this run may attempt after CIDR/range expansion; raise it only when you intentionally want full subnets or very large provider corpora. Batch controls how many IPs run per wave. Threads controls parallel sockets. Timeout ms controls how long each connect/TLS/HTTP check can wait.\n\n" +
                        "Filtering and sorting\n" +
                        "Results owns all browsing controls: Successful only, Has TLS or HTTP, Has HTTP, Known provider only, TLS 1.3 only, provider filter, SNI filter, provider text filter, certificate filter, max latency, visible row budget, and min score. Sort by Score to surface the strongest candidates.\n\n" +
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
                renderScanPlanPreviews();
                refreshActionButtons();
            });
        }, "source-loader").start();
    }

    private void warmSourceCaches() {
        loadAsset(SourceCatalog.DEFAULT_TARGETS);
        loadAsset(SourceCatalog.DEFAULT_EDGES_EXTRA);
        communityEdgeCorpus(SourceCatalog.MAYBEPSIPHON_EDGE_IPS, SourceCatalog.COMMUNITY_EDGE_CIDRS_24);
        loadAsset(SourceCatalog.DEFAULT_SNIS);
        loadAsset(SourceCatalog.MAYBEPSIPHON_SNI_HOSTS);
        loadAssetTokens(SourceCatalog.AKAMAI_AS20940);
        loadAsset(SourceCatalog.AKAMAI_HOSTS_184X);
        loadAssetTokens(SourceCatalog.AWS_CLOUDFRONT_RANGES);
        loadAssetTokens(SourceCatalog.FASTLY_AS54113);
        loadAssetTokens(SourceCatalog.CLOUDFLARE_RANGES);
        loadAssetTokens(SourceCatalog.GITHUB_PAGES_RANGES);
        loadAssetTokens(SourceCatalog.AZURE_FRONTDOOR_RANGES);
        loadAssetTokens(SourceCatalog.GOOGLE_CDN_RANGES);
        loadAssetTokens(SourceCatalog.BUNNY_RANGES);
        loadAssetTokens(SourceCatalog.STACKPATH_EDGIO_RANGES);
        loadAssetTokens(SourceCatalog.OTHER_CLOUD_RANGES);
    }

    private void rebuildManagedSources() {
        rebuildManagedSourcesBg(
            checked(defaultSniEnabled),
            checked(communitySourceEnabled), intValue(communitySampleInput, 0),
            checked(akamaiSourceEnabled), intValue(akamaiSampleInput, 0),
            checked(cloudfrontSourceEnabled), intValue(cloudfrontSampleInput, 0),
            checked(fastlySourceEnabled), intValue(fastlySampleInput, 0),
            checked(cloudflareSourceEnabled), intValue(cloudflareSampleInput, 0),
            checked(otherNetworkSourceEnabled), intValue(otherNetworkSampleInput, 0)
        );
        if (sourceSummaryView != null) {
            sourceSummaryView.setText(getSummaryText(
                checked(defaultSniEnabled),
                checked(communitySourceEnabled),
                checked(akamaiSourceEnabled),
                checked(cloudfrontSourceEnabled),
                checked(fastlySourceEnabled),
                checked(cloudflareSourceEnabled),
                checked(otherNetworkSourceEnabled)
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
            boolean otherNetwork, int otherNetworkCount) {
        synchronized (selectedSourceTargets) {
            selectedSourceTargets.clear();
        }
        synchronized (selectedSourceSnis) {
            selectedSourceSnis.clear();
        }
        if (defaultSni) {
            synchronized (selectedSourceSnis) {
                selectedSourceSnis.addAll(loadAsset(SourceCatalog.DEFAULT_SNIS));
                selectedSourceSnis.addAll(loadAsset(SourceCatalog.MAYBEPSIPHON_SNI_HOSTS));
            }
        }
        if (community) {
            synchronized (selectedSourceTargets) {
                selectedSourceTargets.addAll(sampleSource(loadAsset(SourceCatalog.DEFAULT_TARGETS), communityCount));
                selectedSourceTargets.addAll(sampleSource(loadAsset(SourceCatalog.DEFAULT_EDGES_EXTRA), communityCount));
                selectedSourceTargets.addAll(sampleSource(communityEdgeCorpus(SourceCatalog.MAYBEPSIPHON_EDGE_IPS, SourceCatalog.COMMUNITY_EDGE_CIDRS_24), communityCount));
            }
        }
        if (akamai) {
            synchronized (selectedSourceTargets) {
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens(SourceCatalog.AKAMAI_AS20940), akamaiCount));
                selectedSourceTargets.addAll(sampleSource(loadAsset(SourceCatalog.AKAMAI_HOSTS_184X), akamaiCount));
            }
            synchronized (selectedSourceSnis) {
                addRelevantSni(selectedSourceSnis, "akamai");
            }
        }
        if (cloudfront) {
            synchronized (selectedSourceTargets) {
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens(SourceCatalog.AWS_CLOUDFRONT_RANGES), cloudfrontCount));
            }
            synchronized (selectedSourceSnis) {
                addRelevantSni(selectedSourceSnis, "aws");
                addRelevantSni(selectedSourceSnis, "cloudfront");
            }
        }
        if (fastly) {
            synchronized (selectedSourceTargets) {
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens(SourceCatalog.FASTLY_AS54113), fastlyCount));
            }
            synchronized (selectedSourceSnis) {
                addRelevantSni(selectedSourceSnis, "fastly");
            }
        }
        if (cloudflare) {
            synchronized (selectedSourceTargets) {
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens(SourceCatalog.CLOUDFLARE_RANGES), cloudflareCount));
            }
            synchronized (selectedSourceSnis) {
                addRelevantSni(selectedSourceSnis, "cloudflare");
            }
        }
        if (otherNetwork) {
            synchronized (selectedSourceTargets) {
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens(SourceCatalog.GITHUB_PAGES_RANGES), otherNetworkCount));
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens(SourceCatalog.AZURE_FRONTDOOR_RANGES), otherNetworkCount));
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens(SourceCatalog.GOOGLE_CDN_RANGES), otherNetworkCount));
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens(SourceCatalog.BUNNY_RANGES), otherNetworkCount));
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens(SourceCatalog.STACKPATH_EDGIO_RANGES), otherNetworkCount));
                selectedSourceTargets.addAll(sampleSource(loadAssetTokens(SourceCatalog.OTHER_CLOUD_RANGES), otherNetworkCount));
            }
            synchronized (selectedSourceSnis) {
                addRelevantSni(selectedSourceSnis, "cloudflare");
                addRelevantSni(selectedSourceSnis, "mapbox");
            }
        }
    }

    private String getSummaryText(boolean defaultSni, boolean community, boolean akamai, boolean cloudfront, boolean fastly, boolean cloudflare, boolean otherNetwork) {
        ArrayList<String> enabled = new ArrayList<>();
        if (community) enabled.add("Community");
        if (akamai) enabled.add("Akamai");
        if (cloudfront) enabled.add("CloudFront");
        if (fastly) enabled.add("Fastly");
        if (cloudflare) enabled.add("Cloudflare");
        if (otherNetwork) enabled.add("Other providers");

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

        return "Managed IP and SNI sources\n" +
                (enabled.isEmpty() ? "No IP source enabled" : joinComma(enabled)) + "\n" +
                targetSize + " source rows -> about " + estimated + " IPs before the IP scan limit.\n" +
                sniSize + " default/provider SNI hostnames " + (defaultSni ? "enabled" : "disabled") + "; custom IPs and SNI hostnames are counted separately.";
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
        int cappedTargets = ScanTargetPlanner.effectiveScanCap(targetCap, estimatedTargets);

        String composition = targetTokens.isEmpty()
                ? "No IP sources selected yet."
                : managedTargets + " managed source rows + " + customTargets + " custom rows, deduped before IP expansion.";

        int sniSize;
        synchronized (selectedSourceSnis) {
            sniSize = selectedSourceSnis.size();
        }

        String routeScope = sniPairingEnabled()
                ? sniSize + " managed SNI hostnames + " + customRoutes + " typed SNI hostnames; SNI mode is " + (isMultiSni ? "all hostnames." : "primary hostname first.")
                : "IP-only scope; SNI/host names are extracted from TLS and HTTP results, not paired as scan input.";

        return "Source health\n" +
                composition + "\n" +
                "Expanded estimate: " + estimatedTargets + " IPs; IP scan limit: " + ScanTargetPlanner.scanLimitLabel(targetCap) +
                (targetCap <= 0 ? " (all expanded IPs eligible)." : (" (" + cappedTargets + " this run).")) + "\n" +
                routeScope + "\n" +
                sourceLoadPostureBg(estimatedTargets, targetCap, threads, batch);
    }

    private String sourceLoadPostureBg(int estimatedTargets, int targetCap, int threads, int batch) {
        int capped = ScanTargetPlanner.effectiveScanCap(targetCap, estimatedTargets);
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
        int cappedTargets = ScanTargetPlanner.effectiveScanCap(targetCap, estimatedTargets);
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

        EdgeRouteProfile route = buildSelectedRouteProfile();
        List<String> previewSample = previewExpandedTargets(targetTokens, Math.min(cappedTargets, PREVIEW_TARGET_LIMIT));
        List<String> previewSnis = sniPairingEnabled() ? combinedSniTokens(rawSnisText) : Collections.singletonList("");
        String previewSni = previewSnis.isEmpty() ? "" : previewSnis.get(0);
        int previewPort = ports.isEmpty() ? 443 : ports.get(0);
        int distinctPlanIds = ScanTargetPlanner.countDistinctPreviewPlans(
                previewSample, previewPort, sniPairingEnabled(), route, previewSni);

        return "IP and SNI scan plan\n" +
                managedTargets + " managed source rows + " + lines(rawTargetsText).size() + " custom rows -> " + estimatedTargets + " IPs available -> " + cappedTargets + " IPs selected (scan limit " + ScanTargetPlanner.scanLimitLabel(targetCap) + ")\n" +
                "TargetPlan preview: " + distinctPlanIds + " distinct plan_id in sample of " + previewSample.size() + "\n" +
                (sniPairingEnabled() ? sniCount + " SNI host" + (sniCount == 1 ? "" : "s") + " kept separate for TLS/Host routing; " : "IP-only TLS/HTTP checks; ") + "ports " + ports + "\n" +
                "Runtime: batch " + batch + ", threads " + threads + ", timeout " + timeout + "ms, HTTP path " + path + "\n" +
                "TLS ClientHello mode: " + tlsMode + "\n" +
                workflowLabels(profiles) + " -> " + (profiles.isEmpty() ? "select at least one manual step." : "about " + units + " connection checks. Preset overlaps are deduped, not overridden.");
    }

    private boolean checked(CheckBox box) {
        return box != null && box.isChecked();
    }

    private boolean isScanRunning() {
        return scanSession.isRunning();
    }

    private boolean hasRunnableTargets() {
        if (portsInput != null && parsePorts(portsInput.getText().toString()).isEmpty()) return false;
        boolean hasCustomTargets = ScanInputAnalyzer.hasValidTargets(targetsInput == null ? "" : targetsInput.getText().toString());
        return hasCustomTargets
                || checked(communitySourceEnabled)
                || checked(akamaiSourceEnabled)
                || checked(cloudfrontSourceEnabled)
                || checked(fastlySourceEnabled)
                || checked(cloudflareSourceEnabled)
                || checked(otherNetworkSourceEnabled);
    }

    private void refreshActionButtons() {
        boolean running = isScanRunning();
        boolean hasTargets = hasRunnableTargets();
        boolean hasResults = !scanSession.results().isEmpty();

        setActionButtonState(startButton, !running && hasTargets, BLUE, Color.rgb(2, 18, 24));
        setActionButtonState(stopButton, running && !scanSession.isStopRequested(), Color.rgb(255, 102, 122), Color.WHITE);
        setActionButtonState(clearButton, !running && hasResults, Color.rgb(34, 51, 66), Color.WHITE);

        if (status != null && !running) {
            status.setText(hasTargets ? "Ready" : "No targets selected");
        }
    }

    private void setActionButtonState(Button button, boolean enabled, int activeBg, int activeFg) {
        if (button == null) return;
        button.setEnabled(enabled);
        button.setAlpha(enabled ? 1.0f : 0.62f);
        button.setTextColor(enabled ? activeFg : Color.rgb(150, 164, 176));
        button.setBackground(glassBg(enabled ? activeBg : Color.rgb(30, 40, 50),
                enabled ? Color.argb(125, 255, 255, 255) : Color.argb(65, 180, 195, 205)));
    }

    private LinkedHashSet<String> sampleSource(Collection<String> values, int count) {
        ArrayList<String> list = new ArrayList<>();
        for (String value : values) {
            String clean = cleanToken(value);
            if (!clean.isEmpty()) list.add(clean);
        }
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (count <= 0) {
            out.addAll(list);
            return out;
        }
        if (list.isEmpty()) return out;
        long totalEstimate = 0;
        long[] starts = new long[list.size()];
        for (int i = 0; i < list.size(); i++) {
            starts[i] = totalEstimate;
            totalEstimate += Math.max(1, estimateExpandedTargetCount(Collections.singletonList(list.get(i)), Integer.MAX_VALUE));
            if (totalEstimate > Integer.MAX_VALUE) totalEstimate = Integer.MAX_VALUE;
        }
        int sampleCount = (int) Math.min(count, totalEstimate);
        for (int i = 0; i < sampleCount; i++) {
            long position = (long) Math.floor(i * (totalEstimate / (double) sampleCount));
            int tokenIndex = tokenIndexForPosition(starts, position);
            out.add(sampleOneExpandedTarget(list.get(tokenIndex), (int) Math.max(0, position - starts[tokenIndex])));
        }
        return out;
    }

    private static int tokenIndexForPosition(long[] starts, long position) {
        int index = Arrays.binarySearch(starts, position);
        if (index >= 0) return index;
        return Math.max(0, Math.min(starts.length - 1, -index - 2));
    }

    private static String sampleOneExpandedTarget(String token, int index) {
        String clean = cleanToken(token);
        if (ScanTargetPlanner.looksLikePrefix(clean)) return sampleCidr(clean, index);
        if (ScanTargetPlanner.looksLikeIpv4Range(clean)) return sampleRange(clean, index);
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
        for (String sni : loadAsset(SourceCatalog.MAYBEPSIPHON_SNI_HOSTS)) {
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
            Object item = spinner.getAdapter().getItem(i);
            if (value.equals(RouteOptions.valueOf(item)) || value.equals(String.valueOf(item))) return i;
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
        EdgeRouteProfile profile = buildSelectedRouteProfile();
        ScanCommandBus.submit(this, ScanCommand.refreshProviderReadiness("activity_ui", profile));
    }

    private void renderRouteSnapshot(ScanForegroundService.RouteSessionSnapshot snapshot) {
        if (routeReadinessView == null) return;
        ScanForegroundService.RouteSessionSnapshot current = snapshot == null
                ? ScanForegroundService.RouteSessionSnapshot.direct()
                : snapshot;
        routeReadinessView.setText(routeReadinessText(current));
    }

    private String routeReadinessText(ScanForegroundService.RouteSessionSnapshot snapshot) {
        StringBuilder sb = new StringBuilder();
        sb.append(snapshot.summary);
        sb.append("\n\nEvidence");
        sb.append("\nprovider=").append(snapshot.provider);
        sb.append(" | state=").append(snapshot.state);
        sb.append("\nconfig_ready=").append(yesNo(snapshot.configReady));
        sb.append(" | session_ready=").append(yesNo(snapshot.sessionReady));
        sb.append("\nprovider_observed=").append(yesNo(snapshot.providerObserved));
        sb.append(" | listener_ready=").append(yesNo(snapshot.listenerReady));
        sb.append("\ndialer_ready=").append(yesNo(snapshot.dialerReady));
        sb.append(" | route_used=").append(yesNo(snapshot.routeUsed));
        sb.append("\nready_to_scan=").append(yesNo(snapshot.ready));
        if (snapshot.profile != null && snapshot.profile.routeId != null && !snapshot.profile.routeId.trim().isEmpty()) {
            sb.append("\nroute_id=").append(snapshot.profile.routeId.trim());
        }
        sb.append("\nupdated=").append(snapshot.updatedAtEpochMs <= 0 ? "not_checked" : new java.text.SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date(snapshot.updatedAtEpochMs)));
        return sb.toString();
    }

    private static String yesNo(boolean value) {
        return value ? "yes" : "no";
    }

    private void openFirstInstalledRouteApp(String label, String... packageNames) {
        PackageManager pm = getPackageManager();
        for (String packageName : packageNames) {
            Intent launch = pm.getLaunchIntentForPackage(packageName);
            if (launch != null) {
                if (routePackageInput != null) routePackageInput.setText(packageName);
                launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(launch);
                toast("Opened " + label + ". Connect it, then return and observe route.");
                return;
            }
        }
        String fallbackPackage = packageNames.length == 0 ? "" : packageNames[0];
        try {
            Intent market = new Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=" + fallbackPackage));
            market.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(market);
            toast(label + " is not installed. Install it, connect, then observe route.");
        } catch (Exception ignored) {
            toast(label + " is not installed. Install it from your app store, connect, then observe route.");
        }
    }

    private String spinnerText(Spinner spinner) {
        return spinner == null || spinner.getSelectedItem() == null ? "" : RouteOptions.valueOf(spinner.getSelectedItem());
    }

    private String safeRouteField(EditText field) {
        if (field == null) return "";
        return field.getText().toString().replace('\r', ' ').replace('\n', ' ').trim();
    }

    private void startScan() {
        if (scanSession.isRunning()) {
            toast("Scan is already running");
            selectTab(1);
            return;
        }
        if (!hasRunnableTargets()) {
            status.setText("No targets selected");
            toast("Add targets or enable a bounded source before starting a route scan");
            selectTab(0);
            refreshActionButtons();
            return;
        }
        rebuildManagedSources();
        List<String> targets = expandTargets(combinedTargetTokens(), intValue(totalInput, 0));
        List<Integer> ports = parsePorts(portsInput.getText().toString());
        if (targets.isEmpty() || ports.isEmpty()) {
            toast("Targets and ports are required");
            refreshActionButtons();
            return;
        }
        if (selectedWorkflowProfiles().isEmpty()) {
            toast("Select at least one manual workflow step");
            selectTab(0);
            updateScanPlanPreview();
            return;
        }
        ScanStagingRequest request = buildStagingRequest();
        if (request == null) {
            refreshActionButtons();
            return;
        }
        resetScanUiForNewSession();
        status.setText("Running");
        refreshActionButtons();
        selectTab(1);
        appendLog(request.logSummary);
        appendResourceWarnings(request.threads, request.batch, request.timeout, request.targets.size());
        ScanCommandBus.submit(this, ScanCommand.startScan("activity_ui", request));
    }

    private ScanStagingRequest buildStagingRequest() {
        rebuildManagedSources();
        int totalCap = intValue(totalInput, 0);
        List<ScanTargetPlanner.ExpandedTarget> expanded = ScanTargetPlanner.expandTargetsDetailed(combinedTargetTokens(), totalCap);
        ArrayList<String> targets = new ArrayList<>(expanded.size());
        ArrayList<TargetExpansionMeta> targetExpansion = new ArrayList<>(expanded.size());
        for (ScanTargetPlanner.ExpandedTarget entry : expanded) {
            targets.add(entry.address);
            targetExpansion.add(entry.expansion);
        }
        List<String> snis = sniPairingEnabled() ? combinedSniTokens() : Collections.singletonList("");
        List<Integer> ports = parsePorts(portsInput.getText().toString());
        if (targets.isEmpty() || ports.isEmpty()) {
            toast("Targets and ports are required");
            return null;
        }
        if (snis.isEmpty()) snis = Collections.singletonList("");
        List<Integer> workflowProfiles = selectedWorkflowProfiles();
        if (workflowProfiles.isEmpty()) {
            toast("Select at least one manual workflow step");
            selectTab(0);
            updateScanPlanPreview();
            return null;
        }
        boolean allSniPreference = sniPairingEnabled() && multiSni.isChecked();
        boolean suppressNoisyLogs = hideNoisyLogs.isChecked();
        String httpPath = pathInput.getText().toString();
        int tlsMode = tlsModeSpinner == null ? 0 : tlsModeSpinner.getSelectedItemPosition();
        int plannedChecks = estimateAttemptUnits(targets.size(), snis.size(), ports.size(), workflowProfiles, allSniPreference);
        int batch = Math.max(1, intValue(batchInput, 2000));
        int threads = Math.max(1, intValue(threadsInput, 32));
        int timeout = Math.max(1, intValue(timeoutInput, 3000));
        EdgeRouteProfile routeProfile = buildSelectedRouteProfile();
        String logSummary = "Scan started: expanded_targets=" + targets.size() + ", sni_hosts=" + snis.size() +
                ", connection_checks=" + plannedChecks + ", ports=" + ports + ", batch=" + batch +
                ", threads=" + threads + ", workflow=" + workflowSpinner.getSelectedItem() +
                ", steps=" + workflowLabels(workflowProfiles) + ", route=" + routeProfile.summary();
        return new ScanStagingRequest(
                targets, targetExpansion, snis, ports, workflowProfiles, plannedChecks,
                batch, threads, timeout, tlsMode, allSniPreference, suppressNoisyLogs,
                sniPairingEnabled(), httpPath, workflowLabels(workflowProfiles), logSummary, routeProfile, true);
    }

    private void resetScanUiForNewSession() {
        ui.removeCallbacks(progressRunnable);
        progressQueued.set(false);
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
        renderBestCard(Collections.emptyList());
    }

    void applySessionSnapshot() {
        ScanSessionUiSnapshot snapshot = scanSession.uiSnapshot();
        if (status != null) {
            if (snapshot.stopRequested) {
                status.setText("Stopping");
            } else if (snapshot.running || !"idle".equals(snapshot.lifecycleState)) {
                status.setText(displayLifecycleState(ScanForegroundService.snapshot()));
            }
        }
        renderRouteSnapshot(ScanForegroundService.routeSnapshot());
        refreshActionButtons();
        scheduleProgressUpdate();
        if (snapshot.running || snapshot.resultCount > 0) {
            scheduleRender();
        }
    }

    private void executeStartScan() {
        applySessionSnapshot();
    }

    void onWorkflowFinishedUi(long generation, boolean stopRequested, ScanTerminalReason terminalReason) {
        if (generation != scanSession.currentGeneration()) return;
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        status.setText(stopRequested ? "Stopped" : "Ready");
        appendLogOnUi((stopRequested ? "Stopped" : "Complete") + " in " + elapsed());
        if (!stopRequested) saveLocalObservationHistory();
        renderProgressDirect();
        renderResults();
        refreshActionButtons();
    }

    void onResultsDrained(java.util.List<ScanResultEvent> logEvents) {
        for (ScanResultEvent event : logEvents) {
            MainActivity.Result r = event.result;
            appendLog("Result " + r.address() + " host=" + dash(r.sni) + " tcp=" + r.tcpPass +
                    " tls=" + r.tlsPass + " http=" + r.httpPass + " q=" + Math.round(r.quality));
        }
        scheduleProgressUpdate();
        scheduleRender();
    }

    void scheduleProgressUpdate() {
        if (!progressQueued.compareAndSet(false, true)) return;
        ui.postDelayed(progressRunnable, 120);
    }

    private void submitExportCommand() {
        ScanCommandBus.submit(this, ScanCommand.exportResults("activity_ui", buildExportSpecFromUi()));
    }

    private ScanExportSpec buildExportSpecFromUi() {
        int format = fileExportSpinner == null ? ScanExportSpec.FORMAT_JSONL : fileExportSpinner.getSelectedItemPosition();
        String redaction = exportPrivacyMode != null && exportPrivacyMode.isChecked() ? "privacy" : "none";
        return new ScanExportSpec(format, redaction, "route_pairing", "maybeedgescanner_export");
    }

    private void onExportCompleted(Intent intent) {
        if (intent == null) return;
        String error = intent.getStringExtra(ScanExportBus.EXTRA_ERROR);
        String path = intent.getStringExtra(ScanExportBus.EXTRA_PATH);
        if (error != null && !error.isEmpty()) {
            toast("Export failed: " + error);
            return;
        }
        if (path != null && !path.isEmpty()) {
            toast("Exported: " + path);
        }
    }

    private void requestStop() {
        if (!isScanRunning()) {
            refreshActionButtons();
            return;
        }
        ScanCommandBus.submit(this, ScanCommand.cancelScan("activity_ui", scanSession.currentGeneration()));
    }

    private void executeCancelScan(ScanCommand command) {
        if (command != null && !scanSession.matchesCommandGeneration(command.generation)) {
            return;
        }
        status.setText("Stopping");
        refreshActionButtons();
        appendLog("Stop requested. Current sockets will finish or time out.");
        applySessionSnapshot();
    }

    private ScanCommand readScanCommand(Intent intent) {
        if (intent == null) return null;
        Object value = intent.getSerializableExtra(ScanCommandBus.EXTRA_COMMAND);
        return value instanceof ScanCommand ? (ScanCommand) value : null;
    }

    private void onScanCommand(ScanCommand command) {
        if (command == null) return;
        switch (command.kind) {
            case START_SCAN:
                executeStartScan();
                break;
            case CANCEL_SCAN:
                executeCancelScan(command);
                break;
            case CLEAR_SESSION:
                resetResultsUiAfterClear();
                applySessionSnapshot();
                break;
            case EXPORT_RESULTS:
                break;
            case REFRESH_PROVIDER_READINESS:
                ScanForegroundService.updateRouteSnapshot(this, buildSelectedRouteProfile());
                renderRouteSnapshot(ScanForegroundService.routeSnapshot());
                break;
            case STOP_SIDECAR:
                break;
            default:
                break;
        }
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

    private void appendResourceWarnings(int threads, int batch, int timeout, int targets) {
        if (threads >= 256 || (batch > 0 && batch >= 250000) || (targets > 0 && targets >= 250000)) {
            appendLog("Warning: high-volume scan selected. Android may throttle sockets, battery, or thermal performance.");
        }
        if (timeout < 250) {
            appendLog("Warning: very low timeout may miss slow-but-working edges.");
        }
    }

    private final Runnable progressRunnable = () -> {
        progressQueued.set(false);
        renderProgressDirect();
    };

    private int progressPercent() {
        int total = Math.max(1, scanSession.totalTargets());
        int checked = Math.max(0, Math.min(scanSession.checkedChecks(), total));
        return (int) Math.min(100, Math.max(0, Math.round((checked * 100.0) / total)));
    }

    private void renderProgressDirect() {
        progress.setMax(Math.max(1, scanSession.totalTargets()));
        int checked = Math.min(scanSession.checkedChecks(), Math.max(1, scanSession.totalTargets()));
        progress.setProgress(checked);
        Stats s = stats();
        String sessionInfo = sessionSummary();
        if (scanSession.totalTargets() <= 0) {
            metrics.setText("No scan yet | TCP 0 | TLS 0 | HTTP 0 | Score 0" + sessionInfo);
        } else {
            metrics.setText(checked + " / " + scanSession.totalTargets() + " checks | attempts completed " + s.rows + " | TCP " + s.tcp +
                    " | TLS " + s.tls + " | HTTP " + s.http + " | Score " + Math.round(s.bestQuality) +
                    " | pending " + scanSession.pendingResults().size() + " | " + elapsed() + sessionInfo);
        }
        countersView.setText("Failed " + s.down + " | timed out " + s.timeout + " | reset " + s.reset +
                " | cert " + s.cert + " | DNS " + s.dns + " | " + resourceLine());
        if (scanSession.isRunning()) {
            ScanForegroundService.updateSessionProgress(checked);
            ScanForegroundService.update(this, "running",
                    checked + " / " + scanSession.totalTargets() + " checks", progressPercent());
        }
    }

    private String sessionSummary() {
        ScanForegroundService.ScanSessionSnapshot snapshot = ScanForegroundService.sessionSnapshot();
        if (snapshot == null || snapshot.sessionId == null || snapshot.sessionId.trim().isEmpty()) {
            return "";
        }
        return " | session " + snapshot.sessionId + " (" + snapshot.completedChecks + "/" + snapshot.plannedChecks + ")";
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

    /** Legacy entry point; drain is service-owned via {@link ScanSessionController}. */
    void drainPendingResults() {
        scanSession.requestResultDrain();
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
            renderBestCard(snapshot);
            resultsAdapter.setResults(Collections.emptyList());
            return;
        }
        renderBestCard(snapshot);
        
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
        int rawCount = scanSession.results().size();
        return ResultSummaryStats.format(summaryRows(rows), rawCount, filterSummary());
    }

    private List<ResultSummaryStats.Row> summaryRows(List<Result> rows) {
        ArrayList<ResultSummaryStats.Row> out = new ArrayList<>(rows.size());
        for (Result r : rows) {
            out.add(new ResultSummaryStats.Row(
                    r.working(),
                    r.totalLatency(),
                    r.quality,
                    r.httpPass,
                    r.tlsPass,
                    sniCandidates(r)
            ));
        }
        return out;
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

    private static String stableBestPlaceholder() {
        return "No successful results yet\nSNI and host names will appear after TLS or HTTP route checks.\n ";
    }

    private void renderBestCard(List<Result> snapshot) {
        if (bestView == null) return;
        if (snapshot == null || snapshot.isEmpty()) {
            bestView.setText(stableBestPlaceholder());
            return;
        }
        Result bestVisible = bestVisibleResult(snapshot);
        if (bestVisible == null) {
            Stats s = stats();
            if (s.rows > 0 && s.tcp == 0 && s.tls == 0 && s.http == 0 && s.timeout >= Math.max(3, s.rows * 8 / 10)) {
                bestView.setText("No successful results yet\nMost attempts are timing out. Try fewer threads, a longer timeout, a smaller target set, or a different route.\n ");
            } else {
                bestView.setText("No successful results visible\nClear filters or show failed attempts to inspect the current scan rows.\n ");
            }
            return;
        }
        String bestLine = "Best: " + bestVisible.summary();
        bestView.setText(bestLine + "\n" + bestSniLine(snapshot) + "\n ");
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
        hasRows = !scanSession.results().isEmpty();
        card.addView(text(hasRows ? "Filters hid every row" : "No visible route results yet", 16, Color.WHITE, true));
        card.addView(text(hasRows ? "Loosen provider, score, latency, SNI, certificate, or status filters to reveal existing scan rows." :
                "Start a scan from Routes. Result cards will stay here; copy and export never replace them.", 12, Color.rgb(205, 226, 238), false));
        Button cta = button(hasRows ? "Clear filters" : "Open Routes", Color.rgb(22, 54, 72), Color.WHITE);
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
        if (requireKnownNetwork != null) requireKnownNetwork.setChecked(false);
        if (requireTls13 != null) requireTls13.setChecked(false);
        if (bestPerIp != null) bestPerIp.setChecked(false);
        if (networkProviderSpinner != null) networkProviderSpinner.setSelection(0);
        if (maxLatencyInput != null) maxLatencyInput.setText("");
        if (networkFilterInput != null) networkFilterInput.setText("");
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
        ResultAnalyticsStats stats = ResultAnalyticsStats.from(rows);
        int total = stats.total;
        analyticsPanel.addView(text("Status distribution", 12, highContrastMode() ? Color.WHITE : MUTED, true));
        analyticsPanel.addView(metricBar("HTTP", stats.http, total, Color.rgb(66, 230, 170)));
        analyticsPanel.addView(metricBar("TLS", stats.tls, total, Color.rgb(55, 212, 255)));
        analyticsPanel.addView(metricBar("TCP", stats.tcp, total, Color.rgb(255, 204, 100)));
        analyticsPanel.addView(metricBar("Down", stats.down, total, Color.rgb(255, 112, 135)));
        analyticsPanel.addView(text("Latency histogram", 12, highContrastMode() ? Color.WHITE : MUTED, true));
        analyticsPanel.addView(metricBar("<120ms", stats.fast, total, Color.rgb(66, 230, 170)));
        analyticsPanel.addView(metricBar("120-299ms", stats.medium, total, Color.rgb(55, 212, 255)));
        analyticsPanel.addView(metricBar("300-699ms", stats.slow, total, Color.rgb(255, 204, 100)));
        analyticsPanel.addView(metricBar("700ms+", stats.verySlow, total, Color.rgb(255, 112, 135)));
        analyticsPanel.addView(text("Network mix", 12, highContrastMode() ? Color.WHITE : MUTED, true));
        ArrayList<Map.Entry<String, Integer>> groups = new ArrayList<>(stats.networkGroups.entrySet());
        groups.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));
        for (int i = 0; i < Math.min(5, groups.size()); i++) {
            Map.Entry<String, Integer> e = groups.get(i);
            analyticsPanel.addView(metricBar(e.getKey(), e.getValue(), total, networkClassificationColor(e.getKey())));
        }
        analyticsPanel.addView(text("Provider health", 12, highContrastMode() ? Color.WHITE : MUTED, true));
        for (ProviderHealthStats.Item h : providerHealth(rows)) {
            analyticsPanel.addView(text(h.label(), 11, Color.WHITE, false));
        }
    }

    private List<ProviderHealthStats.Item> providerHealth(List<Result> rows) {
        return ProviderHealthStats.fromResults(rows, 6);
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

    private int networkClassificationColor(String classification) {
        String c = classification == null ? "" : classification.toLowerCase(Locale.US);
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
        ResultFilterEngine.Spec spec = new ResultFilterEngine.Spec();
        spec.requireWorking = filterWorking.isChecked();
        spec.requireTlsOrHttp = filterTlsHttp.isChecked();
        spec.requireHttp = requireHttp.isChecked();
        spec.requireKnownClassification = requireKnownNetwork.isChecked();
        spec.requireTls13 = requireTls13.isChecked();
        spec.bestPerEndpoint = bestPerIp.isChecked();
        spec.maxLatency = intValue(maxLatencyInput, 0);
        spec.minQuality = intValue(minQualityInput, 0);
        spec.sortMode = sortSpinner.getSelectedItemPosition();
        spec.networkPreset = networkProviderSpinner == null || networkProviderSpinner.getSelectedItem() == null ? "Any provider" : String.valueOf(networkProviderSpinner.getSelectedItem());
        spec.networkText = networkFilterInput == null ? "" : networkFilterInput.getText().toString();
        spec.certText = certFilterInput == null ? "" : certFilterInput.getText().toString();
        spec.hostText = sniFilterInput == null ? "" : sniFilterInput.getText().toString();

        return ResultFilterEngine.apply(scanSession.results().snapshot(), spec, new ResultFilterEngine.Accessor<Result>() {
            @Override public boolean working(Result row) { return row.working(); }
            @Override public boolean tlsPass(Result row) { return row.tlsPass; }
            @Override public boolean httpPass(Result row) { return row.httpPass; }
            @Override public String tlsVersion(Result row) { return row.tlsVersion; }
            @Override public long totalLatency(Result row) { return row.totalLatency(); }
            @Override public double quality(Result row) { return row.quality; }
            @Override public String networkClassification(Result row) { return row.networkClassification; }
            @Override public String certificateText(Result row) { return row.tlsCert; }
            @Override public String hostHintText(Result row) { return row.sni; }
            @Override public String endpointKey(Result row) { return row.ip + ":" + row.port; }
            @Override public String sortHostKey(Result row) { return row.sni == null ? "" : row.sni; }
        });
    }

    private String filterSummary() {
        ArrayList<String> active = new ArrayList<>();
        if (filterWorking != null && filterWorking.isChecked()) active.add("successful");
        if (filterTlsHttp != null && filterTlsHttp.isChecked()) active.add("has TLS or HTTP");
        if (requireHttp != null && requireHttp.isChecked()) active.add("HTTP");
        if (requireKnownNetwork != null && requireKnownNetwork.isChecked()) active.add("known provider");
        if (requireTls13 != null && requireTls13.isChecked()) active.add("TLS 1.3");
        if (bestPerIp != null && bestPerIp.isChecked()) active.add("best/IP");
        if (networkProviderSpinner != null && networkProviderSpinner.getSelectedItemPosition() > 0) active.add(String.valueOf(networkProviderSpinner.getSelectedItem()));
        if (maxLatencyInput != null && !maxLatencyInput.getText().toString().trim().isEmpty()) active.add("latency");
        if (minQualityInput != null && !minQualityInput.getText().toString().trim().isEmpty()) active.add("score");
        if (networkFilterInput != null && !networkFilterInput.getText().toString().trim().isEmpty()) active.add("network text");
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
        signal.addView(statusDot(r.networkClassification, !"UNKNOWN".equalsIgnoreCase(r.networkClassification), BLUE), smallChipLp());
        TextView body = text(latencySparkline(r) + "  " + r.totalLatency() + "ms | HTTP " + r.httpStatus +
                " | Score " + Math.round(r.quality), 12, Color.WHITE, false);
        formatMonospace(body, 12);
        card.addView(top);
        card.addView(route);
        card.addView(signal);
        card.addView(body);
        if (!compactMode() && !r.tlsVersion.isEmpty()) card.addView(text(r.tlsVersion + " | " + r.tlsCipher + " | ALPN " + dash(r.alpn) + " | TLS " + dash(r.tlsProfile), 11, highContrastMode() ? Color.WHITE : MUTED, false));
        if (!compactMode() && !r.routeProviderId.isEmpty()) card.addView(text("Route " + r.routeProviderId + " | " + r.routeBinding + " | " + r.routeProtocolMode + " | DNS " + r.routeDnsPolicy, 11, Color.rgb(175, 230, 215), false));
        if (!compactMode() && r.http3Hint) card.addView(text("HTTP/3 advertised via Alt-Svc: " + trim(r.altSvc, 120), 11, Color.rgb(150, 232, 255), false));
        if (!compactMode() && !r.tlsCert.isEmpty()) card.addView(text(trim(r.tlsCert, 120), 11, highContrastMode() ? Color.WHITE : MUTED, false));
        String failureLabel = resultFailureLabel(r);
        if (!failureLabel.isEmpty()) card.addView(text(failureLabel, 11, Color.rgb(255, 180, 180), false));
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
        try {
            ExportPayload payload = ResultExportFormatter.buildSelectedFormat(
                    rows,
                    format,
                    String.valueOf(exportSpinner.getSelectedItem())
            );
            copyToClipboardOrDialog(payload.label, payload.content);
        } catch (Exception e) {
            toast("Copy failed: " + e.getMessage());
        }
    }

    private void copyVisibleCsv() {
        List<Result> rows = filteredResults();
        copyToClipboardOrDialog("visible CSV", ResultExportFormatter.buildVisibleCsv(rows));
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

    private void copyDiagnosticsRedacted() {
        String output = diagnosticOutputView == null ? "" : String.valueOf(diagnosticOutputView.getText());
        DiagnosticsCopyActions.copyRedacted(
                output,
                redacted -> copyToClipboardOrDialog("diagnostics redacted", redacted),
                this::toast
        );
    }

    private void copyDiagnosticsFullWithConfirmation() {
        String output = diagnosticOutputView == null ? "" : String.valueOf(diagnosticOutputView.getText());
        DiagnosticsCopyActions.copyFullWithConfirmation(
                new AlertDialog.Builder(this),
                output,
                full -> copyToClipboardOrDialog("diagnostics full", full),
                this::toast
        );
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

    private void clearResults() {
        ScanCommandBus.submit(this, ScanCommand.clearSession("activity_ui"));
    }

    void resetResultsUiAfterClear() {
        ui.removeCallbacks(progressRunnable);
        progressQueued.set(false);
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
        metrics.setText("No scan yet | TCP 0 | TLS 0 | HTTP 0 | Score 0");
        countersView.setText("Failed 0 | timed out 0 | reset 0 | cert 0 | DNS 0 | " + resourceLine());
        renderBestCard(Collections.emptyList());
        renderStableHistoryPanel();
        refreshActionButtons();
    }

    private void saveLocalObservationHistory() {
        try {
            LocalObservationHistoryStore.mergeSuccessfulRun(
                    getSharedPreferences("maybeedgescanner", MODE_PRIVATE),
                    scanSession.results().snapshot()
            );
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
            List<LocalObservationHistoryStore.Entry> entries = LocalObservationHistoryStore.loadTopStable(
                    getSharedPreferences("maybeedgescanner", MODE_PRIVATE),
                    2,
                    8
            );
            LinearLayout chips = row();
            chips.setGravity(Gravity.START);
            for (LocalObservationHistoryStore.Entry entry : entries) {
                chips.addView(chip(entry.displayLabel(), true), smallChipLp());
            }
            if (entries.isEmpty()) chips.addView(chip("Run scans to build local stability history", true), smallChipLp());
            stableHistoryPanel.addView(chips);
        } catch (Exception e) {
            stableHistoryPanel.addView(text("History unavailable", 11, MUTED, false));
        }
    }

    static String resultFailureLabel(Result r) {
        if (r == null) return "";
        if (r.errorCode != null && !r.errorCode.isEmpty()) {
            return PhaseResult.displayLabel(r.errorCode, r.finalPhase, "");
        }
        for (int i = r.phaseResults.size() - 1; i >= 0; i--) {
            PhaseResult phase = r.phaseResults.get(i);
            if (phase != null && !"success".equals(phase.status) && !"skipped".equals(phase.status)) {
                String label = phase.displayLabel();
                if (!label.isEmpty()) return label;
            }
        }
        return r.reason == null ? "" : r.reason;
    }

    private Stats stats() {
        Stats s = new Stats();
        List<Result> snapshot = scanSession.results().snapshot();
        s.rows = snapshot.size();
        for (Result r : snapshot) {
                if (r.tcpPass) s.tcp++;
                if (r.tlsPass) s.tls++;
                if (r.httpPass) s.http++;
                if (!r.working()) s.down++;
                String reason = r.reason.toLowerCase(Locale.US);
                if (r.phaseStatusPresent("timeout") || r.errorCodeEndsWith("_TIMEOUT")) s.timeout++;
                if (r.phaseStatusPresent("reset") || r.errorCodeEndsWith("_RESET")) s.reset++;
                if (r.indicatesCertIssue()) s.cert++;
                if (r.phaseNamed("dns") || (r.errorCode != null && r.errorCode.startsWith("DNS"))) s.dns++;
                if (r.quality > s.bestQuality) { s.bestQuality = r.quality; s.best = r; }
        }
        return s;
    }

    private static class Stats {
        int rows, tcp, tls, http, down, timeout, reset, cert, dns;
        double bestQuality;
        Result best;
    }

    static final class ExportPayload {
        final String label;
        final String content;

        ExportPayload(String label, String content) {
            this.label = label;
            this.content = content;
        }
    }

    static class Result implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
        final String target, ip, sni;
        final int port;
        long rowId;
        boolean tcpPass, tlsPass, httpPass;
        long tcpLatencyMs, tlsLatencyMs, httpLatencyMs;
        int httpStatus;
        String tlsVersion = "", tlsCipher = "", tlsCert = "", certFingerprint = "", alpn = "", tlsProfile = "", altSvc = "", reason = "", networkClassification = "UNKNOWN";
        String routeId = "", routeProviderId = "", routeBinding = "", routeProtocolMode = "", routeAuthMode = "", routeDnsPolicy = "", routeReadiness = "";
        final java.util.ArrayList<PhaseResult> phaseResults = new java.util.ArrayList<>();
        String finalPhase = "", errorCode = "";
        TargetPlanRecord targetPlan;
        boolean http3Hint;
        double quality;

        Result(String target, String ip, int port, String sni) {
            this.target = target; this.ip = ip; this.port = port; this.sni = sni == null ? "" : sni;
        }
        static Result down(String target, String ip, int port, String sni, String reason) {
            Result r = new Result(target, ip, port, sni);
            r.reason = reason;
            r.recordPhase(PhaseResult.failure("dns", 0, null, "DNS_RESOLUTION_FAILED"));
            return r.finish();
        }
        Result attachTargetPlan(TargetPlanRecord plan) {
            this.targetPlan = plan;
            return this;
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
            recordPhase(PhaseResult.success("route", 0));
            return this;
        }
        void recordPhase(PhaseResult phase) {
            if (phase == null) return;
            phaseResults.add(phase);
            if (!"success".equals(phase.status) && !"skipped".equals(phase.status)) {
                finalPhase = phase.phase;
                if (phase.errorCode != null && !phase.errorCode.isEmpty()) {
                    errorCode = phase.errorCode;
                }
            }
        }
        boolean phaseStatusPresent(String status) {
            for (PhaseResult phase : phaseResults) {
                if (status.equals(phase.status)) return true;
            }
            return false;
        }
        boolean phaseNamed(String phaseName) {
            for (PhaseResult phase : phaseResults) {
                if (phaseName.equals(phase.phase)) return true;
            }
            return false;
        }
        boolean errorCodeEndsWith(String suffix) {
            return errorCode != null && !errorCode.isEmpty() && errorCode.endsWith(suffix);
        }
        boolean indicatesCertIssue() {
            for (PhaseResult phase : phaseResults) {
                if (phase.errorCode != null) {
                    String upper = phase.errorCode.toUpperCase(Locale.US);
                    if (upper.contains("TLS") || upper.contains("CERT")) return true;
                }
            }
            String legacy = reason == null ? "" : reason.toLowerCase(Locale.US);
            return legacy.contains("cert");
        }
        void tcp(int timeout) {
            long t = System.currentTimeMillis();
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(ip, port), timeout);
                tcpPass = true;
                tcpLatencyMs = System.currentTimeMillis() - t;
                recordPhase(PhaseResult.success("tcp", tcpLatencyMs));
            } catch (Exception e) {
                reason = classify(e);
                recordPhase(PhaseResult.failure("tcp", System.currentTimeMillis() - t, e, ""));
            }
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
                recordPhase(PhaseResult.success("tcp", tcpLatencyMs));
                raw.setSoTimeout(timeout);
                try (SSLSocket ssl = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, host, port, true)) {
                    ssl.setSoTimeout(timeout);
                    configureTlsSocket(ssl, activeMode, false);
                    ssl.startHandshake();
                    tlsPass = true;
                    tlsLatencyMs = System.currentTimeMillis() - t;
                    recordPhase(PhaseResult.success("tls", tlsLatencyMs));
                    tlsVersion = ssl.getSession().getProtocol();
                    tlsCipher = ssl.getSession().getCipherSuite();
                    alpn = selectedAlpn(ssl);
                    Certificate[] certs = ssl.getSession().getPeerCertificates();
                    if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                        X509Certificate c = (X509Certificate) certs[0];
                        tlsCert = c.getSubjectX500Principal().getName();
                        certFingerprint = sha256(c.getEncoded());
                    }
                } catch (Exception handshake) {
                    reason = classify(handshake);
                    recordPhase(PhaseResult.failure("tls", Math.max(0L, System.currentTimeMillis() - t), handshake, ""));
                }
            } catch (Exception e) {
                reason = classify(e);
                recordPhase(PhaseResult.failure("tcp", System.currentTimeMillis() - t, e, ""));
            }
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
                recordPhase(PhaseResult.success("tcp", tcpLatencyMs));
                raw.setSoTimeout(timeout);
                try (SSLSocket ssl = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, host, port, true)) {
                    ssl.setSoTimeout(timeout);
                    configureTlsSocket(ssl, activeMode, true);
                    ssl.startHandshake();
                    tlsPass = true;
                    alpn = selectedAlpn(ssl);
                    long tlsMs = System.currentTimeMillis() - t;
                    recordPhase(PhaseResult.success("tls", tlsMs));
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
                    String httpPhase = PhaseResult.httpPhaseFromAlpn(alpn);
                    if (httpPass) {
                        recordPhase(PhaseResult.success(httpPhase, httpLatencyMs));
                    } else {
                        recordPhase(PhaseResult.failure(httpPhase, httpLatencyMs, null, "HTTP_PROBE_FAILED"));
                    }
                } catch (Exception handshake) {
                    reason = classify(handshake);
                    recordPhase(PhaseResult.failure("tls", Math.max(0L, System.currentTimeMillis() - t), handshake, ""));
                }
            } catch (Exception e) {
                reason = classify(e);
                recordPhase(PhaseResult.failure("tcp", System.currentTimeMillis() - t, e, ""));
            }
        }
        Result finish() {
            if (finalPhase == null || finalPhase.isEmpty()) {
                if (httpPass) finalPhase = PhaseResult.httpPhaseFromAlpn(alpn);
                else if (tlsPass) finalPhase = "tls";
                else if (tcpPass) finalPhase = "tcp";
                else if (!phaseResults.isEmpty()) finalPhase = phaseResults.get(phaseResults.size() - 1).phase;
            }
            networkClassification = detectNetworkClassification(ip, sni, tlsCert);
            double stage = (tcpPass ? 25 : 0) + (tlsPass ? 35 : 0) + (httpPass ? 25 : 0);
            long latency = totalLatency();
            double latencyScore = latency > 0 ? 10000.0 / (latency + 100.0) : 0;
            quality = stage + latencyScore * 0.25 + (tlsVersion.contains("1.3") ? 8 : 0) +
                    ("h2".equalsIgnoreCase(alpn) ? 5 : 0) + (http3Hint ? 4 : 0) +
                    (!certFingerprint.isEmpty() ? 8 : 0) + (networkClassification.equals("UNKNOWN") ? 0 : 6) - (reason.isEmpty() ? 0 : 7);
            return this;
        }
        boolean working() { return tcpPass || tlsPass || httpPass; }
        String address() { return ip == null || ip.isEmpty() ? target : ip + ":" + port; }
        long totalLatency() { return (tcpPass ? tcpLatencyMs : 0) + (tlsPass ? tlsLatencyMs : 0) + (httpPass ? httpLatencyMs : 0); }
        String summary() { return address() + " " + sni + " " + networkClassification + routeSummarySuffix() + " q=" + Math.round(quality) + " " + totalLatency() + "ms"; }
        String routeSummarySuffix() { return routeProviderId == null || routeProviderId.isEmpty() ? "" : " route=" + routeProviderId + "/" + routeProtocolMode; }
        JSONObject json() throws Exception {
            JSONObject o = new JSONObject();
            o.put("target", target); o.put("ip", ip); o.put("port", port); o.put("sni", sni);
            o.put("tcpPass", tcpPass); o.put("tlsPass", tlsPass); o.put("httpPass", httpPass);
            o.put("tcpLatencyMs", tcpLatencyMs); o.put("tlsLatencyMs", tlsLatencyMs); o.put("httpLatencyMs", httpLatencyMs);
            o.put("httpStatus", httpStatus); o.put("tlsVersion", tlsVersion); o.put("tlsCipher", tlsCipher);
            o.put("alpn", alpn); o.put("tlsProfile", tlsProfile); o.put("altSvc", altSvc); o.put("http3Hint", http3Hint);
            o.put("tlsCert", tlsCert); o.put("certFingerprint", certFingerprint); o.put("network_classification", networkClassification);
            o.put("routeId", routeId); o.put("routeProviderId", routeProviderId); o.put("routeBinding", routeBinding);
            o.put("routeProtocolMode", routeProtocolMode); o.put("routeAuthMode", routeAuthMode);
            o.put("routeDnsPolicy", routeDnsPolicy); o.put("routeReadiness", routeReadiness);
            o.put("quality", quality); o.put("reason", reason);
            if (!finalPhase.isEmpty()) o.put("final_phase", finalPhase);
            if (errorCode != null && !errorCode.isEmpty()) o.put("error_code", errorCode);
            if (!phaseResults.isEmpty()) {
                org.json.JSONArray phases = new org.json.JSONArray();
                for (PhaseResult phase : phaseResults) phases.put(phase.toJson());
                o.put("phase_results", phases);
            }
            if (targetPlan != null) {
                o.put("target_plan", targetPlan.toJson());
                o.put("plan_id", targetPlan.planId());
                o.put("result_correlation_id", targetPlan.correlationId());
            }
            return o;
        }
        String csv() {
            return q(target)+","+q(ip)+","+port+","+q(sni)+","+tcpPass+","+tlsPass+","+httpPass+","+httpStatus+","+
                    totalLatency()+","+q(alpn)+","+q(tlsProfile)+","+http3Hint+","+q(networkClassification)+","+Math.round(quality)+","+q(reason);
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
    private static List<String> lines(String s) { return ScanTargetPlanner.lines(s); }
    private static List<String> unique(Collection<String> in) { return ScanTargetPlanner.unique(in); }
    private static List<Integer> parsePorts(String s) { return ScanTargetPlanner.parsePorts(s); }
    private static List<String> cap(List<String> in, int n) { return new ArrayList<>(in.subList(0, Math.min(in.size(), Math.max(1, n)))); }
    private static String first(List<String> xs) { return xs.isEmpty() ? "" : xs.get(0); }
    private static boolean isIpv4(String x) { return ScanTargetPlanner.isIpv4(x); }
    private static boolean isIp(String x) { return ScanTargetPlanner.isIp(x); }
    private static List<String> resolve(String target) { return ScanTargetPlanner.resolve(target); }
    private static List<String> expandTargets(List<String> raw) { return ScanTargetPlanner.expandTargets(raw); }

    private static List<String> expandTargets(List<String> raw, int totalCap) { return ScanTargetPlanner.expandTargets(raw, totalCap); }
    private static int estimateExpandedTargetCount(Collection<String> raw, int perTokenCap) { return ScanTargetPlanner.estimateExpandedTargetCount(raw, perTokenCap); }
    private static int estimateCidrCount(String cidr, int cap) { return ScanTargetPlanner.estimateCidrCount(cidr, cap); }
    private static int estimateRangeCount(String range, int cap) { return ScanTargetPlanner.estimateRangeCount(range, cap); }
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
    private static String detectNetworkClassification(String ip, String sni, String cert) {
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
    private static String cleanToken(String s) { return ScanTargetPlanner.cleanToken(s); }
    private String elapsed() { long s = Math.max(0, (System.currentTimeMillis() - scanSession.scanStartedAt()) / 1000); return s + "s"; }
    private void clip(String s) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText("MaybeEdgeScanner", s));
        }
    }
    private String resourceLine() {
        long now = System.currentTimeMillis();
        if (now - cachedResourceLineAt < 5000) return cachedResourceLine;
        cachedResourceLine = RuntimeResourceReporter.resourceLine(this);
        cachedResourceLineAt = now;
        return cachedResourceLine;
    }

    private String deviceLine() {
        String model = (Build.MANUFACTURER + " " + Build.MODEL).trim();
        String abi = Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "unknown ABI";
        return model + " | Android " + Build.VERSION.RELEASE + " API " + Build.VERSION.SDK_INT + " | " + abi;
    }
    private void appendLog(String s) {
        scanSession.runOnUi(activity -> activity.appendLogOnUi(s));
    }

    void appendLogOnUi(String s) {
        String line = DiagnosticsLogPipeline.timestamped(s);
        DiagnosticsLogPipeline.appendLine(logLines, stableLogBuilder, line, this::rebuildStableLogBuilder);
        refreshLogView();
    }
    private void refreshLogView() {
        DiagnosticsLogPipeline.dispatchRefresh(this::refreshLogViewDirect, ui);
    }
    private void refreshLogViewDirect() {
        logRenderedAt = DiagnosticsLogPipeline.render(
                logView,
                activeTab,
                logFilterInput,
                logLines,
                stableLogBuilder,
                logRenderedAt,
                lastRenderedLogText,
                text -> lastRenderedLogText = text
        );
    }
    private void runNetworkDiagnostics() {
        NetworkDiagnosticsRunner.run(
                this,
                ui,
                diagnosticOutputView,
                runDiagnosticsButton,
                diagnosticsOfflineMode,
                diagnosticsIncludePublicIp,
                this::appendLog
        );
    }
    private void rebuildStableLogBuilder() { stableLogBuilder.setLength(0); for (String x : logLines) stableLogBuilder.append(x).append('\n'); }
    private int intValue(EditText e, int defaultValue) { try { String s = e.getText().toString().trim(); return s.isEmpty() ? defaultValue : Integer.parseInt(s); } catch (Exception ex) { return defaultValue; } }
    private static int clampInt(int value, int min, int max) { return Math.max(min, Math.min(max, value)); }
    private LinearLayout column() { return ScannerUiKit.column(this); }
    private LinearLayout row() { return ScannerUiKit.row(this); }
    private TextView text(String s, int sp, int color, boolean bold) { return ScannerUiKit.text(this, s, sp, color, bold); }
    private TextView panelText(String s) { TextView v = text(s, 12, Color.WHITE, false); v.setBackground(glassBg(PANEL, Color.argb(95, 255, 255, 255))); v.setPadding(dp(10), dp(8), dp(10), dp(8)); setOuterMargin(v, 0, dp(5), 0, dp(5)); return v; }
    private TextView glassText(String s) { TextView v = panelText(s); v.setTextColor(Color.rgb(196, 223, 235)); return v; }
    private TextView quietNote(String body) { TextView v = text(body, 11, Color.rgb(185, 210, 222), false); v.setBackground(glassBg(Color.rgb(8, 20, 29), Color.argb(45, 255, 255, 255))); v.setPadding(dp(9), dp(6), dp(9), dp(6)); setOuterMargin(v, 0, dp(4), 0, dp(6)); return v; }

    private LinearLayout compactResultViewControls() {
        LinearLayout group = column();
        group.setBackground(glassBg(Color.rgb(10, 24, 34), Color.argb(50, 255, 255, 255)));
        group.setPadding(dp(7), dp(5), dp(7), dp(7));
        setOuterMargin(group, 0, dp(4), 0, dp(4));
        group.addView(text("Display", 11, MUTED, true));
        group.addView(compactSegmentRow("View", new String[]{"Cards", "Heatmap"}, visualizationButtons, visualizationMode, index -> {
            visualizationMode = index;
            if (resultsAdapter != null) resultsAdapter.notifyDataSetChanged();
            scheduleRender();
        }));
        group.addView(compactSegmentRow("Cards", new String[]{"Comfort", "High contrast", "Compact"}, densityButtons, densityMode, index -> {
            densityMode = index;
            if (resultsAdapter != null) resultsAdapter.notifyDataSetChanged();
            scheduleRender();
        }));
        return group;
    }

    private LinearLayout compactSegmentRow(String label, String[] names, ArrayList<Button> buttons, int selectedIndex, SegmentHandler afterChange) {
        LinearLayout line = row();
        line.setGravity(Gravity.CENTER_VERTICAL);
        TextView labelView = text(label, 10, Color.rgb(170, 194, 208), true);
        labelView.setGravity(Gravity.CENTER_VERTICAL);
        line.addView(labelView, fixedWidth(64));
        buttons.clear();
        for (int i = 0; i < names.length; i++) {
            final int index = i;
            Button b = button(names[i], Color.rgb(20, 40, 52), Color.WHITE);
            b.setMinHeight(dp(34));
            b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
            b.setContentDescription(label + ": " + names[i]);
            b.setOnClickListener(v -> {
                if (afterChange != null) afterChange.onSelect(index);
                refreshSegmentButtons(buttons, index);
            });
            buttons.add(b);
            line.addView(b, weight());
        }
        refreshSegmentButtons(buttons, selectedIndex);
        return line;
    }

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
        card.addView(text("Privileged radio tools", 12, Color.rgb(210, 231, 240), true));
        card.addView(text("Radio mode changes need Shizuku, Sui, root, or a local ADB bridge that is already running. Use this panel in order: check readiness, grant access, check the bridge, read current values, then make confirmed writes only when the readback looks sane.", 11, MUTED, false));

        shizukuStatusView = panelText("Shizuku: checking");
        card.addView(shizukuStatusView);
        shizukuNextStepView = quietNote(shizukuUnavailableNextStep());
        card.addView(shizukuNextStepView);

        LinearLayout statusRow = row();
        Button check = button("Check Shizuku", Color.rgb(24, 45, 58), Color.WHITE);
        Button request = button("Grant access", Color.rgb(24, 45, 58), Color.WHITE);
        check.setOnClickListener(v -> refreshShizukuState());
        request.setOnClickListener(v -> requestShizukuPermission());
        statusRow.addView(check, weight());
        statusRow.addView(request, weight());
        card.addView(statusRow);

        LinearLayout probeRow = row();
        Button probe = button("Check bridge", Color.rgb(24, 45, 58), Color.WHITE);
        Button read = button("Read radio", Color.rgb(24, 45, 58), Color.WHITE);
        probe.setOnClickListener(v -> runShizukuRadioCommand("Bridge capability check", ShizukuCommandBuilder.buildBridgeProbeCommand(RADIO_MODE_KEYS), false));
        read.setOnClickListener(v -> runShizukuRadioCommand("Read radio modes", ShizukuCommandBuilder.buildReadModesCommand(RADIO_MODE_KEYS), false));
        probeRow.addView(probe, weight());
        probeRow.addView(read, weight());
        card.addView(probeRow);

        LinearLayout shizukuAppRow = row();
        Button openShizuku = button("Open Shizuku", Color.rgb(24, 45, 58), Color.WHITE);
        Button shizukuGuide = button("Setup help", Color.rgb(24, 45, 58), Color.WHITE);
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

        shizukuOutputView = panelText("No privileged action has run. Check the bridge first, then read current radio values before any write.");
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
                setShizukuOutput("Privileged service connected. Check the bridge before writing radio settings.");
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
                    ? "Shizuku access granted. Check the bridge next, then read current radio values."
                    : "Shizuku access denied. Open Shizuku, allow this app under authorized apps, then tap Check Shizuku.");
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
                setShizukuNextStep("Next: update Shizuku from the official GitHub APK, reopen it, then tap Check Shizuku.");
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
                ? "Next: check the bridge, then read current radio values. Use writes only after readback looks sane for this device and SIM."
                : "Next: tap Grant access, approve this app in Shizuku, then check the bridge.");
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
                    + "Last check: " + shizukuLastProbeLine();
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
                + "Server: " + version + " | Last check: " + shizukuLastProbeLine() + "\n"
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
            return "Next: open Shizuku, start it with Wireless debugging, return here, then tap Check Shizuku.";
        }
        return "Next: start Shizuku with computer ADB after boot, or use root/Sui, then return and tap Check Shizuku.";
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
        return "Capability: backend permissions vary; check the bridge before any write.";
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
            setShizukuOutput("Shizuku is already allowed. Check the bridge next, then read current radio values.");
            toast("Shizuku is already allowed");
            return;
        }
        try {
            if (Shizuku.isPreV11()) {
                setShizukuOutput("This device is running an unsupported Shizuku server. Update Shizuku, then try again.");
                setShizukuNextStep("Next: update Shizuku from the official GitHub APK, reopen it, then tap Check Shizuku.");
                return;
            }
            if (Shizuku.shouldShowRequestPermissionRationale()) {
                setShizukuOutput("Shizuku permission was denied with rationale required. Open Shizuku, allow this app, then tap Check.");
                setShizukuNextStep("Next: open Shizuku, allow this app under authorized apps, then tap Check Shizuku.");
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
                
                ShizukuProcessRunner.CommandResult put = runShizukuProcessCapture(new String[]{"/system/bin/sh", "-c", script.toString()}, 8);
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
                ShizukuProcessRunner.CommandResult get = runShizukuProcessCapture(new String[]{"/system/bin/sh", "-c", readScript.toString()}, 8);
                output.append("readback_initial:\n").append(get.stdout.trim()).append('\n');
                if (!get.stderr.trim().isEmpty()) output.append("stderr: ").append(get.stderr.trim()).append('\n');
                try { Thread.sleep(1500L); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                ShizukuProcessRunner.CommandResult settled = runShizukuProcessCapture(new String[]{"/system/bin/sh", "-c", readScript.toString()}, 8);
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
        if (!ShizukuRadioActions.beginRun(shizukuCommandRunning, this::setShizukuOutput, this::toast)) return;
        setShizukuOutput(label + " running...");
        ShizukuRadioActions.executeAsync(
                label,
                command,
                writeAction,
                expectedValue,
                RADIO_MODE_KEYS,
                this::runShizukuProcessCapture,
                (finalOutput, finalExitCode, verifiedWrite, bridgeProbeSucceeded) ->
            ui.post(() -> {
                shizukuCommandRunning.set(false);
                if (bridgeProbeSucceeded) {
                    lastShizukuProbeAt = System.currentTimeMillis();
                }
                refreshShizukuState();
                setShizukuOutput(finalOutput);
                toast(finalExitCode == 0 ? (writeAction ? (verifiedWrite ? "Radio mode verified" : "Radio write not verified") : "Radio modes read") : "Shizuku command failed");
            })
        );
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

    private ShizukuProcessRunner.CommandResult runShizukuProcessCapture(String[] command, int timeoutSeconds) throws Exception {
        return ShizukuProcessRunner.runCapture(command, timeoutSeconds);
    }

    private String safeMessage(Throwable e) {
        return ShizukuProcessRunner.safeMessage(e);
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
    private TextView section(String s) { return ScannerUiKit.section(this, s, Color.rgb(180, 215, 230)); }
    private TextView pill(String s) { TextView v = text(s, 13, BLUE, true); v.setGravity(Gravity.CENTER); v.setBackground(glassBg(Color.rgb(16, 35, 50), BLUE)); v.setPadding(dp(12), dp(8), dp(12), dp(8)); setOuterMargin(v, 0, dp(8), 0, dp(8)); return v; }
    private EditText area(String hint) { EditText e = input("", false); e.setHint(hint); e.setMinLines(3); e.setMaxLines(7); e.setGravity(Gravity.TOP); return e; }
    private EditText input(String s, boolean number) { return ScannerUiKit.input(this, s, number, FIELD, Color.argb(85, 255, 255, 255)); }
    private CheckBox check(String s) { return ScannerUiKit.check(this, s, BLUE); }
    private Button button(String s, int bg, int fg) { return ScannerUiKit.button(this, s, bg, fg, Color.argb(125, 255, 255, 255)); }
    private Spinner spinner(String[] values) { return ScannerUiKit.spinner(this, values, FIELD, Color.argb(85, 255, 255, 255)); }

    private Spinner routeOptionSpinner(RouteOptions.Option[] values) {
        Spinner s = new Spinner(this);
        ArrayAdapter<RouteOptions.Option> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, values);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        s.setAdapter(adapter);
        s.setBackground(glassBg(FIELD, Color.argb(85, 255, 255, 255)));
        s.setPadding(dp(8), dp(5), dp(8), dp(5));
        return s;
    }
    private LinearLayout box(String label, View child) { return ScannerUiKit.box(this, label, child, Color.rgb(10, 24, 34), Color.argb(60, 255, 255, 255), Color.rgb(180, 215, 230)); }
    private LinearLayout.LayoutParams weight() { return ScannerUiKit.weight(this); }
    private LinearLayout.LayoutParams fixedWidth(int widthDp) { return ScannerUiKit.fixedWidth(this, widthDp); }
    private int dp(int v) { return ScannerUiKit.dp(this, v); }
    private void toast(String s) {
        if (s == null || s.trim().isEmpty()) return;
        String msg = s.trim();
        if (feedbackView == null) {
            if (status != null) status.setText(msg.length() > 42 ? msg.substring(0, 39) + "..." : msg);
            return;
        }
        feedbackView.setText(msg);
        feedbackView.setVisibility(View.VISIBLE);
        feedbackView.bringToFront();
        ui.removeCallbacks(hideFeedbackRunnable);
        long delay = Math.max(2800L, Math.min(6500L, msg.length() * 70L));
        ui.postDelayed(hideFeedbackRunnable, delay);
    }
    private void copySupport(String label, String address) {
        clip(address);
        toast("MaybeEdgeScanner " + label + " address copied");
    }
    private String supportEvm() { return "0x8988ed09DA218799e99Fb1E94243cC1C1cB41A40"; }
    private String supportBtc() { return "bc1qt2mxzmlcv3re4pjemshejzq0hj3c8dgp0e5tvx"; }
    private void openSupportGitHub() {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, android.net.Uri.parse(SUPPORT_GITHUB)));
        } catch (Exception e) {
            clip(SUPPORT_GITHUB);
            toast("MaybeEdgeScanner GitHub link copied");
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
        int fillAlpha = highContrastMode() ? 245 : 232;
        int shineAlpha = highContrastMode() ? 28 : 48;
        return ScannerUiKit.glassBg(this, fill, stroke, highContrastMode(), compactMode());
    }
    private void setOuterMargin(View v, int l, int t, int r, int b) { ScannerUiKit.setOuterMargin(v, l, t, r, b); }

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
            final TextView networkChip;
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
                networkChip = (TextView) signal.getChildAt(3);
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
                route.setText("SNI route " + dash(r.sni));
                route.setTextSize(TypedValue.COMPLEX_UNIT_SP, compactMode() ? 11 : 12);
                route.setTextColor(highContrastMode() ? Color.WHITE : Color.rgb(190, 218, 232));
                bindStatusChip(tcpChip, "TCP", r.tcpPass, Color.rgb(54, 166, 255));
                bindStatusChip(tlsChip, "TLS", r.tlsPass, Color.rgb(66, 230, 170));
                bindStatusChip(httpChip, "HTTP", r.httpPass, Color.rgb(255, 204, 100));
                bindStatusChip(networkChip, r.networkClassification, !"UNKNOWN".equalsIgnoreCase(r.networkClassification), BLUE);
                body.setText(latencySparkline(r) + "  " + r.totalLatency() + "ms | HTTP " + r.httpStatus + " | Score " + Math.round(r.quality));
                bindOptionalLine(tlsLine, !compactMode() && !r.tlsVersion.isEmpty(), r.tlsVersion + " | " + r.tlsCipher + " | ALPN " + dash(r.alpn) + " | TLS " + dash(r.tlsProfile), highContrastMode() ? Color.WHITE : MUTED);
                bindOptionalLine(http3Line, !compactMode() && r.http3Hint, "HTTP/3 advertised via Alt-Svc: " + trim(r.altSvc, 120), Color.rgb(150, 232, 255));
                bindOptionalLine(certLine, !compactMode() && !r.tlsCert.isEmpty(), trim(r.tlsCert, 120), highContrastMode() ? Color.WHITE : MUTED);
                String failureLabel = resultFailureLabel(r);
                bindOptionalLine(reasonLine, !failureLabel.isEmpty(), failureLabel, Color.rgb(255, 180, 180));
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
                r.reason + "|" + r.networkClassification + "|" + Math.round(r.quality * 100.0);
    }

}

