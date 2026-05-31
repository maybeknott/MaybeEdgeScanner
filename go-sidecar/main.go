package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/time/rate"
)

type scanRequest struct {
	Targets                []string             `json:"targets"`
	SNIs                   []string             `json:"snis"`
	Ports                  []int                `json:"ports"`
	RoutePlugin            *RoutingPluginConfig `json:"route_plugin,omitempty"`
	HTTPPath               string               `json:"http_path"`
	Threads                int                  `json:"threads"`
	TimeoutMS              int                  `json:"timeout_ms"`
	MaxTargets             int                  `json:"max_targets"`
	MaxCIDRHosts           int                  `json:"max_cidr_hosts"`
	BatchSize              int                  `json:"batch_size"`
	MultiSNI               bool                 `json:"multi_sni"`
	HTTPProbe              bool                 `json:"http_probe"`
	Randomize              bool                 `json:"randomize"`
	RatePerSecond          int                  `json:"rate_per_second"`
	JitterMS               int                  `json:"jitter_ms"`
	RespectSafety          bool                 `json:"respect_safety"`
	SafetyPreset           string               `json:"safety_preset,omitempty"`
	BroadScanConfirmed     bool                 `json:"broad_scan_confirmed,omitempty"`
	TLSFingerprint         string               `json:"tls_fingerprint"`
	EnablePayloadSplitting bool                 `json:"enable_payload_splitting"`
	SplitByteBoundary      int                  `json:"split_byte_boundary"`
}

type result struct {
	Target                string `json:"target"`
	IP                    string `json:"ip"`
	Port                  int    `json:"port"`
	SNI                   string `json:"sni"`
	TCP                   bool   `json:"tcp"`
	TLS                   bool   `json:"tls"`
	HTTP                  bool   `json:"http"`
	HTTPStatus            int    `json:"http_status"`
	TLSVersion            string `json:"tls_version,omitempty"`
	TLSCipher             string `json:"tls_cipher,omitempty"`
	CertVerified          bool   `json:"cert_verified"`
	ALPN                  string `json:"alpn,omitempty"`
	TLSFingerprint        string `json:"tls_fingerprint,omitempty"`
	CertSubject           string `json:"cert_subject,omitempty"`
	ServerHeader          string `json:"server_header,omitempty"`
	CacheHeader           string `json:"cache_header,omitempty"`
	AltSvc                string `json:"alt_svc,omitempty"`
	HTTP3Hint             bool   `json:"http3_hint,omitempty"`
	HTTPProbeCode         string `json:"http_probe_code,omitempty"`
	NetworkClassification string `json:"network_classification"`
	ProviderID            string `json:"provider_id,omitempty"`
	ProviderName          string `json:"provider_name,omitempty"`
	ProviderPrefix        string `json:"provider_prefix,omitempty"`
	ProviderConfidence    string `json:"provider_confidence,omitempty"`
	ProviderCorpusID      string `json:"provider_corpus_id,omitempty"`
	ProviderSource        string `json:"provider_source,omitempty"`
	RequestedRouteID      string `json:"requested_route_id,omitempty"`
	ObservedRouteID       string `json:"observed_route_id,omitempty"`
	ObservedRouteType     string `json:"observed_route_type,omitempty"`
	RouteUsed             bool   `json:"route_used,omitempty"`
	RouteMismatchCode     string `json:"route_mismatch_code,omitempty"`
	RouteConfigReady      bool   `json:"route_config_ready"`
	RouteDialerReady      bool   `json:"route_dialer_ready"`
	RouteObserved         bool   `json:"route_observed"`
	RouteEvidenceState    string `json:"route_evidence_state,omitempty"`
	RouteID               string `json:"route_id,omitempty"`
	RouteProviderID       string `json:"route_provider_id,omitempty"`
	RouteBinding          string `json:"route_binding,omitempty"`
	RouteProtocolMode     string `json:"route_protocol_mode,omitempty"`
	RouteAuthMode         string `json:"route_auth_mode,omitempty"`
	RouteDNSPolicy        string `json:"route_dns_policy,omitempty"`
	RouteStrategy         string `json:"route_strategy,omitempty"`
	RouteProviderChain    string `json:"route_provider_chain,omitempty"`
	RouteFrontingPolicy   string `json:"route_fronting_policy,omitempty"`
	RouteLANSharing       bool   `json:"route_lan_sharing,omitempty"`
	RouteBeastMode        bool   `json:"route_beast_mode,omitempty"`
	RouteReadiness        string `json:"route_readiness,omitempty"`
	RouteReadinessSource  string `json:"route_readiness_source,omitempty"`
	RouteErrorCode        string `json:"route_error_code,omitempty"`
	LatencyMS             int64  `json:"latency_ms"`
	Score                 int    `json:"score"`
	ErrorCode             string `json:"error_code,omitempty"`
	Error                 string `json:"error,omitempty"`
	FinalPhase            string        `json:"final_phase,omitempty"`
	PhaseResults          []PhaseResult `json:"phase_results,omitempty"`
	BatchNumber           int    `json:"batch_number"`
}

type stats struct {
	Total       int `json:"total"`
	Checked     int `json:"checked"`
	Working     int `json:"working"`
	TLSWorking  int `json:"tls_working"`
	HTTPWorking int `json:"http_working"`
	Down        int `json:"down"`
	Batches     int `json:"batches"`
	Batch       int `json:"batch"`
}

var (
	activeCancelMu       sync.Mutex
	activeCancel         context.CancelFunc
	activeSerial         uint64
	metricScansStarted   atomic.Uint64
	metricScansCompleted atomic.Uint64
	metricScanResults    atomic.Uint64
	metricTCPPass        atomic.Uint64
	metricTLSPass        atomic.Uint64
	metricHTTPPass       atomic.Uint64
	metricTimeouts       atomic.Uint64
	metricResets         atomic.Uint64
	metricDNSRuns        atomic.Uint64
	metricSafetySkipped  atomic.Uint64
	metricBackoffEvents  atomic.Uint64
	globalBackoffNS      atomic.Int64
	safetyCIDRPrefixes   = loadSafetyPrefixes()
	activeControlPlane   *sidecarControlPlane
)

type DPIObfuscationOptions struct {
	EnablePayloadSplitting bool `json:"enable_payload_splitting"`
	SplitByteBoundary      int  `json:"split_byte_boundary"`
}

type ObfuscatedConn struct {
	net.Conn
	SplitBoundary int
}

func (c *ObfuscatedConn) Write(b []byte) (int, error) {
	if len(b) > c.SplitBoundary {
		n1, err := c.Conn.Write(b[:c.SplitBoundary])
		if err != nil {
			return n1, err
		}
		time.Sleep(50 * time.Microsecond)
		n2, err := c.Conn.Write(b[c.SplitBoundary:])
		return n1 + n2, err
	}
	return c.Conn.Write(b)
}

func DialObfuscatedSocket(ctx context.Context, network, addr string, timeout time.Duration, opts DPIObfuscationOptions) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if opts.EnablePayloadSplitting && opts.SplitByteBoundary > 0 {
		return &ObfuscatedConn{Conn: rawConn, SplitBoundary: opts.SplitByteBoundary}, nil
	}
	return rawConn, nil
}

type RadixNode struct {
	Prefix  *netip.Prefix
	Payload string
	Left    *RadixNode
	Right   *RadixNode
}

type CorporateNetworkIndex struct {
	sync.RWMutex
	RootNode *RadixNode
}

var networkClassificationIndex = &CorporateNetworkIndex{}

func (cni *CorporateNetworkIndex) Insert(prefix netip.Prefix, payload string) {
	cni.Lock()
	defer cni.Unlock()
	cni.RootNode = insertNode(cni.RootNode, prefix, payload, 0)
}

func insertNode(node *RadixNode, prefix netip.Prefix, payload string, bitIndex int) *RadixNode {
	if node == nil {
		node = &RadixNode{}
	}
	if bitIndex == prefix.Bits() {
		p := prefix
		node.Prefix = &p
		node.Payload = payload
		return node
	}
	bit := getBit(prefix.Addr(), bitIndex)
	if bit == 0 {
		node.Left = insertNode(node.Left, prefix, payload, bitIndex+1)
	} else {
		node.Right = insertNode(node.Right, prefix, payload, bitIndex+1)
	}
	return node
}

func (cni *CorporateNetworkIndex) MatchLongestPrefix(addr netip.Addr) (string, bool) {
	cni.RLock()
	defer cni.RUnlock()
	var bestPayload string
	var found bool
	curr := cni.RootNode
	for bitIndex := 0; curr != nil; bitIndex++ {
		if curr.Prefix != nil && curr.Prefix.Contains(addr) {
			bestPayload = curr.Payload
			found = true
		}
		if bitIndex >= addr.BitLen() {
			break
		}
		bit := getBit(addr, bitIndex)
		if bit == 0 {
			curr = curr.Left
		} else {
			curr = curr.Right
		}
	}
	return bestPayload, found
}

func getBit(addr netip.Addr, bitIndex int) int {
	bytes := addr.AsSlice()
	byteIdx := bitIndex / 8
	bitIdx := 7 - (bitIndex % 8)
	if byteIdx >= len(bytes) {
		return 0
	}
	return int((bytes[byteIdx] >> bitIdx) & 1)
}

func initNetworkClassificationIndex() {
	cdns := map[string][]string{
		"cloudflare": {
			"104.16.0.0/12", "172.64.0.0/13", "2606:4700::/32",
		},
		"fastly": {
			"151.101.0.0/16", "2a04:4e42::/32",
		},
		"cloudfront": {
			"13.32.0.0/15", "13.224.0.0/14", "18.64.0.0/14", "54.230.0.0/16",
		},
		"akamai": {
			"23.32.0.0/11", "23.192.0.0/11", "184.24.0.0/13", "2a02:26f0::/32",
		},
	}
	for payload, cidrs := range cdns {
		for _, cidr := range cidrs {
			if prefix, err := netip.ParsePrefix(cidr); err == nil {
				networkClassificationIndex.Insert(prefix, payload)
			}
		}
	}
}

func main() {
	initNetworkClassificationIndex()
	if err := initProviderCorpusObserver(); err != nil {
		slog.Warn("provider corpus observer disabled", "error", err)
	}
	control, err := newSidecarControlPlane()
	if err != nil {
		slog.Error("sidecar control-plane initialization failed", "error", err)
		os.Exit(1)
	}
	activeControlPlane = control
	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
	mux.HandleFunc("/grafana-dashboard.json", grafanaDashboard)
	mux.HandleFunc("/api/scan", control.requireMutationAuth(scan))
	mux.HandleFunc("/api/dns", control.requireMutationAuth(scanDNS))
	mux.HandleFunc("/api/stop", control.requireMutationAuth(control.stop))
	mux.HandleFunc("/api/shutdown", control.requireMutationAuth(control.shutdown))
	mux.HandleFunc("/api/heartbeat", control.requireReadAuth(control.heartbeat))
	mux.HandleFunc("/api/plugins", routingPlugins)
	mux.HandleFunc("/api/plugins/validate", control.requireMutationAuth(validateRoutingPlugin))
	mux.HandleFunc("/api/provider-corpus", providerCorpusStatusHandler)
	mux.HandleFunc("/api/export/nmap", control.requireMutationAuth(exportNmap))
	mux.HandleFunc("/metrics", control.requireReadAuth(metrics))
	mux.HandleFunc("/health", control.requireReadAuth(func(w http.ResponseWriter, _ *http.Request) {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "time": time.Now().Format(time.RFC3339),
			"goroutines": runtime.NumGoroutine(), "heap_bytes": mem.HeapAlloc,
		})
	}))

	addr := "127.0.0.1:10808"
	srv := &http.Server{Addr: addr, Handler: mux}
	control.setShutdown(srv.Shutdown)
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopSignals()
	go func() {
		<-ctx.Done()
		activeCancelMu.Lock()
		if activeCancel != nil {
			activeCancel()
		}
		activeCancelMu.Unlock()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("MaybeEdgeScanner sidecar graceful shutdown failed", "error", err)
		}
	}()
	slog.Info("MaybeEdgeScanner sidecar listening", "url", "http://"+addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("MaybeEdgeScanner sidecar stopped", "error", err)
		os.Exit(1)
	}
	slog.Info("MaybeEdgeScanner sidecar stopped")
}

func index(w http.ResponseWriter, _ *http.Request) {
	page := `<!doctype html><html><head><meta name=viewport content="width=device-width,initial-scale=1"><title>MaybeEdgeScanner Sidecar</title>
<style>
:root{color-scheme:dark;--bg:#071018;--panel:rgba(16,27,37,.82);--line:#263948;--text:#eef6fb;--muted:#8aa2b3;--accent:#32d0bd;--good:#42e6aa;--warn:#ffd166;--bad:#ff8585}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 10%,#13364a,transparent 30%),radial-gradient(circle at 90% 0,#26304d,transparent 34%),var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,Segoe UI,Arial,sans-serif}main{max-width:1280px;margin:auto;padding:22px}.top{display:flex;align-items:end;justify-content:space-between;gap:16px;flex-wrap:wrap}.tabs{display:flex;gap:8px;margin:16px 0}.tab{width:auto;border-color:#34566b;background:#0d1a25;color:#bce7f0}.tab.active{background:var(--accent);color:#04201d}.grid{display:grid;grid-template-columns:350px 1fr;gap:16px}@media(max-width:900px){.grid{grid-template-columns:1fr}}.card{background:var(--panel);backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.13);border-radius:14px;padding:16px;box-shadow:0 20px 60px rgba(0,0,0,.22)}textarea,input,select,button{width:100%;border-radius:10px;border:1px solid #31495b;background:#08131d;color:#eaf5fb;padding:10px;margin:6px 0}button{background:var(--accent);color:#04201d;font-weight:800;cursor:pointer}.danger{background:#ff6b6b;color:#270506}.muted{color:var(--muted)}.row{display:grid;grid-template-columns:1fr 1fr;gap:8px}.bar{height:8px;background:#263948;border-radius:20px;overflow:hidden}.fill{height:100%;width:0;background:linear-gradient(90deg,var(--accent),#8ef0d1)}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #203241;text-align:left}th{color:#8aa2b3;position:sticky;top:0;background:#101b25}.ok{color:var(--good)}.bad{color:var(--bad)}.pill{display:inline-block;padding:3px 8px;border-radius:999px;background:#142636;color:#9fc2d7;font-size:12px}.ring{width:104px;height:104px;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--accent) 0deg,#263948 0deg);font-weight:900}.ring span{width:78px;height:78px;border-radius:50%;display:grid;place-items:center;background:#071018}.dash{display:grid;grid-template-columns:120px 1fr;gap:14px;align-items:center}.density-compact td,.density-compact th{padding:4px;font-size:12px}.hex{display:grid;grid-template-columns:repeat(32,1fr);gap:2px;margin-top:10px}.cell{aspect-ratio:1;background:#263948;border-radius:3px}.cell.good{background:#42e6aa}.cell.bad{background:#ff8585}.cell.mid{background:#ffd166}</style></head><body><main>
<div class=top><div><h1>MaybeEdgeScanner Sidecar</h1><p class=muted>Live SNI/IP/CIDR scanner with progress telemetry, safety policy, and filtered data grid.</p></div><div><button onclick="document.body.classList.toggle('density-compact')">Toggle density</button></div></div>
<div class=tabs><button class="tab active" onclick="showTab('scan',this)">Scan</button><button class=tab onclick="showTab('analytics',this)">Analytics</button><button class=tab onclick="showTab('help',this)">Help</button></div>
<div class=grid><section class=card><label>Targets</label><textarea id=targets rows=11>{{.Targets}}</textarea><label>SNIs</label><textarea id=snis rows=6>{{.SNIs}}</textarea>
<div class=row><input id=maxTargets type=number value=0 placeholder="0 = unlimited"><input id=batchSize type=number value=12000></div><div class=row><input id=threads type=number value=64><input id=timeout type=number value=2500></div><input id=visibleRows type=number value=1000 placeholder="Visible rows">
<div class=row><input id=ports value="443"><input id=path value="/"></div><select id=tlsFingerprint><option value=rotate>Rotate TLS fingerprint</option><option value=chrome>Chrome ClientHello</option><option value=firefox>Firefox ClientHello</option><option value=ios>iOS ClientHello</option><option value=randomized>Randomized ALPN ClientHello</option><option value=randomized-no-alpn>Randomized no-ALPN ClientHello</option></select><select id=safetyPreset><option value=standard>Standard policy</option><option value=safe_quick>Safe quick policy</option></select><div class=row><input id=rate type=number value=250 placeholder="Rate/sec"><input id=jitter type=number value=25 placeholder="Jitter ms"></div>
<label><input id=multi type=checkbox checked style="width:auto"> Multi-SNI</label><label><input id=http type=checkbox checked style="width:auto"> HTTP HEAD probe</label><label><input id=randomize type=checkbox checked style="width:auto"> Randomize target order</label><label><input id=safety type=checkbox checked style="width:auto"> Block reserved/unsafe ranges</label>
<button onclick=start()>Start Scan</button><button class=danger onclick=stop()>Stop</button></section>
<section class=card id=tab-scan><div class=dash><div class=ring id=ring><span id=ringText>0%</span></div><div><h3 id=status>Ready</h3><div class=bar><div class=fill id=fill></div></div><p id=metrics class=muted></p></div></div><table><thead><tr><th>Target</th><th>IP</th><th>SNI</th><th>Checks</th><th>ms</th><th>ALPN</th><th>Network</th><th>Provider</th></tr></thead><tbody id=rows></tbody></table></section>
<section class=card id=tab-analytics style="display:none"><h3>Analytics</h3><p class=muted id=analyticsText>No scan yet.</p><div class=hex id=hex></div></section>
<section class=card id=tab-help style="display:none"><h3>Safety and UX</h3><p class=muted>Rate/sec and jitter reduce IDS-like sequential bursts. Safety mode drops private, loopback, multicast, and default-route CIDRs. Use exports or /metrics for external dashboards.</p></section></div>
<script>
function authHeaders(extra){return Object.assign({},extra||{})}
let rows=[];function v(id){return document.getElementById(id).value}function set(s){document.getElementById('status').textContent=s}
function showTab(id,el){for(let x of ['scan','analytics','help'])document.getElementById('tab-'+x).style.display=x===id?'block':'none';for(let b of document.querySelectorAll('.tab'))b.classList.remove('active');el.classList.add('active')}
async function start(){rows=[];document.getElementById('rows').innerHTML='';document.getElementById('hex').innerHTML='';set('Starting');let r=await fetch('/api/scan',{method:'POST',headers:authHeaders({'content-type':'application/json'}),body:JSON.stringify({targets:v('targets').split(/[\s,;]+/).filter(Boolean),snis:v('snis').split(/[\s,;]+/).filter(Boolean),ports:v('ports').split(/[\s,;]+/).filter(Boolean).map(Number),http_path:v('path'),tls_fingerprint:v('tlsFingerprint'),safety_preset:v('safetyPreset'),max_targets:+v('maxTargets'),batch_size:+v('batchSize'),threads:+v('threads'),timeout_ms:+v('timeout'),rate_per_second:+v('rate'),jitter_ms:+v('jitter'),randomize:document.getElementById('randomize').checked,respect_safety:document.getElementById('safety').checked,multi_sni:document.getElementById('multi').checked,http_probe:document.getElementById('http').checked})});let rd=r.body.getReader(),d=new TextDecoder(),buf='';while(true){let x=await rd.read();if(x.done)break;buf+=d.decode(x.value,{stream:true});let parts=buf.split(/\n/);buf=parts.pop();for(let p of parts){if(!p.trim())continue;let e=JSON.parse(p);if(e.type==='init'){let sp=e.safety_policy||{};set('Scanning '+e.total+' jobs in '+e.batches+' batches · '+(sp.preset||'policy'))}if(e.type==='progress'){render(e.result,e.stats)}if(e.type==='done'){set(e.stopped?'Stopped':'Done')}}}}
async function stop(){await fetch('/api/stop',{method:'POST',headers:authHeaders()});set('Stopping')}
function esc(x){return String(x??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function render(r,s){rows.push(r);rows.sort((a,b)=>b.score-a.score||a.latency_ms-b.latency_ms);let visible=Math.max(1,+v('visibleRows')||rows.length);let shown=rows.slice(0,visible);let pct=s.checked*100/Math.max(1,s.total);document.getElementById('fill').style.width=pct+'%';document.getElementById('ring').style.background='conic-gradient(var(--accent) '+(pct*3.6)+'deg,#263948 0deg)';document.getElementById('ringText').textContent=Math.round(pct)+'%';document.getElementById('metrics').textContent='Checked '+s.checked+'/'+s.total+' · working '+s.working+' · TLS '+s.tls_working+' · HTTP '+s.http_working+' · batch '+s.batch+'/'+s.batches+' · showing '+shown.length+'/'+rows.length;document.getElementById('rows').innerHTML=shown.map(x=>'<tr title="'+esc((x.tls_version||'')+' '+(x.cert_subject||''))+'"><td>'+esc(x.target)+'</td><td>'+esc(x.ip+':'+x.port)+'</td><td>'+esc(x.sni||'--')+'</td><td><span class="'+(x.tcp?'ok':'bad')+'">TCP</span> <span class="'+(x.tls?'ok':'bad')+'">TLS</span> <span class="'+(x.http?'ok':'bad')+'">HTTP</span></td><td>'+(x.latency_ms||'')+'</td><td>'+esc(x.alpn||'--')+'</td><td><span class=pill>'+esc(x.network_classification)+'</span></td><td><span class=pill title="'+esc(x.provider_prefix||'')+'">'+esc(x.provider_id||'--')+'</span></td></tr>').join('');document.getElementById('analyticsText').textContent='Top score '+(rows[0]?.score||0)+' · network groups '+new Set(rows.map(x=>x.network_classification)).size+' · provider groups '+new Set(rows.map(x=>x.provider_id).filter(Boolean)).size;let h=document.getElementById('hex');{let c=document.createElement('div');c.className='cell '+(r.http?'good':r.tls||r.tcp?'mid':'bad');h.appendChild(c)}}
</script></main></body></html>`
	data := map[string]string{
		"Targets": strings.Join(loadLines("assets/default_edges_extra.txt"), "\n"),
		"SNIs":    strings.Join(loadLines("assets/default_snis.txt"), "\n"),
	}
	if activeControlPlane != nil {
		activeControlPlane.setBrowserCookie(w)
	}
	_ = template.Must(template.New("index").Parse(page)).Execute(w, data)
}

func grafanaDashboard(w http.ResponseWriter, _ *http.Request) {
	body, err := os.ReadFile(filepath.Clean("grafana-dashboard.json"))
	if err != nil {
		writePublicError(w, http.StatusNotFound, "DASHBOARD_NOT_FOUND", "grafana dashboard not found", nil)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(body)
}

func scan(w http.ResponseWriter, r *http.Request) {
	var serial uint64
	if r.Method != http.MethodPost {
		writePublicMethodNotAllowed(w, http.MethodPost)
		return
	}
	if activeControlPlane != nil {
		activeControlPlane.setState("scan_starting")
		defer activeControlPlane.setState("idle")
	}
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writePublicBadRequest(w, "invalid scan request body")
		return
	}
	metricScansStarted.Add(1)
	if activeControlPlane != nil {
		activeControlPlane.setState("scan_running")
	}
	req.normalize()
	routePlan, err := validateScanRoutePlugin(req.RoutePlugin)
	if err != nil {
		writePluginValidationError(w, "ROUTE_PLUGIN_INVALID", "route_plugin", publicPluginValidationMessage(err))
		return
	}
	globalBackoffNS.Store(0)
	explicitTargets := len(req.Targets) > 0
	skippedBefore := metricSafetySkipped.Load()
	targets := expandTargets(req.Targets, req.MaxTargets, req.MaxCIDRHosts, req.RespectSafety)
	expansionSafetySkipped := metricSafetySkipped.Load() - skippedBefore
	if len(targets) == 0 && !explicitTargets {
		targets = expandTargets(loadLines("assets/default_edges_extra.txt"), req.MaxTargets, req.MaxCIDRHosts, req.RespectSafety)
	}
	if len(targets) == 0 && explicitTargets {
		writeScanInputError(w, "NO_USABLE_TARGETS", "no usable targets after CIDR/range expansion and safety filtering", map[string]any{
			"submitted_target_count": len(req.Targets),
			"respect_safety":         req.RespectSafety,
		})
		return
	}
	if len(req.SNIs) == 0 {
		req.SNIs = loadLines("assets/default_snis.txt")
	}
	if req.MaxTargets > 0 && len(targets) > req.MaxTargets {
		targets = targets[:req.MaxTargets]
	}
	if req.Randomize {
		shuffleStrings(targets)
	}
	safetyPolicy := safetyPolicyObservation(req, len(targets))
	warnings := scanWarnings(req, targets)
	warnings = append(warnings, safetyPolicy.Warnings...)
	expansionSummary := map[string]any{
		"submitted_tokens": len(req.Targets),
		"expanded_targets": len(targets),
		"safety_skipped":   expansionSafetySkipped,
	}

	ctx, cancel := context.WithCancel(r.Context())
	activeCancelMu.Lock()
	if activeCancel != nil {
		activeCancel()
	}
	activeSerial++
	serial = activeSerial
	activeCancel = cancel
	activeCancelMu.Unlock()
	defer func() {
		activeCancelMu.Lock()
		if activeSerial == serial {
			activeCancel = nil
		}
		activeCancelMu.Unlock()
		globalBackoffNS.Store(0)
		cancel()
	}()

	w.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	jobsTotal := len(targets) * len(req.Ports)
	st := stats{Total: jobsTotal, Batches: int(math.Ceil(float64(len(targets)) / float64(req.BatchSize)))}
	if routePlan.Valid {
		if routePlan.HasRuntimeRoute() {
			warnings = append(warnings, "Route plan includes an attachable runtime dial path; requested and observed route IDs are emitted per result.")
		} else {
			warnings = append(warnings, "Route validation is present, but this scan request does not include an attachable runtime route dial path.")
		}
	}
	if err := enc.Encode(map[string]any{"type": "init", "total": st.Total, "batches": st.Batches, "warnings": warnings, "safety_policy": safetyPolicy, "expansion": expansionSummary, "route_plugin": routePlan.Public()}); err != nil {
		cancel()
		return
	}
	flush(flusher)

	var checked atomic.Int64
	var working atomic.Int64
	var tlsWorking atomic.Int64
	var httpWorking atomic.Int64
	var down atomic.Int64

	limiter := newRateLimiter(req.RatePerSecond)
	recentErrors := newErrorRingBuffer(64)
	for start, batchNo := 0, 1; start < len(targets) && ctx.Err() == nil; start, batchNo = start+req.BatchSize, batchNo+1 {
		end := min(len(targets), start+req.BatchSize)
		jobs := make(chan string)
		results := make(chan result, resultBufferSize(req.BatchSize))
		var wg sync.WaitGroup
		for i := 0; i < min(req.Threads, end-start); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for t := range jobs {
					if ctx.Err() != nil {
						return
					}
					for _, port := range req.Ports {
						if ctx.Err() != nil {
							return
						}
						if backoffDelay := globalBackoffNS.Load(); backoffDelay > 0 {
							select {
							case <-ctx.Done():
								return
							case <-time.After(time.Duration(backoffDelay)):
							}
						}
						waitRate(ctx, limiter, req.JitterMS)
						res := probe(ctx, t, port, req, batchNo, routePlan)
						select {
						case <-ctx.Done():
							return
						case results <- res:
						}
					}
				}
			}()
		}
		go func() {
			defer close(jobs)
			for _, t := range targets[start:end] {
				select {
				case <-ctx.Done():
					return
				case jobs <- t:
				}
			}
		}()
		go func() { wg.Wait(); close(results) }()
		for res := range results {
			c := int(checked.Add(1))
			metricScanResults.Add(1)
			if res.TCP || res.TLS || res.HTTP {
				working.Add(1)
			} else {
				down.Add(1)
			}
			if res.TLS {
				metricTLSPass.Add(1)
				tlsWorking.Add(1)
			}
			if res.HTTP {
				metricHTTPPass.Add(1)
				httpWorking.Add(1)
			}
			if res.TCP {
				metricTCPPass.Add(1)
			}
			if resultIndicatesTimeout(res) {
				metricTimeouts.Add(1)
			}
			if resultIndicatesReset(res) {
				metricResets.Add(1)
			}
			if res.Error != "" {
				recentErrors.Append(res.Error)
				trackAdaptiveBackoff(recentErrors.Snapshot(), req.RatePerSecond)
			}
			payloadStats := stats{
				Total: st.Total, Checked: c, Working: int(working.Load()),
				TLSWorking: int(tlsWorking.Load()), HTTPWorking: int(httpWorking.Load()),
				Down: int(down.Load()), Batches: st.Batches, Batch: batchNo,
			}
			if err := enc.Encode(map[string]any{"type": "progress", "result": res, "stats": payloadStats}); err != nil {
				cancel()
				return
			}
			flush(flusher)
		}
	}
	if ctx.Err() == nil {
		metricScansCompleted.Add(1)
	}
	if err := enc.Encode(map[string]any{"type": "done", "stopped": ctx.Err() != nil}); err != nil {
		cancel()
		return
	}
	flush(flusher)
}

func metrics(w http.ResponseWriter, _ *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w, "maybeedgescanner_scans_started_total %d\n", metricScansStarted.Load())
	_, _ = fmt.Fprintf(w, "maybeedgescanner_scans_completed_total %d\n", metricScansCompleted.Load())
	_, _ = fmt.Fprintf(w, "maybeedgescanner_results_total %d\n", metricScanResults.Load())
	_, _ = fmt.Fprintf(w, "maybeedgescanner_tcp_pass_total %d\n", metricTCPPass.Load())
	_, _ = fmt.Fprintf(w, "maybeedgescanner_tls_pass_total %d\n", metricTLSPass.Load())
	_, _ = fmt.Fprintf(w, "maybeedgescanner_http_pass_total %d\n", metricHTTPPass.Load())
	_, _ = fmt.Fprintf(w, "maybeedgescanner_timeout_total %d\n", metricTimeouts.Load())
	_, _ = fmt.Fprintf(w, "maybeedgescanner_reset_total %d\n", metricResets.Load())
	_, _ = fmt.Fprintf(w, "maybeedgescanner_dns_runs_total %d\n", metricDNSRuns.Load())
	_, _ = fmt.Fprintf(w, "maybeedgescanner_safety_skipped_total %d\n", metricSafetySkipped.Load())
	_, _ = fmt.Fprintf(w, "maybeedgescanner_backoff_events_total %d\n", metricBackoffEvents.Load())
	_, _ = fmt.Fprintf(w, "maybeedgescanner_goroutines %d\n", runtime.NumGoroutine())
	_, _ = fmt.Fprintf(w, "maybeedgescanner_heap_bytes %d\n", mem.HeapAlloc)
}

func routingPlugins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writePublicMethodNotAllowed(w, http.MethodGet)
		return
	}
	body, err := routingPluginsJSON()
	if err != nil {
		writePublicError(w, http.StatusInternalServerError, "PLUGIN_REGISTRY_UNAVAILABLE", "routing plugin registry unavailable", nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func providerCorpusStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writePublicMethodNotAllowed(w, http.MethodGet)
		return
	}
	status, ok := providerCorpusStore.Status(time.Now())
	if !ok {
		writePublicError(w, http.StatusNotFound, "PROVIDER_CORPUS_UNAVAILABLE", "provider corpus status unavailable", nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func validateRoutingPlugin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writePublicMethodNotAllowed(w, http.MethodPost)
		return
	}
	var cfg RoutingPluginConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writePluginValidationError(w, "PLUGIN_CONFIG_MALFORMED", "request_body", "invalid plugin validation request body")
		return
	}
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		writePluginValidationError(w, "PLUGIN_REGISTRY_UNAVAILABLE", "registry", "routing plugin registry unavailable")
		return
	}
	result, err := validateRoutingPluginConfig(registry, cfg)
	if err != nil {
		writePluginValidationError(w, "PLUGIN_CONFIG_INVALID", "config", publicPluginValidationMessage(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func writePluginValidationError(w http.ResponseWriter, code, field, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schema_version": sidecarAPIVersion,
		"valid":          false,
		"status":         "error",
		"phase":          publicErrorPhase(code),
		"retryable":      false,
		"error_code":     code,
		"field":          field,
		"message":        message,
	})
}

type scanRoutePlan struct {
	Valid      bool                          `json:"valid"`
	Validation RoutingPluginConfigValidation `json:"validation,omitempty"`
	RuntimeCfg *RouteConfig                  `json:"-"`
}

func validateScanRoutePlugin(cfg *RoutingPluginConfig) (scanRoutePlan, error) {
	if cfg == nil || strings.TrimSpace(cfg.PluginID) == "" {
		return scanRoutePlan{}, nil
	}
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		return scanRoutePlan{}, err
	}
	validation, err := validateRoutingPluginConfig(registry, *cfg)
	if err != nil {
		return scanRoutePlan{}, err
	}
	plan := scanRoutePlan{Valid: true, Validation: validation}
	runtimeCfg, runtimeOK := buildRouteRuntimeConfig(*cfg, validation)
	if runtimeOK {
		plan.RuntimeCfg = runtimeCfg
	}
	return plan, nil
}

func (p scanRoutePlan) Public() any {
	if !p.Valid {
		return nil
	}
	return p.Validation
}

func (p scanRoutePlan) ApplyRequestedToResult(res *result) {
	if res == nil || !p.Valid {
		return
	}
	res.RouteID = p.Validation.RouteID
	res.RequestedRouteID = p.Validation.RouteID
	res.RouteConfigReady = true
	res.RouteDialerReady = p.HasRuntimeRoute()
	res.RouteObserved = false
	res.RouteReadinessSource = "validation_template"
	if p.HasRuntimeRoute() {
		res.RouteEvidenceState = "requested_runtime_pending_observation"
	} else {
		res.RouteEvidenceState = "requested_observer_only"
	}
}

func (p scanRoutePlan) HasRuntimeRoute() bool {
	return p.Valid && p.RuntimeCfg != nil
}

func (p scanRoutePlan) RouteConfigForProbe(timeoutMS int) RouteConfig {
	cfg := *p.RuntimeCfg
	cfg.Timeout = time.Duration(timeoutMS) * time.Millisecond
	return cfg
}

func (p scanRoutePlan) ApplyObservedToResult(res *result, obs *RouteObservation) {
	if res == nil || !p.Valid || obs == nil {
		return
	}
	res.RouteUsed = strings.EqualFold(obs.Status, "success")
	res.RouteConfigReady = true
	res.RouteDialerReady = p.HasRuntimeRoute()
	res.RouteObserved = true
	res.ObservedRouteID = obs.RouteID
	res.ObservedRouteType = string(obs.RouteType)
	if res.RouteID == "" {
		res.RouteID = p.Validation.RouteID
	}
	if res.RequestedRouteID == "" {
		res.RequestedRouteID = p.Validation.RouteID
	}
	if res.RequestedRouteID != "" && res.ObservedRouteID != "" && res.RequestedRouteID != res.ObservedRouteID {
		res.RouteMismatchCode = "ROUTE_REQUEST_OBSERVATION_MISMATCH"
	}
	if res.RouteUsed {
		res.RouteEvidenceState = "observed_attached"
	} else {
		res.RouteEvidenceState = "observed_failed"
	}
	res.RouteID = obs.RouteID
	res.RouteProviderID = obs.ProviderID
	res.RouteBinding = obs.RouteBinding
	res.RouteProtocolMode = obs.ProtocolMode
	res.RouteAuthMode = obs.AuthMode
	res.RouteDNSPolicy = obs.DNSPolicy
	res.RouteReadiness = obs.Status
	res.RouteReadinessSource = "observation"
	if obs.ErrorCode != "" {
		res.RouteErrorCode = obs.ErrorCode
	}
	res.RouteStrategy = p.Validation.RouteStrategy
	res.RouteProviderChain = p.Validation.ProviderChain
	res.RouteFrontingPolicy = p.Validation.FrontingPolicy
	res.RouteLANSharing = p.Validation.LANSharing
	res.RouteBeastMode = p.Validation.BeastMode
}

func (p scanRoutePlan) ApplyRouteNotObserved(res *result) {
	if res == nil || !p.Valid {
		return
	}
	if res.RouteID == "" {
		res.RouteID = p.Validation.RouteID
	}
	if res.RequestedRouteID == "" {
		res.RequestedRouteID = p.Validation.RouteID
	}
	res.RouteUsed = false
	res.RouteConfigReady = true
	res.RouteDialerReady = p.HasRuntimeRoute()
	res.RouteObserved = false
	res.RouteReadiness = p.Validation.Observation.ReadinessState
	res.RouteReadinessSource = "validation_template"
	if p.HasRuntimeRoute() {
		res.RouteEvidenceState = "requested_runtime_not_observed"
		res.RouteMismatchCode = "ROUTE_REQUEST_NOT_OBSERVED"
		if res.RouteErrorCode == "" {
			res.RouteErrorCode = "ROUTE_REQUEST_NOT_OBSERVED"
		}
		return
	}
	res.RouteEvidenceState = "requested_observer_only"
}

func buildRouteRuntimeConfig(cfg RoutingPluginConfig, validation RoutingPluginConfigValidation) (*RouteConfig, bool) {
	if !validation.Valid || !validation.Attachable {
		return nil, false
	}
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return nil, false
	}
	if err := validateProxyEndpoint(endpoint); err != nil {
		return nil, false
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return nil, false
	}
	var routeType RouteType
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "socks5":
		routeType = RouteSOCKS5
	case "http", "http-connect":
		routeType = RouteHTTPConnect
	default:
		return nil, false
	}
	runtimeCfg := &RouteConfig{
		RouteID:        cfg.RouteID,
		Type:           routeType,
		ProxyAddress:   parsed.Host,
		DNSPolicy:      validation.DNSPolicy,
		Timeout:        time.Second,
		ProviderID:     firstNonEmpty(validation.PluginID, validation.PluginType),
		RouteBinding:   validation.RouteBinding,
		ProtocolMode:   validation.ProtocolMode,
		AuthMode:       validation.AuthMode,
		SplitTunnel:    validation.SplitTunnel,
		UpstreamMode:   validation.UpstreamMode,
		DownstreamMode: validation.DownstreamMode,
	}
	return runtimeCfg, true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func publicPluginValidationMessage(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, errPluginConfig):
		return "routing plugin configuration is invalid; inspect error_code, field, and local diagnostics"
	case errors.Is(err, errPluginDescriptor):
		return "routing plugin registry is invalid"
	case errors.Is(err, errRouteValidation):
		return "route configuration is invalid"
	default:
		return "routing plugin validation failed"
	}
}

func exportNmap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writePublicMethodNotAllowed(w, http.MethodPost)
		return
	}
	var rows []result
	if err := json.NewDecoder(r.Body).Decode(&rows); err != nil {
		writePublicBadRequest(w, "invalid export request body")
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = fmt.Fprintln(w, `<?xml version="1.0" encoding="UTF-8"?>`)
	_, _ = fmt.Fprintln(w, `<nmaprun scanner="MaybeEdgeScanner" args="edge scan export">`)
	for _, row := range rows {
		if row.IP == "" || row.Port <= 0 {
			continue
		}
		state := "closed"
		if row.TCP || row.TLS || row.HTTP {
			state = "open"
		}
		addrType := "ipv4"
		if strings.Contains(row.IP, ":") {
			addrType = "ipv6"
		}
		_, _ = fmt.Fprintf(w, `<host><status state="up"/><address addr="%s" addrtype="%s"/><ports><port protocol="tcp" portid="%d"><state state="%s"/><service name="%s" product="%s"/></port></ports></host>`+"\n",
			xmlEscape(row.IP), addrType, row.Port, state, xmlEscape(row.SNI), xmlEscape(row.NetworkClassification))
	}
	_, _ = fmt.Fprintln(w, `</nmaprun>`)
}

func xmlEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			if r == '\t' || r == '\n' || r == '\r' || r >= 0x20 {
				b.WriteRune(r)
			} else {
				b.WriteRune('?')
			}
		}
	}
	return b.String()
}

func (r *scanRequest) normalize() {
	r.Targets = unique(r.Targets)
	r.SNIs = unique(r.SNIs)
	if r.Threads <= 0 {
		r.Threads = max(4, runtime.NumCPU()*2)
	}
	if r.TimeoutMS <= 0 {
		r.TimeoutMS = 2500
	}
	var ports []int
	for _, port := range r.Ports {
		if port > 0 && port < 65536 {
			ports = append(ports, port)
		}
	}
	if len(ports) == 0 {
		ports = []int{443}
	}
	r.Ports = ports
	if strings.TrimSpace(r.HTTPPath) == "" {
		r.HTTPPath = "/"
	}
	if !strings.HasPrefix(r.HTTPPath, "/") {
		r.HTTPPath = "/" + r.HTTPPath
	}
	if r.MaxTargets < 0 {
		r.MaxTargets = 0
	}
	if r.MaxCIDRHosts < 0 {
		r.MaxCIDRHosts = 0
	}
	if r.BatchSize <= 0 {
		r.BatchSize = 12000
	}
	if r.RatePerSecond < 0 {
		r.RatePerSecond = 0
	}
	if r.JitterMS < 0 {
		r.JitterMS = 0
	}
	r.applySafetyPreset()
	r.TLSFingerprint = normalizeTLSFingerprint(r.TLSFingerprint)
}

func probe(ctx context.Context, target string, port int, req scanRequest, batchNo int, routePlan scanRoutePlan) result {
	res := result{Target: target, Port: port, BatchNumber: batchNo, NetworkClassification: "unknown"}
	routePlan.ApplyRequestedToResult(&res)
	var phases []PhaseResult
	dnsStart := time.Now()
	ips, sni, err := resolveTargetCandidates(target)
	if len(ips) > 0 {
		res.IP = ips[0]
	}
	res.SNI = sni
	if err != nil {
		dnsPhase := newPhaseFailure("dns", err, time.Since(dnsStart).Milliseconds(), "DNS_RESOLUTION_FAILED")
		res.PhaseResults = []PhaseResult{dnsPhase}
		res.FinalPhase = "dns"
		res.ErrorCode = dnsPhase.ErrorCode
		res.Error = err.Error()
		return res
	}
	snis := candidateSNIs(sni, req.SNIs, req.MultiSNI)
	var lastErr error
	var lastErrCode string
	var observedRoute *RouteObservation

	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		res.IP = ip
		res.applyProviderObservation(observeProvider(ip))
		res.NetworkClassification = detectNetworkClassification(ip, sni, "")
		var tlsAttempted bool
		var anyTCPOK bool
		for _, candidateSNI := range snis {
			if ctx.Err() != nil {
				break
			}
			fingerprint := chooseTLSFingerprint(req.TLSFingerprint)
			tlsAttempted = true
			start := time.Now()
			conn, tcpOK, tlsInfo, tlsOK, tlsErr, routeObs := tlsProbeOpen(ctx, ip, port, candidateSNI, req.TimeoutMS, fingerprint, DPIObfuscationOptions{EnablePayloadSplitting: req.EnablePayloadSplitting, SplitByteBoundary: req.SplitByteBoundary}, routePlan)
			if tcpOK {
				anyTCPOK = true
			}
			if routeObs != nil {
				observedRoute = routeObs
			}
			if tlsErr != nil {
				lastErr = tlsErr
				lastErrCode = classifyNetworkError(tlsErr, "tls")
				phases = append(phases, newPhaseFailure("tls", tlsErr, time.Since(start).Milliseconds(), lastErrCode))
			}
			if tlsOK {
				elapsed := time.Since(start).Milliseconds()
				res.TCP = true
				res.LatencyMS = elapsed
				res.TLS = true
				res.SNI = candidateSNI
				res.TLSVersion = tlsInfo.Version
				res.TLSCipher = tlsInfo.Cipher
				res.CertVerified = tlsInfo.Verified
				res.ALPN = tlsInfo.ALPN
				res.TLSFingerprint = fingerprint
				res.CertSubject = tlsInfo.Subject
				res.NetworkClassification = detectNetworkClassification(ip, candidateSNI, tlsInfo.Subject)
				phases = append(phases, newPhaseSuccess("tcp", elapsed))
				if strings.TrimSpace(candidateSNI) != "" && !tlsInfo.Verified {
					phases = append(phases, newPhaseFailure("tls", fmt.Errorf("hostname verification failed"), elapsed, "TLS_VERIFY_HOSTNAME_MISMATCH"))
				} else {
					phases = append(phases, newPhaseSuccess("tls", elapsed))
				}
				if req.HTTPProbe {
					httpStart := time.Now()
					res.HTTP, res.HTTPStatus, res.ServerHeader, res.CacheHeader, res.AltSvc, res.HTTP3Hint, res.HTTPProbeCode = probeHTTPOverNegotiatedALPN(ctx, conn, ip, candidateSNI, req.HTTPPath, req.TimeoutMS, tlsInfo.ALPN)
					httpPhase := httpPhaseFromALPN(tlsInfo.ALPN)
					httpMs := time.Since(httpStart).Milliseconds()
					if res.HTTP {
						phases = append(phases, newPhaseSuccess(httpPhase, httpMs))
					} else if strings.TrimSpace(res.HTTPProbeCode) != "" {
						phases = append(phases, newPhaseFailure(httpPhase, fmt.Errorf("%s", res.HTTPProbeCode), httpMs, res.HTTPProbeCode))
					}
				}
				_ = conn.Close()
				break
			}
		}
		if anyTCPOK {
			res.TCP = true
		}
		if !res.TLS && tlsAttempted && !anyTCPOK {
			tcpStart := time.Now()
			res.TCP, err = tcpWithError(ctx, ip, port, req.TimeoutMS, routePlan, &observedRoute)
			tcpMs := time.Since(tcpStart).Milliseconds()
			res.LatencyMS = tcpMs
			if err != nil {
				lastErr = err
				lastErrCode = classifyNetworkError(err, "tcp")
				phases = append(phases, newPhaseFailure("tcp", err, tcpMs, lastErrCode))
			} else {
				phases = append(phases, newPhaseSuccess("tcp", tcpMs))
			}
		}
		if res.TLS || res.TCP {
			break
		}
	}
	if !res.TLS && !res.TCP && lastErr != nil {
		res.ErrorCode = lastErrCode
		res.Error = lastErr.Error()
	}
	if routePlan.Valid {
		if observedRoute != nil {
			routePlan.ApplyObservedToResult(&res, observedRoute)
		} else {
			routePlan.ApplyRouteNotObserved(&res)
		}
		if routePhase, ok := buildRoutePhaseResult(res); ok {
			phases = append(phases, routePhase)
		}
	}
	res.PhaseResults = phases
	res.FinalPhase = finalizeFinalPhase(res, phases, lastErrCode)
	if routePlan.Valid && strings.TrimSpace(res.RouteErrorCode) != "" && res.FinalPhase == "" {
		res.FinalPhase = "route"
	}
	res.Score = score(res)
	return res
}

func resolveTarget(target string) (string, string, error) {
	ips, sni, err := resolveTargetCandidates(target)
	if err != nil {
		return "", sni, err
	}
	return ips[0], sni, nil
}

func resolveTargetCandidates(target string) ([]string, string, error) {
	if net.ParseIP(target) != nil {
		return []string{target}, "", nil
	}
	ips, err := net.LookupIP(target)
	if err != nil || len(ips) == 0 {
		return nil, "", errors.New("DNS failed")
	}
	var out []string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	for _, ip := range ips {
		if ip.To4() == nil && ip.To16() != nil {
			out = append(out, ip.String())
		}
	}
	if len(out) == 0 {
		return nil, "", errors.New("no IP address")
	}
	return uniqueInOrder(out), target, nil
}

func candidateSNIs(resolvedSNI string, corpus []string, multiSNI bool) []string {
	if multiSNI {
		candidates := make([]string, 0, len(corpus)+1)
		if strings.TrimSpace(resolvedSNI) != "" {
			candidates = append(candidates, resolvedSNI)
		}
		candidates = append(candidates, corpus...)
		return uniqueInOrder(candidates)
	}
	if strings.TrimSpace(resolvedSNI) != "" {
		return []string{resolvedSNI}
	}
	if len(corpus) > 0 {
		return []string{corpus[0]}
	}
	return []string{""}
}

func uniqueInOrder(xs []string) []string {
	set := make(map[string]bool)
	var out []string
	for _, x := range xs {
		for _, part := range strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ';' || r == '\r' || r == '\n' || r == '\t' || r == ' ' }) {
			part = strings.TrimSpace(part)
			if part != "" && !set[part] {
				set[part] = true
				out = append(out, part)
			}
		}
	}
	return out
}

func tcp(ctx context.Context, ip string, port int, timeoutMS int) bool {
	ok, _ := tcpWithError(ctx, ip, port, timeoutMS, scanRoutePlan{}, nil)
	return ok
}

func tcpWithError(ctx context.Context, ip string, port int, timeoutMS int, routePlan scanRoutePlan, observedRoute **RouteObservation) (bool, error) {
	network := "tcp4"
	if strings.Contains(ip, ":") {
		network = "tcp6"
	}
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	if routePlan.HasRuntimeRoute() {
		cfg := routePlan.RouteConfigForProbe(timeoutMS)
		conn, obs, err := dialViaRoute(ctx, network, target, cfg)
		if observedRoute != nil {
			*observedRoute = &obs
		}
		if err != nil {
			return false, err
		}
		_ = conn.Close()
		return true, nil
	}
	d := net.Dialer{Timeout: time.Duration(timeoutMS) * time.Millisecond}
	conn, err := d.DialContext(ctx, network, target)
	if err != nil {
		return false, err
	}
	_ = conn.Close()
	return true, nil
}

type tlsInfo struct {
	Version  string
	Cipher   string
	ALPN     string
	Verified bool
	Subject  string
}

func tlsProbe(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string, opts DPIObfuscationOptions) (tlsInfo, bool) {
	conn, _, info, ok, _, _ := tlsProbeOpen(ctx, ip, port, sni, timeoutMS, fingerprint, opts, scanRoutePlan{})
	if conn != nil {
		_ = conn.Close()
	}
	return info, ok
}

func tlsProbeOpen(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string, opts DPIObfuscationOptions, routePlan scanRoutePlan) (*tls.UConn, bool, tlsInfo, bool, error, *RouteObservation) {
	conn, tcpOK, err, routeObs := dialUTLS(ctx, ip, port, sni, timeoutMS, fingerprint, opts, routePlan)
	if err != nil {
		return nil, tcpOK, tlsInfo{}, false, err, routeObs
	}
	state := conn.ConnectionState()
	info := tlsInfo{Version: tlsVersionName(state.Version), Cipher: cipherSuiteName(state.CipherSuite), ALPN: state.NegotiatedProtocol}
	if len(state.PeerCertificates) > 0 {
		verifyName := strings.TrimSpace(sni)
		if verifyName == "" {
			verifyName = conn.RemoteAddr().String()
			if host, _, err := net.SplitHostPort(verifyName); err == nil {
				verifyName = host
			}
		}
		optsVerify := x509.VerifyOptions{
			DNSName:       verifyName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range state.PeerCertificates[1:] {
			optsVerify.Intermediates.AddCert(cert)
		}
		_, verifyErr := state.PeerCertificates[0].Verify(optsVerify)
		info.Verified = verifyErr == nil
		info.Subject = state.PeerCertificates[0].Subject.String()
	}
	if ctx.Err() != nil {
		_ = conn.Close()
		return nil, true, info, false, ctx.Err(), routeObs
	}
	return conn, true, info, true, nil, routeObs
}

func httpProbe(ctx context.Context, ip string, port int, sni, path string, timeoutMS int, fingerprint string) (bool, int, string, string, string, bool) {
	conn, _, err, _ := dialUTLSWithALPN(ctx, ip, port, sni, timeoutMS, fingerprint, []string{"http/1.1"}, DPIObfuscationOptions{}, scanRoutePlan{})
	if err != nil {
		return false, 0, "", "", "", false
	}
	defer conn.Close()
	return httpProbeConn(ctx, conn, ip, sni, path, timeoutMS)
}

func httpProbeConn(ctx context.Context, conn net.Conn, ip string, sni, path string, timeoutMS int) (bool, int, string, string, string, bool) {
	rollingDeadline := time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
	_ = conn.SetDeadline(rollingDeadline)

	host := strings.TrimSpace(sni)
	if host == "" {
		host = ip
	}
	if _, err := fmt.Fprintf(conn, "HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: MaybeScanner/1.2\r\nCache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nX-Maybe-Cachebuster: %d\r\nConnection: close\r\n\r\n", path, host, time.Now().UnixNano()); err != nil {
		return false, 0, "", "", "", false
	}
	reader := pooledReader(io.LimitReader(conn, 64*1024))
	defer putReader(reader)

	_ = conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
	line, err := readLimitedLine(reader, 4096)
	status := parseHTTPStatus(line)
	server, cache, altSvc := "", "", ""
	if err == nil && status > 0 {
		for i := 0; i < 48; i++ {
			_ = conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
			header, hErr := readLimitedLine(reader, 4096)
			if hErr != nil {
				break
			}
			header = strings.TrimRight(header, "\r\n")
			if strings.TrimSpace(header) == "" {
				break
			}
			lower := strings.ToLower(header)
			if strings.HasPrefix(lower, "server:") {
				server = strings.TrimSpace(header[len("server:"):])
			}
			if strings.HasPrefix(lower, "x-cache:") || strings.HasPrefix(lower, "cf-cache-status:") || strings.HasPrefix(lower, "age:") {
				if cache != "" {
					cache += "; "
				}
				cache += strings.TrimSpace(header)
			}
			if strings.HasPrefix(lower, "alt-svc:") {
				altSvc = strings.TrimSpace(header[len("alt-svc:"):])
			}
		}
	}
	return ctx.Err() == nil && err == nil && status > 0 && status < 500, status, server, cache, altSvc, strings.Contains(strings.ToLower(altSvc), "h3")
}

func probeHTTPOverNegotiatedALPN(ctx context.Context, conn net.Conn, ip string, sni string, path string, timeoutMS int, negotiatedALPN string) (bool, int, string, string, string, bool, string) {
	if strings.EqualFold(strings.TrimSpace(negotiatedALPN), "h2") {
		return false, 0, "", "", "", false, "HTTP2_UNSUPPORTED_IN_PROBE"
	}
	httpOK, status, server, cache, altSvc, http3 := httpProbeConn(ctx, conn, ip, sni, path, timeoutMS)
	return httpOK, status, server, cache, altSvc, http3, ""
}

func dialUTLS(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string, opts DPIObfuscationOptions, routePlan scanRoutePlan) (*tls.UConn, bool, error, *RouteObservation) {
	return dialUTLSWithALPN(ctx, ip, port, sni, timeoutMS, fingerprint, []string{"h2", "http/1.1"}, opts, routePlan)
}

func dialUTLSWithALPN(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string, nextProtos []string, opts DPIObfuscationOptions, routePlan scanRoutePlan) (*tls.UConn, bool, error, *RouteObservation) {
	network := "tcp4"
	if strings.Contains(ip, ":") {
		network = "tcp6"
	}
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	var rawConn net.Conn
	var routeObs *RouteObservation
	if routePlan.HasRuntimeRoute() {
		cfg := routePlan.RouteConfigForProbe(timeoutMS)
		conn, obs, err := dialViaRoute(ctx, network, target, cfg)
		routeObs = &obs
		if err != nil {
			return nil, false, err, routeObs
		}
		rawConn = conn
	} else {
		conn, err := DialObfuscatedSocket(ctx, network, target, time.Duration(timeoutMS)*time.Millisecond, opts)
		if err != nil {
			return nil, false, err, nil
		}
		rawConn = conn
	}
	deadline := time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
	_ = rawConn.SetDeadline(deadline)
	serverName := strings.TrimSpace(sni)
	conn := tls.UClient(rawConn, &tls.Config{
		ServerName: serverName, MinVersion: tls.VersionTLS12, NextProtos: nextProtos,
		// This is a scanner: continue handshakes so mismatched SNI/Host routes and
		// edge certificates can be measured and reported instead of hidden as TLS failures.
		InsecureSkipVerify: true,
	}, clientHelloID(fingerprint))
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = rawConn.Close()
		case <-done:
		}
	}()
	if err := conn.Handshake(); err != nil {
		close(done)
		_ = rawConn.Close()
		return nil, true, err, routeObs
	}
	close(done)
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, true, err, routeObs
	}
	_ = conn.SetDeadline(deadline)
	return conn, true, nil, routeObs
}

func normalizeTLSFingerprint(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "auto", "rotate":
		return "rotate"
	case "chrome", "firefox", "ios", "randomized", "randomized-no-alpn":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return "rotate"
	}
}

func chooseTLSFingerprint(mode string) string {
	if mode != "rotate" {
		return mode
	}
	choices := []string{"chrome", "firefox", "randomized"}
	return choices[rand.Intn(len(choices))]
}

func clientHelloID(fingerprint string) tls.ClientHelloID {
	switch fingerprint {
	case "chrome":
		return tls.HelloChrome_Auto
	case "firefox":
		return tls.HelloFirefox_Auto
	case "ios":
		return tls.HelloIOS_Auto
	case "randomized-no-alpn":
		return tls.HelloRandomizedNoALPN
	default:
		return tls.HelloRandomizedALPN
	}
}

func cipherSuiteName(id uint16) string {
	switch id {
	case 0x1301:
		return "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		return "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case 0xc02b:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case 0xc02f:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case 0xc02c:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case 0xc030:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case 0xcca9:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
	case 0xcca8:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
	default:
		return fmt.Sprintf("0x%04x", id)
	}
}

func score(r result) int {
	s := 0
	if r.TCP {
		s += 20
	}
	if r.TLS {
		s += 35
	}
	if r.HTTP {
		s += 35
	}
	if strings.EqualFold(r.TLSVersion, "TLS1.3") {
		s += 8
	}
	if strings.EqualFold(r.ALPN, "h2") {
		s += 7
	}
	if r.HTTP3Hint {
		s += 6
	}
	if r.NetworkClassification != "" && r.NetworkClassification != "unknown" {
		s += 8
	}
	if r.TLSFingerprint != "" {
		s += 3
	}
	if r.LatencyMS > 0 {
		s += max(0, 45-int(math.Log1p(float64(r.LatencyMS))*8))
	}
	if r.Error != "" {
		s -= 8
	}
	if s < 0 {
		return 0
	}
	return s
}

func classifyNetworkError(err error, phase string) string {
	if err == nil {
		return ""
	}
	lower := strings.ToLower(err.Error())
	prefix := "SCAN"
	switch phase {
	case "dns":
		prefix = "DNS"
	case "tcp":
		prefix = "TCP_CONNECT"
	case "tls":
		prefix = "TLS_HANDSHAKE"
	case "http":
		prefix = "HTTP"
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(lower, "timeout"):
		return prefix + "_TIMEOUT"
	case strings.Contains(lower, "reset"):
		return prefix + "_RESET"
	case strings.Contains(lower, "refused"):
		return prefix + "_REFUSED"
	default:
		return prefix + "_FAILED"
	}
}

func detectNetworkClassification(ip, sni, cert string) string {
	if addr, err := netip.ParseAddr(ip); err == nil {
		if classification, ok := networkClassificationIndex.MatchLongestPrefix(addr); ok {
			return classification
		}
	}
	host := strings.ToLower(sni + " " + cert)
	switch {
	case strings.Contains(host, "cloudflare"):
		return "cloudflare"
	case strings.Contains(host, "github") || strings.Contains(host, "fastly"):
		return "fastly"
	case strings.Contains(host, "akamai"):
		return "akamai"
	case strings.Contains(host, "cloudfront") || strings.Contains(host, "amazon"):
		return "cloudfront"
	default:
		return "unknown"
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

func parseHTTPStatus(line string) int {
	parts := strings.Fields(line)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return 0
	}
	code, _ := strconv.Atoi(parts[1])
	return code
}

func loadLines(name string) []string {
	f, err := os.Open(filepath.Clean(name))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return unique(out)
}

func expansionBudget(n int) int {
	if n <= 0 {
		return math.MaxInt
	}
	return n
}

func expandTargets(raw []string, capCount int, maxCIDRHosts int, respectSafety bool) []string {
	capCount = expansionBudget(capCount)
	maxCIDRHosts = expansionBudget(maxCIDRHosts)
	set := make(map[[16]byte]bool)
	var out []string
	for _, item := range raw {
		quotaRemaining := capCount - len(out)
		if quotaRemaining <= 0 {
			break
		}
		for _, expanded := range expandOneStateful(strings.TrimSpace(item), min(maxCIDRHosts, quotaRemaining), respectSafety, set) {
			if expanded != "" {
				addr, err := netip.ParseAddr(expanded)
				if err == nil {
					set[addr.As16()] = true
				}
				out = append(out, expanded)
			}
		}
	}
	return out
}

func expandOneStateful(s string, remaining int, respectSafety bool, seen map[[16]byte]bool) []string {
	if remaining <= 0 || s == "" {
		return nil
	}
	if strings.Contains(s, "-") && !strings.Contains(s, "/") {
		return expandRange(s, remaining, respectSafety, seen)
	}
	if !strings.Contains(s, "/") {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil
		}
		if seen[addr.As16()] {
			return nil
		}
		if respectSafety && isReservedOrUnsafe(addr) {
			return nil
		}
		seen[addr.As16()] = true
		return []string{s}
	}
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return nil
	}
	prefix = prefix.Masked()
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	current := prefix.Addr()
	if current.Is4() && hostBits > 1 {
		current = current.Next()
	}
	var out []string
	for current.IsValid() && prefix.Contains(current) && len(out) < remaining {
		if current.Is4() && hostBits > 1 && !prefix.Contains(current.Next()) {
			break
		}
		if seen[current.As16()] {
			current = current.Next()
			continue
		}
		seen[current.As16()] = true
		if !respectSafety || !isReservedOrUnsafe(current) {
			out = append(out, current.String())
		} else {
			metricSafetySkipped.Add(1)
		}
		current = current.Next()
	}
	return out
}

func expandRange(s string, remaining int, respectSafety bool, seen map[[16]byte]bool) []string {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 || remaining <= 0 {
		return nil
	}
	start, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil
	}
	end, err := netip.ParseAddr(strings.TrimSpace(parts[1]))
	if err != nil || start.Is4() != end.Is4() {
		return nil
	}
	if start.Compare(end) > 0 {
		return nil
	}
	var out []string
	for current := start; current.IsValid() && current.Compare(end) <= 0 && len(out) < remaining; current = current.Next() {
		if seen[current.As16()] {
			continue
		}
		seen[current.As16()] = true
		if !respectSafety || !isReservedOrUnsafe(current) {
			out = append(out, current.String())
		} else {
			metricSafetySkipped.Add(1)
		}
	}
	return out
}

func isReservedOrUnsafe(addr netip.Addr) bool {
	for _, prefix := range safetyCIDRPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsMulticast() || addr.IsUnspecified()
}

func loadSafetyPrefixes() []netip.Prefix {
	lines := append([]string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
	}, loadLines("assets/do_not_scan_cidrs.txt")...)
	var prefixes []netip.Prefix
	seen := map[string]bool{}
	for _, line := range lines {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(line))
		if err != nil {
			continue
		}
		key := prefix.Masked().String()
		if !seen[key] {
			seen[key] = true
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	return prefixes
}

var readerPool = sync.Pool{New: func() any {
	return bufio.NewReaderSize(nil, 16*1024)
}}

func pooledReader(r io.Reader) *bufio.Reader {
	reader := readerPool.Get().(*bufio.Reader)
	reader.Reset(r)
	return reader
}

func putReader(reader *bufio.Reader) {
	reader.Reset(bytes.NewReader(nil))
	readerPool.Put(reader)
}

func readLimitedLine(reader *bufio.Reader, limit int) (string, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				line = append(line, chunk...)
				if len(line) >= limit {
					return "", errors.New("line too long")
				}
				continue
			}
			line = append(line, chunk...)
			if len(line) > limit {
				return "", errors.New("line too long")
			}
			return string(line), err
		}
		line = append(line, chunk...)
		break
	}
	if len(line) > limit {
		return "", errors.New("line too long")
	}
	return string(line), nil
}

type errorRingBuffer struct {
	storage []string
	cursor  int
	full    bool
}

func newErrorRingBuffer(capacity int) *errorRingBuffer {
	if capacity < 1 {
		capacity = 1
	}
	return &errorRingBuffer{storage: make([]string, capacity)}
}

func (rb *errorRingBuffer) Append(errText string) {
	if rb == nil || len(rb.storage) == 0 {
		return
	}
	rb.storage[rb.cursor] = errText
	rb.cursor = (rb.cursor + 1) % len(rb.storage)
	if rb.cursor == 0 {
		rb.full = true
	}
}

func (rb *errorRingBuffer) Snapshot() []string {
	if rb == nil || len(rb.storage) == 0 {
		return nil
	}
	count := rb.cursor
	start := 0
	if rb.full {
		count = len(rb.storage)
		start = rb.cursor
	}
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		errText := rb.storage[(start+i)%len(rb.storage)]
		if errText != "" {
			out = append(out, errText)
		}
	}
	return out
}

func trackAdaptiveBackoff(recentErrors []string, ratePerSecond int) {
	if ratePerSecond <= 0 || len(recentErrors) < 24 {
		globalBackoffNS.Store(0)
		return
	}
	var noisy int
	for _, errText := range recentErrors {
		lower := strings.ToLower(errText)
		if strings.Contains(lower, "timeout") || strings.Contains(lower, "reset") {
			noisy++
		}
	}
	if noisy*100/len(recentErrors) >= 40 {
		metricBackoffEvents.Add(1)
		delay := time.Duration(min(2000, 250+noisy*25)) * time.Millisecond
		globalBackoffNS.Store(delay.Nanoseconds())
	}
}

func scanWarnings(req scanRequest, targets []string) []string {
	var warnings []string
	if req.BatchSize > resultBufferSize(req.BatchSize) {
		warnings = append(warnings, "Batch size is preserved; the internal result channel buffer is bounded to protect process memory.")
	}
	if req.RatePerSecond == 0 {
		warnings = append(warnings, "No rate limit configured: scans may look bursty to IDS/IPS systems.")
	}
	unsafe := 0
	for _, target := range targets {
		if addr, err := netip.ParseAddr(target); err == nil {
			if isReservedOrUnsafe(addr) {
				unsafe++
				if unsafe >= 5 {
					break
				}
			}
		}
	}
	if unsafe > 0 {
		warnings = append(warnings, "Reserved/private/special-use addresses were present and are skipped when safety mode is enabled.")
	}
	return warnings
}

func resultBufferSize(batchSize int) int {
	if batchSize <= 0 {
		return 1
	}
	return min(batchSize, 1048576)
}

func shuffleStrings(xs []string) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(xs), func(i, j int) { xs[i], xs[j] = xs[j], xs[i] })
}

func newRateLimiter(ratePerSecond int) *rate.Limiter {
	if ratePerSecond <= 0 {
		return nil
	}
	burst := max(1, min(ratePerSecond, 512))
	return rate.NewLimiter(rate.Limit(ratePerSecond), burst)
}

func waitRate(ctx context.Context, limiter *rate.Limiter, jitterMS int) {
	if limiter != nil {
		if err := limiter.Wait(ctx); err != nil {
			return
		}
	}
	if jitterMS > 0 {
		delay := time.Duration(rand.Intn(jitterMS+1)) * time.Millisecond
		select {
		case <-ctx.Done():
		case <-time.After(delay):
		}
	}
}

func unique(xs []string) []string {
	set := make(map[string]bool)
	var out []string
	for _, x := range xs {
		for _, part := range strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ';' || r == '\r' || r == '\n' || r == '\t' || r == ' ' }) {
			part = strings.TrimSpace(part)
			if part != "" && !set[part] {
				set[part] = true
				out = append(out, part)
			}
		}
	}
	sort.Strings(out)
	return out
}

func flush(f http.Flusher) {
	if f != nil {
		f.Flush()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func atoi(s string, fallback int) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return v
}
