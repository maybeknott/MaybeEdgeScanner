package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
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
)

type scanRequest struct {
	Targets        []string `json:"targets"`
	SNIs           []string `json:"snis"`
	Ports          []int    `json:"ports"`
	HTTPPath       string   `json:"http_path"`
	Threads        int      `json:"threads"`
	TimeoutMS      int      `json:"timeout_ms"`
	MaxTargets     int      `json:"max_targets"`
	MaxCIDRHosts   int      `json:"max_cidr_hosts"`
	BatchSize      int      `json:"batch_size"`
	MultiSNI       bool     `json:"multi_sni"`
	HTTPProbe      bool     `json:"http_probe"`
	Randomize      bool     `json:"randomize"`
	RatePerSecond  int      `json:"rate_per_second"`
	JitterMS       int      `json:"jitter_ms"`
	RespectSafety  bool     `json:"respect_safety"`
	TLSFingerprint string   `json:"tls_fingerprint"`
}

type result struct {
	Target         string `json:"target"`
	IP             string `json:"ip"`
	Port           int    `json:"port"`
	SNI            string `json:"sni"`
	TCP            bool   `json:"tcp"`
	TLS            bool   `json:"tls"`
	HTTP           bool   `json:"http"`
	HTTPStatus     int    `json:"http_status"`
	TLSVersion     string `json:"tls_version,omitempty"`
	TLSCipher      string `json:"tls_cipher,omitempty"`
	ALPN           string `json:"alpn,omitempty"`
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
	CertSubject    string `json:"cert_subject,omitempty"`
	ServerHeader   string `json:"server_header,omitempty"`
	CacheHeader    string `json:"cache_header,omitempty"`
	AltSvc         string `json:"alt_svc,omitempty"`
	HTTP3Hint      bool   `json:"http3_hint,omitempty"`
	CDN            string `json:"cdn"`
	LatencyMS      int64  `json:"latency_ms"`
	Score          int    `json:"score"`
	Error          string `json:"error,omitempty"`
	BatchNumber    int    `json:"batch_number"`
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
	safetyCIDRPrefixes   = loadSafetyPrefixes()
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
	mux.HandleFunc("/grafana-dashboard.json", grafanaDashboard)
	mux.HandleFunc("/api/scan", scan)
	mux.HandleFunc("/api/dns", scanDNS)
	mux.HandleFunc("/api/stop", stop)
	mux.HandleFunc("/api/export/nmap", exportNmap)
	mux.HandleFunc("/metrics", metrics)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "time": time.Now().Format(time.RFC3339),
			"goroutines": runtime.NumGoroutine(), "heap_bytes": mem.HeapAlloc,
		})
	})

	addr := "127.0.0.1:10808"
	srv := &http.Server{Addr: addr, Handler: mux}
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
<div class=top><div><h1>MaybeEdgeScanner Sidecar</h1><p class=muted>Live SNI/IP/CIDR scanner with progress telemetry, safety limits, and filtered data grid.</p></div><div><button onclick="document.body.classList.toggle('density-compact')">Toggle density</button></div></div>
<div class=tabs><button class="tab active" onclick="showTab('scan',this)">Scan</button><button class=tab onclick="showTab('analytics',this)">Analytics</button><button class=tab onclick="showTab('help',this)">Help</button></div>
<div class=grid><section class=card><label>Targets</label><textarea id=targets rows=11>{{.Targets}}</textarea><label>SNIs</label><textarea id=snis rows=6>{{.SNIs}}</textarea>
<div class=row><input id=maxTargets type=number value=72000><input id=batchSize type=number value=12000></div><div class=row><input id=threads type=number value=64><input id=timeout type=number value=2500></div>
<div class=row><input id=ports value="443"><input id=path value="/"></div><select id=tlsFingerprint><option value=rotate>Rotate TLS fingerprint</option><option value=chrome>Chrome ClientHello</option><option value=firefox>Firefox ClientHello</option><option value=ios>iOS ClientHello</option><option value=randomized>Randomized ALPN ClientHello</option><option value=randomized-no-alpn>Randomized no-ALPN ClientHello</option></select><div class=row><input id=rate type=number value=250 placeholder="Rate/sec"><input id=jitter type=number value=25 placeholder="Jitter ms"></div>
<label><input id=multi type=checkbox checked style="width:auto"> Multi-SNI</label><label><input id=http type=checkbox checked style="width:auto"> HTTP HEAD probe</label><label><input id=randomize type=checkbox checked style="width:auto"> Randomize target order</label><label><input id=safety type=checkbox checked style="width:auto"> Block reserved/unsafe ranges</label>
<button onclick=start()>Start Scan</button><button class=danger onclick=stop()>Stop</button></section>
<section class=card id=tab-scan><div class=dash><div class=ring id=ring><span id=ringText>0%</span></div><div><h3 id=status>Ready</h3><div class=bar><div class=fill id=fill></div></div><p id=metrics class=muted></p></div></div><table><thead><tr><th>Target</th><th>IP</th><th>SNI</th><th>Checks</th><th>ms</th><th>ALPN</th><th>CDN</th></tr></thead><tbody id=rows></tbody></table></section>
<section class=card id=tab-analytics style="display:none"><h3>Analytics</h3><p class=muted id=analyticsText>No scan yet.</p><div class=hex id=hex></div></section>
<section class=card id=tab-help style="display:none"><h3>Safety and UX</h3><p class=muted>Rate/sec and jitter reduce IDS-like sequential bursts. Safety mode drops private, loopback, multicast, and default-route CIDRs. Use exports or /metrics for external dashboards.</p></section></div>
<script>
let rows=[];function v(id){return document.getElementById(id).value}function set(s){document.getElementById('status').textContent=s}
function showTab(id,el){for(let x of ['scan','analytics','help'])document.getElementById('tab-'+x).style.display=x===id?'block':'none';for(let b of document.querySelectorAll('.tab'))b.classList.remove('active');el.classList.add('active')}
async function start(){rows=[];document.getElementById('rows').innerHTML='';document.getElementById('hex').innerHTML='';set('Starting');let r=await fetch('/api/scan',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({targets:v('targets').split(/[\s,;]+/).filter(Boolean),snis:v('snis').split(/[\s,;]+/).filter(Boolean),ports:v('ports').split(/[\s,;]+/).filter(Boolean).map(Number),http_path:v('path'),tls_fingerprint:v('tlsFingerprint'),max_targets:+v('maxTargets'),batch_size:+v('batchSize'),threads:+v('threads'),timeout_ms:+v('timeout'),rate_per_second:+v('rate'),jitter_ms:+v('jitter'),randomize:document.getElementById('randomize').checked,respect_safety:document.getElementById('safety').checked,multi_sni:document.getElementById('multi').checked,http_probe:document.getElementById('http').checked})});let rd=r.body.getReader(),d=new TextDecoder(),buf='';while(true){let x=await rd.read();if(x.done)break;buf+=d.decode(x.value,{stream:true});let parts=buf.split(/\n/);buf=parts.pop();for(let p of parts){if(!p.trim())continue;let e=JSON.parse(p);if(e.type==='init'){set('Scanning '+e.total+' jobs in '+e.batches+' batches')}if(e.type==='progress'){render(e.result,e.stats)}if(e.type==='done'){set(e.stopped?'Stopped':'Done')}}}}
async function stop(){await fetch('/api/stop',{method:'POST'});set('Stopping')}
function esc(x){return String(x??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function render(r,s){rows.push(r);rows.sort((a,b)=>b.score-a.score||a.latency_ms-b.latency_ms);let pct=s.checked*100/Math.max(1,s.total);document.getElementById('fill').style.width=pct+'%';document.getElementById('ring').style.background='conic-gradient(var(--accent) '+(pct*3.6)+'deg,#263948 0deg)';document.getElementById('ringText').textContent=Math.round(pct)+'%';document.getElementById('metrics').textContent='Checked '+s.checked+'/'+s.total+' · working '+s.working+' · TLS '+s.tls_working+' · HTTP '+s.http_working+' · batch '+s.batch+'/'+s.batches;document.getElementById('rows').innerHTML=rows.slice(0,250).map(x=>'<tr title="'+esc((x.tls_version||'')+' '+(x.cert_subject||''))+'"><td>'+esc(x.target)+'</td><td>'+esc(x.ip+':'+x.port)+'</td><td>'+esc(x.sni||'--')+'</td><td><span class="'+(x.tcp?'ok':'bad')+'">TCP</span> <span class="'+(x.tls?'ok':'bad')+'">TLS</span> <span class="'+(x.http?'ok':'bad')+'">HTTP</span></td><td>'+(x.latency_ms||'')+'</td><td>'+esc(x.alpn||'--')+'</td><td><span class=pill>'+esc(x.cdn)+'</span></td></tr>').join('');document.getElementById('analyticsText').textContent='Top score '+(rows[0]?.score||0)+' · CDN groups '+new Set(rows.map(x=>x.cdn)).size;let h=document.getElementById('hex');if(h.childElementCount<1024){let c=document.createElement('div');c.className='cell '+(r.http?'good':r.tls||r.tcp?'mid':'bad');h.appendChild(c)}}
</script></main></body></html>`
	data := map[string]string{
		"Targets": strings.Join(loadLines("assets/default_edges_extra.txt"), "\n"),
		"SNIs":    strings.Join(loadLines("assets/default_snis.txt"), "\n"),
	}
	_ = template.Must(template.New("index").Parse(page)).Execute(w, data)
}

func grafanaDashboard(w http.ResponseWriter, _ *http.Request) {
	body, err := os.ReadFile(filepath.Clean("grafana-dashboard.json"))
	if err != nil {
		http.Error(w, "grafana dashboard not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(body)
}

func scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	metricScansStarted.Add(1)
	req.normalize()
	targets := expandTargets(req.Targets, req.MaxTargets, req.MaxCIDRHosts, req.RespectSafety)
	if len(targets) == 0 {
		targets = expandTargets(loadLines("assets/default_edges_extra.txt"), req.MaxTargets, req.MaxCIDRHosts, req.RespectSafety)
	}
	if len(req.SNIs) == 0 {
		req.SNIs = loadLines("assets/default_snis.txt")
	}
	if len(targets) > req.MaxTargets {
		targets = targets[:req.MaxTargets]
	}
	if req.Randomize {
		shuffleStrings(targets)
	}
	warnings := scanWarnings(req, targets)

	ctx, cancel := context.WithCancel(r.Context())
	activeCancelMu.Lock()
	if activeCancel != nil {
		activeCancel()
	}
	activeSerial++
	serial := activeSerial
	activeCancel = cancel
	activeCancelMu.Unlock()
	defer func() {
		activeCancelMu.Lock()
		if activeSerial == serial {
			activeCancel = nil
		}
		activeCancelMu.Unlock()
		cancel()
	}()

	w.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	jobsTotal := len(targets) * len(req.Ports)
	st := stats{Total: jobsTotal, Batches: int(math.Ceil(float64(len(targets)) / float64(req.BatchSize)))}
	_ = enc.Encode(map[string]any{"type": "init", "total": st.Total, "batches": st.Batches, "warnings": warnings})
	flush(flusher)

	var checked atomic.Int64
	var working atomic.Int64
	var tlsWorking atomic.Int64
	var httpWorking atomic.Int64
	var down atomic.Int64

	limiter := newRateLimiter(req.RatePerSecond)
	if limiter != nil {
		defer limiter.Stop()
	}
	for start, batchNo := 0, 1; start < len(targets) && ctx.Err() == nil; start, batchNo = start+req.BatchSize, batchNo+1 {
		end := min(len(targets), start+req.BatchSize)
		jobs := make(chan string)
		results := make(chan result)
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
						waitRate(ctx, limiter, req.JitterMS)
						results <- probe(ctx, t, port, req, batchNo)
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
		recentErrors := make([]string, 0, 64)
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
			if strings.Contains(strings.ToLower(res.Error), "timeout") {
				metricTimeouts.Add(1)
			}
			if strings.Contains(strings.ToLower(res.Error), "reset") {
				metricResets.Add(1)
			}
			if res.Error != "" {
				recentErrors = append(recentErrors, res.Error)
				if len(recentErrors) > 64 {
					recentErrors = recentErrors[len(recentErrors)-64:]
				}
				adaptiveBackoff(ctx, recentErrors, req.RatePerSecond)
			}
			payloadStats := stats{
				Total: st.Total, Checked: c, Working: int(working.Load()),
				TLSWorking: int(tlsWorking.Load()), HTTPWorking: int(httpWorking.Load()),
				Down: int(down.Load()), Batches: st.Batches, Batch: batchNo,
			}
			_ = enc.Encode(map[string]any{"type": "progress", "result": res, "stats": payloadStats})
			flush(flusher)
		}
	}
	if ctx.Err() == nil {
		metricScansCompleted.Add(1)
	}
	_ = enc.Encode(map[string]any{"type": "done", "stopped": ctx.Err() != nil})
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

func stop(w http.ResponseWriter, _ *http.Request) {
	activeCancelMu.Lock()
	if activeCancel != nil {
		activeCancel()
	}
	activeCancelMu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "stopping"})
}

func exportNmap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var rows []result
	if err := json.NewDecoder(r.Body).Decode(&rows); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
			xmlEscape(row.IP), addrType, row.Port, state, xmlEscape(row.SNI), xmlEscape(row.CDN))
	}
	_, _ = fmt.Fprintln(w, `</nmaprun>`)
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
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
	if r.MaxTargets <= 0 {
		r.MaxTargets = 72000
	}
	if r.MaxTargets > 144000 {
		r.MaxTargets = 144000
	}
	if r.MaxCIDRHosts <= 0 {
		r.MaxCIDRHosts = min(r.MaxTargets, 4096)
	}
	if r.MaxCIDRHosts > 16384 {
		r.MaxCIDRHosts = 16384
	}
	if r.BatchSize <= 0 || r.BatchSize > r.MaxTargets {
		r.BatchSize = min(12000, r.MaxTargets)
	}
	if r.RatePerSecond < 0 {
		r.RatePerSecond = 0
	}
	if r.JitterMS < 0 {
		r.JitterMS = 0
	}
	r.TLSFingerprint = normalizeTLSFingerprint(r.TLSFingerprint)
}

func probe(ctx context.Context, target string, port int, req scanRequest, batchNo int) result {
	res := result{Target: target, Port: port, BatchNumber: batchNo, CDN: "unknown"}
	ip, sni, err := resolveTarget(target)
	res.IP, res.SNI = ip, sni
	if err != nil {
		res.Error = err.Error()
		return res
	}
	snis := candidateSNIs(sni, req.SNIs, req.MultiSNI)

	start := time.Now()
	res.TCP = tcp(ctx, ip, port, req.TimeoutMS)
	res.LatencyMS = time.Since(start).Milliseconds()
	res.CDN = detectCDN(ip, sni, "")
	for _, candidateSNI := range snis {
		if ctx.Err() != nil {
			break
		}
		fingerprint := chooseTLSFingerprint(req.TLSFingerprint)
		tlsInfo, tlsOK := tlsProbe(ctx, ip, port, candidateSNI, req.TimeoutMS, fingerprint)
		if tlsOK {
			res.TLS = true
			res.SNI = candidateSNI
			res.TLSVersion = tlsInfo.Version
			res.TLSCipher = tlsInfo.Cipher
			res.ALPN = tlsInfo.ALPN
			res.TLSFingerprint = fingerprint
			res.CertSubject = tlsInfo.Subject
			res.CDN = detectCDN(ip, candidateSNI, tlsInfo.Subject)
			if req.HTTPProbe {
				res.HTTP, res.HTTPStatus, res.ServerHeader, res.CacheHeader, res.AltSvc, res.HTTP3Hint = httpProbe(ctx, ip, port, candidateSNI, req.HTTPPath, req.TimeoutMS, fingerprint)
			}
			break
		}
	}
	res.Score = score(res)
	return res
}

func resolveTarget(target string) (string, string, error) {
	if net.ParseIP(target) != nil {
		return target, "", nil
	}
	ips, err := net.LookupIP(target)
	if err != nil || len(ips) == 0 {
		return "", "", errors.New("DNS failed")
	}
	for _, ip := range ips {
		if ip.To4() == nil && ip.To16() != nil {
			return ip.String(), target, nil
		}
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), target, nil
		}
	}
	return "", "", errors.New("no IP address")
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
	d := net.Dialer{Timeout: time.Duration(timeoutMS) * time.Millisecond}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

type tlsInfo struct {
	Version string
	Cipher  string
	ALPN    string
	Subject string
}

func tlsProbe(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string) (tlsInfo, bool) {
	conn, err := dialUTLS(ctx, ip, port, sni, timeoutMS, fingerprint)
	if err != nil {
		return tlsInfo{}, false
	}
	state := conn.ConnectionState()
	info := tlsInfo{Version: tlsVersionName(state.Version), Cipher: cipherSuiteName(state.CipherSuite), ALPN: state.NegotiatedProtocol}
	if len(state.PeerCertificates) > 0 {
		info.Subject = state.PeerCertificates[0].Subject.String()
	}
	_ = conn.Close()
	return info, ctx.Err() == nil
}

func httpProbe(ctx context.Context, ip string, port int, sni, path string, timeoutMS int, fingerprint string) (bool, int, string, string, string, bool) {
	conn, err := dialUTLSWithALPN(ctx, ip, port, sni, timeoutMS, fingerprint, []string{"http/1.1"})
	if err != nil {
		return false, 0, "", "", "", false
	}
	defer conn.Close()
	host := strings.TrimSpace(sni)
	if host == "" {
		host = ip
	}
	_, _ = fmt.Fprintf(conn, "HEAD %s?cachebuster=%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: MaybeEdgeScanner/1.2\r\nConnection: close\r\n\r\n", path, time.Now().UnixNano(), host)
	reader := pooledReader(conn)
	defer putReader(reader)
	line, err := reader.ReadString('\n')
	status := parseHTTPStatus(line)
	server, cache, altSvc := "", "", ""
	for i := 0; i < 48; i++ {
		header, hErr := reader.ReadString('\n')
		if hErr != nil || strings.TrimSpace(header) == "" {
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
	return ctx.Err() == nil && err == nil && status > 0 && status < 500, status, server, cache, altSvc, strings.Contains(strings.ToLower(altSvc), "h3")
}

func dialUTLS(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string) (*tls.UConn, error) {
	return dialUTLSWithALPN(ctx, ip, port, sni, timeoutMS, fingerprint, []string{"h2", "http/1.1"})
}

func dialUTLSWithALPN(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string, nextProtos []string) (*tls.UConn, error) {
	d := net.Dialer{Timeout: time.Duration(timeoutMS) * time.Millisecond}
	rawConn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, err
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
	if err := conn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(deadline)
	return conn, nil
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
	if r.CDN != "" && r.CDN != "unknown" {
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

func detectCDN(ip, sni, cert string) string {
	host := strings.ToLower(sni + " " + cert)
	switch {
	case strings.Contains(host, "cloudflare") || strings.HasPrefix(ip, "104.16.") || strings.HasPrefix(ip, "104.17.") || strings.HasPrefix(ip, "104.18."):
		return "cloudflare"
	case strings.Contains(host, "github") || strings.HasPrefix(ip, "151.101."):
		return "fastly"
	case strings.HasPrefix(ip, "23.") || strings.HasPrefix(ip, "184.") || strings.HasPrefix(ip, "96.") || strings.HasPrefix(ip, "2."):
		return "akamai"
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

func expandTargets(raw []string, capCount int, maxCIDRHosts int, respectSafety bool) []string {
	set := make(map[string]bool)
	var out []string
	for _, item := range raw {
		for _, expanded := range expandOne(strings.TrimSpace(item), min(maxCIDRHosts, capCount-len(out)), respectSafety) {
			if expanded != "" && !set[expanded] {
				set[expanded] = true
				out = append(out, expanded)
				if len(out) >= capCount {
					return out
				}
			}
		}
	}
	return out
}

func expandOne(s string, remaining int, respectSafety bool) []string {
	if remaining <= 0 || s == "" {
		return nil
	}
	if strings.Contains(s, "-") && !strings.Contains(s, "/") {
		return expandRange(s, remaining, respectSafety)
	}
	if !strings.Contains(s, "/") {
		if respectSafety && isReservedOrUnsafe(s) {
			return nil
		}
		return []string{s}
	}
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return nil
	}
	prefix = prefix.Masked()
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if respectSafety && hostBits > maxAllowedHostBits(prefix.Addr()) {
		metricSafetySkipped.Add(1)
		return nil
	}
	current := prefix.Addr()
	if current.Is4() && hostBits > 1 {
		current = current.Next()
	}
	var out []string
	for current.IsValid() && prefix.Contains(current) && len(out) < remaining {
		if current.Is4() && hostBits > 1 && !prefix.Contains(current.Next()) {
			break
		}
		text := current.String()
		if !respectSafety || !isReservedOrUnsafe(text) {
			out = append(out, text)
		} else {
			metricSafetySkipped.Add(1)
		}
		current = current.Next()
	}
	return out
}

func expandRange(s string, remaining int, respectSafety bool) []string {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 || remaining <= 0 {
		return nil
	}
	start, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
	if err != nil || !start.Is4() {
		return nil
	}
	end, err := netip.ParseAddr(strings.TrimSpace(parts[1]))
	if err != nil || !end.Is4() {
		return nil
	}
	if start.Compare(end) > 0 {
		return nil
	}
	var out []string
	for current := start; current.IsValid() && current.Compare(end) <= 0 && len(out) < remaining; current = current.Next() {
		text := current.String()
		if !respectSafety || !isReservedOrUnsafe(text) {
			out = append(out, text)
		} else {
			metricSafetySkipped.Add(1)
		}
	}
	return out
}

func isReservedOrUnsafe(ipText string) bool {
	ip := net.ParseIP(ipText)
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		addr, err := netip.ParseAddr(ipText)
		if err == nil {
			for _, prefix := range safetyCIDRPrefixes {
				if prefix.Contains(addr) {
					return true
				}
			}
		}
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() || ip.IsUnspecified()
	}
	addr, err := netip.ParseAddr(ipText)
	if err == nil {
		for _, prefix := range safetyCIDRPrefixes {
			if prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
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

func maxAllowedHostBits(addr netip.Addr) int {
	if addr.Is4() {
		return 16
	}
	return 20
}

var readerPool = sync.Pool{New: func() any {
	return bufio.NewReaderSize(nil, 16*1024)
}}

func pooledReader(r net.Conn) *bufio.Reader {
	reader := readerPool.Get().(*bufio.Reader)
	reader.Reset(r)
	return reader
}

func putReader(reader *bufio.Reader) {
	reader.Reset(nil)
	readerPool.Put(reader)
}

func adaptiveBackoff(ctx context.Context, recentErrors []string, ratePerSecond int) {
	if ratePerSecond <= 0 || len(recentErrors) < 24 {
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
		select {
		case <-ctx.Done():
		case <-time.After(delay):
		}
	}
}

func scanWarnings(req scanRequest, targets []string) []string {
	var warnings []string
	if req.Threads > 512 {
		warnings = append(warnings, "High thread count: monitor file descriptors, battery, and network resets.")
	}
	if req.BatchSize > 100000 {
		warnings = append(warnings, "Very large batch size: UI consumers should stream results and avoid keeping all rows in memory.")
	}
	if req.RatePerSecond == 0 {
		warnings = append(warnings, "No rate limit configured: scans may look bursty to IDS/IPS systems.")
	}
	unsafe := 0
	for _, target := range targets {
		if isReservedOrUnsafe(target) {
			unsafe++
			if unsafe >= 5 {
				break
			}
		}
	}
	if unsafe > 0 {
		warnings = append(warnings, "Reserved/private/special-use addresses were present and are skipped when safety mode is enabled.")
	}
	return warnings
}

func shuffleStrings(xs []string) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(xs), func(i, j int) { xs[i], xs[j] = xs[j], xs[i] })
}

func newRateLimiter(rate int) *time.Ticker {
	if rate <= 0 {
		return nil
	}
	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	return time.NewTicker(interval)
}

func waitRate(ctx context.Context, limiter *time.Ticker, jitterMS int) {
	if limiter != nil {
		select {
		case <-ctx.Done():
			return
		case <-limiter.C:
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
