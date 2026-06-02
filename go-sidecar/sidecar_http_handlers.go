package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

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
	if r.Method != http.MethodPost {
		writePublicMethodNotAllowed(w, http.MethodPost)
		return
	}
	if activeControlPlane != nil {
		activeControlPlane.setState("scan_starting")
		defer activeControlPlane.setState("idle")
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writePublicBadRequest(w, "invalid scan request body")
		return
	}
	if v1, ok := decodeSidecarScanRequestV1(bodyBytes); ok {
		runPlanDrivenScan(w, r, v1)
		return
	}
	metricScansStarted.Add(1)
	if activeControlPlane != nil {
		activeControlPlane.setState("scan_running")
	}
	prep, err := prepareLegacyScan(bodyBytes)
	if err != nil {
		var req scanRequest
		_ = json.Unmarshal(bodyBytes, &req)
		switch {
		case errors.Is(err, errInvalidScanRequest):
			writePublicBadRequest(w, "invalid scan request body")
			return
		case errors.Is(err, errNoUsableTargets):
			writeScanInputError(w, "NO_USABLE_TARGETS", "no usable targets after CIDR/range expansion and safety filtering", map[string]any{
				"submitted_target_count": len(req.Targets),
				"respect_safety":         req.RespectSafety,
			})
			return
		case errors.Is(err, errNoTargetsSelected):
			writeScanInputError(w, "NO_TARGETS_SELECTED", "no targets selected", map[string]any{
				"submitted_target_count": 0,
			})
			return
		default:
			writePluginValidationError(w, "ROUTE_PLUGIN_INVALID", "route_plugin", publicPluginValidationMessage(err))
			return
		}
	}
	if prep.routePlan.Valid && !prep.routePlan.HasRuntimeRoute() {
		code, message, details := prep.routePlan.RuntimeUnavailableError()
		writePublicError(w, http.StatusConflict, code, message, details)
		return
	}
	runScanWorkItems(w, r, prep.req, prep.items, prep.warnings, prep.safetyPolicy, prep.expansionSummary, prep.routePlan)
}

func metrics(w http.ResponseWriter, _ *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	writePrometheusMetrics(w, "maybeedgescanner", mem)
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
