package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestCandidateSNIsKeepsTargetsAndCorpusSeparate(t *testing.T) {
	corpus := []string{"cdn.example", "front.example", "cdn.example"}
	cases := []struct {
		name        string
		resolvedSNI string
		multi       bool
		want        []string
	}{
		{name: "domain single mode uses resolved host", resolvedSNI: "target.example", multi: false, want: []string{"target.example"}},
		{name: "ip single mode uses primary corpus sni", resolvedSNI: "", multi: false, want: []string{"cdn.example"}},
		{name: "domain multi mode tests target then corpus", resolvedSNI: "target.example", multi: true, want: []string{"target.example", "cdn.example", "front.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := candidateSNIs(tc.resolvedSNI, corpus, tc.multi); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("candidateSNIs()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestExpandTargetsExpandsIPv4RangesAndSmallCIDRs(t *testing.T) {
	got := expandTargets([]string{"203.0.113.7-203.0.113.9", "198.51.100.42/32"}, 10, 10, false)
	want := []string{"203.0.113.7", "203.0.113.8", "203.0.113.9", "198.51.100.42"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expandTargets()=%v, want %v", got, want)
	}
}

func TestExpandRangeHonorsSafety(t *testing.T) {
	got := expandTargets([]string{"192.168.1.1-192.168.1.3"}, 10, 10, true)
	if len(got) != 0 {
		t.Fatalf("expandTargets()=%v, want private range skipped", got)
	}
}

func TestExpandTargetsDoesNotSpendRangeBudgetOnDuplicates(t *testing.T) {
	got := expandTargets([]string{"203.0.113.7", "203.0.113.7-203.0.113.9"}, 3, 3, false)
	want := []string{"203.0.113.7", "203.0.113.8", "203.0.113.9"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expandTargets()=%v, want %v", got, want)
	}
}

func TestExpandTargetsDoesNotRejectBroadPublicCIDRWhenBudgetProvided(t *testing.T) {
	got := expandTargets([]string{"8.8.0.0/15"}, 3, 3, true)
	want := []string{"8.8.0.1", "8.8.0.2", "8.8.0.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expandTargets()=%v, want %v", got, want)
	}
}

func TestScanRejectsExplicitTargetsFilteredToZero(t *testing.T) {
	body := bytes.NewBufferString(`{"targets":["192.168.0.0/24"],"snis":["example.com"],"ports":[443],"respect_safety":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("scan status=%d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), `"error_code":"NO_USABLE_TARGETS"`) {
		t.Fatalf("missing NO_USABLE_TARGETS error envelope: %s", rec.Body.String())
	}
}

func TestScanRejectsMalformedBodyWithSanitizedError(t *testing.T) {
	body := bytes.NewBufferString(`{"targets":["198.51.100.1"],"ports":[`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("scan status=%d, want %d", rec.Code, http.StatusBadRequest)
	}
	got := rec.Body.String()
	if !strings.Contains(got, "invalid scan request body") || strings.Contains(strings.ToLower(got), "unexpected") {
		t.Fatalf("scan decode error was not sanitized: %q", got)
	}
}

func TestGrafanaDashboardNotFoundReturnsStructuredError(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir(%q) error: %v", tmp, err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	req := httptest.NewRequest(http.MethodGet, "/api/grafana-dashboard", nil)
	rec := httptest.NewRecorder()
	grafanaDashboard(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("dashboard status=%d, want %d", rec.Code, http.StatusNotFound)
	}
	if !strings.Contains(rec.Body.String(), `"error_code":"DASHBOARD_NOT_FOUND"`) {
		t.Fatalf("dashboard error was not structured: %q", rec.Body.String())
	}
}

func TestScanRejectsNonPostWithStructuredMethodError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/scan", nil)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("scan status=%d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	got := rec.Body.String()
	if !strings.Contains(got, `"error_code":"METHOD_NOT_ALLOWED"`) || !strings.Contains(got, `"required_method":"POST"`) {
		t.Fatalf("scan method error was not structured: %q", got)
	}
}

func TestScanAcceptsLargeExplicitWorkloadRequest(t *testing.T) {
	body := bytes.NewBufferString(`{"targets":["198.51.100.1"],"snis":["example.com"],"ports":[443],"threads":999999}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan status=%d, want %d body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"type":"init"`) {
		t.Fatalf("expected init frame, got: %q", rec.Body.String())
	}
}

func TestScanSafeQuickDoesNotRequireBroadScanConfirmation(t *testing.T) {
	body := bytes.NewBufferString(`{
		"targets":["8.8.8.8","8.8.4.4","1.1.1.1"],
		"snis":["edge.example.test"],
		"ports":[443],
		"safety_preset":"safe_quick",
		"broad_scan_confirmed":false,
		"max_targets":0,
		"max_cidr_hosts":0
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan status=%d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"error_code":"BROAD_SCAN_CONFIRMATION_REQUIRED"`) {
		t.Fatalf("broad scan confirmation gate should be removed: %s", rec.Body.String())
	}
}

func TestExportNmapRejectsMalformedBodyWithSanitizedError(t *testing.T) {
	body := bytes.NewBufferString(`[{"ip":"198.51.100.1","port":443}`)
	req := httptest.NewRequest(http.MethodPost, "/api/export/nmap", body)
	rec := httptest.NewRecorder()
	exportNmap(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("export status=%d, want %d", rec.Code, http.StatusBadRequest)
	}
	got := rec.Body.String()
	if !strings.Contains(got, "invalid export request body") || strings.Contains(strings.ToLower(got), "unexpected") {
		t.Fatalf("export decode error was not sanitized: %q", got)
	}
}

func TestExportNmapRejectsNonPostWithStructuredMethodError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/export/nmap", nil)
	rec := httptest.NewRecorder()
	exportNmap(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("export status=%d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	got := rec.Body.String()
	if !strings.Contains(got, `"error_code":"METHOD_NOT_ALLOWED"`) || !strings.Contains(got, `"required_method":"POST"`) {
		t.Fatalf("export method error was not structured: %q", got)
	}
}

func TestValidateRoutingPluginEndpointReturnsObservationTemplate(t *testing.T) {
	body := bytes.NewBufferString(`{
		"schema_version":1,
		"route_id":"route-windscribe-wireguard",
		"plugin_id":"windscribe",
		"enabled":true,
		"remote_dns":true,
		"profile_ref":"ref:windscribe-wireguard",
		"credential_ref":"ref:windscribe-session",
		"fields":{
			"mode":"wireguard",
			"auth_mode":"wsnet_session_ref",
			"dns_policy":"ctrld",
			"downstream_mode":"vpn_interface"
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/validate", body)
	rec := httptest.NewRecorder()
	validateRoutingPlugin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", rec.Code, rec.Body.String())
	}
	var result RoutingPluginConfigValidation
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Valid ||
		result.Observation.ProviderID == nil ||
		*result.Observation.ProviderID != "windscribe" ||
		result.Observation.ErrorCode == nil ||
		*result.Observation.ErrorCode != "PLUGIN_ROUTE_NOT_READY" ||
		result.Observation.RouteBinding != "profile_backed_vpn_or_proxy" {
		t.Fatalf("unexpected validation response: %#v", result)
	}
}

func TestValidateRoutingPluginEndpointReturnsStructuredError(t *testing.T) {
	body := bytes.NewBufferString(`{"schema_version":1,"route_id":"route-bad","plugin_id":"windscribe","enabled":true,"fields":{"mode":"wireguard"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/validate", body)
	rec := httptest.NewRecorder()
	validateRoutingPlugin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("validate status=%d body=%s", rec.Code, rec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["valid"] != false || result["error_code"] != "PLUGIN_CONFIG_INVALID" || result["field"] != "config" {
		t.Fatalf("unexpected structured error: %#v", result)
	}
	if strings.Contains(rec.Body.String(), "wireguard") || strings.Contains(rec.Body.String(), "route-bad") {
		t.Fatalf("public validation error leaked config detail: %s", rec.Body.String())
	}
}

func TestScanRequestEmitsObservedRouteForAttachableWindscribeLocalProxy(t *testing.T) {
	proxyListener := listenLocalTCP(t)
	defer proxyListener.Close()
	go serveOneHTTPConnect(t, proxyListener, http.StatusOK)
	body := bytes.NewBufferString(`{
		"targets":["198.51.100.10"],
		"snis":["edge.example.test"],
		"ports":[443],
		"respect_safety":false,
		"max_targets":1,
		"timeout_ms":25,
		"route_plugin":{
			"schema_version":1,
			"route_id":"route-windscribe-local",
			"plugin_id":"windscribe",
			"enabled":true,
			"endpoint":"http://` + proxyListener.Addr().String() + `",
			"profile_ref":"ref:windscribe-local",
			"fields":{"mode":"local_proxy","dns_policy":"ctrld"}
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan status=%d body=%s", rec.Code, rec.Body.String())
	}
	bodyText := rec.Body.String()
	if !strings.Contains(bodyText, `"requested_route_id":"route-windscribe-local"`) {
		t.Fatalf("requested route id not attached to scan stream: %s", bodyText)
	}
	if !strings.Contains(bodyText, `"observed_route_id":"route-windscribe-local"`) || !strings.Contains(bodyText, `"route_provider_id":"windscribe"`) || !strings.Contains(bodyText, `"route_used":true`) {
		t.Fatalf("attachable windscribe local proxy route did not emit observed route evidence: %s", bodyText)
	}
	if !strings.Contains(bodyText, `"route_config_ready":true`) || !strings.Contains(bodyText, `"route_dialer_ready":true`) || !strings.Contains(bodyText, `"route_evidence_state":"observed_attached"`) {
		t.Fatalf("attachable windscribe local proxy route did not emit readiness evidence fields: %s", bodyText)
	}
	if !strings.Contains(bodyText, `"route_observed":true`) || !strings.Contains(bodyText, `"route_readiness_source":"observation"`) {
		t.Fatalf("attachable windscribe local proxy route did not emit observation-source evidence fields: %s", bodyText)
	}
}

func TestScanRequestFailsWhenWindscribeRouteIsObserverOnly(t *testing.T) {
	body := bytes.NewBufferString(`{
		"targets":["192.0.2.1"],
		"snis":["edge.example.test"],
		"ports":[443],
		"respect_safety":false,
		"max_targets":1,
		"timeout_ms":1,
		"route_plugin":{
			"schema_version":1,
			"route_id":"route-windscribe-wireguard",
			"plugin_id":"windscribe",
			"enabled":true,
			"profile_ref":"ref:windscribe-profile",
			"fields":{"mode":"wireguard","dns_policy":"ctrld"}
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("scan status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid json error envelope: %v body=%s", err, rec.Body.String())
	}
	if envelope["error_code"] != "ROUTE_UNSUPPORTED" {
		t.Fatalf("expected ROUTE_UNSUPPORTED, got %#v body=%s", envelope["error_code"], rec.Body.String())
	}
	details, _ := envelope["details"].(map[string]any)
	if details == nil {
		t.Fatalf("expected details in route unsupported response: %s", rec.Body.String())
	}
	if details["requested_route_id"] != "route-windscribe-wireguard" || details["plugin_id"] != "windscribe" {
		t.Fatalf("unexpected route unsupported details: %#v", details)
	}
	if details["route_binding"] != "profile_backed_vpn_or_proxy" {
		t.Fatalf("unexpected route binding in unsupported details: %#v", details)
	}
	if details["protocol_mode"] != "wireguard" {
		t.Fatalf("unexpected protocol mode in unsupported details: %#v", details)
	}
	if details["attachable"] != false {
		t.Fatalf("expected attachable=false in unsupported details: %#v", details)
	}
	readinessProbe, _ := details["readiness_probe"].(string)
	if readinessProbe == "" || !strings.Contains(strings.ToLower(readinessProbe), "route observation") {
		t.Fatalf("unexpected readiness probe in unsupported details: %#v", details)
	}
}

func TestScanRequestFailsWhenPsiphonRouteIsNotReadyForRuntimeDialing(t *testing.T) {
	body := bytes.NewBufferString(`{
		"targets":["192.0.2.1"],
		"snis":["edge.example.test"],
		"ports":[443],
		"respect_safety":false,
		"max_targets":1,
		"timeout_ms":1,
		"route_plugin":{
			"schema_version":1,
			"route_id":"route-psiphon-supervised-no-endpoint",
			"plugin_id":"psiphon",
			"enabled":true,
			"config_ref":"ref:psiphon-config",
			"fields":{"mode":"tunnel_core_supervised"}
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("scan status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid json error envelope: %v body=%s", err, rec.Body.String())
	}
	if envelope["error_code"] != "ROUTE_NOT_READY" {
		t.Fatalf("expected ROUTE_NOT_READY, got %#v body=%s", envelope["error_code"], rec.Body.String())
	}
	details, _ := envelope["details"].(map[string]any)
	if details == nil {
		t.Fatalf("expected details in route not ready response: %s", rec.Body.String())
	}
	if details["requested_route_id"] != "route-psiphon-supervised-no-endpoint" || details["plugin_id"] != "psiphon" {
		t.Fatalf("unexpected route not ready details: %#v", details)
	}
	if details["route_binding"] != "tunnel_core_local_proxy" {
		t.Fatalf("unexpected route binding in not-ready details: %#v", details)
	}
	if details["protocol_mode"] != "tunnel_core_supervised" {
		t.Fatalf("unexpected protocol mode in not-ready details: %#v", details)
	}
	if details["attachable"] != false {
		t.Fatalf("expected attachable=false in not-ready details: %#v", details)
	}
	readinessProbe, _ := details["readiness_probe"].(string)
	if readinessProbe == "" || !strings.Contains(strings.ToLower(readinessProbe), "loopback") {
		t.Fatalf("unexpected readiness probe in not-ready details: %#v", details)
	}
}

func TestScanRequestEmitsObservedRouteForAttachableRuntimeRoute(t *testing.T) {
	proxyListener := listenLocalTCP(t)
	defer proxyListener.Close()
	go serveOneHTTPConnect(t, proxyListener, http.StatusOK)
	body := bytes.NewBufferString(`{
		"targets":["198.51.100.10"],
		"ports":[443],
		"respect_safety":false,
		"max_targets":1,
		"timeout_ms":25,
		"route_plugin":{
			"schema_version":1,
			"route_id":"route-generic-attach",
			"plugin_id":"generic-proxy",
			"enabled":true,
			"endpoint":"http://` + proxyListener.Addr().String() + `",
			"fields":{"dns_policy":"remote"}
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan status=%d body=%s", rec.Code, rec.Body.String())
	}
	bodyText := rec.Body.String()
	if !strings.Contains(bodyText, `"requested_route_id":"route-generic-attach"`) ||
		!strings.Contains(bodyText, `"observed_route_id":"route-generic-attach"`) ||
		!strings.Contains(bodyText, `"route_used":true`) {
		t.Fatalf("attachable route did not emit observed route evidence: %s", bodyText)
	}
	if !strings.Contains(bodyText, `"route_config_ready":true`) || !strings.Contains(bodyText, `"route_dialer_ready":true`) || !strings.Contains(bodyText, `"route_evidence_state":"observed_attached"`) {
		t.Fatalf("attachable route did not emit route readiness execution evidence: %s", bodyText)
	}
	if !strings.Contains(bodyText, `"route_observed":true`) || !strings.Contains(bodyText, `"route_readiness_source":"observation"`) {
		t.Fatalf("attachable route did not emit route observation-source evidence fields: %s", bodyText)
	}
}

func TestScanRequestKeepsObservedRouteEvidenceWhenAttachableProxyConnectFails(t *testing.T) {
	proxyListener := listenLocalTCP(t)
	defer proxyListener.Close()
	go func() {
		for i := 0; i < 3; i++ {
			serveOneHTTPConnect(t, proxyListener, http.StatusProxyAuthRequired)
		}
	}()
	body := bytes.NewBufferString(`{
		"targets":["198.51.100.10"],
		"ports":[443],
		"respect_safety":false,
		"max_targets":1,
		"timeout_ms":25,
		"route_plugin":{
			"schema_version":1,
			"route_id":"route-generic-attach-fail",
			"plugin_id":"generic-proxy",
			"enabled":true,
			"endpoint":"http://` + proxyListener.Addr().String() + `",
			"fields":{"dns_policy":"remote"}
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan status=%d body=%s", rec.Code, rec.Body.String())
	}
	bodyText := rec.Body.String()
	if !strings.Contains(bodyText, `"requested_route_id":"route-generic-attach-fail"`) ||
		!strings.Contains(bodyText, `"observed_route_id":"route-generic-attach-fail"`) {
		t.Fatalf("requested/observed route IDs missing after proxy failure: %s", bodyText)
	}
	if strings.Contains(bodyText, `"route_used":true`) || !strings.Contains(bodyText, `"route_evidence_state":"observed_failed"`) {
		t.Fatalf("route failure evidence missing: %s", bodyText)
	}
	if !strings.Contains(bodyText, `"route_error_code":"PROXY_407_AUTH_REQUIRED"`) {
		t.Fatalf("expected proxy auth failure code in route observation: %s", bodyText)
	}
}

func TestProbeHTTPOverNegotiatedALPNSkipsHTTP11ForH2(t *testing.T) {
	httpOK, status, server, cache, altSvc, http3, code := probeHTTPOverNegotiatedALPN(context.Background(), nil, "192.0.2.5", "", "/", 1000, "h2")
	if httpOK || status != 0 || server != "" || cache != "" || altSvc != "" || http3 {
		t.Fatalf("unexpected HTTP probe output for h2 skip: ok=%v status=%d server=%q cache=%q altSvc=%q http3=%v", httpOK, status, server, cache, altSvc, http3)
	}
	if code != "HTTP2_UNSUPPORTED_IN_PROBE" {
		t.Fatalf("unexpected probe code %q", code)
	}
}

func TestProbeHTTPOverNegotiatedALPNExecutesHTTP11WhenAllowed(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader := bufio.NewReader(server)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nServer: unit-test\r\n\r\n")
	}()
	httpOK, status, serverHeader, _, _, _, code := probeHTTPOverNegotiatedALPN(context.Background(), client, "192.0.2.5", "", "/", 1000, "http/1.1")
	<-done
	if !httpOK || status != 200 || serverHeader != "unit-test" {
		t.Fatalf("unexpected HTTP probe output: ok=%v status=%d server=%q", httpOK, status, serverHeader)
	}
	if code != "" {
		t.Fatalf("unexpected probe code %q", code)
	}
}

func TestProbeHTTPOverNegotiatedALPNAcceptsEOFWithValidStatusLine(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader := bufio.NewReader(server)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK")
		_ = server.Close()
	}()
	httpOK, status, _, _, _, _, code := probeHTTPOverNegotiatedALPN(context.Background(), client, "192.0.2.6", "", "/", 1000, "http/1.1")
	<-done
	if !httpOK || status != 200 {
		t.Fatalf("expected success with status 200, got ok=%v status=%d", httpOK, status)
	}
	if code != "" {
		t.Fatalf("expected empty probe code for valid EOF status line, got %q", code)
	}
}

func TestProbeHTTPOverNegotiatedALPNReturnsParseFailureForMalformedStatus(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader := bufio.NewReader(server)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(server, "not-http\r\n\r\n")
		_ = server.Close()
	}()
	httpOK, status, _, _, _, _, code := probeHTTPOverNegotiatedALPN(context.Background(), client, "192.0.2.7", "", "/", 1000, "http/1.1")
	<-done
	if httpOK || status != 0 {
		t.Fatalf("expected malformed status failure, got ok=%v status=%d", httpOK, status)
	}
	if code != "HTTP_PARSE_FAILED" {
		t.Fatalf("expected HTTP_PARSE_FAILED, got %q", code)
	}
}

func TestProbeHTTPOverNegotiatedALPNFailsOnMidHeaderTruncation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader := bufio.NewReader(server)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nServer: test")
		_ = server.Close()
	}()
	httpOK, _, _, _, _, _, code := probeHTTPOverNegotiatedALPN(context.Background(), client, "192.0.2.8", "", "/", 1000, "http/1.1")
	<-done
	if httpOK {
		t.Fatal("expected failure on mid-header truncation")
	}
	if code != "HTTP_FAILED" {
		t.Fatalf("expected HTTP_FAILED, got %q", code)
	}
}

func TestClassifyNetworkError(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		phase string
		want  string
	}{
		{name: "timeout", err: errors.New("i/o timeout"), phase: "tcp", want: "TCP_CONNECT_TIMEOUT"},
		{name: "reset", err: errors.New("connection reset by peer"), phase: "tls", want: "TLS_HANDSHAKE_RESET"},
		{name: "refused", err: errors.New("connection refused"), phase: "tcp", want: "TCP_CONNECT_REFUSED"},
		{name: "default", err: errors.New("network unreachable"), phase: "tcp", want: "TCP_CONNECT_FAILED"},
		{name: "dns default", err: errors.New("no such host"), phase: "dns", want: "DNS_FAILED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyNetworkError(tc.err, tc.phase); got != tc.want {
				t.Fatalf("classifyNetworkError()=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestTrackAdaptiveBackoffControllerOwnsDelayAndReset(t *testing.T) {
	globalBackoffNS.Store(0)
	noisy := make([]string, 32)
	for i := range noisy {
		noisy[i] = "connection timeout"
	}
	trackAdaptiveBackoff(noisy, 250)
	if globalBackoffNS.Load() <= 0 {
		t.Fatalf("expected controller to set backoff delay, got %d", globalBackoffNS.Load())
	}
	trackAdaptiveBackoff([]string{"ok"}, 250)
	if globalBackoffNS.Load() != 0 {
		t.Fatalf("expected controller to clear backoff delay, got %d", globalBackoffNS.Load())
	}
}

func TestValidateScanRoutePluginBuildsRuntimeConfigForGenericProxy(t *testing.T) {
	plan, err := validateScanRoutePlugin(&RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-generic-proxy",
		PluginID:      "generic-proxy",
		Enabled:       true,
		Endpoint:      "socks5://127.0.0.1:1080",
		Fields:        map[string]string{"dns_policy": "remote"},
	})
	if err != nil {
		t.Fatalf("validateScanRoutePlugin() error: %v", err)
	}
	if !plan.Valid || !plan.HasRuntimeRoute() {
		t.Fatalf("expected valid attachable route plan, got %+v", plan)
	}
	cfg := plan.RouteConfigForProbe(2000)
	if cfg.RouteID != "route-generic-proxy" || cfg.Type != RouteSOCKS5 || cfg.ProxyAddress != "127.0.0.1:1080" {
		t.Fatalf("unexpected runtime route config: %+v", cfg)
	}
}

func TestValidateScanRoutePluginBuildsRuntimeConfigForWindscribeLocalProxy(t *testing.T) {
	plan, err := validateScanRoutePlugin(&RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-local",
		PluginID:      "windscribe",
		Enabled:       true,
		Endpoint:      "http://127.0.0.1:8080",
		ProfileRef:    "ref:windscribe-local",
		Fields: map[string]string{
			"mode":       "local_proxy",
			"dns_policy": "ctrld",
		},
	})
	if err != nil {
		t.Fatalf("validateScanRoutePlugin() error: %v", err)
	}
	if !plan.Valid || !plan.HasRuntimeRoute() {
		t.Fatalf("expected valid attachable windscribe local proxy plan, got %+v", plan)
	}
	cfg := plan.RouteConfigForProbe(2500)
	if cfg.RouteID != "route-windscribe-local" || cfg.Type != RouteHTTPConnect || cfg.ProxyAddress != "127.0.0.1:8080" {
		t.Fatalf("unexpected windscribe runtime route config: %+v", cfg)
	}
}

func TestValidateScanRoutePluginBuildsRuntimeConfigForPsiphonLocalProxy(t *testing.T) {
	plan, err := validateScanRoutePlugin(&RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-psiphon-local",
		PluginID:      "psiphon",
		Enabled:       true,
		ConfigRef:     "ref:psiphon-config",
		Endpoint:      "socks5://127.0.0.1:1080",
		Fields: map[string]string{
			"mode":       "tunnel_core_supervised",
			"dns_policy": "remote_dns",
		},
	})
	if err != nil {
		t.Fatalf("validateScanRoutePlugin() error: %v", err)
	}
	if !plan.Valid || !plan.HasRuntimeRoute() {
		t.Fatalf("expected valid attachable psiphon local proxy plan, got %+v", plan)
	}
	cfg := plan.RouteConfigForProbe(2500)
	if cfg.RouteID != "route-psiphon-local" || cfg.Type != RouteSOCKS5 || cfg.ProxyAddress != "127.0.0.1:1080" {
		t.Fatalf("unexpected psiphon runtime route config: %+v", cfg)
	}
}

func TestApplyObservedRouteRecordsRequestedAndObservedIDs(t *testing.T) {
	plan, err := validateScanRoutePlugin(&RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-generic-proxy",
		PluginID:      "generic-proxy",
		Enabled:       true,
		Endpoint:      "socks5://127.0.0.1:1080",
	})
	if err != nil {
		t.Fatalf("validateScanRoutePlugin() error: %v", err)
	}
	row := result{}
	plan.ApplyRequestedToResult(&row)
	obs := &RouteObservation{
		RouteID:      "route-generic-proxy",
		RouteType:    RouteSOCKS5,
		Status:       "success",
		ProviderID:   "generic-proxy",
		DNSPolicy:    "remote",
		RouteBinding: "local_proxy_gateway",
	}
	plan.ApplyObservedToResult(&row, obs)
	if !row.RouteUsed || row.RequestedRouteID != "route-generic-proxy" || row.ObservedRouteID != "route-generic-proxy" {
		t.Fatalf("unexpected route ID tracking: %+v", row)
	}
	if row.RouteMismatchCode != "" {
		t.Fatalf("unexpected mismatch code: %q", row.RouteMismatchCode)
	}
	if !row.RouteConfigReady || !row.RouteDialerReady || row.RouteEvidenceState != "observed_attached" {
		t.Fatalf("unexpected route readiness evidence state: %+v", row)
	}
	if !row.RouteObserved || row.RouteReadinessSource != "observation" {
		t.Fatalf("unexpected route observation/readiness source state: %+v", row)
	}
}

func TestApplyObservedRouteDetectsRequestedObservedMismatch(t *testing.T) {
	plan, err := validateScanRoutePlugin(&RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-requested",
		PluginID:      "generic-proxy",
		Enabled:       true,
		Endpoint:      "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("validateScanRoutePlugin() error: %v", err)
	}
	row := result{}
	plan.ApplyRequestedToResult(&row)
	obs := &RouteObservation{
		RouteID:   "route-observed",
		RouteType: RouteHTTPConnect,
		Status:    "success",
	}
	plan.ApplyObservedToResult(&row, obs)
	if row.RouteMismatchCode != "ROUTE_REQUEST_OBSERVATION_MISMATCH" {
		t.Fatalf("expected mismatch code, got %+v", row)
	}
	if row.RouteEvidenceState != "observed_attached" {
		t.Fatalf("expected observed_attached evidence state, got %+v", row)
	}
	if !row.RouteObserved || row.RouteReadinessSource != "observation" {
		t.Fatalf("expected observed route evidence source, got %+v", row)
	}
}

func TestApplyRouteNotObservedUsesRuntimeNotObservedEvidenceState(t *testing.T) {
	plan, err := validateScanRoutePlugin(&RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-requested",
		PluginID:      "generic-proxy",
		Enabled:       true,
		Endpoint:      "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("validateScanRoutePlugin() error: %v", err)
	}
	row := result{}
	plan.ApplyRequestedToResult(&row)
	plan.ApplyRouteNotObserved(&row)
	if !row.RouteConfigReady || !row.RouteDialerReady {
		t.Fatalf("expected route config/dialer readiness flags, got %+v", row)
	}
	if row.RouteEvidenceState != "requested_runtime_not_observed" || row.RouteMismatchCode != "ROUTE_REQUEST_NOT_OBSERVED" {
		t.Fatalf("expected runtime-not-observed evidence/mismatch, got %+v", row)
	}
	if row.RouteObserved || row.RouteReadinessSource != "validation_template" {
		t.Fatalf("expected validation-template readiness source for not-observed route, got %+v", row)
	}
}
