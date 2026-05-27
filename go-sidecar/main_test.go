package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestScanRejectsOverCapWorkloadRequest(t *testing.T) {
	body := bytes.NewBufferString(`{"targets":["198.51.100.1"],"snis":["example.com"],"ports":[443],"threads":999999}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	rec := httptest.NewRecorder()
	scan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("scan status=%d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), "scan request exceeds sidecar safety limits") {
		t.Fatalf("unexpected error body: %q", rec.Body.String())
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

func TestScanRequestAttachesRouteMetadataToInit(t *testing.T) {
	body := bytes.NewBufferString(`{
		"targets":["192.0.2.1"],
		"snis":["edge.example.test"],
		"ports":[443],
		"respect_safety":false,
		"max_targets":1,
		"timeout_ms":1,
		"route_plugin":{
			"schema_version":1,
			"route_id":"route-windscribe-local",
			"plugin_id":"windscribe",
			"enabled":true,
			"endpoint":"http://127.0.0.1:18080",
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
	if !strings.Contains(rec.Body.String(), `"route_id":"route-windscribe-local"`) ||
		!strings.Contains(rec.Body.String(), `"route_provider_id":"windscribe"`) ||
		!strings.Contains(rec.Body.String(), `"route_dns_policy":"ctrld"`) {
		t.Fatalf("route metadata not attached to scan stream: %s", rec.Body.String())
	}
}
