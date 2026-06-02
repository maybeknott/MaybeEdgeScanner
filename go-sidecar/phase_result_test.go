package main

import (
	"errors"
	"testing"
)

func TestAppendTLSOutcomePhasesHostnameMismatch(t *testing.T) {
	phases := appendTLSOutcomePhases(nil, "expected.example", false, 12)
	if len(phases) != 2 {
		t.Fatalf("len(phases)=%d want 2", len(phases))
	}
	if phases[1].ErrorCode != "TLS_VERIFY_HOSTNAME_MISMATCH" {
		t.Fatalf("ErrorCode=%q want TLS_VERIFY_HOSTNAME_MISMATCH", phases[1].ErrorCode)
	}
}

func TestDecodeSidecarScanRequestV1(t *testing.T) {
	body := []byte(`{"schema_version":1,"request_id":"req-1","product_mode":"route_pairing","plans":[{"plan_id":"p1","raw_token":"198.51.100.1","resolved_ip":"198.51.100.1","port":443,"sni_host":null,"sni_mode":"ip_only_no_sni","result_correlation_id":"c1","dns_mode":"pre_resolved","safety_status":"allowed"}],"scan_options":{"timeout_ms":1000,"connect_timeout_ms":500,"tls_timeout_ms":500,"http_timeout_ms":500,"threads":1,"http_probe":false,"http_path":"/","http_protocol_policy":"alpn_select","body_limit_bytes":1024,"result_stream":"ndjson"},"safety_policy":{"respect_reserved_ranges":true,"max_plans":10,"max_cidr_hosts":0,"rate_per_second":0,"jitter_ms":0}}`)
	got, ok := decodeSidecarScanRequestV1(body)
	if !ok {
		t.Fatal("expected v1 decode")
	}
	if len(got.planWorkItems()) != 1 {
		t.Fatalf("planWorkItems()=%d want 1", len(got.planWorkItems()))
	}
}

func TestSidecarScanRequestV1CollectsRequestedRouteIDs(t *testing.T) {
	body := []byte(`{"schema_version":1,"request_id":"req-route","product_mode":"route_pairing","plans":[{"plan_id":"p1","raw_token":"198.51.100.1","resolved_ip":"198.51.100.1","port":443,"route_id":"route-a","safety_status":"allowed"},{"plan_id":"p2","raw_token":"198.51.100.2","resolved_ip":"198.51.100.2","port":443,"route_id":"route-a","safety_status":"allowed"},{"plan_id":"p3","raw_token":"198.51.100.3","resolved_ip":"198.51.100.3","port":443,"route_id":"route-b","safety_status":"allowed"}],"scan_options":{"timeout_ms":1000,"threads":1,"http_probe":false,"http_path":"/"},"safety_policy":{"respect_reserved_ranges":false,"max_plans":10,"max_cidr_hosts":0,"rate_per_second":0,"jitter_ms":0}}`)
	got, ok := decodeSidecarScanRequestV1(body)
	if !ok {
		t.Fatal("expected v1 decode")
	}
	ids := got.requestedRouteIDs()
	if len(ids) != 2 || ids[0] != "route-a" || ids[1] != "route-b" {
		t.Fatalf("requestedRouteIDs()=%#v", ids)
	}
}

func TestPhaseStatusFromCode(t *testing.T) {
	if got := phaseStatusFromCode("ROUTE_REQUEST_NOT_OBSERVED", errors.New("x")); got != "failed" {
		t.Fatalf("phaseStatusFromCode()=%q want failed", got)
	}
	cases := []struct {
		code string
		want string
	}{
		{code: "TCP_CONNECT_TIMEOUT", want: "timeout"},
		{code: "TCP_CONNECT_REFUSED", want: "refused"},
		{code: "TLS_HANDSHAKE_RESET", want: "reset"},
		{code: "PROXY_CONNECT_MALFORMED_RESPONSE", want: "malformed"},
		{code: "SAFETY_RESERVED_RANGE_EXCLUDED", want: "skipped"},
		{code: "HTTP2_UNSUPPORTED_IN_PROBE", want: "unsupported"},
		{code: "LOCAL_API_THROTTLED", want: "throttled"},
	}
	for _, tc := range cases {
		if got := phaseStatusFromCode(tc.code, errors.New("x")); got != tc.want {
			t.Fatalf("phaseStatusFromCode(%q)=%q want %q", tc.code, got, tc.want)
		}
	}
}

func TestBuildRoutePhaseResult(t *testing.T) {
	res := result{RouteErrorCode: "ROUTE_REQUEST_NOT_OBSERVED", RouteObserved: false}
	phase, ok := buildRoutePhaseResult(res)
	if !ok || phase.Phase != "route" || phase.ErrorCode != "ROUTE_REQUEST_NOT_OBSERVED" {
		t.Fatalf("unexpected route phase %#v ok=%v", phase, ok)
	}
}

func TestFinalizeFinalPhasePrefersRouteEvidenceFailure(t *testing.T) {
	res := result{HTTP: true, TLS: true, ALPN: "http/1.1", PhaseResults: []PhaseResult{
		newPhaseSuccess("tcp", 10),
		newPhaseSuccess("tls", 20),
		newPhaseFailure("route", errors.New("not observed"), 0, "ROUTE_REQUEST_NOT_OBSERVED"),
	}}
	if got := finalizeFinalPhase(res, res.PhaseResults, ""); got != "route" {
		t.Fatalf("finalizeFinalPhase()=%q want route", got)
	}
}

func TestResultErrorSignalsIncludeRouteAndStructuredPhases(t *testing.T) {
	res := result{
		RouteErrorCode: "PROXY_407_AUTH_REQUIRED",
		ErrorCode:      "LEGACY_FAILED",
		Error:          "legacy text",
		PhaseResults: []PhaseResult{
			newPhaseSuccess("tcp", 1),
			newPhaseFailure("route", errors.New("proxy auth"), 2, "PROXY_407_AUTH_REQUIRED"),
			newPhaseFailure("tcp", errors.New("timeout"), 3, "TCP_CONNECT_TIMEOUT"),
		},
	}
	signals := resultErrorSignals(res)
	if len(signals) != 5 {
		t.Fatalf("signals=%#v", signals)
	}
	if signals[0] != "PROXY_407_AUTH_REQUIRED" || signals[1] != "TCP_CONNECT_TIMEOUT" {
		t.Fatalf("phase signals not first: %#v", signals)
	}
}
