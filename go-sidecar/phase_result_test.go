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

func TestPhaseStatusFromCode(t *testing.T) {
	if got := phaseStatusFromCode("ROUTE_REQUEST_NOT_OBSERVED", errors.New("x")); got != "failed" {
		t.Fatalf("phaseStatusFromCode()=%q want failed", got)
	}
}

func TestBuildRoutePhaseResult(t *testing.T) {
	res := result{RouteErrorCode: "ROUTE_REQUEST_NOT_OBSERVED", RouteObserved: false}
	phase, ok := buildRoutePhaseResult(res)
	if !ok || phase.Phase != "route" || phase.ErrorCode != "ROUTE_REQUEST_NOT_OBSERVED" {
		t.Fatalf("unexpected route phase %#v ok=%v", phase, ok)
	}
}
