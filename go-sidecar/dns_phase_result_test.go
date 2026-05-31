package main

import (
	"testing"
)

func TestFinalizeDNSPhaseResultsSuccess(t *testing.T) {
	res := dnsResult{
		LatencyMS: 12,
		Attempts: []dnsAttempt{
			{Transport: "udp", Outcome: "success", LatencyMS: int64Ptr(12)},
		},
	}
	finalizeDNSPhaseResults(&res)
	if len(res.PhaseResults) != 1 {
		t.Fatalf("expected 1 phase, got %d", len(res.PhaseResults))
	}
	if res.PhaseResults[0].Status != "success" || res.PhaseResults[0].Phase != "dns" {
		t.Fatalf("unexpected phase: %+v", res.PhaseResults[0])
	}
	if res.FinalPhase != "dns" {
		t.Fatalf("final_phase=%q", res.FinalPhase)
	}
}

func TestFinalizeDNSPhaseResultsTruncatedRetry(t *testing.T) {
	res := dnsResult{
		ErrorCode: "DNS_TRUNCATED_RETRY_FAILED",
		Error:     "tcp retry failed",
		Attempts: []dnsAttempt{
			{Transport: "udp", Outcome: "truncated", ErrorCode: "DNS_TRUNCATED"},
			{Transport: "tcp", Outcome: "error", ErrorCode: "DNS_TRUNCATED_RETRY_FAILED", Error: "timeout"},
		},
	}
	finalizeDNSPhaseResults(&res)
	if len(res.PhaseResults) < 2 {
		t.Fatalf("expected >=2 phases, got %d", len(res.PhaseResults))
	}
	last := res.PhaseResults[len(res.PhaseResults)-1]
	if last.ErrorCode != "DNS_TRUNCATED_RETRY_FAILED" {
		t.Fatalf("last code=%q", last.ErrorCode)
	}
}

func int64Ptr(v int64) *int64 {
	return &v
}
