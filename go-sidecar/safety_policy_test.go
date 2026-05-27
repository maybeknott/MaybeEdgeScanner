package main

import "testing"

func TestSafeQuickPresetAppliesSafetyDefaultsWithoutShrinkingUserBudget(t *testing.T) {
	req := scanRequest{
		SafetyPreset:  safetyPresetSafeQuick,
		MaxTargets:    5000,
		MaxCIDRHosts:  4096,
		BatchSize:     1000,
		RatePerSecond: 250,
		JitterMS:      0,
	}
	req.normalize()
	if !req.RespectSafety {
		t.Fatal("safe_quick must force RespectSafety")
	}
	if req.MaxTargets != 5000 || req.MaxCIDRHosts != 4096 || req.BatchSize != 1000 {
		t.Fatalf("safe_quick unexpectedly shrank user scan budget: %+v", req)
	}
	if req.RatePerSecond != 250 || req.JitterMS != 10 {
		t.Fatalf("unexpected safe_quick default policy: %+v", req)
	}
}

func TestSafeQuickConfirmedBroadScanDoesNotChangeUserBudget(t *testing.T) {
	req := scanRequest{
		SafetyPreset:       safetyPresetSafeQuick,
		BroadScanConfirmed: true,
		MaxTargets:         5000,
		MaxCIDRHosts:       4096,
		BatchSize:          1000,
	}
	req.normalize()
	if req.MaxTargets != 5000 || req.MaxCIDRHosts != 4096 || req.BatchSize != 1000 {
		t.Fatalf("confirmed safe_quick unexpectedly changed budget: %+v", req)
	}
}

func TestSafeQuickPreservesLargeExplicitBudget(t *testing.T) {
	req := scanRequest{
		SafetyPreset:  safetyPresetSafeQuick,
		MaxTargets:    999999,
		MaxCIDRHosts:  250000,
		BatchSize:     500000,
		RatePerSecond: 1000,
		JitterMS:      25,
	}
	req.normalize()
	if req.MaxTargets != 999999 || req.MaxCIDRHosts != 250000 || req.BatchSize != 500000 {
		t.Fatalf("safe_quick must preserve large explicit budget: %+v", req)
	}
	if req.RatePerSecond != 1000 || req.JitterMS != 25 {
		t.Fatalf("safe_quick must preserve explicit rate/jitter policy: %+v", req)
	}
}

func TestNormalizeDefaultsOnlyWhenBudgetMissing(t *testing.T) {
	req := scanRequest{MaxTargets: -1, MaxCIDRHosts: -1, BatchSize: -1}
	req.normalize()
	if req.MaxTargets != 72000 {
		t.Fatalf("MaxTargets default=%d, want 72000", req.MaxTargets)
	}
	if req.MaxCIDRHosts != 4096 {
		t.Fatalf("MaxCIDRHosts default=%d, want 4096", req.MaxCIDRHosts)
	}
	if req.BatchSize != 12000 {
		t.Fatalf("BatchSize default=%d, want 12000", req.BatchSize)
	}
}

func TestLegacyCompatPresetDoesNotForceSafetyBudgets(t *testing.T) {
	req := scanRequest{MaxTargets: 5000, MaxCIDRHosts: 1024, BatchSize: 1000, RatePerSecond: 0}
	req.normalize()
	if req.SafetyPreset != safetyPresetLegacyCompat {
		t.Fatalf("SafetyPreset=%q, want legacy_compat", req.SafetyPreset)
	}
	if req.RespectSafety {
		t.Fatal("legacy compatibility must not force RespectSafety")
	}
	if req.MaxTargets != 5000 || req.MaxCIDRHosts != 1024 || req.BatchSize != 1000 {
		t.Fatalf("legacy compatibility unexpectedly changed budget: %+v", req)
	}
}

func TestSafetyPolicyObservationDoesNotAuthorizeFromProviderClassification(t *testing.T) {
	req := scanRequest{SafetyPreset: safetyPresetSafeQuick}
	req.normalize()
	obs := safetyPolicyObservation(req, 2000000)
	if obs.ProviderClassificationAuthorizes {
		t.Fatal("provider classification must never authorize scanning")
	}
	if !obs.BroadScanConfirmationRequired {
		t.Fatal("safe_quick without explicit confirmation should report broad scan confirmation requirement")
	}
}
