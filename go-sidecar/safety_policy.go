package main

type SafetyPolicyObservation struct {
	PolicyID                         string   `json:"policy_id"`
	Preset                           string   `json:"preset"`
	AuthorizationRequired            bool     `json:"authorization_required"`
	RespectSafety                    bool     `json:"respect_safety"`
	MaxTargetsEffective              int      `json:"max_targets_effective"`
	MaxCIDRHostsEffective            int      `json:"max_cidr_hosts_effective"`
	RatePerSecondEffective           int      `json:"rate_per_second_effective"`
	JitterMSEffective                int      `json:"jitter_ms_effective"`
	TargetCount                      int      `json:"target_count"`
	BroadScanConfirmed               bool     `json:"broad_scan_confirmed"`
	BroadScanConfirmationRequired    bool     `json:"broad_scan_confirmation_required"`
	SpecialRangesBlocked             bool     `json:"special_ranges_blocked"`
	ProviderClassificationAuthorizes bool     `json:"provider_classification_authorizes"`
	Warnings                         []string `json:"warnings,omitempty"`
}

const (
	safetyPresetStandard  = "standard"
	safetyPresetSafeQuick = "safe_quick"
)

func (r *scanRequest) applySafetyPreset() {
	switch r.SafetyPreset {
	case safetyPresetSafeQuick:
		r.RespectSafety = true
		if r.RatePerSecond <= 0 {
			r.RatePerSecond = 250
		}
		if r.JitterMS <= 0 {
			r.JitterMS = 10
		}
	case safetyPresetStandard:
	default:
		r.SafetyPreset = safetyPresetStandard
	}
}

func safetyPolicyObservation(req scanRequest, targetCount int) SafetyPolicyObservation {
	policyID := "standard-v1"
	if req.SafetyPreset == safetyPresetSafeQuick {
		policyID = "safe_quick-v1"
	}
	obs := SafetyPolicyObservation{
		PolicyID:                         policyID,
		Preset:                           req.SafetyPreset,
		AuthorizationRequired:            false,
		RespectSafety:                    req.RespectSafety,
		MaxTargetsEffective:              req.MaxTargets,
		MaxCIDRHostsEffective:            req.MaxCIDRHosts,
		RatePerSecondEffective:           req.RatePerSecond,
		JitterMSEffective:                req.JitterMS,
		TargetCount:                      targetCount,
		BroadScanConfirmed:               req.BroadScanConfirmed,
		BroadScanConfirmationRequired:    false,
		SpecialRangesBlocked:             req.RespectSafety,
		ProviderClassificationAuthorizes: false,
	}
	if req.SafetyPreset == safetyPresetStandard && !req.RespectSafety {
		obs.Warnings = append(obs.Warnings, "Standard policy: reserved/special range filtering follows the explicit respect_safety setting.")
	}
	if req.RatePerSecond == 0 {
		obs.Warnings = append(obs.Warnings, "No effective rate limit is configured.")
	}
	return obs
}
