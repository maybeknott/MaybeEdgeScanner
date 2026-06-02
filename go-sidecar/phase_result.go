package main

import (
	"fmt"
	"strings"
)

// PhaseResult is the v1 per-phase probe outcome carried on scan NDJSON results.
type PhaseResult struct {
	Phase      string         `json:"phase"`
	Status     string         `json:"status"`
	DurationMS int64          `json:"duration_ms"`
	ErrorCode  string         `json:"error_code,omitempty"`
	Retryable  bool           `json:"retryable"`
	Evidence   map[string]any `json:"evidence,omitempty"`
}

func newPhaseSuccess(phase string, durationMS int64) PhaseResult {
	return PhaseResult{
		Phase:      phase,
		Status:     "success",
		DurationMS: durationMS,
		Retryable:  false,
		Evidence:   map[string]any{},
	}
}

func newPhaseFailure(phase string, err error, durationMS int64, errorCode string) PhaseResult {
	code := strings.TrimSpace(errorCode)
	if code == "" && err != nil {
		code = classifyNetworkError(err, phase)
	}
	return PhaseResult{
		Phase:      phase,
		Status:     phaseStatusFromCode(code, err),
		DurationMS: durationMS,
		ErrorCode:  code,
		Retryable:  phaseRetryable(code),
		Evidence:   boundedPhaseEvidence(err),
	}
}

func phaseStatusFromCode(code string, err error) string {
	if code == "" && err == nil {
		return "success"
	}
	upper := strings.ToUpper(code)
	switch {
	case strings.HasSuffix(upper, "_TIMEOUT"):
		return "timeout"
	case strings.HasSuffix(upper, "_REFUSED"):
		return "refused"
	case strings.HasSuffix(upper, "_RESET"):
		return "reset"
	case strings.Contains(upper, "_MALFORMED"):
		return "malformed"
	case strings.Contains(upper, "_SKIPPED"), strings.HasSuffix(upper, "_EXCLUDED"):
		return "skipped"
	case strings.Contains(upper, "_UNSUPPORTED"):
		return "unsupported"
	case strings.HasSuffix(upper, "_CANCELLED"):
		return "cancelled"
	case strings.Contains(upper, "_THROTTLED"):
		return "throttled"
	default:
		return "failed"
	}
}

func phaseRetryable(code string) bool {
	upper := strings.ToUpper(strings.TrimSpace(code))
	switch {
	case strings.HasSuffix(upper, "_TIMEOUT"):
		return true
	case strings.HasSuffix(upper, "_RESET"):
		return true
	case upper == "DNS_TRUNCATED_TCP_RETRY_FAILED":
		return true
	default:
		return false
	}
}

func boundedPhaseEvidence(err error) map[string]any {
	if err == nil {
		return nil
	}
	detail := redactSensitiveString(err.Error())
	if len(detail) > 200 {
		detail = detail[:200]
	}
	return map[string]any{"detail": detail}
}

func appendTLSOutcomePhases(phases []PhaseResult, candidateSNI string, certVerified bool, elapsed int64) []PhaseResult {
	phases = append(phases, newPhaseSuccess("tcp", elapsed))
	if strings.TrimSpace(candidateSNI) != "" && !certVerified {
		return append(phases, newPhaseFailure("tls", fmt.Errorf("hostname verification failed"), elapsed, "TLS_VERIFY_HOSTNAME_MISMATCH"))
	}
	return append(phases, newPhaseSuccess("tls", elapsed))
}

func httpPhaseFromALPN(alpn string) string {
	if strings.Contains(strings.ToLower(alpn), "h2") {
		return "http2"
	}
	return "http1"
}

func finalizeFinalPhase(res result, phases []PhaseResult, lastErrCode string) string {
	if phase := finalRouteFailurePhase(phases); phase != "" {
		return phase
	}
	if res.HTTP {
		return httpPhaseFromALPN(res.ALPN)
	}
	if res.TLS {
		return "tls"
	}
	if res.TCP {
		return "tcp"
	}
	for i := len(phases) - 1; i >= 0; i-- {
		if phases[i].Status != "success" && phases[i].Status != "skipped" {
			return phases[i].Phase
		}
	}
	if lastErrCode != "" {
		return "tcp"
	}
	return ""
}

func finalRouteFailurePhase(phases []PhaseResult) string {
	for i := len(phases) - 1; i >= 0; i-- {
		if phases[i].Phase == "route" && phases[i].Status != "success" && phases[i].Status != "skipped" {
			return "route"
		}
	}
	return ""
}

func resultIndicatesTimeout(res result) bool {
	for _, phase := range res.PhaseResults {
		if phase.Status == "timeout" || strings.HasSuffix(strings.ToUpper(phase.ErrorCode), "_TIMEOUT") {
			return true
		}
	}
	return strings.HasSuffix(res.ErrorCode, "_TIMEOUT")
}

func resultIndicatesReset(res result) bool {
	for _, phase := range res.PhaseResults {
		if phase.Status == "reset" || strings.HasSuffix(strings.ToUpper(phase.ErrorCode), "_RESET") {
			return true
		}
	}
	return strings.HasSuffix(res.ErrorCode, "_RESET")
}

func resultErrorSignals(res result) []string {
	var signals []string
	for _, phase := range res.PhaseResults {
		if phase.Status == "" || phase.Status == "success" || phase.Status == "skipped" {
			continue
		}
		signal := strings.TrimSpace(phase.ErrorCode)
		if signal == "" {
			signal = strings.TrimSpace(phase.Status)
		}
		if signal != "" {
			signals = append(signals, signal)
		}
	}
	if strings.TrimSpace(res.RouteErrorCode) != "" {
		signals = append(signals, strings.TrimSpace(res.RouteErrorCode))
	}
	if strings.TrimSpace(res.ErrorCode) != "" {
		signals = append(signals, strings.TrimSpace(res.ErrorCode))
	}
	if strings.TrimSpace(res.Error) != "" {
		signals = append(signals, strings.TrimSpace(res.Error))
	}
	return signals
}

func buildRoutePhaseResult(res result) (PhaseResult, bool) {
	code := strings.TrimSpace(res.RouteErrorCode)
	if code != "" {
		return newPhaseFailure("route", fmt.Errorf("%s", code), 0, code), true
	}
	if res.RouteObserved && res.RouteUsed {
		return newPhaseSuccess("route", 0), true
	}
	if res.RouteObserved && !res.RouteUsed {
		return PhaseResult{
			Phase:     "route",
			Status:    "failed",
			ErrorCode: firstNonEmpty(res.RouteMismatchCode, "ROUTE_OBSERVATION_FAILED"),
			Retryable: false,
			Evidence:  map[string]any{"route_evidence_state": res.RouteEvidenceState},
		}, true
	}
	return PhaseResult{}, false
}
