package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func writePublicBadRequest(w http.ResponseWriter, message string) {
	writePublicError(w, http.StatusBadRequest, "BAD_REQUEST", message, nil)
}

func writeScanInputError(w http.ResponseWriter, code, message string, details map[string]any) {
	writePublicError(w, http.StatusBadRequest, code, message, details)
}

func writePublicMethodNotAllowed(w http.ResponseWriter, requiredMethod string) {
	writePublicError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed", map[string]any{
		"required_method": requiredMethod,
	})
}

func writePublicMethodNotAllowedForRequest(w http.ResponseWriter, r *http.Request, requiredMethod string) {
	writePublicErrorForRequest(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed", map[string]any{
		"required_method": requiredMethod,
	})
}

func writePublicError(w http.ResponseWriter, status int, code, message string, details map[string]any) {
	writePublicErrorForRequest(w, nil, status, code, message, details)
}

func writePublicErrorForRequest(w http.ResponseWriter, r *http.Request, status int, code, message string, details map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	payload := map[string]any{
		"schema_version": sidecarAPIVersion,
		"error_code":     code,
		"message":        message,
		"status":         "error",
		"phase":          publicErrorPhase(code),
		"retryable":      publicErrorRetryable(code, status),
	}
	if id := requestCorrelationID(r); id != "" {
		payload["request_id"] = id
	}
	if len(details) > 0 {
		redacted := redactPublicDetails(details)
		if method, ok := redacted["required_method"]; ok {
			payload["required_method"] = method
			delete(redacted, "required_method")
		}
		if len(redacted) > 0 {
			payload["details"] = redacted
		}
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func requestCorrelationID(r *http.Request) string {
	if r == nil {
		return ""
	}
	for _, key := range []string{"X-Request-Id", "X-Request-ID", "X-Correlation-Id", "X-Correlation-ID"} {
		if value := strings.TrimSpace(r.Header.Get(key)); value != "" {
			return value
		}
	}
	return ""
}

func publicErrorPhase(code string) string {
	switch {
	case strings.HasPrefix(code, "DNS_"):
		return "dns"
	case strings.HasPrefix(code, "PLUGIN_"), strings.HasPrefix(code, "ROUTE_"):
		return "route"
	case code == "METHOD_NOT_ALLOWED", code == "LOCAL_API_UNAUTHORIZED", code == "BAD_REQUEST":
		return "api"
	case strings.HasPrefix(code, "NO_"):
		return "scan_input"
	case code == "DASHBOARD_NOT_FOUND", code == "PROVIDER_CORPUS_UNAVAILABLE":
		return "read"
	default:
		return "scan"
	}
}

func publicErrorRetryable(code string, status int) bool {
	switch code {
	case "DNS_TIMEOUT", "DNS_TRUNCATED_RETRY_FAILED":
		return true
	default:
		return status >= http.StatusInternalServerError
	}
}

func redactPublicDetails(details map[string]any) map[string]any {
	if len(details) == 0 {
		return nil
	}
	out := make(map[string]any, len(details))
	for key, value := range details {
		switch key {
		case "proxy_password", "token", "authorization", "cookie", "set_cookie":
			continue
		default:
			if s, ok := value.(string); ok {
				out[key] = redactSensitiveString(s)
			} else {
				out[key] = value
			}
		}
	}
	return out
}

func redactSensitiveString(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "password="),
		strings.Contains(lower, "token="),
		strings.Contains(lower, "bearer "),
		strings.Contains(lower, "set-cookie"):
		return "[redacted]"
	default:
		return value
	}
}
