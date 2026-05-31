package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicAPIErrorEnvelopeRequiredFields(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
	req.Header.Set("X-Request-Id", "req-b3-audit-1")
	writePublicErrorForRequest(rec, req, http.StatusUnauthorized, "LOCAL_API_UNAUTHORIZED", "unauthorized sidecar control request", nil)

	assertPublicErrorEnvelope(t, rec, "LOCAL_API_UNAUTHORIZED", "req-b3-audit-1")
}

func TestPublicAPIErrorEnvelopeScanInputDetails(t *testing.T) {
	rec := httptest.NewRecorder()
	writeScanInputError(rec, "NO_TARGETS_SELECTED", "no targets selected", map[string]any{
		"submitted_target_count": 0,
	})

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if payload["error_code"] != "NO_TARGETS_SELECTED" {
		t.Fatalf("error_code=%v", payload["error_code"])
	}
	if payload["phase"] != "scan_input" {
		t.Fatalf("phase=%v", payload["phase"])
	}
	details, ok := payload["details"].(map[string]any)
	if !ok {
		t.Fatalf("expected details object, got %#v", payload["details"])
	}
	if details["submitted_target_count"].(float64) != 0 {
		t.Fatalf("details=%#v", details)
	}
}

func TestRootDashboardIsHTMLNotJSONAPI(t *testing.T) {
	rec := httptest.NewRecorder()
	index(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("content-type=%q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "<!doctype html>") {
		t.Fatalf("expected HTML dashboard body")
	}
}

func assertPublicErrorEnvelope(t *testing.T, rec *httptest.ResponseRecorder, wantCode, wantRequestID string) {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal failed: %v body=%s", err, rec.Body.String())
	}
	for _, key := range []string{"error_code", "message", "status", "phase", "retryable"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("missing %q in %#v", key, payload)
		}
	}
	if payload["error_code"] != wantCode {
		t.Fatalf("error_code=%v want %q", payload["error_code"], wantCode)
	}
	if payload["status"] != "error" {
		t.Fatalf("status=%v", payload["status"])
	}
	if payload["request_id"] != wantRequestID {
		t.Fatalf("request_id=%v want %q", payload["request_id"], wantRequestID)
	}
	if strings.Contains(rec.Body.String(), "http.Error") {
		t.Fatalf("raw http error text leaked: %s", rec.Body.String())
	}
}
