package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicAPIErrorEnvelopeParity(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	if err := initProviderCorpusObserver(); err != nil {
		t.Fatalf("initProviderCorpusObserver failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan", cp.requireMutationAuth(scan))
	mux.HandleFunc("/api/dns", cp.requireMutationAuth(scanDNS))
	mux.HandleFunc("/api/stop", cp.requireMutationAuth(cp.stop))
	mux.HandleFunc("/api/shutdown", cp.requireMutationAuth(cp.shutdown))
	mux.HandleFunc("/api/export/nmap", cp.requireMutationAuth(exportNmap))
	mux.HandleFunc("/api/plugins", routingPlugins)
	mux.HandleFunc("/api/plugins/validate", cp.requireMutationAuth(validateRoutingPlugin))
	mux.HandleFunc("/api/provider-corpus", providerCorpusStatusHandler)
	mux.HandleFunc("/api/heartbeat", cp.requireReadAuth(cp.heartbeat))
	mux.HandleFunc("/metrics", cp.requireReadAuth(metrics))
	mux.HandleFunc("/health", cp.requireReadAuth(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))

	server := httptest.NewServer(mux)
	defer server.Close()

	type parityCase struct {
		name         string
		method       string
		path         string
		body         string
		useAuth      bool
		wantStatus   int
		wantError    string
		wantContains string
	}

	cases := []parityCase{
		{name: "scan method guard", method: http.MethodGet, path: "/api/scan", wantStatus: http.StatusMethodNotAllowed, wantError: "METHOD_NOT_ALLOWED", wantContains: `"required_method":"POST"`},
		{name: "scan unauthorized", method: http.MethodPost, path: "/api/scan", wantStatus: http.StatusUnauthorized, wantError: "LOCAL_API_UNAUTHORIZED"},
		{name: "scan bad request", method: http.MethodPost, path: "/api/scan", body: "{", useAuth: true, wantStatus: http.StatusBadRequest, wantError: "BAD_REQUEST"},
		{name: "dns method guard", method: http.MethodGet, path: "/api/dns", wantStatus: http.StatusMethodNotAllowed, wantError: "METHOD_NOT_ALLOWED", wantContains: `"required_method":"POST"`},
		{name: "dns unauthorized", method: http.MethodPost, path: "/api/dns", wantStatus: http.StatusUnauthorized, wantError: "LOCAL_API_UNAUTHORIZED"},
		{name: "dns bad request", method: http.MethodPost, path: "/api/dns", body: "{", useAuth: true, wantStatus: http.StatusBadRequest, wantError: "BAD_REQUEST"},
		{name: "stop method guard", method: http.MethodGet, path: "/api/stop", wantStatus: http.StatusMethodNotAllowed, wantError: "METHOD_NOT_ALLOWED", wantContains: `"required_method":"POST"`},
		{name: "stop unauthorized", method: http.MethodPost, path: "/api/stop", wantStatus: http.StatusUnauthorized, wantError: "LOCAL_API_UNAUTHORIZED"},
		{name: "stop success", method: http.MethodPost, path: "/api/stop", useAuth: true, wantStatus: http.StatusOK, wantContains: `"status":"stopping"`},
		{name: "shutdown method guard", method: http.MethodGet, path: "/api/shutdown", wantStatus: http.StatusMethodNotAllowed, wantError: "METHOD_NOT_ALLOWED", wantContains: `"required_method":"POST"`},
		{name: "shutdown unauthorized", method: http.MethodPost, path: "/api/shutdown", wantStatus: http.StatusUnauthorized, wantError: "LOCAL_API_UNAUTHORIZED"},
		{name: "shutdown success", method: http.MethodPost, path: "/api/shutdown", useAuth: true, wantStatus: http.StatusOK, wantContains: `"status":"shutting_down"`},
		{name: "export method guard", method: http.MethodGet, path: "/api/export/nmap", wantStatus: http.StatusMethodNotAllowed, wantError: "METHOD_NOT_ALLOWED", wantContains: `"required_method":"POST"`},
		{name: "export unauthorized", method: http.MethodPost, path: "/api/export/nmap", wantStatus: http.StatusUnauthorized, wantError: "LOCAL_API_UNAUTHORIZED"},
		{name: "export bad request", method: http.MethodPost, path: "/api/export/nmap", body: "{}", useAuth: true, wantStatus: http.StatusBadRequest, wantError: "BAD_REQUEST"},
		{name: "plugins method guard", method: http.MethodPost, path: "/api/plugins", wantStatus: http.StatusMethodNotAllowed, wantError: "METHOD_NOT_ALLOWED", wantContains: `"required_method":"GET"`},
		{name: "plugins validate method guard", method: http.MethodGet, path: "/api/plugins/validate", wantStatus: http.StatusMethodNotAllowed, wantError: "METHOD_NOT_ALLOWED", wantContains: `"required_method":"POST"`},
		{name: "plugins validate unauthorized", method: http.MethodPost, path: "/api/plugins/validate", wantStatus: http.StatusUnauthorized, wantError: "LOCAL_API_UNAUTHORIZED"},
		{name: "plugins validate malformed", method: http.MethodPost, path: "/api/plugins/validate", body: "{", useAuth: true, wantStatus: http.StatusBadRequest, wantError: "PLUGIN_CONFIG_MALFORMED"},
		{name: "provider corpus method guard", method: http.MethodPost, path: "/api/provider-corpus", wantStatus: http.StatusMethodNotAllowed, wantError: "METHOD_NOT_ALLOWED", wantContains: `"required_method":"GET"`},
		{name: "heartbeat method guard", method: http.MethodPost, path: "/api/heartbeat", useAuth: true, wantStatus: http.StatusMethodNotAllowed, wantError: "METHOD_NOT_ALLOWED", wantContains: `"required_method":"GET"`},
		{name: "heartbeat unauthorized", method: http.MethodGet, path: "/api/heartbeat", wantStatus: http.StatusUnauthorized, wantError: "LOCAL_API_UNAUTHORIZED"},
		{name: "metrics method guard", method: http.MethodPost, path: "/metrics", useAuth: true, wantStatus: http.StatusMethodNotAllowed, wantError: "METHOD_NOT_ALLOWED", wantContains: `"required_method":"GET"`},
		{name: "metrics unauthorized", method: http.MethodGet, path: "/metrics", wantStatus: http.StatusUnauthorized, wantError: "LOCAL_API_UNAUTHORIZED"},
		{name: "health method guard", method: http.MethodPost, path: "/health", useAuth: true, wantStatus: http.StatusMethodNotAllowed, wantError: "METHOD_NOT_ALLOWED", wantContains: `"required_method":"GET"`},
		{name: "health unauthorized", method: http.MethodGet, path: "/health", wantStatus: http.StatusUnauthorized, wantError: "LOCAL_API_UNAUTHORIZED"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := io.Reader(http.NoBody)
			if tc.body != "" {
				reqBody = bytes.NewBufferString(tc.body)
			}
			req, err := http.NewRequest(tc.method, server.URL+tc.path, reqBody)
			if err != nil {
				t.Fatalf("new request failed: %v", err)
			}
			if tc.useAuth {
				req.Header.Set("Authorization", "Bearer "+cp.token)
			}
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer res.Body.Close()
			raw, _ := io.ReadAll(res.Body)
			body := string(raw)

			if res.StatusCode != tc.wantStatus {
				t.Fatalf("status=%d, want %d body=%s", res.StatusCode, tc.wantStatus, body)
			}
			if tc.wantError != "" && !strings.Contains(body, `"error_code":"`+tc.wantError+`"`) {
				t.Fatalf("expected error_code %q, got body=%s", tc.wantError, body)
			}
			if tc.wantContains != "" && !strings.Contains(body, tc.wantContains) {
				t.Fatalf("expected body to contain %q, got %s", tc.wantContains, body)
			}
		})
	}
}
