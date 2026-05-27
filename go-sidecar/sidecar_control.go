package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

const (
	sidecarAPIVersion      = 1
	defaultRequestBodySize = 8 << 20
	sidecarTokenCookieName = "sidecar_token"
	defaultSourceOfferURL  = "https://github.com/maybeknott/MaybeEdgeScanner"
	defaultLicenseID       = "AGPL-3.0-or-later"
)

type sidecarControlPlane struct {
	token       string
	startedAt   time.Time
	nonce       string
	state       atomic.Value
	lastBeatNS  atomic.Int64
	shutdownFn  atomic.Value
	manualStops atomic.Uint64
}

type heartbeatPayload struct {
	Version              int    `json:"version"`
	Nonce                string `json:"nonce"`
	ScanSessionID        string `json:"scan_session_id"`
	ParentPIDIfAvailable int    `json:"parent_pid_if_available"`
	SidecarPID           int    `json:"sidecar_pid"`
	MonotonicTimestampMS int64  `json:"monotonic_timestamp_ms"`
	ExpiryMS             int64  `json:"expiry_ms"`
	State                string `json:"state"`
	UptimeMS             int64  `json:"uptime_ms"`
	Goroutines           int    `json:"goroutines"`
	ManualStops          uint64 `json:"manual_stops"`
	TokenRequired        bool   `json:"token_required"`
	LicenseID            string `json:"license_id"`
	SourceOfferURL       string `json:"source_offer_url"`
	SourceRevision       string `json:"source_revision,omitempty"`
}

func newSidecarControlPlane() *sidecarControlPlane {
	token := strings.TrimSpace(os.Getenv("MAYBEEDGESCANNER_SIDECAR_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("MAYBESCANNER_SIDECAR_TOKEN"))
	}
	if token == "" {
		token = randomHex(32)
	}
	cp := &sidecarControlPlane{
		token:     token,
		startedAt: time.Now(),
		nonce:     randomHex(16),
	}
	cp.state.Store("idle")
	cp.lastBeatNS.Store(time.Now().UnixNano())
	return cp
}

func (cp *sidecarControlPlane) setShutdown(fn func(context.Context) error) {
	cp.shutdownFn.Store(fn)
}

func (cp *sidecarControlPlane) setState(state string) {
	if strings.TrimSpace(state) == "" {
		state = "unknown"
	}
	cp.state.Store(state)
}

func (cp *sidecarControlPlane) stateString() string {
	if value, ok := cp.state.Load().(string); ok && value != "" {
		return value
	}
	return "unknown"
}

func (cp *sidecarControlPlane) requireMutationAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if !cp.authorized(r) {
			http.Error(w, "unauthorized sidecar control request", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, defaultRequestBodySize)
		next(w, r)
	}
}

func (cp *sidecarControlPlane) authorized(r *http.Request) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		auth = strings.TrimSpace(auth[7:])
	}
	if auth == "" {
		auth = strings.TrimSpace(r.Header.Get("X-Sidecar-Token"))
	}
	if auth == "" {
		if cookie, err := r.Cookie(sidecarTokenCookieName); err == nil {
			auth = strings.TrimSpace(cookie.Value)
		}
	}
	if auth == "" {
		auth = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	return subtle.ConstantTimeCompare([]byte(auth), []byte(cp.token)) == 1
}

func (cp *sidecarControlPlane) setBrowserCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sidecarTokenCookieName,
		Value:    cp.token,
		Path:     "/api/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (cp *sidecarControlPlane) heartbeat(w http.ResponseWriter, _ *http.Request) {
	cp.lastBeatNS.Store(time.Now().UnixNano())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cp.heartbeatPayload())
}

func (cp *sidecarControlPlane) heartbeatPayload() heartbeatPayload {
	now := time.Now()
	sourceOfferURL := strings.TrimSpace(os.Getenv("MAYBEEDGESCANNER_SOURCE_OFFER_URL"))
	if sourceOfferURL == "" {
		sourceOfferURL = strings.TrimSpace(os.Getenv("MAYBESCANNER_SOURCE_OFFER_URL"))
	}
	if sourceOfferURL == "" {
		sourceOfferURL = defaultSourceOfferURL
	}
	sourceRevision := strings.TrimSpace(os.Getenv("MAYBEEDGESCANNER_SOURCE_REVISION"))
	if sourceRevision == "" {
		sourceRevision = strings.TrimSpace(os.Getenv("MAYBESCANNER_SOURCE_REVISION"))
	}
	if sourceRevision == "" {
		sourceRevision = strings.TrimSpace(os.Getenv("GITHUB_SHA"))
	}
	return heartbeatPayload{
		Version:              sidecarAPIVersion,
		Nonce:                cp.nonce,
		ScanSessionID:        "active-" + cp.stateString(),
		ParentPIDIfAvailable: os.Getppid(),
		SidecarPID:           os.Getpid(),
		MonotonicTimestampMS: now.Sub(cp.startedAt).Milliseconds(),
		ExpiryMS:             15000,
		State:                cp.stateString(),
		UptimeMS:             now.Sub(cp.startedAt).Milliseconds(),
		Goroutines:           runtime.NumGoroutine(),
		ManualStops:          cp.manualStops.Load(),
		TokenRequired:        true,
		LicenseID:            defaultLicenseID,
		SourceOfferURL:       sourceOfferURL,
		SourceRevision:       sourceRevision,
	}
}

func (cp *sidecarControlPlane) stop(w http.ResponseWriter, _ *http.Request) {
	cp.manualStops.Add(1)
	cp.setState("manual_stop")
	activeCancelMu.Lock()
	if activeCancel != nil {
		activeCancel()
	}
	activeCancelMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "stopping", "reason": "manual_stop"})
}

func (cp *sidecarControlPlane) shutdown(w http.ResponseWriter, _ *http.Request) {
	cp.manualStops.Add(1)
	cp.setState("shutdown_requested")
	activeCancelMu.Lock()
	if activeCancel != nil {
		activeCancel()
	}
	activeCancelMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "shutting_down"})
	if value := cp.shutdownFn.Load(); value != nil {
		if fn, ok := value.(func(context.Context) error); ok {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = fn(ctx)
			}()
		}
	}
}

func randomHex(bytesLen int) string {
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(buf)
}
