package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mustNewSidecarControlPlane(t *testing.T) *sidecarControlPlane {
	t.Helper()
	cp, err := newSidecarControlPlane()
	if err != nil {
		t.Fatalf("newSidecarControlPlane() error: %v", err)
	}
	return cp
}

func TestSidecarMutationAuthRejectsMissingToken(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	called := false
	handler := cp.requireMutationAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/stop", nil)
	handler(rec, req)
	if called {
		t.Fatal("handler called without token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rec.Body.String(), `"error_code":"LOCAL_API_UNAUTHORIZED"`) {
		t.Fatalf("expected structured unauthorized error, got %s", rec.Body.String())
	}
}

func TestSidecarMutationAuthAcceptsBearerToken(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	called := false
	handler := cp.requireMutationAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/stop", nil)
	req.Header.Set("Authorization", "Bearer "+cp.token)
	handler(rec, req)
	if !called {
		t.Fatal("handler not called with valid token")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestSidecarMutationAuthAcceptsHttpOnlyCookie(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	called := false
	handler := cp.requireMutationAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/stop", nil)
	req.AddCookie(&http.Cookie{Name: sidecarTokenCookieName, Value: cp.token})
	handler(rec, req)
	if !called {
		t.Fatal("handler not called with valid sidecar cookie")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestSidecarBrowserCookieIsHttpOnlyAndAPIScoped(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	rec := httptest.NewRecorder()
	cp.setBrowserCookie(rec)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != sidecarTokenCookieName || cookie.Value != cp.token {
		t.Fatalf("unexpected cookie: %#v", cookie)
	}
	if !cookie.HttpOnly {
		t.Fatal("sidecar token cookie must be HttpOnly")
	}
	if cookie.Path != "/api/" {
		t.Fatalf("cookie path=%q, want /api/", cookie.Path)
	}
}

func TestSidecarMutationAuthRequiresPostBeforeToken(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/stop", nil)
	req.Header.Set("Authorization", "Bearer "+cp.token)
	cp.requireMutationAuth(func(w http.ResponseWriter, r *http.Request) {})(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if !strings.Contains(rec.Body.String(), `"error_code":"METHOD_NOT_ALLOWED"`) || !strings.Contains(rec.Body.String(), `"required_method":"POST"`) {
		t.Fatalf("expected structured method error, got %s", rec.Body.String())
	}
}

func TestSidecarMutationAuthLimitsBodySize(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	handler := cp.requireMutationAuth(func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Body.Read(make([]byte, defaultRequestBodySize+1))
		if err == nil {
			t.Fatal("expected limited reader error")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(strings.Repeat("x", defaultRequestBodySize+1024)))
	req.Header.Set("Authorization", "Bearer "+cp.token)
	handler(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestHeartbeatPayloadIsVersionedAndTokenRedacted(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	payload := cp.heartbeatPayload()
	if payload.Version != sidecarAPIVersion {
		t.Fatalf("version=%d, want %d", payload.Version, sidecarAPIVersion)
	}
	if !payload.TokenRequired {
		t.Fatal("heartbeat must advertise token requirement")
	}
	if strings.Contains(payload.Nonce, cp.token) {
		t.Fatal("heartbeat leaked token through nonce")
	}
	if payload.LicenseID == "" {
		t.Fatal("heartbeat must include license id")
	}
	if payload.SourceOfferURL == "" {
		t.Fatal("heartbeat must include source offer URL")
	}
}

func TestSidecarMutationAuthRejectsQueryToken(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	called := false
	handler := cp.requireMutationAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/stop?token="+cp.token, nil)
	handler(rec, req)
	if called {
		t.Fatal("handler called with query token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestSidecarMutationAuthRejectsLengthMismatchedToken(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	called := false
	handler := cp.requireMutationAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/stop", nil)
	req.Header.Set("X-Sidecar-Token", "x")
	handler(rec, req)
	if called {
		t.Fatal("handler called with wrong token length")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestSidecarMutationAuthRejectsWrongSameLengthToken(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	called := false
	handler := cp.requireMutationAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/stop", nil)
	req.Header.Set("X-Sidecar-Token", strings.Repeat("a", len(cp.token)))
	handler(rec, req)
	if called {
		t.Fatal("handler called with wrong same-length token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestSidecarReadAuthRejectsMissingToken(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	called := false
	handler := cp.requireReadAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	handler(rec, req)
	if called {
		t.Fatal("read handler called without token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rec.Body.String(), `"error_code":"LOCAL_API_UNAUTHORIZED"`) {
		t.Fatalf("expected structured unauthorized error, got %s", rec.Body.String())
	}
}

func TestSidecarReadAuthAcceptsBearerToken(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	called := false
	handler := cp.requireReadAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+cp.token)
	handler(rec, req)
	if !called {
		t.Fatal("read handler not called with valid token")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestSidecarReadAuthAcceptsHttpOnlyCookieForMetrics(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	called := false
	handler := cp.requireReadAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.AddCookie(&http.Cookie{Name: sidecarTokenCookieName, Value: cp.token})
	handler(rec, req)
	if !called {
		t.Fatal("metrics read handler not called with valid sidecar cookie")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestSidecarReadAuthRequiresGetBeforeToken(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+cp.token)
	cp.requireReadAuth(func(w http.ResponseWriter, r *http.Request) {})(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if !strings.Contains(rec.Body.String(), `"error_code":"METHOD_NOT_ALLOWED"`) || !strings.Contains(rec.Body.String(), `"required_method":"GET"`) {
		t.Fatalf("expected structured method error, got %s", rec.Body.String())
	}
}

func TestSidecarReadAuthRejectsMissingTokenForHealth(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	called := false
	handler := cp.requireReadAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler(rec, req)
	if called {
		t.Fatal("health read handler called without token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rec.Body.String(), `"error_code":"LOCAL_API_UNAUTHORIZED"`) {
		t.Fatalf("expected structured unauthorized error for /health, got %s", rec.Body.String())
	}
}

func TestSidecarReadAuthAcceptsBearerTokenForHealth(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	called := false
	handler := cp.requireReadAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Authorization", "Bearer "+cp.token)
	handler(rec, req)
	if !called {
		t.Fatal("health read handler not called with valid token")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestSidecarReadAuthAcceptsHttpOnlyCookieForHealth(t *testing.T) {
	cp := mustNewSidecarControlPlane(t)
	called := false
	handler := cp.requireReadAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.AddCookie(&http.Cookie{Name: sidecarTokenCookieName, Value: cp.token})
	handler(rec, req)
	if !called {
		t.Fatal("health read handler not called with valid sidecar cookie")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestNewSidecarControlPlaneFailsClosedWhenRNGFails(t *testing.T) {
	prev := randomHexGenerator
	t.Cleanup(func() {
		randomHexGenerator = prev
	})
	randomHexGenerator = func(int) (string, error) {
		return "", errors.New("rng unavailable")
	}
	if _, err := newSidecarControlPlane(); err == nil {
		t.Fatal("expected sidecar control plane init failure when RNG fails")
	}
}
