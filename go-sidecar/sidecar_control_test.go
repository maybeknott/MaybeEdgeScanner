package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSidecarMutationAuthRejectsMissingToken(t *testing.T) {
	cp := newSidecarControlPlane()
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
}

func TestSidecarMutationAuthAcceptsBearerToken(t *testing.T) {
	cp := newSidecarControlPlane()
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
	cp := newSidecarControlPlane()
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
	cp := newSidecarControlPlane()
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
	cp := newSidecarControlPlane()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/stop", nil)
	req.Header.Set("Authorization", "Bearer "+cp.token)
	cp.requireMutationAuth(func(w http.ResponseWriter, r *http.Request) {})(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestSidecarMutationAuthLimitsBodySize(t *testing.T) {
	cp := newSidecarControlPlane()
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
	cp := newSidecarControlPlane()
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
