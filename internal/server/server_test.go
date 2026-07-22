package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"agent-gateway/internal/auth"
	"agent-gateway/internal/channel"
	"agent-gateway/internal/config"
	"agent-gateway/internal/domain"
	sqlitestore "agent-gateway/internal/store/sqlite"
)

func newRootTestServer() *Server {
	s := &Server{
		channels: &channel.Manager{},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics:  &gatewayMetrics{},
		mux:      http.NewServeMux(),
	}
	s.routes()
	return s
}

func TestRootAvailableWithoutPlatformConnections(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	newRootTestServer().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("root status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var response struct {
		Code int `json:"code"`
		Data struct {
			Service             string `json:"service"`
			Status              string `json:"status"`
			PlatformConnections int    `json:"platformConnections"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Code != 0 || response.Data.Service != "agent-gateway" || response.Data.Status != "ok" || response.Data.PlatformConnections != 0 {
		t.Fatalf("unexpected root response: %#v", response)
	}
}

func TestRootHandlerKeepsUnknownPathsNotFound(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	newRootTestServer().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestRootRejectsUnsupportedMethods(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	newRootTestServer().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("root POST status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
	if allow := recorder.Header().Get("Allow"); allow != http.MethodGet {
		t.Fatalf("Allow header = %q, want %q", allow, http.MethodGet)
	}
}

func newLocalAuthTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := sqlitestore.Open(t.TempDir() + "/gateway.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UnixMilli()
	if err := st.BootstrapTenant(context.Background(), domain.Tenant{ID: "local", Name: "Local Gateway", Status: "active", CreatedAt: now, UpdatedAt: now}, []string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	local, err := auth.NewLocal("admin", "$2y$10$zyl54qe9Gnag/R1Z3zyPKOl1ky4JeO0xx.FfkmDsTudw/ld/T6io2", "Administrator", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}
	browser := auth.NewBrowser(st, auth.NewOIDC(), local, false, time.Hour, time.Hour, "")
	channels := channel.NewManager(st, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), 1<<20, 16, time.Second)
	t.Cleanup(channels.Close)
	return New(config.Config{AuthMode: "local", TenantHMACSecret: "01234567890123456789012345678901", RateLimitPerMinute: 1000, MaxConcurrentStreams: 8}, st, browser, channels, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func responseCookie(recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name && cookie.Value != "" {
			return cookie
		}
	}
	return nil
}

func TestLocalLoginCreatesGatewaySession(t *testing.T) {
	server := newLocalAuthTestServer(t)
	sessionRequest := httptest.NewRequest(http.MethodGet, "http://example.com/api/gateway/session", nil)
	sessionRecorder := httptest.NewRecorder()
	server.ServeHTTP(sessionRecorder, sessionRequest)
	if sessionRecorder.Code != http.StatusOK {
		t.Fatalf("anonymous session status = %d, body=%s", sessionRecorder.Code, sessionRecorder.Body.String())
	}
	var anonymous struct {
		Data struct {
			Authenticated bool           `json:"authenticated"`
			CSRFToken     string         `json:"csrfToken"`
			Tenant        map[string]any `json:"tenant"`
			Auth          struct {
				Mode     string `json:"mode"`
				LoginURL string `json:"loginUrl"`
			} `json:"auth"`
		} `json:"data"`
	}
	if err := json.Unmarshal(sessionRecorder.Body.Bytes(), &anonymous); err != nil {
		t.Fatal(err)
	}
	if anonymous.Data.Authenticated || anonymous.Data.CSRFToken == "" || anonymous.Data.Auth.Mode != "local" || anonymous.Data.Auth.LoginURL != "/login" {
		t.Fatalf("unexpected anonymous session: %#v", anonymous.Data)
	}
	if _, exposed := anonymous.Data.Tenant["tenantId"]; exposed {
		t.Fatal("session must not expose tenantId")
	}
	anonymousCookie := responseCookie(sessionRecorder, auth.AnonymousCookieName)
	if anonymousCookie == nil {
		t.Fatal("anonymous session cookie is required")
	}

	loginRequest := httptest.NewRequest(http.MethodPost, "http://example.com/api/gateway/login", strings.NewReader(`{"username":"admin","password":"password"}`))
	loginRequest.AddCookie(anonymousCookie)
	loginRequest.Header.Set("Content-Type", "application/json")
	loginRequest.Header.Set("X-CSRF-Token", anonymous.Data.CSRFToken)
	loginRecorder := httptest.NewRecorder()
	server.ServeHTTP(loginRecorder, loginRequest)
	if loginRecorder.Code != http.StatusOK {
		t.Fatalf("login status = %d, body=%s", loginRecorder.Code, loginRecorder.Body.String())
	}
	webCookie := responseCookie(loginRecorder, auth.SessionCookieName)
	if webCookie == nil || !webCookie.HttpOnly || webCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected web session cookie: %#v", webCookie)
	}

	authenticatedRequest := httptest.NewRequest(http.MethodGet, "http://example.com/api/gateway/session", nil)
	authenticatedRequest.AddCookie(webCookie)
	authenticatedRecorder := httptest.NewRecorder()
	server.ServeHTTP(authenticatedRecorder, authenticatedRequest)
	if !bytes.Contains(authenticatedRecorder.Body.Bytes(), []byte(`"authenticated":true`)) || !bytes.Contains(authenticatedRecorder.Body.Bytes(), []byte(`"subject":"local:admin"`)) {
		t.Fatalf("unexpected authenticated session: %s", authenticatedRecorder.Body.String())
	}
}

func TestLocalLoginRotatesExistingSession(t *testing.T) {
	server := newLocalAuthTestServer(t)
	sessionRequest := httptest.NewRequest(http.MethodGet, "http://example.com/api/gateway/session", nil)
	sessionRecorder := httptest.NewRecorder()
	server.ServeHTTP(sessionRecorder, sessionRequest)
	var anonymous struct {
		Data struct {
			CSRFToken string `json:"csrfToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(sessionRecorder.Body.Bytes(), &anonymous); err != nil {
		t.Fatal(err)
	}
	login := func(cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "http://example.com/api/gateway/login", strings.NewReader(`{"username":"admin","password":"password"}`))
		request.AddCookie(cookie)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrf)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		return recorder
	}
	firstLogin := login(responseCookie(sessionRecorder, auth.AnonymousCookieName), anonymous.Data.CSRFToken)
	oldCookie := responseCookie(firstLogin, auth.SessionCookieName)
	currentRequest := httptest.NewRequest(http.MethodGet, "http://example.com/api/gateway/session", nil)
	currentRequest.AddCookie(oldCookie)
	currentRecorder := httptest.NewRecorder()
	server.ServeHTTP(currentRecorder, currentRequest)
	var current struct {
		Data struct {
			CSRFToken string `json:"csrfToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(currentRecorder.Body.Bytes(), &current); err != nil {
		t.Fatal(err)
	}
	secondLogin := login(oldCookie, current.Data.CSRFToken)
	if secondLogin.Code != http.StatusOK || responseCookie(secondLogin, auth.SessionCookieName) == nil {
		t.Fatalf("second login failed: status=%d body=%s", secondLogin.Code, secondLogin.Body.String())
	}
	staleRequest := httptest.NewRequest(http.MethodGet, "http://example.com/api/gateway/session", nil)
	staleRequest.AddCookie(oldCookie)
	staleRecorder := httptest.NewRecorder()
	server.ServeHTTP(staleRecorder, staleRequest)
	if bytes.Contains(staleRecorder.Body.Bytes(), []byte(`"authenticated":true`)) {
		t.Fatalf("rotated session cookie remained valid: %s", staleRecorder.Body.String())
	}
}

func TestLocalLoginCredentialFailureStaysInline(t *testing.T) {
	server := newLocalAuthTestServer(t)
	sessionRequest := httptest.NewRequest(http.MethodGet, "http://example.com/api/gateway/session", nil)
	sessionRecorder := httptest.NewRecorder()
	server.ServeHTTP(sessionRecorder, sessionRequest)
	var session struct {
		Data struct {
			CSRFToken string `json:"csrfToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(sessionRecorder.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://example.com/api/gateway/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
	request.AddCookie(responseCookie(sessionRecorder, auth.AnonymousCookieName))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", session.Data.CSRFToken)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), "invalid_credentials") || strings.Contains(recorder.Body.String(), "authentication_required") {
		t.Fatalf("unexpected credential failure: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestUnauthorizedUsesConfiguredLoginSurface(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.com/app/chat?agent=public#draft", nil)
	for _, test := range []struct {
		mode string
		path string
	}{
		{mode: "local", path: "/login?return_to="},
		{mode: "oidc", path: "/auth/login?return_to="},
	} {
		t.Run(test.mode, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server := &Server{cfg: config.Config{AuthMode: test.mode}}
			server.writeUnauthorized(recorder, request)
			if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), test.path) {
				t.Fatalf("unexpected unauthorized response: status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestPlatformAuthenticationFailureIsNotExposedAsBrowser401(t *testing.T) {
	status, code, message := normalizeUpstreamAuthError(http.StatusUnauthorized, "unauthorized", "bad channel token")
	if status != http.StatusBadGateway || code != "upstream_auth_failed" || message != "Platform upstream authentication failed" {
		t.Fatalf("unexpected normalized error: status=%d code=%q message=%q", status, code, message)
	}
}

func TestValidReturnToRejectsExternalNavigation(t *testing.T) {
	for _, value := range []string{"https://evil.example/path", "//evil.example/path", `/\\evil.example/path`, `/%5cevil.example/path`} {
		if got := validReturnTo(value); got != "/" {
			t.Fatalf("validReturnTo(%q) = %q, want /", value, got)
		}
	}
	if got := validReturnTo("/copilot/public-agent?chat=one#latest"); got != "/copilot/public-agent?chat=one#latest" {
		t.Fatalf("safe return path = %q", got)
	}
}
