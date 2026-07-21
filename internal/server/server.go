package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"agent-gateway/internal/auth"
	"agent-gateway/internal/channel"
	"agent-gateway/internal/config"
	"agent-gateway/internal/domain"
	"agent-gateway/internal/id"
	"agent-gateway/internal/limit"
	"agent-gateway/internal/store"
)

type Server struct {
	cfg            config.Config
	store          store.Store
	browser        *auth.Browser
	channels       *channel.Manager
	platformTokens *auth.PlatformTokens
	logger         *slog.Logger
	mux            *http.ServeMux
	httpServer     *http.Server
	browserMu      sync.RWMutex
	browsers       map[*browserConnection]struct{}
	limiter        *limit.Limiter
	metrics        *gatewayMetrics
}

func New(cfg config.Config, st store.Store, browser *auth.Browser, channels *channel.Manager, platformTokens *auth.PlatformTokens, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{cfg: cfg, store: st, browser: browser, channels: channels, platformTokens: platformTokens, logger: logger, mux: http.NewServeMux(), browsers: map[*browserConnection]struct{}{}, limiter: limit.New(cfg.RateLimitPerMinute, cfg.MaxConcurrentStreams), metrics: &gatewayMetrics{}}
	channels.SetPushHandler(s.handlePlatformPush)
	s.routes()
	s.httpServer = &http.Server{Addr: cfg.ListenAddr, Handler: s, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleRoot)
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/metrics", s.handleMetrics)
	s.mux.HandleFunc("/ws/agent", s.channels.ServePlatformHTTP)
	s.mux.HandleFunc("/internal/resource/pull/", s.handleResourcePull)
	s.mux.HandleFunc("/internal/resource/push/", s.handleResourcePush)
	s.mux.Handle("/auth/login", s.withIdentity(http.HandlerFunc(s.handleLogin)))
	s.mux.Handle("/auth/callback", s.withIdentity(http.HandlerFunc(s.handleCallback)))
	s.mux.Handle("/auth/logout", s.withIdentity(http.HandlerFunc(s.handleLogout)))
	s.mux.Handle("/ws", s.withIdentity(http.HandlerFunc(s.handleBrowserWS)))
	s.mux.Handle("/api/", s.withIdentity(http.HandlerFunc(s.handleAPI)))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	observed := &observedResponseWriter{ResponseWriter: w}
	s.mux.ServeHTTP(observed, r)
	s.metrics.observe(observed.statusCode())
	s.logger.Debug("http request", "method", r.Method, "path", r.URL.Path, "elapsed_ms", time.Since(started).Milliseconds())
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service":             "agent-gateway",
		"status":              "ok",
		"platformConnections": s.channels.ConnectionCount(),
		"endpoints": map[string]string{
			"agents":  "/api/agents",
			"health":  "/healthz",
			"metrics": "/metrics",
		},
	})
}

func (s *Server) ListenAndServe() error {
	err := s.httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func (s *Server) Shutdown(ctx context.Context) error {
	s.channels.Close()
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) withIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, err := s.store.TenantByHost(r.Context(), r.Host)
		if err != nil {
			writeAPIError(w, http.StatusNotFound, "tenant_not_found", "No active tenant is mapped to this host")
			return
		}
		principal, err := s.browser.Resolve(w, r, tenant)
		if err != nil {
			writeUnauthorized(w, r)
			return
		}
		if !s.browser.ValidateCSRF(r, principal) {
			writeAPIError(w, http.StatusForbidden, "csrf_failed", "CSRF token is missing or invalid")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && !s.limiter.Allow([]string{"tenant:" + tenant.ID, "principal:" + tenant.ID + ":" + principal.OwnerKind() + ":" + principal.OwnerID()}, time.Now()) {
			writeAPIError(w, http.StatusTooManyRequests, "rate_limited", "Request rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r.WithContext(withIdentityContext(r.Context(), tenant, principal)))
	})
}

func writeUnauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="agent-gateway"`)
	writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{"code": "authentication_required", "message": "Authentication is required", "loginUrl": "/auth/login?return_to=" + url.QueryEscape(safeReturnTo(r))}})
}
func safeReturnTo(r *http.Request) string {
	if r == nil {
		return "/"
	}
	value := r.URL.RequestURI()
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "/"
	}
	return value
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "database_unavailable", "Database is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "database": "sqlite", "platformConnections": s.channels.ConnectionCount(), "timestamp": time.Now().UnixMilli()})
}

func (s *Server) baseURL(r *http.Request) string {
	if s.cfg.PublicBaseURL != "" {
		return s.cfg.PublicBaseURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if value := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); value == "http" || value == "https" {
		scheme = value
	}
	host := r.Host
	return scheme + "://" + host
}

func validReturnTo(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "/"
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return "/"
	}
	return parsed.RequestURI()
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	if tenant.OIDCIssuer == "" || tenant.OIDCClientID == "" {
		writeAPIError(w, http.StatusNotImplemented, "oidc_not_configured", "OIDC is not configured for this tenant")
		return
	}
	state := id.RandomToken(32)
	verifier := id.RandomToken(48)
	nonce := id.RandomToken(24)
	redirectURI := s.baseURL(r) + "/auth/callback"
	returnTo := validReturnTo(r.URL.Query().Get("return_to"))
	now := time.Now().UnixMilli()
	flow := domain.OIDCFlow{TenantID: tenant.ID, StateHash: auth.HashToken(state), Verifier: verifier, Nonce: nonce, RedirectURI: redirectURI, ReturnTo: returnTo, AnonymousID: principal.AnonymousID, ExpiresAt: time.Now().Add(s.cfg.OIDCFlowTTL).UnixMilli(), CreatedAt: now}
	if err := s.store.PutOIDCFlow(r.Context(), flow); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "oidc_flow_failed", "Could not start authentication")
		return
	}
	destination, err := s.browser.OIDC().AuthorizationURL(r.Context(), tenant, redirectURI, state, nonce, verifier)
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, "oidc_discovery_failed", err.Error())
		return
	}
	http.Redirect(w, r, destination, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tenant := tenantFromContext(r.Context())
	if providerError := strings.TrimSpace(r.URL.Query().Get("error")); providerError != "" {
		writeAPIError(w, http.StatusUnauthorized, "oidc_denied", providerError)
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if state == "" || code == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_oidc_callback", "state and code are required")
		return
	}
	flow, err := s.store.ConsumeOIDCFlow(r.Context(), tenant.ID, auth.HashToken(state), time.Now().UnixMilli())
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_oidc_state", "OIDC state is invalid or expired")
		return
	}
	identity, err := s.browser.OIDC().Exchange(r.Context(), tenant, flow.RedirectURI, code, flow.Verifier, flow.Nonce)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "oidc_exchange_failed", err.Error())
		return
	}
	if err := s.browser.CreateSession(r.Context(), w, tenant.ID, identity, flow.AnonymousID); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "session_create_failed", "Could not create session")
		return
	}
	s.audit(r.Context(), identity.Subject, "auth.login", tenant.ID, "success", nil)
	http.Redirect(w, r, flow.ReturnTo, http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	_ = s.browser.Logout(r.Context(), w, tenant.ID, r)
	s.audit(r.Context(), principal.Subject, "auth.logout", tenant.ID, "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"loggedOut": true})
}

func (s *Server) audit(ctx context.Context, subject, action, target, result string, metadata any) {
	if subject == "" {
		subject = "anonymous"
	}
	raw, _ := json.Marshal(metadata)
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte(`{}`)
	}
	tenant := tenantFromContext(ctx)
	subjectHash := auth.OwnerReference(s.cfg.TenantHMACSecret, tenant.ID, "audit", subject)
	_ = s.store.AppendAudit(context.Background(), domain.AuditRecord{TenantID: tenant.ID, ID: id.New("audit"), Subject: subjectHash, Action: action, Target: target, Result: result, Metadata: raw, CreatedAt: time.Now().UnixMilli()})
}

func originHost(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	host := parsed.Hostname()
	return strings.ToLower(host)
}
func requestHostname(r *http.Request) string {
	host := r.Host
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(parsedHost)
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}
func (s *Server) browserOriginAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	if originHost(origin) == requestHostname(r) {
		return true
	}
	for _, allowed := range s.cfg.AllowedBrowserOrigins {
		if strings.EqualFold(strings.TrimRight(allowed, "/"), strings.TrimRight(origin, "/")) {
			return true
		}
	}
	return false
}

func hashBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
