package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"agent-gateway/internal/domain"
	"agent-gateway/internal/id"
	"agent-gateway/internal/store"
)

const (
	SessionCookieName   = "agw_session"
	AnonymousCookieName = "agw_anonymous"
)

var ErrInvalidBearer = errors.New("invalid bearer token")

type Browser struct {
	store               store.Store
	oidc                *OIDC
	secure              bool
	sessionTTL          time.Duration
	anonymousTTL        time.Duration
	bootstrapAdminToken string
}

func NewBrowser(st store.Store, oidc *OIDC, secure bool, sessionTTL, anonymousTTL time.Duration, bootstrapAdminToken string) *Browser {
	return &Browser{store: st, oidc: oidc, secure: secure, sessionTTL: sessionTTL, anonymousTTL: anonymousTTL, bootstrapAdminToken: strings.TrimSpace(bootstrapAdminToken)}
}

func (b *Browser) Resolve(w http.ResponseWriter, r *http.Request, tenant domain.Tenant) (domain.Principal, error) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(authorization, "Bearer ") {
		raw := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
		if b.bootstrapAdminToken != "" && subtle.ConstantTimeCompare([]byte(raw), []byte(b.bootstrapAdminToken)) == 1 {
			return domain.Principal{TenantID: tenant.ID, Subject: "bootstrap-admin", DisplayName: "Bootstrap Admin", Roles: []string{"gateway_admin"}, Groups: []string{}, Authenticated: true, AuthMethod: "bootstrap"}, nil
		}
		identity, err := b.oidc.VerifyBearer(r.Context(), tenant, raw)
		if err != nil {
			return domain.Principal{}, ErrInvalidBearer
		}
		tokenTenant := ""
		for _, key := range []string{"tenant_id", "tenantId"} {
			if value, ok := identity.Claims[key].(string); ok && strings.TrimSpace(value) != "" {
				tokenTenant = strings.TrimSpace(value)
				break
			}
		}
		if tokenTenant == "" || tokenTenant != tenant.ID {
			return domain.Principal{}, ErrInvalidBearer
		}
		return domain.Principal{TenantID: tenant.ID, Subject: identity.Subject, DisplayName: identity.DisplayName, Roles: identity.Roles, Groups: identity.Groups, Authenticated: true, AuthMethod: "bearer"}, nil
	}
	if cookie, err := r.Cookie(SessionCookieName); err == nil && strings.TrimSpace(cookie.Value) != "" {
		session, err := b.store.WebSession(r.Context(), tenant.ID, HashToken(cookie.Value))
		if err == nil {
			return domain.Principal{TenantID: tenant.ID, Subject: session.Subject, DisplayName: session.DisplayName, Roles: session.Roles, Groups: session.Groups, Authenticated: true, AuthMethod: "session", CSRFToken: session.CSRFToken}, nil
		}
	}
	if cookie, err := r.Cookie(AnonymousCookieName); err == nil && strings.TrimSpace(cookie.Value) != "" {
		session, err := b.store.AnonymousSession(r.Context(), tenant.ID, HashToken(cookie.Value))
		if err == nil {
			return domain.Principal{TenantID: tenant.ID, AnonymousID: session.AnonymousID, Authenticated: false, AuthMethod: "anonymous", CSRFToken: session.CSRFToken}, nil
		}
	}
	return b.newAnonymous(w, r.Context(), tenant.ID)
}

func (b *Browser) newAnonymous(w http.ResponseWriter, ctx context.Context, tenantID string) (domain.Principal, error) {
	raw := id.RandomToken(32)
	now := time.Now().UnixMilli()
	session := domain.AnonymousSession{TenantID: tenantID, SessionHash: HashToken(raw), AnonymousID: id.New("anon"), CSRFToken: id.RandomToken(24), ExpiresAt: time.Now().Add(b.anonymousTTL).UnixMilli(), CreatedAt: now, UpdatedAt: now}
	if err := b.store.PutAnonymousSession(ctx, session); err != nil {
		return domain.Principal{}, err
	}
	b.setCookie(w, AnonymousCookieName, raw, time.UnixMilli(session.ExpiresAt))
	return domain.Principal{TenantID: tenantID, AnonymousID: session.AnonymousID, Authenticated: false, AuthMethod: "anonymous", CSRFToken: session.CSRFToken}, nil
}

func (b *Browser) CreateSession(ctx context.Context, w http.ResponseWriter, tenantID string, identity OIDCIdentity, anonymousID string) error {
	raw := id.RandomToken(32)
	now := time.Now().UnixMilli()
	session := domain.WebSession{TenantID: tenantID, SessionHash: HashToken(raw), Subject: identity.Subject, DisplayName: identity.DisplayName, Roles: identity.Roles, Groups: identity.Groups, CSRFToken: id.RandomToken(24), ExpiresAt: time.Now().Add(b.sessionTTL).UnixMilli(), CreatedAt: now, UpdatedAt: now}
	if err := b.store.PutWebSession(ctx, session); err != nil {
		return err
	}
	if anonymousID != "" {
		if err := b.store.ClaimAnonymous(ctx, tenantID, anonymousID, identity.Subject); err != nil {
			return err
		}
	}
	b.setCookie(w, SessionCookieName, raw, time.UnixMilli(session.ExpiresAt))
	b.clearCookie(w, AnonymousCookieName)
	return nil
}

func (b *Browser) Logout(ctx context.Context, w http.ResponseWriter, tenantID string, r *http.Request) error {
	if cookie, err := r.Cookie(SessionCookieName); err == nil {
		_ = b.store.DeleteWebSession(ctx, tenantID, HashToken(cookie.Value))
	}
	b.clearCookie(w, SessionCookieName)
	return nil
}

func (b *Browser) ValidateCSRF(r *http.Request, principal domain.Principal) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	if principal.AuthMethod == "bearer" || principal.AuthMethod == "bootstrap" {
		return true
	}
	provided := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	expected := strings.TrimSpace(principal.CSRFToken)
	return expected != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func (b *Browser) setCookie(w http.ResponseWriter, name, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: b.secure, SameSite: http.SameSiteLaxMode, Expires: expires, MaxAge: int(time.Until(expires).Seconds())})
}
func (b *Browser) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: b.secure, SameSite: http.SameSiteLaxMode, Expires: time.Unix(0, 0), MaxAge: -1})
}
func (b *Browser) OIDC() *OIDC { return b.oidc }
