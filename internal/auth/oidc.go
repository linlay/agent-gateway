package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"agent-gateway/internal/domain"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type OIDCIdentity struct {
	Subject     string
	DisplayName string
	Roles       []string
	Groups      []string
	Claims      map[string]any
}

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type cachedProvider struct {
	discovery oidcDiscovery
	keys      map[string]*rsa.PublicKey
	loadedAt  time.Time
}

type OIDC struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]cachedProvider
}

func NewOIDC() *OIDC {
	return &OIDC{client: &http.Client{Timeout: 10 * time.Second}, cache: map[string]cachedProvider{}}
}

func (o *OIDC) AuthorizationURL(ctx context.Context, tenant domain.Tenant, redirectURI, state, nonce, verifier string) (string, error) {
	provider, err := o.provider(ctx, tenant.OIDCIssuer, false)
	if err != nil {
		return "", err
	}
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", tenant.OIDCClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", "openid profile email")
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", PKCEChallenge(verifier))
	query.Set("code_challenge_method", "S256")
	return provider.discovery.AuthorizationEndpoint + "?" + query.Encode(), nil
}

func (o *OIDC) Exchange(ctx context.Context, tenant domain.Tenant, redirectURI, code, verifier, nonce string) (OIDCIdentity, error) {
	provider, err := o.provider(ctx, tenant.OIDCIssuer, false)
	if err != nil {
		return OIDCIdentity{}, err
	}
	secret := ""
	if tenant.OIDCClientSecretEnv != "" {
		secret = os.Getenv(tenant.OIDCClientSecretEnv)
	}
	config := oauth2.Config{ClientID: tenant.OIDCClientID, ClientSecret: secret, RedirectURL: redirectURI, Endpoint: oauth2.Endpoint{AuthURL: provider.discovery.AuthorizationEndpoint, TokenURL: provider.discovery.TokenEndpoint}, Scopes: []string{"openid", "profile", "email"}}
	token, err := config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return OIDCIdentity{}, fmt.Errorf("oidc token exchange failed: %w", err)
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	if strings.TrimSpace(rawIDToken) == "" {
		return OIDCIdentity{}, errors.New("oidc response has no id_token")
	}
	return o.verify(ctx, tenant, rawIDToken, nonce)
}

func (o *OIDC) VerifyBearer(ctx context.Context, tenant domain.Tenant, raw string) (OIDCIdentity, error) {
	return o.verify(ctx, tenant, raw, "")
}

func (o *OIDC) verify(ctx context.Context, tenant domain.Tenant, raw, nonce string) (OIDCIdentity, error) {
	provider, err := o.provider(ctx, tenant.OIDCIssuer, false)
	if err != nil {
		return OIDCIdentity{}, err
	}
	parse := func(keys map[string]*rsa.PublicKey) (jwt.MapClaims, error) {
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != "RS256" {
				return nil, errors.New("unsupported oidc token alg")
			}
			kid, _ := token.Header["kid"].(string)
			key := keys[kid]
			if key == nil {
				return nil, errors.New("oidc signing key not found")
			}
			return key, nil
		}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(provider.discovery.Issuer), jwt.WithAudience(tenant.OIDCClientID), jwt.WithExpirationRequired())
		if err != nil || !token.Valid {
			return nil, errors.New("invalid oidc token")
		}
		return claims, nil
	}
	claims, err := parse(provider.keys)
	if err != nil {
		provider, refreshErr := o.provider(ctx, tenant.OIDCIssuer, true)
		if refreshErr != nil {
			return OIDCIdentity{}, err
		}
		claims, err = parse(provider.keys)
	}
	if err != nil {
		return OIDCIdentity{}, err
	}
	if nonce != "" && claimString(claims, "nonce") != nonce {
		return OIDCIdentity{}, errors.New("oidc nonce mismatch")
	}
	sub := claimString(claims, "sub")
	if sub == "" {
		return OIDCIdentity{}, errors.New("oidc subject is required")
	}
	rolesClaim := tenant.RolesClaim
	if rolesClaim == "" {
		rolesClaim = "roles"
	}
	groupsClaim := tenant.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	name := claimString(claims, "name")
	if name == "" {
		name = claimString(claims, "preferred_username")
	}
	if name == "" {
		name = claimString(claims, "email")
	}
	return OIDCIdentity{Subject: sub, DisplayName: name, Roles: claimList(claims[rolesClaim]), Groups: claimList(claims[groupsClaim]), Claims: map[string]any(claims)}, nil
}

func claimList(value any) []string {
	items := []string{}
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				items = append(items, strings.TrimSpace(text))
			}
		}
	case []string:
		items = append(items, typed...)
	case string:
		for _, item := range strings.FieldsFunc(typed, func(r rune) bool { return r == ',' || r == ' ' }) {
			if item != "" {
				items = append(items, item)
			}
		}
	}
	return items
}

func (o *OIDC) provider(ctx context.Context, issuer string, force bool) (cachedProvider, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return cachedProvider{}, errors.New("oidc issuer is not configured")
	}
	o.mu.Lock()
	cached, ok := o.cache[issuer]
	o.mu.Unlock()
	if ok && !force && time.Since(cached.loadedAt) < 5*time.Minute {
		return cached, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return cachedProvider{}, err
	}
	response, err := o.client.Do(request)
	if err != nil {
		return cachedProvider{}, err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return cachedProvider{}, fmt.Errorf("oidc discovery returned %d", response.StatusCode)
	}
	var discovery oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&discovery); err != nil {
		return cachedProvider{}, err
	}
	if strings.TrimRight(discovery.Issuer, "/") != issuer {
		return cachedProvider{}, errors.New("oidc discovery issuer mismatch")
	}
	keys, err := o.fetchKeys(ctx, discovery.JWKSURI)
	if err != nil {
		return cachedProvider{}, err
	}
	cached = cachedProvider{discovery: discovery, keys: keys, loadedAt: time.Now()}
	o.mu.Lock()
	o.cache[issuer] = cached
	o.mu.Unlock()
	return cached, nil
}

func (o *OIDC) fetchKeys(ctx context.Context, uri string) (map[string]*rsa.PublicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	response, err := o.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return nil, fmt.Errorf("oidc jwks returned %d", response.StatusCode)
	}
	var payload struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&payload); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, item := range payload.Keys {
		if item.Kty != "RSA" {
			continue
		}
		nRaw, err := base64.RawURLEncoding.DecodeString(item.N)
		if err != nil {
			continue
		}
		eRaw, err := base64.RawURLEncoding.DecodeString(item.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eRaw {
			e = e<<8 + int(b)
		}
		if e > 0 {
			keys[item.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nRaw), E: e}
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("oidc jwks contains no RSA keys")
	}
	return keys, nil
}
