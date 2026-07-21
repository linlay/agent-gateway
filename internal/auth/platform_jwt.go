package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"agent-gateway/internal/id"
	"agent-gateway/internal/store"

	"github.com/golang-jwt/jwt/v5"
)

const PlatformAudience = "agent-gateway-platform"

type PlatformIdentity struct {
	TenantID   string
	PlatformID string
	ChannelID  string
	Subject    string
	JTI        string
	ExpiresAt  int64
}

type PlatformTokens struct {
	issuer     string
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	store      store.Store
	ttl        time.Duration
}

func NewPlatformTokens(issuer, publicFile, privateFile string, st store.Store, ttl time.Duration) (*PlatformTokens, error) {
	service := &PlatformTokens{issuer: strings.TrimSpace(issuer), store: st, ttl: ttl}
	if publicFile != "" {
		key, err := loadRSAPublicKey(publicFile)
		if err != nil {
			return nil, err
		}
		service.publicKey = key
	}
	if privateFile != "" {
		key, err := loadRSAPrivateKey(privateFile)
		if err != nil {
			return nil, err
		}
		service.privateKey = key
		if service.publicKey == nil {
			service.publicKey = &key.PublicKey
		}
	}
	return service, nil
}

func (s *PlatformTokens) Configured() bool { return s != nil && s.publicKey != nil }
func (s *PlatformTokens) CanIssue() bool   { return s != nil && s.privateKey != nil }

func (s *PlatformTokens) Verify(ctx context.Context, raw string) (PlatformIdentity, error) {
	if !s.Configured() {
		return PlatformIdentity{}, errors.New("platform jwt verification is not configured")
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(strings.TrimSpace(raw), claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unsupported platform jwt alg")
		}
		return s.publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(PlatformAudience), jwt.WithIssuer(s.issuer), jwt.WithExpirationRequired())
	if err != nil || !token.Valid {
		return PlatformIdentity{}, fmt.Errorf("invalid platform jwt")
	}
	identity := PlatformIdentity{
		TenantID: claimString(claims, "tenant_id"), PlatformID: claimString(claims, "platform_id"),
		ChannelID: claimString(claims, "channel_id"), Subject: claimString(claims, "sub"), JTI: claimString(claims, "jti"),
	}
	if identity.TenantID == "" || identity.PlatformID == "" || identity.ChannelID == "" || identity.JTI == "" || identity.Subject != "platform:"+identity.PlatformID {
		return PlatformIdentity{}, errors.New("platform jwt required claims are invalid")
	}
	issuedAt, err := claims.GetIssuedAt()
	if err != nil || issuedAt == nil {
		return PlatformIdentity{}, errors.New("platform jwt iat is required")
	}
	expiresAt, _ := claims.GetExpirationTime()
	if expiresAt == nil {
		return PlatformIdentity{}, errors.New("platform jwt exp is required")
	}
	identity.ExpiresAt = expiresAt.UnixMilli()
	if err := s.store.ValidatePlatformCredential(ctx, identity.TenantID, identity.PlatformID, HashToken(identity.JTI), time.Now().UnixMilli()); err != nil {
		return PlatformIdentity{}, errors.New("platform credential is not active")
	}
	return identity, nil
}

func (s *PlatformTokens) Issue(ctx context.Context, tenantID, platformID, channelID string) (string, int64, error) {
	if !s.CanIssue() {
		return "", 0, errors.New("platform jwt signing is not configured")
	}
	now := time.Now()
	ttl := s.ttl
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	expiresAt := now.Add(ttl)
	jti := id.RandomToken(24)
	claims := jwt.MapClaims{
		"iss": s.issuer, "aud": PlatformAudience, "sub": "platform:" + platformID,
		"tenant_id": tenantID, "platform_id": platformID, "channel_id": channelID, "jti": jti,
		"iat": now.Unix(), "exp": expiresAt.Unix(),
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(s.privateKey)
	if err != nil {
		return "", 0, err
	}
	if err := s.store.AddPlatformCredential(ctx, tenantID, platformID, HashToken(jti), expiresAt.UnixMilli()); err != nil {
		return "", 0, err
	}
	return raw, expiresAt.UnixMilli(), nil
}

func claimString(claims jwt.MapClaims, key string) string {
	value, _ := claims[key].(string)
	return strings.TrimSpace(value)
}

func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read platform public key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("invalid platform public key pem")
	}
	if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if key, ok := parsed.(*rsa.PublicKey); ok {
			return key, nil
		}
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		if key, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return key, nil
		}
	}
	return nil, errors.New("platform public key is not RSA")
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read platform private key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("invalid platform private key pem")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if key, ok := parsed.(*rsa.PrivateKey); ok {
			return key, nil
		}
	}
	return nil, errors.New("platform private key is not RSA")
}
