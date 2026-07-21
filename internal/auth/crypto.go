package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

func HashToken(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func OwnerReference(secret, tenantID, ownerKind, ownerID string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(tenantID + "\x00" + ownerKind + "\x00" + ownerID))
	return strings.ToLower(base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:15]))
}

func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
