package auth

import (
	"crypto/subtle"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type Local struct {
	username     string
	passwordHash []byte
	displayName  string
	roles        []string
}

func NewLocal(username, passwordHash, displayName string, roles []string) (*Local, error) {
	username = strings.TrimSpace(username)
	passwordHash = strings.TrimSpace(passwordHash)
	if username == "" || passwordHash == "" {
		return nil, errors.New("local username and password hash are required")
	}
	if _, err := bcrypt.Cost([]byte(passwordHash)); err != nil {
		return nil, errors.New("local password hash must be a valid bcrypt hash")
	}
	if strings.TrimSpace(displayName) == "" {
		displayName = username
	}
	cleanRoles := make([]string, 0, len(roles))
	for _, role := range roles {
		if value := strings.TrimSpace(role); value != "" {
			cleanRoles = append(cleanRoles, value)
		}
	}
	return &Local{username: username, passwordHash: []byte(passwordHash), displayName: strings.TrimSpace(displayName), roles: cleanRoles}, nil
}

func (l *Local) Authenticate(username, password string) (OIDCIdentity, bool) {
	if l == nil || len(password) == 0 || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(username)), []byte(l.username)) != 1 {
		return OIDCIdentity{}, false
	}
	if bcrypt.CompareHashAndPassword(l.passwordHash, []byte(password)) != nil {
		return OIDCIdentity{}, false
	}
	return OIDCIdentity{Subject: "local:" + l.username, DisplayName: l.displayName, Roles: append([]string(nil), l.roles...), Groups: []string{}, Claims: map[string]any{"auth_method": "local"}}, true
}
