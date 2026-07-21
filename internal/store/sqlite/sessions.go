package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"agent-gateway/internal/domain"
)

func (s *Store) WebSession(ctx context.Context, tenantID, sessionHash string) (domain.WebSession, error) {
	var item domain.WebSession
	var rolesJSON, groupsJSON string
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id,session_hash,subject,display_name,roles_json,groups_json,csrf_token,expires_at,created_at,updated_at
		FROM web_sessions WHERE tenant_id=? AND session_hash=? AND expires_at>?`, tenantID, sessionHash, time.Now().UnixMilli()).
		Scan(&item.TenantID, &item.SessionHash, &item.Subject, &item.DisplayName, &rolesJSON, &groupsJSON,
			&item.CSRFToken, &item.ExpiresAt, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.WebSession{}, mapSQLError(err)
	}
	_ = json.Unmarshal([]byte(rolesJSON), &item.Roles)
	_ = json.Unmarshal([]byte(groupsJSON), &item.Groups)
	if item.Roles == nil {
		item.Roles = []string{}
	}
	if item.Groups == nil {
		item.Groups = []string{}
	}
	return item, nil
}

func (s *Store) PutWebSession(ctx context.Context, item domain.WebSession) error {
	now := time.Now().UnixMilli()
	if item.CreatedAt == 0 {
		item.CreatedAt = now
	}
	item.UpdatedAt = now
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `INSERT INTO web_sessions(tenant_id,session_hash,subject,display_name,roles_json,groups_json,csrf_token,expires_at,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,session_hash) DO UPDATE SET subject=excluded.subject,display_name=excluded.display_name,
		roles_json=excluded.roles_json,groups_json=excluded.groups_json,csrf_token=excluded.csrf_token,expires_at=excluded.expires_at,updated_at=excluded.updated_at`,
		item.TenantID, item.SessionHash, item.Subject, item.DisplayName, jsonText(item.Roles), jsonText(item.Groups), item.CSRFToken, item.ExpiresAt, item.CreatedAt, item.UpdatedAt)
	return mapSQLError(err)
}

func (s *Store) DeleteWebSession(ctx context.Context, tenantID, sessionHash string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE tenant_id=? AND session_hash=?`, tenantID, sessionHash)
	return err
}

func (s *Store) AnonymousSession(ctx context.Context, tenantID, sessionHash string) (domain.AnonymousSession, error) {
	var item domain.AnonymousSession
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id,session_hash,anonymous_id,csrf_token,expires_at,created_at,updated_at
		FROM anonymous_sessions WHERE tenant_id=? AND session_hash=? AND expires_at>?`, tenantID, sessionHash, time.Now().UnixMilli()).
		Scan(&item.TenantID, &item.SessionHash, &item.AnonymousID, &item.CSRFToken, &item.ExpiresAt, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.AnonymousSession{}, mapSQLError(err)
	}
	return item, nil
}

func (s *Store) PutAnonymousSession(ctx context.Context, item domain.AnonymousSession) error {
	now := time.Now().UnixMilli()
	if item.CreatedAt == 0 {
		item.CreatedAt = now
	}
	item.UpdatedAt = now
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `INSERT INTO anonymous_sessions(tenant_id,session_hash,anonymous_id,csrf_token,expires_at,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant_id,session_hash) DO UPDATE SET anonymous_id=excluded.anonymous_id,csrf_token=excluded.csrf_token,
		expires_at=excluded.expires_at,updated_at=excluded.updated_at`, item.TenantID, item.SessionHash, item.AnonymousID, item.CSRFToken, item.ExpiresAt, item.CreatedAt, item.UpdatedAt)
	return mapSQLError(err)
}

func (s *Store) PutOIDCFlow(ctx context.Context, item domain.OIDCFlow) error {
	if item.CreatedAt == 0 {
		item.CreatedAt = time.Now().UnixMilli()
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `INSERT INTO oidc_flows(tenant_id,state_hash,verifier,nonce,redirect_uri,return_to,anonymous_id,expires_at,created_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, item.TenantID, item.StateHash, item.Verifier, item.Nonce, item.RedirectURI, item.ReturnTo, item.AnonymousID, item.ExpiresAt, item.CreatedAt)
	return mapSQLError(err)
}

func (s *Store) ConsumeOIDCFlow(ctx context.Context, tenantID, stateHash string, now int64) (domain.OIDCFlow, error) {
	var item domain.OIDCFlow
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT tenant_id,state_hash,verifier,nonce,redirect_uri,return_to,anonymous_id,expires_at,created_at
			FROM oidc_flows WHERE tenant_id=? AND state_hash=? AND expires_at>?`, tenantID, stateHash, now).
			Scan(&item.TenantID, &item.StateHash, &item.Verifier, &item.Nonce, &item.RedirectURI, &item.ReturnTo, &item.AnonymousID, &item.ExpiresAt, &item.CreatedAt)
		if err != nil {
			return mapSQLError(err)
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM oidc_flows WHERE tenant_id=? AND state_hash=?`, tenantID, stateHash)
		return err
	})
	return item, err
}

func (s *Store) ClaimAnonymous(ctx context.Context, tenantID, anonymousID, subject string) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE chat_bindings SET owner_kind='user',owner_id=?,updated_at=?
			WHERE tenant_id=? AND owner_kind='anonymous' AND owner_id=?`, subject, time.Now().UnixMilli(), tenantID, anonymousID)
		if err != nil {
			return err
		}
		if _, err := result.RowsAffected(); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE resource_bindings SET owner_kind='user',owner_id=?,updated_at=? WHERE tenant_id=? AND owner_kind='anonymous' AND owner_id=?`, subject, time.Now().UnixMilli(), tenantID, anonymousID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE idempotency_keys SET owner_kind='user',owner_id=? WHERE tenant_id=? AND owner_kind='anonymous' AND owner_id=?`, subject, tenantID, anonymousID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM anonymous_sessions WHERE tenant_id=? AND anonymous_id=?`, tenantID, anonymousID)
		return err
	})
}
