package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"agent-gateway/internal/domain"
	storepkg "agent-gateway/internal/store"
)

func (s *Store) CreateChatRunBindings(ctx context.Context, chat domain.ChatBinding, run domain.RunBinding, idem *domain.IdempotencyBinding) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO chat_bindings(tenant_id,chat_id,owner_kind,owner_id,agent_id,route_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, chat.TenantID, chat.ChatID, chat.OwnerKind, chat.OwnerID, chat.AgentID, chat.RouteID, chat.Status, chat.CreatedAt, chat.UpdatedAt); err != nil {
			return mapSQLError(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO run_bindings(tenant_id,run_id,chat_id,route_id,request_id,status,last_seq,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, run.TenantID, run.RunID, run.ChatID, run.RouteID, run.RequestID, run.Status, run.LastSeq, run.CreatedAt, run.UpdatedAt); err != nil {
			return mapSQLError(err)
		}
		return insertIdempotency(ctx, tx, idem)
	})
}

func (s *Store) CreateChatBinding(ctx context.Context, chat domain.ChatBinding) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `INSERT INTO chat_bindings(tenant_id,chat_id,owner_kind,owner_id,agent_id,route_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, chat.TenantID, chat.ChatID, chat.OwnerKind, chat.OwnerID, chat.AgentID, chat.RouteID, chat.Status, chat.CreatedAt, chat.UpdatedAt)
	return mapSQLError(err)
}

func (s *Store) CreateRunBinding(ctx context.Context, run domain.RunBinding, idem *domain.IdempotencyBinding) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO run_bindings(tenant_id,run_id,chat_id,route_id,request_id,status,last_seq,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, run.TenantID, run.RunID, run.ChatID, run.RouteID, run.RequestID, run.Status, run.LastSeq, run.CreatedAt, run.UpdatedAt); err != nil {
			return mapSQLError(err)
		}
		return insertIdempotency(ctx, tx, idem)
	})
}

func insertIdempotency(ctx context.Context, tx *sql.Tx, item *domain.IdempotencyBinding) error {
	if item == nil {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO idempotency_keys(tenant_id,idempotency_key,owner_kind,owner_id,request_hash,chat_id,run_id,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, item.TenantID, item.KeyHash, item.OwnerKind, item.OwnerID, item.RequestHash, item.ChatID, item.RunID, item.ExpiresAt, item.CreatedAt)
	return mapSQLError(err)
}

func (s *Store) IdempotencyBinding(ctx context.Context, tenantID, keyHash string) (domain.IdempotencyBinding, error) {
	var item domain.IdempotencyBinding
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id,idempotency_key,owner_kind,owner_id,request_hash,chat_id,run_id,expires_at,created_at FROM idempotency_keys WHERE tenant_id=? AND idempotency_key=? AND expires_at>?`, tenantID, keyHash, time.Now().UnixMilli()).Scan(&item.TenantID, &item.KeyHash, &item.OwnerKind, &item.OwnerID, &item.RequestHash, &item.ChatID, &item.RunID, &item.ExpiresAt, &item.CreatedAt)
	return item, mapSQLError(err)
}

func (s *Store) PutViewportBinding(ctx context.Context, item domain.ViewportBinding) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `INSERT INTO viewport_bindings(tenant_id,run_id,chat_id,route_id,viewport_key,created_at,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant_id,run_id,viewport_key) DO UPDATE SET updated_at=excluded.updated_at`, item.TenantID, item.RunID, item.ChatID, item.RouteID, item.ViewportKey, item.CreatedAt, item.UpdatedAt)
	return mapSQLError(err)
}

func (s *Store) ViewportBinding(ctx context.Context, tenantID, runID, viewportKey string) (domain.ViewportBinding, error) {
	var item domain.ViewportBinding
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id,run_id,chat_id,route_id,viewport_key,created_at,updated_at FROM viewport_bindings WHERE tenant_id=? AND run_id=? AND viewport_key=?`, tenantID, runID, viewportKey).Scan(&item.TenantID, &item.RunID, &item.ChatID, &item.RouteID, &item.ViewportKey, &item.CreatedAt, &item.UpdatedAt)
	return item, mapSQLError(err)
}

func scanChat(scanner interface{ Scan(...any) error }) (domain.ChatBinding, error) {
	var item domain.ChatBinding
	err := scanner.Scan(&item.TenantID, &item.ChatID, &item.OwnerKind, &item.OwnerID, &item.AgentID, &item.RouteID, &item.Status, &item.CreatedAt, &item.UpdatedAt)
	return item, mapSQLError(err)
}
func scanRun(scanner interface{ Scan(...any) error }) (domain.RunBinding, error) {
	var item domain.RunBinding
	err := scanner.Scan(&item.TenantID, &item.RunID, &item.ChatID, &item.RouteID, &item.RequestID, &item.Status, &item.LastSeq, &item.CreatedAt, &item.UpdatedAt)
	return item, mapSQLError(err)
}

func (s *Store) ChatBinding(ctx context.Context, tenantID, chatID string) (domain.ChatBinding, error) {
	return scanChat(s.db.QueryRowContext(ctx, `SELECT tenant_id,chat_id,owner_kind,owner_id,agent_id,route_id,status,created_at,updated_at FROM chat_bindings WHERE tenant_id=? AND chat_id=?`, tenantID, chatID))
}
func (s *Store) RunBinding(ctx context.Context, tenantID, runID string) (domain.RunBinding, error) {
	return scanRun(s.db.QueryRowContext(ctx, `SELECT tenant_id,run_id,chat_id,route_id,request_id,status,last_seq,created_at,updated_at FROM run_bindings WHERE tenant_id=? AND run_id=?`, tenantID, runID))
}
func (s *Store) RunBindingByRequest(ctx context.Context, tenantID, requestID string) (domain.RunBinding, error) {
	return scanRun(s.db.QueryRowContext(ctx, `SELECT tenant_id,run_id,chat_id,route_id,request_id,status,last_seq,created_at,updated_at FROM run_bindings WHERE tenant_id=? AND request_id=?`, tenantID, requestID))
}

func (s *Store) ListChatBindings(ctx context.Context, tenantID, ownerKind, ownerID, agentID string) ([]domain.ChatBinding, error) {
	query := `SELECT tenant_id,chat_id,owner_kind,owner_id,agent_id,route_id,status,created_at,updated_at FROM chat_bindings WHERE tenant_id=? AND owner_kind=? AND owner_id=?`
	args := []any{tenantID, ownerKind, ownerID}
	if agentID != "" {
		query += ` AND agent_id=?`
		args = append(args, agentID)
	}
	query += ` ORDER BY updated_at DESC,chat_id DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []domain.ChatBinding{}
	for rows.Next() {
		item, err := scanChat(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) UpdateRunProgress(ctx context.Context, tenantID, runID, status string, lastSeq, now int64) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `UPDATE run_bindings SET status=?,last_seq=CASE WHEN last_seq>? THEN last_seq ELSE ? END,updated_at=? WHERE tenant_id=? AND run_id=?`, status, lastSeq, lastSeq, now, tenantID, runID)
	return err
}
func (s *Store) UpdateChatBindingStatus(ctx context.Context, tenantID, chatID, status string, now int64) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.db.ExecContext(ctx, `UPDATE chat_bindings SET status=?,updated_at=? WHERE tenant_id=? AND chat_id=?`, status, now, tenantID, chatID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return storepkg.ErrNotFound
	}
	return nil
}
func (s *Store) DeleteChatBinding(ctx context.Context, tenantID, chatID string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.db.ExecContext(ctx, `DELETE FROM chat_bindings WHERE tenant_id=? AND chat_id=?`, tenantID, chatID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return storepkg.ErrNotFound
	}
	return nil
}

func scanResource(scanner interface{ Scan(...any) error }) (domain.ResourceBinding, error) {
	var item domain.ResourceBinding
	err := scanner.Scan(&item.TenantID, &item.ResourceKey, &item.ChatID, &item.OwnerKind, &item.OwnerID, &item.RouteID, &item.Direction, &item.TokenHash, &item.SpoolPath, &item.FileName, &item.MimeType, &item.SizeBytes, &item.SHA256, &item.Status, &item.ExpiresAt, &item.CreatedAt, &item.UpdatedAt)
	return item, mapSQLError(err)
}

func (s *Store) PutResourceBinding(ctx context.Context, item domain.ResourceBinding) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `INSERT INTO resource_bindings(tenant_id,resource_key,chat_id,owner_kind,owner_id,route_id,direction,token_hash,spool_path,file_name,mime_type,size_bytes,sha256,status,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, item.TenantID, item.ResourceKey, item.ChatID, item.OwnerKind, item.OwnerID, item.RouteID, item.Direction, item.TokenHash, item.SpoolPath, item.FileName, item.MimeType, item.SizeBytes, item.SHA256, item.Status, item.ExpiresAt, item.CreatedAt, item.UpdatedAt)
	return mapSQLError(err)
}

func (s *Store) ResourceBindingByToken(ctx context.Context, tenantID, tokenHash string, now int64) (domain.ResourceBinding, error) {
	return scanResource(s.db.QueryRowContext(ctx, `SELECT tenant_id,resource_key,chat_id,owner_kind,owner_id,route_id,direction,token_hash,spool_path,file_name,mime_type,size_bytes,sha256,status,expires_at,created_at,updated_at FROM resource_bindings WHERE tenant_id=? AND token_hash=? AND expires_at>?`, tenantID, tokenHash, now))
}

func (s *Store) ClaimResourceBinding(ctx context.Context, tenantID, resourceKey, fromStatus, toStatus string, now int64) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.db.ExecContext(ctx, `UPDATE resource_bindings SET status=?,updated_at=? WHERE tenant_id=? AND resource_key=? AND status=? AND expires_at>?`, toStatus, now, tenantID, resourceKey, fromStatus, now)
	if err != nil {
		return mapSQLError(err)
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return storepkg.ErrConflict
	}
	return nil
}

func (s *Store) UpdateResourceBinding(ctx context.Context, tenantID, resourceKey, status, spoolPath, mimeType string, sizeBytes, now int64) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.db.ExecContext(ctx, `UPDATE resource_bindings SET status=?,spool_path=CASE WHEN ?='' THEN spool_path ELSE ? END,mime_type=CASE WHEN ?='' THEN mime_type ELSE ? END,size_bytes=CASE WHEN ?<0 THEN size_bytes ELSE ? END,updated_at=? WHERE tenant_id=? AND resource_key=?`, status, spoolPath, spoolPath, mimeType, mimeType, sizeBytes, sizeBytes, now, tenantID, resourceKey)
	if err != nil {
		return mapSQLError(err)
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return storepkg.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteResourceBinding(ctx context.Context, tenantID, resourceKey string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `DELETE FROM resource_bindings WHERE tenant_id=? AND resource_key=?`, tenantID, resourceKey)
	return err
}

func (s *Store) AppendAudit(ctx context.Context, item domain.AuditRecord) error {
	if item.Metadata == nil {
		item.Metadata = json.RawMessage(`{}`)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,tenant_id,subject,action,target,result,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?)`, item.ID, item.TenantID, item.Subject, item.Action, item.Target, item.Result, string(item.Metadata), item.CreatedAt)
	return mapSQLError(err)
}
func (s *Store) ListAudit(ctx context.Context, tenantID string, limit int) ([]domain.AuditRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT tenant_id,audit_id,subject,action,target,result,metadata_json,created_at FROM audit_logs WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []domain.AuditRecord{}
	for rows.Next() {
		var item domain.AuditRecord
		var metadata string
		if err := rows.Scan(&item.TenantID, &item.ID, &item.Subject, &item.Action, &item.Target, &item.Result, &metadata, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Metadata = json.RawMessage(metadata)
		items = append(items, item)
	}
	return items, rows.Err()
}
