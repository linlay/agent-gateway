package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"agent-gateway/internal/domain"
	storepkg "agent-gateway/internal/store"

	_ "modernc.org/sqlite"
)

type Store struct {
	db      *sql.DB
	writeMu sync.Mutex
}

func Open(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}).String() +
		"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(0)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error                   { return s.db.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) IntegrityCheck(ctx context.Context) error {
	var result string
	if err := s.db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("sqlite integrity check failed: %s", result)
	}
	return nil
}

func (s *Store) Backup(ctx context.Context, destination string) error {
	abs, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(abs); err == nil {
		return fmt.Errorf("backup destination already exists: %s", abs)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err = s.db.ExecContext(ctx, `VACUUM INTO ?`, abs)
	return err
}

func (s *Store) migrate(ctx context.Context) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	var version int
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version)
	if err != nil {
		return err
	}
	if version > schemaVersion {
		return fmt.Errorf("sqlite schema version %d is newer than supported %d", version, schemaVersion)
	}
	if version == 0 {
		if _, err := tx.ExecContext(ctx, migrationV1); err != nil {
			return fmt.Errorf("apply migration v1: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`, schemaVersion, time.Now().UnixMilli()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) writeTx(ctx context.Context, fn func(*sql.Tx) error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.HasPrefix(host, "[") {
		if end := strings.Index(host, "]"); end > 0 {
			return host[1:end]
		}
	}
	if idx := strings.LastIndex(host, ":"); idx > 0 && !strings.Contains(host[idx+1:], ":") {
		host = host[:idx]
	}
	return strings.TrimSuffix(host, ".")
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func jsonText(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func mapSQLError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return storepkg.ErrNotFound
	}
	if err != nil && (strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "constraint failed")) {
		return fmt.Errorf("%w: %v", storepkg.ErrConflict, err)
	}
	return err
}

func scanTenant(scanner interface{ Scan(...any) error }) (domain.Tenant, error) {
	var item domain.Tenant
	err := scanner.Scan(&item.ID, &item.Name, &item.Status, &item.OIDCIssuer, &item.OIDCClientID,
		&item.OIDCClientSecretEnv, &item.RolesClaim, &item.GroupsClaim, &item.CreatedAt, &item.UpdatedAt)
	return item, mapSQLError(err)
}

const tenantColumns = `tenant_id,name,status,oidc_issuer,oidc_client_id,oidc_client_secret_env,roles_claim,groups_claim,created_at,updated_at`

func (s *Store) BootstrapTenant(ctx context.Context, tenant domain.Tenant, hosts []string) error {
	now := time.Now().UnixMilli()
	if tenant.Status == "" {
		tenant.Status = "active"
	}
	if tenant.RolesClaim == "" {
		tenant.RolesClaim = "roles"
	}
	if tenant.GroupsClaim == "" {
		tenant.GroupsClaim = "groups"
	}
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO tenants(`+tenantColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id) DO NOTHING`, tenant.ID, tenant.Name, tenant.Status, tenant.OIDCIssuer, tenant.OIDCClientID, tenant.OIDCClientSecretEnv, tenant.RolesClaim, tenant.GroupsClaim, now, now); err != nil {
			return mapSQLError(err)
		}
		for _, rawHost := range hosts {
			host := normalizeHost(rawHost)
			if host == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO tenant_hosts(tenant_id,host,created_at) VALUES(?,?,?) ON CONFLICT(tenant_id,host) DO NOTHING`, tenant.ID, host, now); err != nil {
				return mapSQLError(err)
			}
		}
		return nil
	})
}

func (s *Store) TenantByHost(ctx context.Context, host string) (domain.Tenant, error) {
	return scanTenant(s.db.QueryRowContext(ctx, `SELECT `+tenantColumns+` FROM tenants WHERE tenant_id=(SELECT tenant_id FROM tenant_hosts WHERE host=?) AND status='active'`, normalizeHost(host)))
}

func (s *Store) TenantByID(ctx context.Context, tenantID string) (domain.Tenant, error) {
	return scanTenant(s.db.QueryRowContext(ctx, `SELECT `+tenantColumns+` FROM tenants WHERE tenant_id=?`, strings.TrimSpace(tenantID)))
}

func (s *Store) ListTenants(ctx context.Context) ([]domain.Tenant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+tenantColumns+` FROM tenants ORDER BY tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []domain.Tenant{}
	for rows.Next() {
		item, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) UpsertTenant(ctx context.Context, tenant domain.Tenant, hosts []string) (domain.Tenant, error) {
	now := time.Now().UnixMilli()
	tenant.ID = strings.TrimSpace(tenant.ID)
	tenant.Name = strings.TrimSpace(tenant.Name)
	if tenant.Status == "" {
		tenant.Status = "active"
	}
	if tenant.RolesClaim == "" {
		tenant.RolesClaim = "roles"
	}
	if tenant.GroupsClaim == "" {
		tenant.GroupsClaim = "groups"
	}
	if tenant.ID == "" || tenant.Name == "" {
		return domain.Tenant{}, fmt.Errorf("tenant id and name are required")
	}
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO tenants(`+tenantColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(tenant_id) DO UPDATE SET name=excluded.name,status=excluded.status,oidc_issuer=excluded.oidc_issuer,
			oidc_client_id=excluded.oidc_client_id,oidc_client_secret_env=excluded.oidc_client_secret_env,
			roles_claim=excluded.roles_claim,groups_claim=excluded.groups_claim,updated_at=excluded.updated_at`,
			tenant.ID, tenant.Name, tenant.Status, tenant.OIDCIssuer, tenant.OIDCClientID, tenant.OIDCClientSecretEnv,
			tenant.RolesClaim, tenant.GroupsClaim, now, now)
		if err != nil {
			return mapSQLError(err)
		}
		for _, host := range hosts {
			host = normalizeHost(host)
			if host == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO tenant_hosts(tenant_id,host,created_at) VALUES(?,?,?) ON CONFLICT(tenant_id,host) DO NOTHING`, tenant.ID, host, now); err != nil {
				return mapSQLError(err)
			}
		}
		return nil
	})
	if err != nil {
		return domain.Tenant{}, err
	}
	return s.TenantByID(ctx, tenant.ID)
}

func scanPlatform(scanner interface{ Scan(...any) error }) (domain.Platform, error) {
	var item domain.Platform
	var enabled int
	err := scanner.Scan(&item.TenantID, &item.ID, &item.Name, &enabled, &item.CreatedAt, &item.UpdatedAt)
	item.Enabled = enabled != 0
	return item, mapSQLError(err)
}

func (s *Store) ListPlatforms(ctx context.Context, tenantID string) ([]domain.Platform, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tenant_id,platform_id,name,enabled,created_at,updated_at FROM platforms WHERE tenant_id=? ORDER BY platform_id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []domain.Platform{}
	for rows.Next() {
		item, err := scanPlatform(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) UpsertPlatform(ctx context.Context, platform domain.Platform) (domain.Platform, error) {
	now := time.Now().UnixMilli()
	if platform.TenantID == "" || platform.ID == "" || strings.TrimSpace(platform.Name) == "" {
		return domain.Platform{}, fmt.Errorf("tenantId, platformId and name are required")
	}
	s.writeMu.Lock()
	_, err := s.db.ExecContext(ctx, `INSERT INTO platforms(tenant_id,platform_id,name,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(tenant_id,platform_id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,updated_at=excluded.updated_at`,
		platform.TenantID, platform.ID, strings.TrimSpace(platform.Name), boolInt(platform.Enabled), now, now)
	s.writeMu.Unlock()
	if err != nil {
		return domain.Platform{}, mapSQLError(err)
	}
	return s.Platform(ctx, platform.TenantID, platform.ID)
}

func (s *Store) Platform(ctx context.Context, tenantID, platformID string) (domain.Platform, error) {
	return scanPlatform(s.db.QueryRowContext(ctx, `SELECT tenant_id,platform_id,name,enabled,created_at,updated_at FROM platforms WHERE tenant_id=? AND platform_id=?`, tenantID, platformID))
}

func (s *Store) AddPlatformCredential(ctx context.Context, tenantID, platformID, jtiHash string, expiresAt int64) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `INSERT INTO platform_credentials(tenant_id,platform_id,jti_hash,expires_at,created_at) VALUES(?,?,?,?,?)`, tenantID, platformID, jtiHash, expiresAt, time.Now().UnixMilli())
	return mapSQLError(err)
}

func (s *Store) ValidatePlatformCredential(ctx context.Context, tenantID, platformID, jtiHash string, now int64) error {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM platform_credentials c JOIN platforms p ON p.tenant_id=c.tenant_id AND p.platform_id=c.platform_id
		WHERE c.tenant_id=? AND c.platform_id=? AND c.jti_hash=? AND c.revoked_at=0 AND c.expires_at>? AND p.enabled=1`, tenantID, platformID, jtiHash, now).Scan(&one)
	return mapSQLError(err)
}

func (s *Store) Cleanup(ctx context.Context, now int64) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		for _, stmt := range []string{
			`DELETE FROM web_sessions WHERE expires_at<=?`, `DELETE FROM anonymous_sessions WHERE expires_at<=?`,
			`DELETE FROM oidc_flows WHERE expires_at<=?`, `DELETE FROM idempotency_keys WHERE expires_at<=?`,
			`DELETE FROM resource_bindings WHERE expires_at>0 AND expires_at<=?`,
		} {
			if _, err := tx.ExecContext(ctx, stmt, now); err != nil {
				return err
			}
		}
		return nil
	})
}

var _ storepkg.Store = (*Store)(nil)
