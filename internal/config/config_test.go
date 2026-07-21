package config

import (
	"path/filepath"
	"testing"
)

func TestLoadRejectsPostgresUntilAdapterExists(t *testing.T) {
	t.Setenv("AGW_DATABASE_DRIVER", "postgres")
	t.Setenv("AGW_TENANT_HMAC_SECRET", "01234567890123456789012345678901")
	if _, err := Load(); err == nil {
		t.Fatal("postgres must remain a reserved but disabled driver in the SQLite release")
	}
}

func TestLoadDevelopmentConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGW_DATABASE_DRIVER", "sqlite")
	t.Setenv("AGW_TENANT_HMAC_SECRET", "01234567890123456789012345678901")
	t.Setenv("AGW_SQLITE_PATH", filepath.Join(dir, "database", "gateway.db"))
	t.Setenv("AGW_SPOOL_DIR", filepath.Join(dir, "spool"))
	t.Setenv("AGW_PUBLIC_BASE_URL", "http://localhost:11945")
	t.Setenv("AGW_COOKIE_SECURE", "false")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseDriver != "sqlite" || cfg.RateLimitPerMinute <= 0 || cfg.MaxConcurrentStreams <= 0 {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}
