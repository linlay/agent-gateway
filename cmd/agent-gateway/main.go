package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"agent-gateway/internal/auth"
	"agent-gateway/internal/channel"
	"agent-gateway/internal/config"
	"agent-gateway/internal/domain"
	"agent-gateway/internal/server"
	sqlitestore "agent-gateway/internal/store/sqlite"
)

func main() {
	checkOnly := flag.Bool("check", false, "check SQLite integrity and exit")
	backupPath := flag.String("backup", "", "write a consistent SQLite backup and exit")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(2)
	}
	st, err := sqlitestore.Open(cfg.SQLitePath)
	if err != nil {
		logger.Error("open sqlite failed", "error", err)
		os.Exit(1)
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if *checkOnly {
		if err := st.IntegrityCheck(ctx); err != nil {
			logger.Error("sqlite integrity check failed", "error", err)
			os.Exit(1)
		}
		logger.Info("sqlite integrity check passed", "database", cfg.SQLitePath)
		return
	}
	if *backupPath != "" {
		if err := st.Backup(ctx, *backupPath); err != nil {
			logger.Error("sqlite backup failed", "error", err)
			os.Exit(1)
		}
		logger.Info("sqlite backup completed", "destination", *backupPath)
		return
	}

	now := time.Now().UnixMilli()
	if err := st.BootstrapTenant(ctx, domain.Tenant{ID: cfg.BootstrapTenantID, Name: cfg.BootstrapTenantName, Status: "active", RolesClaim: "roles", GroupsClaim: "groups", CreatedAt: now, UpdatedAt: now}, cfg.BootstrapHosts); err != nil {
		logger.Error("bootstrap tenant failed", "error", err)
		os.Exit(1)
	}
	platformTokens, err := auth.NewPlatformTokens(cfg.PlatformJWTIssuer, cfg.PlatformJWTPublicKeyFile, cfg.PlatformJWTPrivateKeyFile, st, cfg.PlatformTokenTTL)
	if err != nil {
		logger.Error("platform token configuration failed", "error", err)
		os.Exit(1)
	}
	oidc := auth.NewOIDC()
	var localAuth *auth.Local
	if cfg.AuthMode == "local" {
		localAuth, err = auth.NewLocal(cfg.LocalUsername, cfg.LocalPasswordHash, cfg.LocalDisplayName, cfg.LocalRoles)
		if err != nil {
			logger.Error("local authentication configuration failed", "error", err)
			os.Exit(2)
		}
	}
	browserAuth := auth.NewBrowser(st, oidc, localAuth, cfg.CookieSecure, cfg.SessionTTL, cfg.AnonymousTTL, cfg.BootstrapAdminToken)
	channels := channel.NewManager(st, platformTokens, logger, cfg.MaxWSMessageBytes, cfg.WriteQueueSize, cfg.PlatformRequestTimeout)
	httpServer := server.New(cfg, st, browserAuth, channels, platformTokens, logger)

	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	defer cleanupCancel()
	go cleanupLoop(cleanupCtx, st, cfg.SpoolDir, cfg.SpoolTTL, logger)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("agent gateway listening", "address", cfg.ListenAddr, "database", "sqlite", "platform_jwt_configured", platformTokens.Configured())
		errCh <- httpServer.ListenAndServe()
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-signals:
		logger.Info("shutdown requested", "signal", sig.String())
	case err := <-errCh:
		if err != nil {
			logger.Error("gateway stopped", "error", err)
			os.Exit(1)
		}
		return
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
}

type cleanupStore interface {
	Cleanup(context.Context, int64) error
}

func cleanupLoop(ctx context.Context, st cleanupStore, spoolDir string, ttl time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		cleanupExpired(ctx, st, spoolDir, ttl, logger)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func cleanupExpired(ctx context.Context, st cleanupStore, spoolDir string, ttl time.Duration, logger *slog.Logger) {
	now := time.Now()
	if err := st.Cleanup(ctx, now.UnixMilli()); err != nil && ctx.Err() == nil {
		logger.Warn("database ttl cleanup failed", "error", err)
	}
	entries, err := os.ReadDir(spoolDir)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Warn("spool cleanup scan failed", "error", err)
		}
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) == ".keep" {
			continue
		}
		info, err := entry.Info()
		if err == nil && now.Sub(info.ModTime()) >= ttl {
			path := filepath.Join(spoolDir, entry.Name())
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				logger.Warn("spool cleanup failed", "file", entry.Name(), "error", err)
			}
		}
	}
}
