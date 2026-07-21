package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr                string
	PublicBaseURL             string
	DatabaseDriver            string
	SQLitePath                string
	SpoolDir                  string
	CookieSecure              bool
	TenantHMACSecret          string
	BootstrapTenantID         string
	BootstrapTenantName       string
	BootstrapHosts            []string
	BootstrapAdminToken       string
	PlatformJWTPublicKeyFile  string
	PlatformJWTPrivateKeyFile string
	PlatformJWTIssuer         string
	SessionTTL                time.Duration
	AnonymousTTL              time.Duration
	OIDCFlowTTL               time.Duration
	PlatformTokenTTL          time.Duration
	ResourceTicketTTL         time.Duration
	SpoolTTL                  time.Duration
	MaxUploadBytes            int64
	MaxWSMessageBytes         int64
	WriteQueueSize            int
	PlatformRequestTimeout    time.Duration
	RateLimitPerMinute        int
	MaxConcurrentStreams      int
	AllowedBrowserOrigins     []string
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddr:                env("AGW_LISTEN_ADDR", ":11945"),
		PublicBaseURL:             strings.TrimRight(env("AGW_PUBLIC_BASE_URL", ""), "/"),
		DatabaseDriver:            strings.ToLower(env("AGW_DATABASE_DRIVER", "sqlite")),
		SQLitePath:                env("AGW_SQLITE_PATH", "./data/gateway.db"),
		SpoolDir:                  env("AGW_SPOOL_DIR", "./data/spool"),
		CookieSecure:              envBool("AGW_COOKIE_SECURE", true),
		TenantHMACSecret:          strings.TrimSpace(os.Getenv("AGW_TENANT_HMAC_SECRET")),
		BootstrapTenantID:         env("AGW_BOOTSTRAP_TENANT_ID", "local"),
		BootstrapTenantName:       env("AGW_BOOTSTRAP_TENANT_NAME", "Local"),
		BootstrapHosts:            csvEnv("AGW_BOOTSTRAP_HOSTS", []string{"localhost", "127.0.0.1"}),
		BootstrapAdminToken:       strings.TrimSpace(os.Getenv("AGW_BOOTSTRAP_ADMIN_TOKEN")),
		PlatformJWTPublicKeyFile:  strings.TrimSpace(os.Getenv("AGW_PLATFORM_JWT_PUBLIC_KEY_FILE")),
		PlatformJWTPrivateKeyFile: strings.TrimSpace(os.Getenv("AGW_PLATFORM_JWT_PRIVATE_KEY_FILE")),
		PlatformJWTIssuer:         env("AGW_PLATFORM_JWT_ISSUER", "agent-gateway"),
		SessionTTL:                envDuration("AGW_SESSION_TTL", 12*time.Hour),
		AnonymousTTL:              envDuration("AGW_ANONYMOUS_TTL", 30*24*time.Hour),
		OIDCFlowTTL:               envDuration("AGW_OIDC_FLOW_TTL", 10*time.Minute),
		PlatformTokenTTL:          envDuration("AGW_PLATFORM_TOKEN_TTL", 30*24*time.Hour),
		ResourceTicketTTL:         envDuration("AGW_RESOURCE_TICKET_TTL", 5*time.Minute),
		SpoolTTL:                  envDuration("AGW_SPOOL_TTL", 30*time.Minute),
		MaxUploadBytes:            envInt64("AGW_MAX_UPLOAD_BYTES", 100<<20),
		MaxWSMessageBytes:         envInt64("AGW_MAX_WS_MESSAGE_BYTES", 1<<20),
		WriteQueueSize:            int(envInt64("AGW_WRITE_QUEUE_SIZE", 256)),
		PlatformRequestTimeout:    envDuration("AGW_PLATFORM_REQUEST_TIMEOUT", 30*time.Second),
		RateLimitPerMinute:        int(envInt64("AGW_RATE_LIMIT_PER_MINUTE", 240)),
		MaxConcurrentStreams:      int(envInt64("AGW_MAX_CONCURRENT_STREAMS", 8)),
		AllowedBrowserOrigins:     csvEnv("AGW_ALLOWED_BROWSER_ORIGINS", nil),
	}
	if cfg.DatabaseDriver != "sqlite" {
		return Config{}, fmt.Errorf("database driver %q is not available in this release; use sqlite", cfg.DatabaseDriver)
	}
	if cfg.SQLitePath == "" || cfg.SpoolDir == "" {
		return Config{}, errors.New("sqlite path and spool directory are required")
	}
	if cfg.PublicBaseURL != "" {
		parsed, err := url.Parse(cfg.PublicBaseURL)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.Scheme != "https" && (parsed.Scheme != "http" || cfg.CookieSecure) {
			return Config{}, errors.New("AGW_PUBLIC_BASE_URL must be an origin; production CookieSecure mode requires https")
		}
	}
	if cfg.SpoolTTL < cfg.ResourceTicketTTL {
		return Config{}, errors.New("AGW_SPOOL_TTL must be greater than or equal to AGW_RESOURCE_TICKET_TTL")
	}
	if len(cfg.TenantHMACSecret) < 32 {
		return Config{}, errors.New("AGW_TENANT_HMAC_SECRET must contain at least 32 bytes")
	}
	if cfg.BootstrapTenantID == "" || len(cfg.BootstrapHosts) == 0 {
		return Config{}, errors.New("bootstrap tenant id and at least one host are required")
	}
	if err := os.MkdirAll(filepath.Dir(cfg.SQLitePath), 0o700); err != nil {
		return Config{}, fmt.Errorf("create sqlite directory: %w", err)
	}
	if err := os.MkdirAll(cfg.SpoolDir, 0o700); err != nil {
		return Config{}, fmt.Errorf("create spool directory: %w", err)
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt64(key string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func csvEnv(key string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return append([]string(nil), fallback...)
	}
	items := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}
