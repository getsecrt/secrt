package config

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		key := key
		if v, ok := os.LookupEnv(key); ok {
			t.Cleanup(func() { _ = os.Setenv(key, v) })
		} else {
			t.Cleanup(func() { _ = os.Unsetenv(key) })
		}
		_ = os.Unsetenv(key)
	}
}

func TestLoad_Defaults(t *testing.T) {
	unsetEnv(t,
		"ENV",
		"LISTEN_ADDR",
		"PUBLIC_BASE_URL",
		"LOG_LEVEL",
		"DATABASE_URL",
		"DB_HOST",
		"DB_PORT",
		"DB_NAME",
		"DB_USER",
		"DB_PASSWORD",
		"DB_SSLMODE",
		"DB_SSLROOTCERT",
		"API_KEY_PEPPER",
	)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Env != "development" {
		t.Fatalf("Env: got %q", cfg.Env)
	}
	if cfg.ListenAddr != ":8080" {
		t.Fatalf("ListenAddr: got %q", cfg.ListenAddr)
	}
	if cfg.PublicBaseURL != "http://localhost:8080" {
		t.Fatalf("PublicBaseURL: got %q", cfg.PublicBaseURL)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("LogLevel: got %q", cfg.LogLevel)
	}

	if cfg.DatabaseURL != "" {
		t.Fatalf("DatabaseURL: expected empty, got %q", cfg.DatabaseURL)
	}
	if cfg.DBHost != "127.0.0.1" {
		t.Fatalf("DBHost: got %q", cfg.DBHost)
	}
	if cfg.DBPort != 5432 {
		t.Fatalf("DBPort: got %d", cfg.DBPort)
	}
	if cfg.DBName != "secrt" {
		t.Fatalf("DBName: got %q", cfg.DBName)
	}
	if cfg.DBUser != "secrt_app" {
		t.Fatalf("DBUser: got %q", cfg.DBUser)
	}
	if cfg.DBPassword != "" {
		t.Fatalf("DBPassword: expected empty, got %q", cfg.DBPassword)
	}
	if cfg.DBSSLMode != "disable" {
		t.Fatalf("DBSSLMode: got %q", cfg.DBSSLMode)
	}
	if cfg.DBSSLRootCert != "" {
		t.Fatalf("DBSSLRootCert: expected empty, got %q", cfg.DBSSLRootCert)
	}
	if cfg.APIKeyPepper != "" {
		t.Fatalf("APIKeyPepper: expected empty in dev, got %q", cfg.APIKeyPepper)
	}

	// Envelope size defaults.
	if cfg.PublicMaxEnvelopeBytes != 256*1024 {
		t.Fatalf("PublicMaxEnvelopeBytes: got %d", cfg.PublicMaxEnvelopeBytes)
	}
	if cfg.AuthedMaxEnvelopeBytes != 1024*1024 {
		t.Fatalf("AuthedMaxEnvelopeBytes: got %d", cfg.AuthedMaxEnvelopeBytes)
	}

	// Quota defaults.
	if cfg.PublicMaxSecrets != 10 {
		t.Fatalf("PublicMaxSecrets: got %d", cfg.PublicMaxSecrets)
	}
	if cfg.PublicMaxTotalBytes != 2*1024*1024 {
		t.Fatalf("PublicMaxTotalBytes: got %d", cfg.PublicMaxTotalBytes)
	}
	if cfg.AuthedMaxSecrets != 1000 {
		t.Fatalf("AuthedMaxSecrets: got %d", cfg.AuthedMaxSecrets)
	}
	if cfg.AuthedMaxTotalBytes != 20*1024*1024 {
		t.Fatalf("AuthedMaxTotalBytes: got %d", cfg.AuthedMaxTotalBytes)
	}
}

func TestLoad_ValidationErrors(t *testing.T) {
	unsetEnv(t,
		"ENV",
		"LISTEN_ADDR",
		"PUBLIC_BASE_URL",
		"LOG_LEVEL",
		"DATABASE_URL",
		"DB_HOST",
		"DB_PORT",
		"DB_NAME",
		"DB_USER",
		"DB_PASSWORD",
		"DB_SSLMODE",
		"DB_SSLROOTCERT",
		"API_KEY_PEPPER",
	)

	t.Run("invalid DB_PORT", func(t *testing.T) {
		t.Setenv("DB_PORT", "nope")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "invalid DB_PORT") {
			t.Fatalf("expected DB_PORT error, got %v", err)
		}
	})

	t.Run("PUBLIC_BASE_URL required", func(t *testing.T) {
		t.Setenv("DB_PORT", "5432")
		t.Setenv("PUBLIC_BASE_URL", "")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "PUBLIC_BASE_URL is required") {
			t.Fatalf("expected PUBLIC_BASE_URL required error, got %v", err)
		}
	})

	t.Run("invalid PUBLIC_BASE_URL", func(t *testing.T) {
		t.Setenv("DB_PORT", "5432")
		t.Setenv("PUBLIC_BASE_URL", "http://[::1")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "invalid PUBLIC_BASE_URL") {
			t.Fatalf("expected invalid PUBLIC_BASE_URL error, got %v", err)
		}
	})

	t.Run("production requires pepper", func(t *testing.T) {
		t.Setenv("DB_PORT", "5432")
		t.Setenv("PUBLIC_BASE_URL", "https://example.com")
		t.Setenv("ENV", "production")
		t.Setenv("API_KEY_PEPPER", "")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "API_KEY_PEPPER is required in production") {
			t.Fatalf("expected pepper required error, got %v", err)
		}
	})
}

func TestLoad_TrimsDatabaseURL(t *testing.T) {
	unsetEnv(t, "DB_PORT", "PUBLIC_BASE_URL", "ENV", "API_KEY_PEPPER", "DATABASE_URL")
	t.Setenv("DB_PORT", "5432")
	t.Setenv("PUBLIC_BASE_URL", "https://example.com")
	t.Setenv("DATABASE_URL", "  postgres://u:p@h:5432/db?sslmode=disable  ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DatabaseURL != "postgres://u:p@h:5432/db?sslmode=disable" {
		t.Fatalf("DatabaseURL trim: got %q", cfg.DatabaseURL)
	}
}

func TestLoad_QuotaOverrides(t *testing.T) {
	unsetEnv(t, "DB_PORT", "PUBLIC_BASE_URL", "ENV", "API_KEY_PEPPER",
		"PUBLIC_MAX_ENVELOPE_BYTES", "AUTHED_MAX_ENVELOPE_BYTES",
		"PUBLIC_MAX_SECRETS", "PUBLIC_MAX_TOTAL_BYTES",
		"AUTHED_MAX_SECRETS", "AUTHED_MAX_TOTAL_BYTES")
	t.Setenv("DB_PORT", "5432")
	t.Setenv("PUBLIC_BASE_URL", "https://example.com")
	t.Setenv("PUBLIC_MAX_ENVELOPE_BYTES", "131072")
	t.Setenv("AUTHED_MAX_ENVELOPE_BYTES", "2097152")
	t.Setenv("PUBLIC_MAX_SECRETS", "50")
	t.Setenv("PUBLIC_MAX_TOTAL_BYTES", "1048576")
	t.Setenv("AUTHED_MAX_SECRETS", "5000")
	t.Setenv("AUTHED_MAX_TOTAL_BYTES", "134217728")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PublicMaxEnvelopeBytes != 131072 {
		t.Fatalf("PublicMaxEnvelopeBytes: got %d", cfg.PublicMaxEnvelopeBytes)
	}
	if cfg.AuthedMaxEnvelopeBytes != 2097152 {
		t.Fatalf("AuthedMaxEnvelopeBytes: got %d", cfg.AuthedMaxEnvelopeBytes)
	}
	if cfg.PublicMaxSecrets != 50 {
		t.Fatalf("PublicMaxSecrets: got %d", cfg.PublicMaxSecrets)
	}
	if cfg.PublicMaxTotalBytes != 1048576 {
		t.Fatalf("PublicMaxTotalBytes: got %d", cfg.PublicMaxTotalBytes)
	}
	if cfg.AuthedMaxSecrets != 5000 {
		t.Fatalf("AuthedMaxSecrets: got %d", cfg.AuthedMaxSecrets)
	}
	if cfg.AuthedMaxTotalBytes != 134217728 {
		t.Fatalf("AuthedMaxTotalBytes: got %d", cfg.AuthedMaxTotalBytes)
	}
}

func TestLoad_QuotaInvalidFallsBackToDefault(t *testing.T) {
	unsetEnv(t, "DB_PORT", "PUBLIC_BASE_URL", "ENV", "API_KEY_PEPPER", "PUBLIC_MAX_SECRETS")
	t.Setenv("DB_PORT", "5432")
	t.Setenv("PUBLIC_BASE_URL", "https://example.com")
	t.Setenv("PUBLIC_MAX_SECRETS", "not-a-number")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PublicMaxSecrets != 10 {
		t.Fatalf("PublicMaxSecrets: got %d, expected default 10", cfg.PublicMaxSecrets)
	}
}

func TestConfig_PostgresURL(t *testing.T) {
	t.Run("uses DatabaseURL when set", func(t *testing.T) {
		cfg := Config{DatabaseURL: "postgres://example.com/db"}
		got, err := cfg.PostgresURL()
		if err != nil {
			t.Fatalf("PostgresURL: %v", err)
		}
		if got != cfg.DatabaseURL {
			t.Fatalf("expected %q got %q", cfg.DatabaseURL, got)
		}
	})

	t.Run("errors when required fields missing", func(t *testing.T) {
		cfg := Config{DBHost: "", DBName: "", DBUser: "", DBSSLMode: ""}
		_, err := cfg.PostgresURL()
		if err == nil || !strings.Contains(err.Error(), "missing env vars:") {
			t.Fatalf("expected missing env vars error, got %v", err)
		}
	})

	t.Run("builds URL from parts", func(t *testing.T) {
		cfg := Config{
			DBHost:        "127.0.0.1",
			DBPort:        5432,
			DBName:        "secrt",
			DBUser:        "secrt_app",
			DBPassword:    "p@ss",
			DBSSLMode:     "disable",
			DBSSLRootCert: "/tmp/root.crt",
		}
		got, err := cfg.PostgresURL()
		if err != nil {
			t.Fatalf("PostgresURL: %v", err)
		}

		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("parse url: %v", err)
		}
		if u.Scheme != "postgres" {
			t.Fatalf("scheme: got %q", u.Scheme)
		}
		if u.Host != "127.0.0.1:5432" {
			t.Fatalf("host: got %q", u.Host)
		}
		if u.Path != "/secrt" {
			t.Fatalf("path: got %q", u.Path)
		}
		if u.User == nil {
			t.Fatalf("expected userinfo")
		}
		if user := u.User.Username(); user != "secrt_app" {
			t.Fatalf("user: got %q", user)
		}
		if pw, ok := u.User.Password(); !ok || pw != "p@ss" {
			t.Fatalf("password: got ok=%v pw=%q", ok, pw)
		}
		q := u.Query()
		if q.Get("sslmode") != "disable" {
			t.Fatalf("sslmode: got %q", q.Get("sslmode"))
		}
		if q.Get("sslrootcert") != "/tmp/root.crt" {
			t.Fatalf("sslrootcert: got %q", q.Get("sslrootcert"))
		}
	})
}
