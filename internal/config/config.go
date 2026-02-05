package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Env           string
	ListenAddr    string
	PublicBaseURL string
	LogLevel      string

	DatabaseURL    string
	DBHost         string
	DBPort         int
	DBName         string
	DBUser         string
	DBPassword     string
	DBSSLMode      string
	DBSSLRootCert  string
	APIKeyPepper   string
}

func Load() (Config, error) {
	cfg := Config{
		Env:           getenvDefault("ENV", "development"),
		ListenAddr:    getenvDefault("LISTEN_ADDR", ":8080"),
		PublicBaseURL: strings.TrimRight(getenvDefault("PUBLIC_BASE_URL", "http://localhost:8080"), "/"),
		LogLevel:      getenvDefault("LOG_LEVEL", "info"),

		DatabaseURL:   strings.TrimSpace(os.Getenv("DATABASE_URL")),
		DBHost:        getenvDefault("DB_HOST", "127.0.0.1"),
		DBName:        getenvDefault("DB_NAME", "secret"),
		DBUser:        getenvDefault("DB_USER", "secret_app"),
		DBPassword:    os.Getenv("DB_PASSWORD"),
		DBSSLMode:     getenvDefault("DB_SSLMODE", "disable"),
		DBSSLRootCert: strings.TrimSpace(os.Getenv("DB_SSLROOTCERT")),
		APIKeyPepper:  strings.TrimSpace(os.Getenv("API_KEY_PEPPER")),
	}

	dbPortStr := getenvDefault("DB_PORT", "5432")
	dbPort, err := strconv.Atoi(dbPortStr)
	if err != nil || dbPort <= 0 || dbPort > 65535 {
		return Config{}, fmt.Errorf("invalid DB_PORT %q", dbPortStr)
	}
	cfg.DBPort = dbPort

	if cfg.PublicBaseURL == "" {
		return Config{}, errors.New("PUBLIC_BASE_URL is required")
	}
	if _, err := url.Parse(cfg.PublicBaseURL); err != nil {
		return Config{}, fmt.Errorf("invalid PUBLIC_BASE_URL: %w", err)
	}

	if cfg.Env == "production" && cfg.APIKeyPepper == "" {
		return Config{}, errors.New("API_KEY_PEPPER is required in production")
	}

	return cfg, nil
}

func (c Config) PostgresURL() (string, error) {
	if c.DatabaseURL != "" {
		return c.DatabaseURL, nil
	}

	missing := make([]string, 0, 5)
	if c.DBHost == "" {
		missing = append(missing, "DB_HOST")
	}
	if c.DBName == "" {
		missing = append(missing, "DB_NAME")
	}
	if c.DBUser == "" {
		missing = append(missing, "DB_USER")
	}
	if c.DBSSLMode == "" {
		missing = append(missing, "DB_SSLMODE")
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("missing env vars: %s", strings.Join(missing, ", "))
	}

	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(c.DBUser, c.DBPassword),
		Host:   fmt.Sprintf("%s:%d", c.DBHost, c.DBPort),
		Path:   c.DBName,
	}

	q := u.Query()
	q.Set("sslmode", c.DBSSLMode)
	if c.DBSSLRootCert != "" {
		q.Set("sslrootcert", c.DBSSLRootCert)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func getenvDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

