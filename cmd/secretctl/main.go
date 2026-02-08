package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"secret/internal/auth"
	"secret/internal/config"
	"secret/internal/database"
	"secret/internal/storage"
	"secret/internal/storage/postgres"
)

func main() {
	if os.Getenv("ENV") != "production" {
		_ = config.LoadDotEnvIfPresent(".env")
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	dbURL, err := cfg.PostgresURL()
	if err != nil {
		fmt.Fprintf(os.Stderr, "db url error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := database.OpenPostgres(ctx, dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "db connection error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	store := postgres.New(conn.DB())

	switch os.Args[1] {
	case "apikey":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "create":
			scopes := ""
			if len(os.Args) >= 4 {
				scopes = strings.TrimSpace(os.Args[3])
			}
			createAPIKey(cfg, store, scopes)
		case "revoke":
			if len(os.Args) < 4 {
				usage()
				os.Exit(2)
			}
			revokeAPIKey(ctx, store, os.Args[3])
		default:
			usage()
			os.Exit(2)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func createAPIKey(cfg config.Config, store storage.APIKeysStore, scopes string) {
	if cfg.APIKeyPepper == "" {
		fmt.Fprintln(os.Stderr, "API_KEY_PEPPER is required to create API keys")
		os.Exit(1)
	}

	apiKey, prefix, hash, err := auth.GenerateAPIKey(cfg.APIKeyPepper)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate api key: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := store.Insert(ctx, storage.APIKey{
		Prefix: prefix,
		Hash:   hash,
		Scopes: scopes,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "insert api key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(apiKey)
}

func revokeAPIKey(ctx context.Context, store storage.APIKeysStore, prefix string) {
	ok, err := store.RevokeByPrefix(ctx, strings.TrimSpace(prefix))
	if err != nil {
		fmt.Fprintf(os.Stderr, "revoke api key: %v\n", err)
		os.Exit(1)
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "not found or already revoked")
		os.Exit(1)
	}
	fmt.Println("revoked")
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  secretctl apikey create [scopes]")
	fmt.Fprintln(os.Stderr, "  secretctl apikey revoke <prefix>")
}
