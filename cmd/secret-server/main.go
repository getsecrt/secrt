package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"secret/internal/api"
	"secret/internal/auth"
	"secret/internal/config"
	"secret/internal/database"
	"secret/internal/storage/postgres"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Convenience for local dev: load .env if present (does not override existing env vars).
	if os.Getenv("ENV") != "production" {
		_ = config.LoadDotEnvIfPresent(".env")
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.LogLevel),
	}))
	slog.SetDefault(logger)

	dbURL, err := cfg.PostgresURL()
	if err != nil {
		slog.Error("db url error", "err", err)
		os.Exit(1)
	}

	conn, err := database.OpenPostgres(ctx, dbURL)
	if err != nil {
		slog.Error("db connection error", "err", err)
		os.Exit(1)
	}
	defer conn.Close()

	migrator := database.NewMigrator(conn)
	applied, err := migrator.Migrate(ctx)
	if err != nil {
		slog.Error("migration error", "err", err)
		os.Exit(1)
	}
	if len(applied) > 0 {
		slog.Info("migrations applied", "count", len(applied))
	}

	store := postgres.New(conn.DB())
	authn := auth.NewAuthenticator(cfg.APIKeyPepper, store)
	srv := api.NewServer(cfg, store, authn)

	// Best-effort cleanup loop for expired secrets.
	go func() {
		t := time.NewTicker(30 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, _ = store.DeleteExpired(cctx, time.Now().UTC())
				cancel()
			}
		}
	}()

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		slog.Info("listening", "addr", cfg.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server error", "err", err)
			cancel()
		}
	}()

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
