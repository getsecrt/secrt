package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"secret/internal/storage"
)

func TestStore_ClosedDB_ReturnsErrors(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("pgx", "postgres://user:pass@127.0.0.1:5432/db?sslmode=disable")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	store := New(db)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sec := storage.Secret{
		ID:        "id",
		ClaimHash: "claim",
		Envelope:  json.RawMessage(`{"ciphertext":"abc"}`),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if err := store.Create(ctx, sec); err == nil || !strings.Contains(err.Error(), "insert secret") {
		t.Fatalf("expected create error, got %v", err)
	}

	if _, err := store.ClaimAndDelete(ctx, "id", "claim", time.Now()); err == nil || !strings.Contains(err.Error(), "claim secret") {
		t.Fatalf("expected claim error, got %v", err)
	}

	if _, err := store.Burn(ctx, "id"); err == nil || !strings.Contains(err.Error(), "burn secret") {
		t.Fatalf("expected burn error, got %v", err)
	}

	if _, err := store.DeleteExpired(ctx, time.Now()); err == nil || !strings.Contains(err.Error(), "delete expired") {
		t.Fatalf("expected delete expired error, got %v", err)
	}

	if _, err := store.GetByPrefix(ctx, "pfx"); err == nil || !strings.Contains(err.Error(), "get api key") {
		t.Fatalf("expected get api key error, got %v", err)
	}

	if err := store.Insert(ctx, storage.APIKey{Prefix: "pfx", Hash: strings.Repeat("a", 64)}); err == nil || !strings.Contains(err.Error(), "insert api key") {
		t.Fatalf("expected insert api key error, got %v", err)
	}

	if _, err := store.RevokeByPrefix(ctx, "pfx"); err == nil || !strings.Contains(err.Error(), "revoke api key") {
		t.Fatalf("expected revoke api key error, got %v", err)
	}
}
