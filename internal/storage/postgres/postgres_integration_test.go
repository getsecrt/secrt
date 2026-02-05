package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"secret/internal/config"
	"secret/internal/database"
	"secret/internal/storage"
)

func loadDotEnvForTests(t *testing.T) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		return
	}
	dir := wd
	for i := 0; i < 6; i++ {
		p := filepath.Join(dir, ".env")
		if _, err := os.Stat(p); err == nil {
			_ = config.LoadDotEnvIfPresent(p)
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return
		}
		dir = parent
	}
}

func testDatabaseURL(t *testing.T) string {
	t.Helper()

	loadDotEnvForTests(t)

	if v := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")); v != "" {
		return v
	}

	cfg, err := config.Load()
	if err != nil {
		t.Skipf("config unavailable: %v", err)
	}
	u, err := cfg.PostgresURL()
	if err != nil {
		t.Skipf("db url unavailable: %v", err)
	}
	return u
}

func openPostgresOrSkip(t *testing.T, databaseURL string) *database.Connection {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := database.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func quoteIdent(id string) string {
	return `"` + strings.ReplaceAll(id, `"`, `""`) + `"`
}

func withSearchPath(databaseURL string, schema string) string {
	u, err := url.Parse(databaseURL)
	if err == nil && u.Scheme != "" {
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String()
	}
	// Fallback for non-URL connection strings.
	return databaseURL + " search_path=" + schema
}

func createTestSchema(t *testing.T, db *sql.DB) string {
	t.Helper()

	schema := "test_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE SCHEMA %s", quoteIdent(schema))); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = db.ExecContext(ctx, fmt.Sprintf("DROP SCHEMA %s CASCADE", quoteIdent(schema)))
	})

	return schema
}

func migrateOrFatal(t *testing.T, conn *database.Connection) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	m := database.NewMigrator(conn)
	applied, err := m.Migrate(ctx)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(applied) == 0 {
		// We expect at least one migration in a fresh schema.
		t.Fatalf("expected migrations to apply in fresh schema")
	}

	// Second run should be idempotent.
	applied2, err := m.Migrate(ctx)
	if err != nil {
		t.Fatalf("migrate second run: %v", err)
	}
	if len(applied2) != 0 {
		t.Fatalf("expected no migrations on second run, got %d", len(applied2))
	}
}

func TestStore_SecretLifecycle(t *testing.T) {
	baseURL := testDatabaseURL(t)
	baseConn := openPostgresOrSkip(t, baseURL)

	schema := createTestSchema(t, baseConn.DB())
	schemaURL := withSearchPath(baseURL, schema)

	conn := openPostgresOrSkip(t, schemaURL)
	migrateOrFatal(t, conn)

	store := New(conn.DB())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := now.Add(1 * time.Hour)

	sec := storage.Secret{
		ID:        "id1",
		ClaimHash: "claimhash1",
		Envelope:  json.RawMessage(`{"ciphertext":"abc"}`),
		ExpiresAt: expiresAt,
	}
	if err := store.Create(ctx, sec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Wrong claim hash should not return anything.
	if _, err := store.ClaimAndDelete(ctx, "id1", "wrong", now); err == nil || !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected not found for wrong claim hash, got %v", err)
	}

	got, err := store.ClaimAndDelete(ctx, "id1", sec.ClaimHash, now)
	if err != nil {
		t.Fatalf("ClaimAndDelete: %v", err)
	}
	var gotEnv any
	var wantEnv any
	if err := json.Unmarshal(got.Envelope, &gotEnv); err != nil {
		t.Fatalf("decode got envelope: %v", err)
	}
	if err := json.Unmarshal(sec.Envelope, &wantEnv); err != nil {
		t.Fatalf("decode want envelope: %v", err)
	}
	if !reflect.DeepEqual(gotEnv, wantEnv) {
		t.Fatalf("envelope mismatch: got=%v want=%v", gotEnv, wantEnv)
	}
	if got.ID != "id1" {
		t.Fatalf("id: got %q", got.ID)
	}
	if !got.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expires_at: got %s want %s", got.ExpiresAt, expiresAt)
	}
	if got.CreatedAt.IsZero() {
		t.Fatalf("expected created_at")
	}

	// Secret should be gone after claim.
	if _, err := store.ClaimAndDelete(ctx, "id1", sec.ClaimHash, now); err == nil || !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected not found after delete, got %v", err)
	}

	// Burn non-existent should report false.
	deleted, err := store.Burn(ctx, "missing")
	if err != nil {
		t.Fatalf("Burn missing: %v", err)
	}
	if deleted {
		t.Fatalf("expected deleted=false for missing")
	}

	// Create another secret and burn it.
	sec2 := storage.Secret{
		ID:        "id2",
		ClaimHash: "claimhash2",
		Envelope:  json.RawMessage(`{"ciphertext":"def"}`),
		ExpiresAt: expiresAt,
	}
	if err := store.Create(ctx, sec2); err != nil {
		t.Fatalf("Create sec2: %v", err)
	}
	deleted, err = store.Burn(ctx, "id2")
	if err != nil {
		t.Fatalf("Burn: %v", err)
	}
	if !deleted {
		t.Fatalf("expected deleted=true")
	}
	if _, err := store.ClaimAndDelete(ctx, "id2", sec2.ClaimHash, now); err == nil || !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected not found after burn, got %v", err)
	}

	// DeleteExpired should remove expired secrets.
	expired := storage.Secret{
		ID:        "id3",
		ClaimHash: "claimhash3",
		Envelope:  json.RawMessage(`{"ciphertext":"ghi"}`),
		ExpiresAt: now.Add(-1 * time.Second),
	}
	if err := store.Create(ctx, expired); err != nil {
		t.Fatalf("Create expired: %v", err)
	}
	n, err := store.DeleteExpired(ctx, now)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 expired delete, got %d", n)
	}
}

func TestStore_APIKeys(t *testing.T) {
	baseURL := testDatabaseURL(t)
	baseConn := openPostgresOrSkip(t, baseURL)

	schema := createTestSchema(t, baseConn.DB())
	schemaURL := withSearchPath(baseURL, schema)

	conn := openPostgresOrSkip(t, schemaURL)
	migrateOrFatal(t, conn)

	store := New(conn.DB())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Missing prefix.
	if _, err := store.GetByPrefix(ctx, "nope"); err == nil || !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}

	if err := store.Insert(ctx, storage.APIKey{
		Prefix: "pfx1",
		Hash:   strings.Repeat("a", 64),
		Scopes: "secrets:write",
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	k, err := store.GetByPrefix(ctx, "pfx1")
	if err != nil {
		t.Fatalf("GetByPrefix: %v", err)
	}
	if k.Prefix != "pfx1" {
		t.Fatalf("prefix: got %q", k.Prefix)
	}
	if k.Hash != strings.Repeat("a", 64) {
		t.Fatalf("hash: got %q", k.Hash)
	}
	if k.Scopes != "secrets:write" {
		t.Fatalf("scopes: got %q", k.Scopes)
	}
	if k.CreatedAt.IsZero() {
		t.Fatalf("expected created_at")
	}
	if k.RevokedAt != nil {
		t.Fatalf("expected not revoked")
	}

	ok, err := store.RevokeByPrefix(ctx, "pfx1")
	if err != nil {
		t.Fatalf("RevokeByPrefix: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true on first revoke")
	}

	k, err = store.GetByPrefix(ctx, "pfx1")
	if err != nil {
		t.Fatalf("GetByPrefix after revoke: %v", err)
	}
	if k.RevokedAt == nil {
		t.Fatalf("expected revoked_at")
	}

	ok, err = store.RevokeByPrefix(ctx, "pfx1")
	if err != nil {
		t.Fatalf("RevokeByPrefix second: %v", err)
	}
	if ok {
		t.Fatalf("expected ok=false on second revoke")
	}

	ok, err = store.RevokeByPrefix(ctx, "missing")
	if err != nil {
		t.Fatalf("RevokeByPrefix missing: %v", err)
	}
	if ok {
		t.Fatalf("expected ok=false for missing")
	}
}
