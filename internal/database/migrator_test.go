package database

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"secret/internal/config"
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

func withSearchPath(databaseURL string, schema string) string {
	u, err := url.Parse(databaseURL)
	if err == nil && u.Scheme != "" {
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String()
	}
	return databaseURL + " search_path=" + schema
}

func quoteIdent(id string) string {
	return `"` + strings.ReplaceAll(id, `"`, `""`) + `"`
}

func createTestSchema(t *testing.T, conn *Connection) string {
	t.Helper()

	schema := "test_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := conn.DB().ExecContext(ctx, "CREATE SCHEMA "+quoteIdent(schema)); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = conn.DB().ExecContext(ctx, "DROP SCHEMA "+quoteIdent(schema)+" CASCADE")
	})
	return schema
}

func openPostgresOrSkip(t *testing.T, databaseURL string) *Connection {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestMigrator_ErrorPaths(t *testing.T) {
	baseURL := testDatabaseURL(t)
	baseConn := openPostgresOrSkip(t, baseURL)

	schema := createTestSchema(t, baseConn)
	schemaURL := withSearchPath(baseURL, schema)
	conn := openPostgresOrSkip(t, schemaURL)

	m := NewMigrator(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Fresh schema has no migrations table yet.
	if _, err := m.getAppliedMigrations(ctx); err == nil {
		t.Fatalf("expected error querying missing migrations table")
	}

	if err := m.ensureMigrationsTable(ctx); err != nil {
		t.Fatalf("ensure migrations table: %v", err)
	}

	// Invalid SQL should fail the migration and roll back.
	if err := m.applyMigration(ctx, "bad.sql", "THIS IS NOT SQL"); err == nil {
		t.Fatalf("expected migration failed error")
	}

	// Drop migrations table inside the transaction to force recording failure.
	if err := m.applyMigration(ctx, "drop_migrations.sql", "DROP TABLE migrations;"); err == nil {
		t.Fatalf("expected record migration error")
	}

	// Closed DB should cause a begin tx failure.
	db := conn.DB()
	_ = conn.Close()
	m2 := &Migrator{db: db}
	if err := m2.applyMigration(ctx, "closed.sql", "SELECT 1"); err == nil {
		t.Fatalf("expected begin tx error on closed db")
	}
}

func TestMigrator_Migrate_ClosedDB(t *testing.T) {
	baseURL := testDatabaseURL(t)
	baseConn := openPostgresOrSkip(t, baseURL)

	schema := createTestSchema(t, baseConn)
	schemaURL := withSearchPath(baseURL, schema)
	conn := openPostgresOrSkip(t, schemaURL)

	m := NewMigrator(conn)
	_ = conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := m.Migrate(ctx); err == nil {
		t.Fatalf("expected migrate error on closed db")
	}
}

func TestMigrator_getMigrationFiles(t *testing.T) {
	t.Parallel()

	m := &Migrator{db: nil}
	files, err := m.getMigrationFiles()
	if err != nil {
		t.Fatalf("getMigrationFiles: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected at least one migration file")
	}
	for _, f := range files {
		if !strings.HasSuffix(f, ".sql") {
			t.Fatalf("non-SQL file: %s", f)
		}
	}
	for i := 1; i < len(files); i++ {
		if files[i] < files[i-1] {
			t.Fatalf("files not sorted: %s before %s", files[i-1], files[i])
		}
	}
}

func TestMigrator_Migrate_HappyPath(t *testing.T) {
	baseURL := testDatabaseURL(t)
	baseConn := openPostgresOrSkip(t, baseURL)

	schema := createTestSchema(t, baseConn)
	schemaURL := withSearchPath(baseURL, schema)
	conn := openPostgresOrSkip(t, schemaURL)

	m := NewMigrator(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	applied, err := m.Migrate(ctx)
	if err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if len(applied) == 0 {
		t.Fatal("expected migrations to be applied")
	}

	applied2, err := m.Migrate(ctx)
	if err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if len(applied2) != 0 {
		t.Fatalf("expected no new migrations, got %d", len(applied2))
	}
}
