package database

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Migrator struct {
	db *sql.DB
}

func NewMigrator(conn *Connection) *Migrator {
	return &Migrator{db: conn.DB()}
}

func (m *Migrator) Migrate(ctx context.Context) ([]string, error) {
	if err := m.ensureMigrationsTable(ctx); err != nil {
		return nil, err
	}

	applied, err := m.getAppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}

	migrations, err := m.getMigrationFiles()
	if err != nil {
		return nil, err
	}

	var newlyApplied []string
	for _, filename := range migrations {
		if _, ok := applied[filename]; ok {
			continue
		}

		sqlContent, err := migrationsFS.ReadFile("migrations/" + filename)
		if err != nil {
			return newlyApplied, fmt.Errorf("read migration %s: %w", filename, err)
		}

		if err := m.applyMigration(ctx, filename, string(sqlContent)); err != nil {
			return newlyApplied, err
		}

		newlyApplied = append(newlyApplied, filename)
	}

	return newlyApplied, nil
}

func (m *Migrator) ensureMigrationsTable(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS migrations (
	filename TEXT PRIMARY KEY,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);`)
	if err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}
	return nil
}

func (m *Migrator) getAppliedMigrations(ctx context.Context) (map[string]struct{}, error) {
	rows, err := m.db.QueryContext(ctx, "SELECT filename FROM migrations")
	if err != nil {
		return nil, fmt.Errorf("query applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]struct{})
	for rows.Next() {
		var filename string
		if err := rows.Scan(&filename); err != nil {
			return nil, fmt.Errorf("scan applied migrations: %w", err)
		}
		applied[filename] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applied migrations: %w", err)
	}

	return applied, nil
}

func (m *Migrator) getMigrationFiles() ([]string, error) {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}

	var migrations []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".sql") {
			migrations = append(migrations, entry.Name())
		}
	}

	sort.Strings(migrations)
	return migrations, nil
}

func (m *Migrator) applyMigration(ctx context.Context, filename, sqlText string) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration tx (%s): %w", filename, err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, sqlText); err != nil {
		return fmt.Errorf("migration failed (%s): %w", filename, err)
	}

	if _, err := tx.ExecContext(ctx, "INSERT INTO migrations (filename) VALUES ($1) ON CONFLICT DO NOTHING", filename); err != nil {
		return fmt.Errorf("record migration (%s): %w", filename, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration (%s): %w", filename, err)
	}
	return nil
}

