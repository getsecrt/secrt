package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Connection struct {
	db *sql.DB
}

func OpenPostgres(ctx context.Context, databaseURL string) (*Connection, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return &Connection{db: db}, nil
}

func (c *Connection) DB() *sql.DB {
	return c.db
}

func (c *Connection) Close() error {
	if c == nil || c.db == nil {
		return nil
	}
	return c.db.Close()
}
