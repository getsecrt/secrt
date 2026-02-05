package database

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestConnection_Close_NilSafe(t *testing.T) {
	t.Parallel()

	var c *Connection
	if err := c.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}

	c2 := &Connection{}
	if err := c2.Close(); err != nil {
		t.Fatalf("nil db Close: %v", err)
	}
}

func TestConnection_DBAndClose(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("pgx", "postgres://user:pass@127.0.0.1:5432/db?sslmode=disable")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	c := &Connection{db: db}
	if got := c.DB(); got != db {
		t.Fatalf("DB(): expected same pointer")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestOpenPostgres_PingFailure(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	_, err := OpenPostgres(ctx, "postgres://user:pass@127.0.0.1:1/db?sslmode=disable")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "ping postgres") {
		t.Fatalf("expected ping error, got %v", err)
	}
}
