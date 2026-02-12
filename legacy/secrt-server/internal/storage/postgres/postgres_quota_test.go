package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"secrt/internal/storage"
)

func TestStore_GetUsage_EmptyOwner(t *testing.T) {
	baseURL := testDatabaseURL(t)
	baseConn := openPostgresOrSkip(t, baseURL)

	schema := createTestSchema(t, baseConn.DB())
	schemaURL := withSearchPath(baseURL, schema)

	conn := openPostgresOrSkip(t, schemaURL)
	migrateOrFatal(t, conn)

	store := New(conn.DB())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	usage, err := store.GetUsage(ctx, "unknown-owner")
	if err != nil {
		t.Fatalf("GetUsage: %v", err)
	}
	if usage.SecretCount != 0 {
		t.Fatalf("expected 0 secrets, got %d", usage.SecretCount)
	}
	if usage.TotalBytes != 0 {
		t.Fatalf("expected 0 bytes, got %d", usage.TotalBytes)
	}
}

func TestStore_GetUsage_ExcludesExpired(t *testing.T) {
	baseURL := testDatabaseURL(t)
	baseConn := openPostgresOrSkip(t, baseURL)

	schema := createTestSchema(t, baseConn.DB())
	schemaURL := withSearchPath(baseURL, schema)

	conn := openPostgresOrSkip(t, schemaURL)
	migrateOrFatal(t, conn)

	store := New(conn.DB())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	owner := "test-owner-expired"

	// Active secret.
	if err := store.Create(ctx, storage.Secret{
		ID:        "active1",
		ClaimHash: "ch1",
		Envelope:  json.RawMessage(`{"ct":"data"}`),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		OwnerKey:  owner,
	}); err != nil {
		t.Fatalf("Create active: %v", err)
	}

	// Expired secret.
	if err := store.Create(ctx, storage.Secret{
		ID:        "expired1",
		ClaimHash: "ch2",
		Envelope:  json.RawMessage(`{"ct":"old"}`),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		OwnerKey:  owner,
	}); err != nil {
		t.Fatalf("Create expired: %v", err)
	}

	usage, err := store.GetUsage(ctx, owner)
	if err != nil {
		t.Fatalf("GetUsage: %v", err)
	}
	if usage.SecretCount != 1 {
		t.Fatalf("expected 1 active secret, got %d", usage.SecretCount)
	}
}

func TestStore_GetUsage_SumsBytes(t *testing.T) {
	baseURL := testDatabaseURL(t)
	baseConn := openPostgresOrSkip(t, baseURL)

	schema := createTestSchema(t, baseConn.DB())
	schemaURL := withSearchPath(baseURL, schema)

	conn := openPostgresOrSkip(t, schemaURL)
	migrateOrFatal(t, conn)

	store := New(conn.DB())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	owner := "test-owner-bytes"
	env1 := json.RawMessage(`{"ct":"hello"}`)
	env2 := json.RawMessage(`{"ct":"world!!"}`)

	if err := store.Create(ctx, storage.Secret{
		ID:        "bytes1",
		ClaimHash: "ch1",
		Envelope:  env1,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		OwnerKey:  owner,
	}); err != nil {
		t.Fatalf("Create 1: %v", err)
	}
	if err := store.Create(ctx, storage.Secret{
		ID:        "bytes2",
		ClaimHash: "ch2",
		Envelope:  env2,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		OwnerKey:  owner,
	}); err != nil {
		t.Fatalf("Create 2: %v", err)
	}

	usage, err := store.GetUsage(ctx, owner)
	if err != nil {
		t.Fatalf("GetUsage: %v", err)
	}
	if usage.SecretCount != 2 {
		t.Fatalf("expected 2 secrets, got %d", usage.SecretCount)
	}
	if usage.TotalBytes <= 0 {
		t.Fatalf("expected positive total bytes, got %d", usage.TotalBytes)
	}
}

func TestStore_GetUsage_SeparateOwners(t *testing.T) {
	baseURL := testDatabaseURL(t)
	baseConn := openPostgresOrSkip(t, baseURL)

	schema := createTestSchema(t, baseConn.DB())
	schemaURL := withSearchPath(baseURL, schema)

	conn := openPostgresOrSkip(t, schemaURL)
	migrateOrFatal(t, conn)

	store := New(conn.DB())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ownerA := "owner-a"
	ownerB := "owner-b"

	// 3 secrets for owner A.
	for i := 0; i < 3; i++ {
		if err := store.Create(ctx, storage.Secret{
			ID:        "a-" + string(rune('0'+i)),
			ClaimHash: "ch-a-" + string(rune('0'+i)),
			Envelope:  json.RawMessage(`{"ct":"a"}`),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			OwnerKey:  ownerA,
		}); err != nil {
			t.Fatalf("Create A-%d: %v", i, err)
		}
	}

	// 1 secret for owner B.
	if err := store.Create(ctx, storage.Secret{
		ID:        "b-0",
		ClaimHash: "ch-b-0",
		Envelope:  json.RawMessage(`{"ct":"b"}`),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		OwnerKey:  ownerB,
	}); err != nil {
		t.Fatalf("Create B: %v", err)
	}

	usageA, err := store.GetUsage(ctx, ownerA)
	if err != nil {
		t.Fatalf("GetUsage A: %v", err)
	}
	if usageA.SecretCount != 3 {
		t.Fatalf("owner A: expected 3, got %d", usageA.SecretCount)
	}

	usageB, err := store.GetUsage(ctx, ownerB)
	if err != nil {
		t.Fatalf("GetUsage B: %v", err)
	}
	if usageB.SecretCount != 1 {
		t.Fatalf("owner B: expected 1, got %d", usageB.SecretCount)
	}
}
