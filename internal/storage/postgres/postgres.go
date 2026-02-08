package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"secret/internal/storage"
)

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Create(ctx context.Context, sec storage.Secret) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO secrets (id, claim_hash, envelope, expires_at, owner_key)
VALUES ($1, $2, $3::jsonb, $4, $5)`,
		sec.ID,
		sec.ClaimHash,
		string(sec.Envelope),
		sec.ExpiresAt,
		sec.OwnerKey,
	)
	if err != nil {
		return fmt.Errorf("insert secret: %w", err)
	}
	return nil
}

func (s *Store) GetUsage(ctx context.Context, ownerKey string) (storage.StorageUsage, error) {
	var u storage.StorageUsage
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*), COALESCE(SUM(LENGTH(envelope::text)), 0)
FROM secrets
WHERE owner_key = $1
  AND expires_at > now()`,
		ownerKey,
	).Scan(&u.SecretCount, &u.TotalBytes)
	if err != nil {
		return storage.StorageUsage{}, fmt.Errorf("get usage: %w", err)
	}
	return u, nil
}

func (s *Store) ClaimAndDelete(ctx context.Context, id string, claimHash string, now time.Time) (storage.Secret, error) {
	var envelopeBytes []byte
	var expiresAt time.Time
	var createdAt time.Time

	err := s.db.QueryRowContext(ctx, `
DELETE FROM secrets
WHERE id = $1
  AND claim_hash = $2
  AND expires_at > $3
RETURNING envelope, expires_at, created_at`,
		id,
		claimHash,
		now,
	).Scan(&envelopeBytes, &expiresAt, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.Secret{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.Secret{}, fmt.Errorf("claim secret: %w", err)
	}

	// Ensure we return canonical JSON (mainly for safety in case DB driver returns non-JSON).
	var raw json.RawMessage
	if len(envelopeBytes) > 0 {
		raw = json.RawMessage(envelopeBytes)
	}

	return storage.Secret{
		ID:        id,
		ClaimHash: claimHash,
		Envelope:  raw,
		ExpiresAt: expiresAt,
		CreatedAt: createdAt,
	}, nil
}

func (s *Store) Burn(ctx context.Context, id string, ownerKey string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE id=$1 AND owner_key=$2`, id, ownerKey)
	if err != nil {
		return false, fmt.Errorf("burn secret: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("burn secret rows affected: %w", err)
	}
	return n > 0, nil
}

func (s *Store) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, fmt.Errorf("delete expired: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete expired rows affected: %w", err)
	}
	return n, nil
}

func (s *Store) GetByPrefix(ctx context.Context, prefix string) (storage.APIKey, error) {
	var k storage.APIKey
	var revokedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
SELECT id, key_prefix, key_hash, scopes, created_at, revoked_at
FROM api_keys
WHERE key_prefix = $1`,
		prefix,
	).Scan(&k.ID, &k.Prefix, &k.Hash, &k.Scopes, &k.CreatedAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.APIKey{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.APIKey{}, fmt.Errorf("get api key: %w", err)
	}
	if revokedAt.Valid {
		k.RevokedAt = &revokedAt.Time
	}
	return k, nil
}

func (s *Store) Insert(ctx context.Context, key storage.APIKey) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO api_keys (key_prefix, key_hash, scopes, revoked_at)
VALUES ($1, $2, $3, $4)`,
		key.Prefix,
		key.Hash,
		key.Scopes,
		key.RevokedAt,
	)
	if err != nil {
		return fmt.Errorf("insert api key: %w", err)
	}
	return nil
}

func (s *Store) RevokeByPrefix(ctx context.Context, prefix string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE api_keys
SET revoked_at = now()
WHERE key_prefix = $1
  AND revoked_at IS NULL`, prefix)
	if err != nil {
		return false, fmt.Errorf("revoke api key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("revoke api key rows affected: %w", err)
	}
	return n > 0, nil
}
