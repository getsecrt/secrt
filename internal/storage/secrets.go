package storage

import (
	"context"
	"encoding/json"
	"time"
)

type Secret struct {
	ID        string
	ClaimHash string
	Envelope  json.RawMessage
	ExpiresAt time.Time
	CreatedAt time.Time
}

type SecretsStore interface {
	Create(ctx context.Context, s Secret) error
	ClaimAndDelete(ctx context.Context, id string, claimHash string, now time.Time) (Secret, error)
	Burn(ctx context.Context, id string) (bool, error)
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

