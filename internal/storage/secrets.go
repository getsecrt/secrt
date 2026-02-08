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
	OwnerKey  string
}

// StorageUsage reports current resource consumption for a given owner.
type StorageUsage struct {
	SecretCount int64
	TotalBytes  int64
}

type SecretsStore interface {
	Create(ctx context.Context, s Secret) error
	ClaimAndDelete(ctx context.Context, id string, claimHash string, now time.Time) (Secret, error)
	Burn(ctx context.Context, id string) (bool, error)
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
	GetUsage(ctx context.Context, ownerKey string) (StorageUsage, error)
}
