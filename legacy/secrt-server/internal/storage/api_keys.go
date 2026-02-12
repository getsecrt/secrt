package storage

import (
	"context"
	"time"
)

type APIKey struct {
	ID        int64
	Prefix    string
	Hash      string
	Scopes    string
	CreatedAt time.Time
	RevokedAt *time.Time
}

type APIKeysStore interface {
	GetByPrefix(ctx context.Context, prefix string) (APIKey, error)
	Insert(ctx context.Context, key APIKey) error
	RevokeByPrefix(ctx context.Context, prefix string) (bool, error)
}
