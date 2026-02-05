package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"secret/internal/storage"
)

const (
	// API keys are formatted as: sk_<prefix>.<secret>
	//
	// We intentionally use '.' as the separator between prefix and secret because
	// the base64url alphabet includes both '-' and '_' characters. Using '_' as a
	// separator would be ambiguous.
	apiKeyPrefix     = "sk_"
	apiKeySeparator  = "."
	apiKeySecretSize = 32
)

var ErrInvalidAPIKey = errors.New("invalid api key")

// ParseAPIKey expects keys in the format: sk_<prefix>.<secret>
// - prefix: short identifier used for lookup/logging (not secret)
// - secret: high-entropy random component
func ParseAPIKey(key string) (prefix string, secret string, err error) {
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, apiKeyPrefix) {
		return "", "", ErrInvalidAPIKey
	}

	rest := strings.TrimPrefix(key, apiKeyPrefix)
	prefix, secret, ok := strings.Cut(rest, apiKeySeparator)
	if !ok {
		return "", "", ErrInvalidAPIKey
	}
	if len(prefix) < 6 {
		return "", "", ErrInvalidAPIKey
	}
	if secret == "" {
		return "", "", ErrInvalidAPIKey
	}
	return prefix, secret, nil
}

// HashAPIKeySecret returns a stable hash suitable for storage, using a server-side pepper.
// We use HMAC-SHA256 to make offline guessing harder if the DB is leaked.
func HashAPIKeySecret(pepper string, prefix string, secret string) (string, error) {
	if pepper == "" {
		return "", errors.New("missing api key pepper")
	}
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte(prefix))
	_, _ = mac.Write([]byte(":"))
	_, _ = mac.Write([]byte(secret))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum), nil
}

type Authenticator struct {
	pepper string
	store  storage.APIKeysStore
}

func NewAuthenticator(pepper string, store storage.APIKeysStore) *Authenticator {
	return &Authenticator{pepper: pepper, store: store}
}

func (a *Authenticator) Authenticate(ctx context.Context, rawKey string) (storage.APIKey, error) {
	prefix, secret, err := ParseAPIKey(rawKey)
	if err != nil {
		return storage.APIKey{}, ErrInvalidAPIKey
	}

	expectedHash, err := HashAPIKeySecret(a.pepper, prefix, secret)
	if err != nil {
		return storage.APIKey{}, err
	}

	keyRecord, err := a.store.GetByPrefix(ctx, prefix)
	if err != nil {
		return storage.APIKey{}, ErrInvalidAPIKey
	}
	if keyRecord.RevokedAt != nil {
		return storage.APIKey{}, ErrInvalidAPIKey
	}

	if !secureEqualsHex(keyRecord.Hash, expectedHash) {
		return storage.APIKey{}, ErrInvalidAPIKey
	}

	return keyRecord, nil
}

// GenerateAPIKey creates a new API key string and its stored hash.
func GenerateAPIKey(pepper string) (apiKey string, prefix string, hash string, err error) {
	prefixBytes := make([]byte, 6)
	if _, err := rand.Read(prefixBytes); err != nil {
		return "", "", "", fmt.Errorf("generate api key prefix: %w", err)
	}
	// base64url without padding; 6 bytes -> 8 chars.
	prefix = base64.RawURLEncoding.EncodeToString(prefixBytes)

	secretBytes := make([]byte, apiKeySecretSize)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", "", fmt.Errorf("generate api key secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)

	apiKey = fmt.Sprintf("%s%s%s%s", apiKeyPrefix, prefix, apiKeySeparator, secret)

	hash, err = HashAPIKeySecret(pepper, prefix, secret)
	if err != nil {
		return "", "", "", err
	}

	return apiKey, prefix, hash, nil
}

func secureEqualsHex(a, b string) bool {
	ab, err1 := hex.DecodeString(a)
	bb, err2 := hex.DecodeString(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return hmac.Equal(ab, bb)
}
