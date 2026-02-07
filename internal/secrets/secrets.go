package secrets

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// DefaultTTL is applied when ttl_seconds is omitted from create requests.
	DefaultTTL = 24 * time.Hour
	// MaxTTL is the longest allowed secret lifetime (1 year).
	MaxTTL = 365 * 24 * time.Hour
	// MaxTTLSeconds mirrors MaxTTL in seconds for input validation.
	MaxTTLSeconds = int64(MaxTTL / time.Second)

	// MaxEnvelopeBytes limits how large the ciphertext envelope can be.
	// This is a safety valve to reduce DoS risk.
	MaxEnvelopeBytes = 64 * 1024
)

var (
	ErrInvalidTTL      = errors.New("invalid ttl")
	ErrInvalidEnvelope = errors.New("invalid envelope")
)

// GenerateID returns a high-entropy, URL-safe identifier for a secret.
// The ID is not a decryption key; it exists to locate a stored envelope.
func GenerateID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// NormalizePublicTTL enforces API TTL bounds for anonymous/public secret creation.
func NormalizePublicTTL(ttlSeconds *int64) (time.Duration, error) {
	return normalizeTTL(ttlSeconds)
}

// NormalizeAuthedTTL enforces API TTL bounds for authenticated callers.
func NormalizeAuthedTTL(ttlSeconds *int64) (time.Duration, error) {
	return normalizeTTL(ttlSeconds)
}

func normalizeTTL(ttlSeconds *int64) (time.Duration, error) {
	if ttlSeconds == nil {
		return DefaultTTL, nil
	}
	if *ttlSeconds <= 0 {
		return 0, ErrInvalidTTL
	}
	if *ttlSeconds > MaxTTLSeconds {
		return 0, ErrInvalidTTL
	}
	d := time.Duration(*ttlSeconds) * time.Second
	// Defensive overflow guard.
	if d <= 0 || d > MaxTTL {
		return 0, ErrInvalidTTL
	}
	return d, nil
}

// ValidateEnvelope performs lightweight validation on the stored ciphertext envelope.
// The service treats the envelope as opaque, but it must be valid JSON.
func ValidateEnvelope(raw json.RawMessage) error {
	if len(raw) == 0 {
		return ErrInvalidEnvelope
	}
	if len(raw) > MaxEnvelopeBytes {
		return ErrInvalidEnvelope
	}
	if !json.Valid(raw) {
		return ErrInvalidEnvelope
	}
	// Enforce "object" envelopes to keep API shape predictable.
	if raw[0] != '{' {
		return ErrInvalidEnvelope
	}
	return nil
}

// HashClaimToken returns base64url(sha256(claim_bytes)).
func HashClaimToken(claimTokenB64 string) (string, error) {
	claimBytes, err := base64.RawURLEncoding.DecodeString(claimTokenB64)
	if err != nil {
		return "", fmt.Errorf("decode claim token: %w", err)
	}
	if len(claimBytes) < 16 {
		// Avoid accepting trivially guessable tokens.
		return "", errors.New("claim token too short")
	}
	sum := sha256.Sum256(claimBytes)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ValidateClaimHash ensures the claim hash is well-formed (sha256 output, base64url).
func ValidateClaimHash(claimHash string) error {
	claimHash = strings.TrimSpace(claimHash)
	if claimHash == "" {
		return errors.New("empty claim hash")
	}
	b, err := base64.RawURLEncoding.DecodeString(claimHash)
	if err != nil {
		return errors.New("invalid claim hash")
	}
	if len(b) != sha256.Size {
		return errors.New("invalid claim hash")
	}
	return nil
}
