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

// PublicTTLChoices are the allowed TTLs for anonymous/public secret creation.
// Keeping this set small reduces abuse and keeps UX simple.
var PublicTTLChoices = []time.Duration{
	10 * time.Minute,
	1 * time.Hour,
	8 * time.Hour,
	24 * time.Hour,
	48 * time.Hour,
	7 * 24 * time.Hour,
	30 * 24 * time.Hour,
}

const (
	DefaultTTL      = 48 * time.Hour
	MinTTL          = 10 * time.Minute
	MaxTTLAuthed    = 30 * 24 * time.Hour
	MaxTTLAnonymous = 30 * 24 * time.Hour

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

// NormalizePublicTTL enforces the allowlist for anonymous/public secret creation.
func NormalizePublicTTL(ttlSeconds *int64) (time.Duration, error) {
	if ttlSeconds == nil {
		return DefaultTTL, nil
	}
	if *ttlSeconds <= 0 {
		return 0, ErrInvalidTTL
	}
	d := time.Duration(*ttlSeconds) * time.Second
	for _, allowed := range PublicTTLChoices {
		if d == allowed {
			return d, nil
		}
	}
	return 0, ErrInvalidTTL
}

// NormalizeAuthedTTL enforces min/max bounds for API-key authenticated callers.
func NormalizeAuthedTTL(ttlSeconds *int64) (time.Duration, error) {
	if ttlSeconds == nil {
		return DefaultTTL, nil
	}
	if *ttlSeconds <= 0 {
		return 0, ErrInvalidTTL
	}
	d := time.Duration(*ttlSeconds) * time.Second
	if d < MinTTL || d > MaxTTLAuthed {
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
