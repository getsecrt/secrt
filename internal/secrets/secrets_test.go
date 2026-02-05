package secrets

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGenerateID(t *testing.T) {
	t.Parallel()

	id, err := GenerateID()
	if err != nil {
		t.Fatalf("GenerateID: %v", err)
	}
	if id == "" {
		t.Fatalf("expected id")
	}

	b, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		t.Fatalf("expected base64url: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b))
	}
}

func TestNormalizePublicTTL(t *testing.T) {
	t.Parallel()

	got, err := NormalizePublicTTL(nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != DefaultTTL {
		t.Fatalf("expected %v, got %v", DefaultTTL, got)
	}

	ttl := int64((48 * time.Hour).Seconds())
	got, err = NormalizePublicTTL(&ttl)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != 48*time.Hour {
		t.Fatalf("expected %v, got %v", 48*time.Hour, got)
	}

	bad := int64((2 * time.Hour).Seconds())
	if _, err := NormalizePublicTTL(&bad); err == nil {
		t.Fatalf("expected error for invalid ttl")
	}

	zero := int64(0)
	if _, err := NormalizePublicTTL(&zero); err == nil {
		t.Fatalf("expected error for zero ttl")
	}
}

func TestNormalizeAuthedTTL(t *testing.T) {
	t.Parallel()

	got, err := NormalizeAuthedTTL(nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != DefaultTTL {
		t.Fatalf("expected %v, got %v", DefaultTTL, got)
	}

	short := int64((1 * time.Minute).Seconds())
	if _, err := NormalizeAuthedTTL(&short); err == nil {
		t.Fatalf("expected error for short ttl")
	}

	long := int64((60 * 24 * time.Hour).Seconds())
	if _, err := NormalizeAuthedTTL(&long); err == nil {
		t.Fatalf("expected error for long ttl")
	}

	neg := int64(-1)
	if _, err := NormalizeAuthedTTL(&neg); err == nil {
		t.Fatalf("expected error for negative ttl")
	}

	min := int64(MinTTL.Seconds())
	if got, err := NormalizeAuthedTTL(&min); err != nil || got != MinTTL {
		t.Fatalf("expected MinTTL ok, got %v err=%v", got, err)
	}

	max := int64(MaxTTLAuthed.Seconds())
	if got, err := NormalizeAuthedTTL(&max); err != nil || got != MaxTTLAuthed {
		t.Fatalf("expected MaxTTLAuthed ok, got %v err=%v", got, err)
	}
}

func TestValidateEnvelope(t *testing.T) {
	t.Parallel()

	if err := ValidateEnvelope(nil); err == nil {
		t.Fatalf("expected error for nil envelope")
	}
	if err := ValidateEnvelope([]byte("not-json")); err == nil {
		t.Fatalf("expected error for invalid json")
	}
	if err := ValidateEnvelope([]byte("[]")); err == nil {
		t.Fatalf("expected error for non-object json")
	}
	if err := ValidateEnvelope([]byte(`{"a":1}`)); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	// Valid JSON object but too large should be rejected.
	oversize := map[string]string{"x": strings.Repeat("y", MaxEnvelopeBytes)}
	raw, _ := json.Marshal(oversize)
	if err := ValidateEnvelope(raw); err == nil {
		t.Fatalf("expected error for oversize envelope")
	}
}

func TestHashClaimToken(t *testing.T) {
	t.Parallel()

	claimBytes := make([]byte, 32)
	if _, err := rand.Read(claimBytes); err != nil {
		t.Fatalf("rand: %v", err)
	}
	claim := base64.RawURLEncoding.EncodeToString(claimBytes)

	got, err := HashClaimToken(claim)
	if err != nil {
		t.Fatalf("HashClaimToken error: %v", err)
	}

	sum := sha256.Sum256(claimBytes)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("hash mismatch: got %q want %q", got, want)
	}

	if _, err := HashClaimToken("not*b64"); err == nil {
		t.Fatalf("expected error for invalid b64")
	}

	short := base64.RawURLEncoding.EncodeToString([]byte("short"))
	if _, err := HashClaimToken(short); err == nil {
		t.Fatalf("expected error for short claim")
	}
}

func TestValidateClaimHash(t *testing.T) {
	t.Parallel()

	if err := ValidateClaimHash(""); err == nil {
		t.Fatalf("expected error for empty")
	}
	if err := ValidateClaimHash("not*b64"); err == nil {
		t.Fatalf("expected error for invalid b64")
	}

	claimBytes := make([]byte, 32)
	if _, err := rand.Read(claimBytes); err != nil {
		t.Fatalf("rand: %v", err)
	}
	sum := sha256.Sum256(claimBytes)
	claimHash := base64.RawURLEncoding.EncodeToString(sum[:])
	if err := ValidateClaimHash(claimHash); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	shortHash := base64.RawURLEncoding.EncodeToString([]byte("tiny"))
	if err := ValidateClaimHash(shortHash); err == nil {
		t.Fatalf("expected error for short hash")
	}
}
