package secrets

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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

	ttl := int64((2 * time.Hour).Seconds())
	got, err = NormalizePublicTTL(&ttl)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != 2*time.Hour {
		t.Fatalf("expected %v, got %v", 2*time.Hour, got)
	}

	max := int64(MaxTTL.Seconds())
	if got, err := NormalizePublicTTL(&max); err != nil || got != MaxTTL {
		t.Fatalf("expected MaxTTL ok, got %v err=%v", got, err)
	}

	zero := int64(0)
	if _, err := NormalizePublicTTL(&zero); err == nil {
		t.Fatalf("expected error for zero ttl")
	}

	over := MaxTTLSeconds + 1
	if _, err := NormalizePublicTTL(&over); err == nil {
		t.Fatalf("expected error for ttl over max")
	}

	neg := int64(-1)
	if _, err := NormalizePublicTTL(&neg); err == nil {
		t.Fatalf("expected error for negative ttl")
	}
}

func TestTTLV1SpecValues(t *testing.T) {
	t.Parallel()

	if DefaultTTL != 24*time.Hour {
		t.Fatalf("DefaultTTL must match spec v1: got %v want %v", DefaultTTL, 24*time.Hour)
	}
	if MaxTTL != 365*24*time.Hour {
		t.Fatalf("MaxTTL must match spec v1: got %v want %v", MaxTTL, 365*24*time.Hour)
	}
	if MaxTTLSeconds != 31536000 {
		t.Fatalf("MaxTTLSeconds must match spec v1: got %d want %d", MaxTTLSeconds, 31536000)
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

	oneSecond := int64(1)
	if got, err := NormalizeAuthedTTL(&oneSecond); err != nil || got != 1*time.Second {
		t.Fatalf("expected 1s ttl ok, got %v err=%v", got, err)
	}

	long := MaxTTLSeconds + 1
	if _, err := NormalizeAuthedTTL(&long); err == nil {
		t.Fatalf("expected error for long ttl")
	}

	neg := int64(-1)
	if _, err := NormalizeAuthedTTL(&neg); err == nil {
		t.Fatalf("expected error for negative ttl")
	}

	max := int64(MaxTTL.Seconds())
	if got, err := NormalizeAuthedTTL(&max); err != nil || got != MaxTTL {
		t.Fatalf("expected MaxTTL ok, got %v err=%v", got, err)
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

type failReader struct{ err error }

func (f *failReader) Read([]byte) (int, error) { return 0, f.err }

func TestGenerateID_RandReadError(t *testing.T) {
	// Not parallel: mutates package-level randReader.
	old := randReader
	randReader = &failReader{err: errors.New("entropy exhausted")}
	defer func() { randReader = old }()

	_, err := GenerateID()
	if err == nil {
		t.Fatal("expected error when rand reader fails")
	}
	if !strings.Contains(err.Error(), "generate id") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNormalizeTTLWithMax_OverflowGuard(t *testing.T) {
	t.Parallel()

	// Use a maxSeconds large enough to pass the range check but whose
	// time.Duration conversion overflows (wraps negative).
	hugeSeconds := int64(1<<62) / int64(time.Second)
	hugeDuration := time.Duration(hugeSeconds+1) * time.Second

	// Ensure the setup actually causes overflow (sanity check).
	if hugeDuration > 0 {
		t.Skip("no overflow on this platform")
	}

	ttl := hugeSeconds
	_, err := normalizeTTLWithMax(&ttl, hugeSeconds, MaxTTL)
	if err == nil {
		t.Fatal("expected error for overflow")
	}
}

func TestValidateEnvelope_BoundarySize(t *testing.T) {
	t.Parallel()

	// Exactly MaxEnvelopeBytes should pass.
	pad := MaxEnvelopeBytes - len(`{"x":""}`)
	exact := `{"x":"` + strings.Repeat("a", pad) + `"}`
	if len(exact) != MaxEnvelopeBytes {
		t.Fatalf("setup: len=%d want %d", len(exact), MaxEnvelopeBytes)
	}
	if err := ValidateEnvelope(json.RawMessage(exact)); err != nil {
		t.Fatalf("exactly max should pass: %v", err)
	}

	// MaxEnvelopeBytes + 1 should fail.
	over := `{"x":"` + strings.Repeat("a", pad+1) + `"}`
	if err := ValidateEnvelope(json.RawMessage(over)); err == nil {
		t.Fatal("expected error for max+1")
	}
}
