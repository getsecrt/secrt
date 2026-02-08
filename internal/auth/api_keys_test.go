package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"secret/internal/storage"
)

type countingReader struct {
	callCount int
	failAt    int
	err       error
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.callCount++
	if c.callCount == c.failAt {
		return 0, c.err
	}
	for i := range p {
		p[i] = byte(c.callCount)
	}
	return len(p), nil
}

type fakeAPIKeyStore struct {
	key storage.APIKey
	err error
}

func (f fakeAPIKeyStore) GetByPrefix(_ context.Context, prefix string) (storage.APIKey, error) {
	if f.err != nil {
		return storage.APIKey{}, f.err
	}
	if prefix != f.key.Prefix {
		return storage.APIKey{}, storage.ErrNotFound
	}
	return f.key, nil
}

func (f fakeAPIKeyStore) Insert(_ context.Context, _ storage.APIKey) error { return nil }
func (f fakeAPIKeyStore) RevokeByPrefix(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func TestParseAPIKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		key    string
		ok     bool
		prefix string
		secret string
	}{
		{name: "missing prefix", key: "bad", ok: false},
		{name: "missing separator", key: "sk_abcdefg", ok: false},
		{name: "short prefix", key: "sk_abc.de", ok: false},
		{name: "empty secret", key: "sk_abcdef.", ok: false},
		{name: "trim spaces", key: "  sk_abcdefgh.secret  ", ok: true, prefix: "abcdefgh", secret: "secret"},
		{name: "ok", key: "sk_abcdefgh.secret", ok: true, prefix: "abcdefgh", secret: "secret"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prefix, secret, err := ParseAPIKey(tt.key)
			if tt.ok && err != nil {
				t.Fatalf("expected ok, got err=%v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected error")
			}
			if tt.ok {
				if prefix != tt.prefix || secret != tt.secret {
					t.Fatalf("unexpected parse result: %q %q", prefix, secret)
				}
			}
		})
	}
}

func TestHashAPIKeySecret(t *testing.T) {
	t.Parallel()

	if _, err := HashAPIKeySecret("", "pfx", "sec"); err == nil {
		t.Fatalf("expected error for missing pepper")
	}

	h1, err := HashAPIKeySecret("pepper", "pfx", "sec")
	if err != nil {
		t.Fatalf("HashAPIKeySecret: %v", err)
	}
	h2, err := HashAPIKeySecret("pepper", "pfx", "sec")
	if err != nil {
		t.Fatalf("HashAPIKeySecret: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("expected stable hash")
	}
	if len(h1) != 64 { // sha256 hex
		t.Fatalf("expected 64 hex chars, got %d", len(h1))
	}
	if strings.Contains(h1, ".") {
		t.Fatalf("expected hex, got %q", h1)
	}
}

func TestGenerateAndAuthenticateAPIKey(t *testing.T) {
	t.Parallel()

	pepper := "test-pepper"
	apiKey, prefix, hash, err := GenerateAPIKey(pepper)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	store := fakeAPIKeyStore{
		key: storage.APIKey{
			ID:        1,
			Prefix:    prefix,
			Hash:      hash,
			Scopes:    "",
			CreatedAt: time.Now(),
			RevokedAt: nil,
		},
	}

	a := NewAuthenticator(pepper, store)
	if _, err := a.Authenticate(context.Background(), apiKey); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// Wrong key should fail.
	if _, err := a.Authenticate(context.Background(), apiKey+"x"); err == nil {
		t.Fatalf("expected error for wrong key")
	}
}

func TestAuthenticate_ErrorCases(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tests := []struct {
		name   string
		pepper string
		raw    string
		store  fakeAPIKeyStore
		want   error
	}{
		{
			name:   "invalid format",
			pepper: "pepper",
			raw:    "nope",
			store:  fakeAPIKeyStore{},
			want:   ErrInvalidAPIKey,
		},
		{
			name:   "missing pepper",
			pepper: "",
			raw:    "sk_abcdefgh.secret",
			store:  fakeAPIKeyStore{},
			want:   errors.New("missing api key pepper"),
		},
		{
			name:   "store error",
			pepper: "pepper",
			raw:    "sk_abcdefgh.secret",
			store:  fakeAPIKeyStore{err: errors.New("boom")},
			want:   ErrInvalidAPIKey,
		},
		{
			name:   "revoked",
			pepper: "pepper",
			raw:    "sk_abcdefgh.secret",
			store: fakeAPIKeyStore{key: storage.APIKey{
				Prefix:    "abcdefgh",
				Hash:      "00",
				CreatedAt: now,
				RevokedAt: &now,
			}},
			want: ErrInvalidAPIKey,
		},
		{
			name:   "hash mismatch",
			pepper: "pepper",
			raw:    "sk_abcdefgh.secret",
			store: fakeAPIKeyStore{key: storage.APIKey{
				Prefix:    "abcdefgh",
				Hash:      "00", // valid hex but wrong length => secureEqualsHex returns false
				CreatedAt: now,
			}},
			want: ErrInvalidAPIKey,
		},
		{
			name:   "stored hash not hex",
			pepper: "pepper",
			raw:    "sk_abcdefgh.secret",
			store: fakeAPIKeyStore{key: storage.APIKey{
				Prefix:    "abcdefgh",
				Hash:      "not-hex",
				CreatedAt: now,
			}},
			want: ErrInvalidAPIKey,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := NewAuthenticator(tt.pepper, tt.store)
			_, err := a.Authenticate(context.Background(), tt.raw)

			if tt.want == ErrInvalidAPIKey {
				if err == nil || !errors.Is(err, ErrInvalidAPIKey) {
					t.Fatalf("expected ErrInvalidAPIKey, got %v", err)
				}
				return
			}
			if tt.want != nil {
				if err == nil || err.Error() != tt.want.Error() {
					t.Fatalf("expected %v, got %v", tt.want, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected nil, got %v", err)
			}
		})
	}
}

func TestSecureEqualsHex(t *testing.T) {
	t.Parallel()

	if secureEqualsHex("zz", "00") {
		t.Fatalf("expected false for invalid hex")
	}
	if secureEqualsHex("00", "zz") {
		t.Fatalf("expected false for invalid hex")
	}
	if !secureEqualsHex("00", "00") {
		t.Fatalf("expected true for equal bytes")
	}
	if secureEqualsHex("00", "01") {
		t.Fatalf("expected false for different bytes")
	}
}

func TestGenerateAPIKey_FirstRandReadError(t *testing.T) {
	// Not parallel: mutates package-level randReader.
	old := randReader
	randReader = &countingReader{failAt: 1, err: errors.New("no entropy")}
	defer func() { randReader = old }()

	_, _, _, err := GenerateAPIKey("pepper")
	if err == nil {
		t.Fatal("expected error on first rand.Read")
	}
	if !strings.Contains(err.Error(), "prefix") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenerateAPIKey_SecondRandReadError(t *testing.T) {
	// Not parallel: mutates package-level randReader.
	old := randReader
	randReader = &countingReader{failAt: 2, err: errors.New("no entropy")}
	defer func() { randReader = old }()

	_, _, _, err := GenerateAPIKey("pepper")
	if err == nil {
		t.Fatal("expected error on second rand.Read")
	}
	if !strings.Contains(err.Error(), "secret") {
		t.Fatalf("unexpected error: %v", err)
	}
}
