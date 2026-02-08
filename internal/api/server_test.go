package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"secret/internal/auth"
	"secret/internal/config"
	"secret/internal/secrets"
	"secret/internal/storage"
)

type memSecretsStore struct {
	mu      sync.Mutex
	secrets map[string]storage.Secret
}

func newMemSecretsStore() *memSecretsStore {
	return &memSecretsStore{secrets: make(map[string]storage.Secret)}
}

func (m *memSecretsStore) Create(_ context.Context, s storage.Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[s.ID] = s
	return nil
}

func (m *memSecretsStore) GetUsage(_ context.Context, ownerKey string) (storage.StorageUsage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var u storage.StorageUsage
	for _, s := range m.secrets {
		if s.OwnerKey == ownerKey {
			u.SecretCount++
			u.TotalBytes += int64(len(s.Envelope))
		}
	}
	return u, nil
}

func (m *memSecretsStore) ClaimAndDelete(_ context.Context, id string, claimHash string, now time.Time) (storage.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[id]
	if !ok {
		return storage.Secret{}, storage.ErrNotFound
	}
	if s.ClaimHash != claimHash {
		return storage.Secret{}, storage.ErrNotFound
	}
	if !s.ExpiresAt.After(now) {
		delete(m.secrets, id)
		return storage.Secret{}, storage.ErrNotFound
	}
	delete(m.secrets, id)
	return s, nil
}

func (m *memSecretsStore) Burn(_ context.Context, id string, ownerKey string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sec, ok := m.secrets[id]
	if !ok {
		return false, nil
	}
	if sec.OwnerKey != ownerKey {
		return false, nil
	}
	delete(m.secrets, id)
	return true, nil
}

func (m *memSecretsStore) DeleteExpired(_ context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for id, s := range m.secrets {
		if !s.ExpiresAt.After(now) {
			delete(m.secrets, id)
			n++
		}
	}
	return n, nil
}

type memAPIKeyStore struct {
	mu   sync.Mutex
	keys map[string]storage.APIKey
}

func newMemAPIKeyStore() *memAPIKeyStore {
	return &memAPIKeyStore{keys: make(map[string]storage.APIKey)}
}

func (m *memAPIKeyStore) GetByPrefix(_ context.Context, prefix string) (storage.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[prefix]
	if !ok {
		return storage.APIKey{}, storage.ErrNotFound
	}
	return k, nil
}

func (m *memAPIKeyStore) Insert(_ context.Context, key storage.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[key.Prefix] = key
	return nil
}

func (m *memAPIKeyStore) RevokeByPrefix(_ context.Context, prefix string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[prefix]
	if !ok {
		return false, nil
	}
	now := time.Now()
	k.RevokedAt = &now
	m.keys[prefix] = k
	return true, nil
}

func TestPublicCreateAndClaimFlow(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	claimToken, err := randomB64(32)
	if err != nil {
		t.Fatalf("random: %v", err)
	}
	claimHash, err := secrets.HashClaimToken(claimToken)
	if err != nil {
		t.Fatalf("HashClaimToken: %v", err)
	}

	ttl := int64((1 * time.Hour).Seconds())
	createReq := CreateSecretRequest{
		Envelope:   json.RawMessage(`{"ciphertext":"abc"}`),
		ClaimHash:  claimHash,
		TTLSeconds: &ttl,
	}

	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status: got %d body=%s", rec.Code, rec.Body.String())
	}

	var createResp CreateSecretResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if createResp.ID == "" {
		t.Fatalf("expected id")
	}

	claimReq := ClaimSecretRequest{Claim: claimToken}
	claimBody, _ := json.Marshal(claimReq)
	claimPath := "/api/v1/secrets/" + createResp.ID + "/claim"

	claimHTTPReq1 := httptest.NewRequest(http.MethodPost, claimPath, bytes.NewReader(claimBody))
	claimHTTPReq1.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, claimHTTPReq1)
	if rec2.Code != http.StatusOK {
		t.Fatalf("claim status: got %d body=%s", rec2.Code, rec2.Body.String())
	}

	// Second claim should fail (already deleted).
	claimHTTPReq2 := httptest.NewRequest(http.MethodPost, claimPath, bytes.NewReader(claimBody))
	claimHTTPReq2.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec3, claimHTTPReq2)
	if rec3.Code != http.StatusNotFound {
		t.Fatalf("second claim status: got %d body=%s", rec3.Code, rec3.Body.String())
	}
}

func TestAuthedCreateRequiresAPIKey(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	pepper := "pepper"

	apiKey, prefix, hash, err := auth.GenerateAPIKey(pepper)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	_ = keyStore.Insert(context.Background(), storage.APIKey{Prefix: prefix, Hash: hash})

	authn := auth.NewAuthenticator(pepper, keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)

	createReq := CreateSecretRequest{
		Envelope:  json.RawMessage(`{"ciphertext":"abc"}`),
		ClaimHash: claimHash,
	}
	body, _ := json.Marshal(createReq)

	// Missing key should be unauthorized.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
	}

	// With key should succeed.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-API-Key", apiKey)
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", rec2.Code, rec2.Body.String())
	}
}

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
