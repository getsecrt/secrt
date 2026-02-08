package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"secrt/internal/auth"
	"secrt/internal/config"
	"secrt/internal/ratelimit"
	"secrt/internal/secrets"
	"secrt/internal/storage"
)

func decodeErrorResponse(t *testing.T, body string) string {
	t.Helper()
	var resp errorResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode error response: %v body=%s", err, body)
	}
	return resp.Error
}

func TestHealthz(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ok, _ := m["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got %#v", m["ok"])
	}
	if _, ok := m["time"].(string); !ok {
		t.Fatalf("expected time string, got %#v", m["time"])
	}
}

func TestCreateSecret_ValidationAndRateLimit(t *testing.T) {
	t.Run("method not allowed", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/public/secrets", nil)
		req.Header.Set("Content-Type", "application/json")

		srv.handleCreateSecret(rec, req, false, "test")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
		}
		if msg := decodeErrorResponse(t, rec.Body.String()); msg != "method not allowed" {
			t.Fatalf("error: got %q", msg)
		}
	})

	t.Run("bad content-type", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "text/plain")

		srv.handleCreateSecret(rec, req, false, "test")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
		}
		if msg := decodeErrorResponse(t, rec.Body.String()); msg != "content-type must be application/json" {
			t.Fatalf("error: got %q", msg)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")

		srv.handleCreateSecret(rec, req, false, "test")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
		}
		if msg := decodeErrorResponse(t, rec.Body.String()); msg != "invalid json" {
			t.Fatalf("error: got %q", msg)
		}
	})

	t.Run("extra json tokens", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		claimToken, _ := randomB64(32)
		claimHash, _ := secrets.HashClaimToken(claimToken)

		body := `{"envelope":{"ciphertext":"abc"},"claim_hash":"` + claimHash + `"}{"x":1}`
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		srv.handleCreateSecret(rec, req, false, "test")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
		}
		if msg := decodeErrorResponse(t, rec.Body.String()); msg != "invalid json" {
			t.Fatalf("error: got %q", msg)
		}
	})

	t.Run("invalid envelope", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		claimToken, _ := randomB64(32)
		claimHash, _ := secrets.HashClaimToken(claimToken)

		body := `{"envelope":[],"claim_hash":"` + claimHash + `"}`
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		srv.handleCreateSecret(rec, req, false, "test")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
		}
		if msg := decodeErrorResponse(t, rec.Body.String()); msg != "invalid envelope" {
			t.Fatalf("error: got %q", msg)
		}
	})

	t.Run("invalid claim hash", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		body := `{"envelope":{"ciphertext":"abc"},"claim_hash":"bad"}`
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		srv.handleCreateSecret(rec, req, false, "test")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
		}
		if msg := decodeErrorResponse(t, rec.Body.String()); msg != "invalid claim_hash" {
			t.Fatalf("error: got %q", msg)
		}
	})

	t.Run("invalid ttl", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		claimToken, _ := randomB64(32)
		claimHash, _ := secrets.HashClaimToken(claimToken)
		ttl := int64((366 * 24 * time.Hour).Seconds())

		reqBody, _ := json.Marshal(CreateSecretRequest{
			Envelope:   json.RawMessage(`{"ciphertext":"abc"}`),
			ClaimHash:  claimHash,
			TTLSeconds: &ttl,
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")

		srv.handleCreateSecret(rec, req, false, "test")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
		}
		if msg := decodeErrorResponse(t, rec.Body.String()); msg != "invalid ttl_seconds" {
			t.Fatalf("error: got %q", msg)
		}
	})

	t.Run("rate limited", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		claimToken, _ := randomB64(32)
		claimHash, _ := secrets.HashClaimToken(claimToken)
		reqBody, _ := json.Marshal(CreateSecretRequest{
			Envelope:  json.RawMessage(`{"ciphertext":"abc"}`),
			ClaimHash: claimHash,
		})

		for i := 0; i < 6; i++ {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "203.0.113.10:1234"

			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusCreated {
				t.Fatalf("req %d: expected 201, got %d body=%s", i, rec.Code, rec.Body.String())
			}
		}

		// 7th request should exceed burst (6).
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.10:1234"

		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429, got %d body=%s", rec.Code, rec.Body.String())
		}

		if ra := rec.Header().Get("Retry-After"); ra != "10" {
			t.Fatalf("expected Retry-After: 10, got %q", ra)
		}

		msg := decodeErrorResponse(t, rec.Body.String())
		if msg != "rate limit exceeded; please try again in a few seconds" {
			t.Fatalf("unexpected error message: %q", msg)
		}
	})
}

type errSecretsStore struct{ err error }

func (e errSecretsStore) Create(context.Context, storage.Secret) error { return e.err }
func (e errSecretsStore) ClaimAndDelete(context.Context, string, string, time.Time) (storage.Secret, error) {
	return storage.Secret{}, e.err
}
func (e errSecretsStore) Burn(context.Context, string, string) (bool, error) {
	return false, e.err
}
func (e errSecretsStore) DeleteExpired(context.Context, time.Time) (int64, error) {
	return 0, e.err
}
func (e errSecretsStore) GetUsage(context.Context, string) (storage.StorageUsage, error) {
	return storage.StorageUsage{}, e.err
}

func TestCreateSecret_InternalErrors(t *testing.T) {
	t.Parallel()

	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, errSecretsStore{err: context.DeadlineExceeded}, authn)

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)
	reqBody, _ := json.Marshal(CreateSecretRequest{
		Envelope:  json.RawMessage(`{"ciphertext":"abc"}`),
		ClaimHash: claimHash,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	srv.handleCreateSecret(rec, req, false, "test")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateSecret_IDGenerationError(t *testing.T) {
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	secStore := newMemSecretsStore()
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)
	srv.generateID = func() (string, error) { return "", errors.New("boom") }

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)
	reqBody, _ := json.Marshal(CreateSecretRequest{
		Envelope:  json.RawMessage(`{"ciphertext":"abc"}`),
		ClaimHash: claimHash,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	srv.handleCreateSecret(rec, req, false, "test")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestClaimSecret_ValidationAndRateLimit(t *testing.T) {
	t.Run("bad content-type", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/id/claim", bytes.NewBufferString(`{}`))
		req.SetPathValue("id", "id")
		req.Header.Set("Content-Type", "text/plain")

		srv.handleClaimSecret(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
		}
		if msg := decodeErrorResponse(t, rec.Body.String()); msg != "content-type must be application/json" {
			t.Fatalf("error: got %q", msg)
		}
	})

	t.Run("invalid claim treated as not found", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/id/claim", bytes.NewBufferString(`{"claim":"not*b64"}`))
		req.SetPathValue("id", "id")
		req.Header.Set("Content-Type", "application/json")

		srv.handleClaimSecret(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("claim required", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/id/claim", bytes.NewBufferString(`{"claim":"  "}`))
		req.SetPathValue("id", "id")
		req.Header.Set("Content-Type", "application/json")

		srv.handleClaimSecret(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
		}
		if msg := decodeErrorResponse(t, rec.Body.String()); msg != "claim is required" {
			t.Fatalf("error: got %q", msg)
		}
	})

	t.Run("rate limited", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		// Ensure claim token is valid base64url and long enough: 16 bytes -> 22 chars.
		claimToken, _ := randomB64(16)
		reqBody, _ := json.Marshal(ClaimSecretRequest{Claim: claimToken})

		for i := 0; i < 10; i++ {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/id/claim", bytes.NewReader(reqBody))
			req.SetPathValue("id", "id")
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "203.0.113.20:5555"

			srv.handleClaimSecret(rec, req)
			// Secret does not exist; we expect 404, not 429.
			if rec.Code != http.StatusNotFound {
				t.Fatalf("req %d: expected 404, got %d body=%s", i, rec.Code, rec.Body.String())
			}
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/id/claim", bytes.NewReader(reqBody))
		req.SetPathValue("id", "id")
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.20:5555"

		srv.handleClaimSecret(rec, req)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429, got %d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestBurnSecret(t *testing.T) {
	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	pepper := "pepper"

	apiKey, prefix, hash, err := auth.GenerateAPIKey(pepper)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	_ = keyStore.Insert(context.Background(), storage.APIKey{Prefix: prefix, Hash: hash})

	otherAPIKey, otherPrefix, otherHash, err := auth.GenerateAPIKey(pepper)
	if err != nil {
		t.Fatalf("GenerateAPIKey(other): %v", err)
	}
	_ = keyStore.Insert(context.Background(), storage.APIKey{Prefix: otherPrefix, Hash: otherHash})

	authn := auth.NewAuthenticator(pepper, keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	// Seed a secret so burn can delete it.
	secStore.secrets["id1"] = storage.Secret{
		ID:        "id1",
		ClaimHash: "x",
		Envelope:  json.RawMessage(`{"c":"x"}`),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		OwnerKey:  "apikey:" + prefix,
	}

	t.Run("unauthorized", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/id1/burn", nil)
		req.SetPathValue("id", "id1")
		srv.handleBurnAuthedSecret(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("burn ok then not found", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/id1/burn", nil)
		req.SetPathValue("id", "id1")
		req.Header.Set("Authorization", "Bearer "+apiKey)
		srv.handleBurnAuthedSecret(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
		}

		// Second burn should 404.
		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/id1/burn", nil)
		req2.SetPathValue("id", "id1")
		req2.Header.Set("X-API-Key", apiKey)
		srv.handleBurnAuthedSecret(rec2, req2)
		if rec2.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d body=%s", rec2.Code, rec2.Body.String())
		}
	})

	t.Run("wrong owner cannot burn", func(t *testing.T) {
		secStore.secrets["id2"] = storage.Secret{
			ID:        "id2",
			ClaimHash: "x",
			Envelope:  json.RawMessage(`{"c":"x"}`),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			OwnerKey:  "apikey:" + prefix,
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/id2/burn", nil)
		req.SetPathValue("id", "id2")
		req.Header.Set("X-API-Key", otherAPIKey)
		srv.handleBurnAuthedSecret(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func newAuthedServer(t *testing.T, secretsStore storage.SecretsStore) (*Server, string) {
	t.Helper()

	keyStore := newMemAPIKeyStore()
	pepper := "pepper"
	apiKey, prefix, hash, err := auth.GenerateAPIKey(pepper)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	_ = keyStore.Insert(context.Background(), storage.APIKey{Prefix: prefix, Hash: hash})

	authn := auth.NewAuthenticator(pepper, keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secretsStore, authn)
	return srv, apiKey
}

func TestBurnSecret_MethodAndStoreErrors(t *testing.T) {
	secStore := newMemSecretsStore()
	secStore.secrets["id1"] = storage.Secret{ID: "id1", ClaimHash: "x", Envelope: json.RawMessage(`{"c":"x"}`), ExpiresAt: time.Now().Add(1 * time.Hour)}

	srv, apiKey := newAuthedServer(t, secStore)

	t.Run("method not allowed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/id1/burn", nil)
		req.SetPathValue("id", "id1")
		req.Header.Set("X-API-Key", apiKey)
		srv.handleBurnAuthedSecret(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("missing id", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets//burn", nil)
		req.SetPathValue("id", "")
		req.Header.Set("X-API-Key", apiKey)
		srv.handleBurnAuthedSecret(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("store error", func(t *testing.T) {
		srv2, apiKey2 := newAuthedServer(t, errSecretsStore{err: context.DeadlineExceeded})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/id/burn", nil)
		req.SetPathValue("id", "id")
		req.Header.Set("X-API-Key", apiKey2)
		srv2.handleBurnAuthedSecret(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestClaimSecret_MethodIdAndStoreErrors(t *testing.T) {
	t.Run("method not allowed", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/id/claim", nil)
		req.SetPathValue("id", "id")
		srv.handleClaimSecret(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("missing id", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets//claim", bytes.NewBufferString(`{"claim":"x"}`))
		req.SetPathValue("id", "")
		req.Header.Set("Content-Type", "application/json")
		srv.handleClaimSecret(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/id/claim", bytes.NewBufferString("{"))
		req.SetPathValue("id", "id")
		req.Header.Set("Content-Type", "application/json")
		srv.handleClaimSecret(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("extra json tokens", func(t *testing.T) {
		secStore := newMemSecretsStore()
		keyStore := newMemAPIKeyStore()
		authn := auth.NewAuthenticator("pepper", keyStore)
		srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

		claimToken, _ := randomB64(16)
		body := `{"claim":"` + claimToken + `"}{"x":1}`

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/id/claim", bytes.NewBufferString(body))
		req.SetPathValue("id", "id")
		req.Header.Set("Content-Type", "application/json")
		srv.handleClaimSecret(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("store error", func(t *testing.T) {
		srv, _ := newAuthedServer(t, errSecretsStore{err: context.DeadlineExceeded})

		claimToken, _ := randomB64(16)
		reqBody, _ := json.Marshal(ClaimSecretRequest{Claim: claimToken})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/id/claim", bytes.NewReader(reqBody))
		req.SetPathValue("id", "id")
		req.Header.Set("Content-Type", "application/json")
		srv.handleClaimSecret(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestAuthedCreate_RateLimitedAndAuthFailures(t *testing.T) {
	secStore := newMemSecretsStore()
	srv, apiKey := newAuthedServer(t, secStore)

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)
	reqBody, _ := json.Marshal(CreateSecretRequest{
		Envelope:  json.RawMessage(`{"ciphertext":"abc"}`),
		ClaimHash: claimHash,
	})

	t.Run("rate limited", func(t *testing.T) {
		// Make it deterministic: always deny.
		srv.apiLimiter = ratelimit.New(0, 0)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", apiKey)
		srv.handleCreateAuthedSecret(rec, req)

		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("authorization not bearer", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Basic abc123")
		srv.handleCreateAuthedSecret(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("invalid api key", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "sk_invalid.invalid")
		srv.handleCreateAuthedSecret(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestClientIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		remoteAddr string
		xff        string // X-Forwarded-For header value; empty = not set
		want       string
	}{
		{
			name:       "direct connection",
			remoteAddr: "192.0.2.1:1234",
			want:       "192.0.2.1",
		},
		{
			name:       "unparseable RemoteAddr falls through",
			remoteAddr: "weird",
			want:       "weird",
		},
		{
			name:       "loopback ipv4 with XFF single IP",
			remoteAddr: "127.0.0.1:1234",
			xff:        "203.0.113.5",
			want:       "203.0.113.5",
		},
		{
			name:       "loopback ipv6 with XFF single IP",
			remoteAddr: "[::1]:1234",
			xff:        "203.0.113.6",
			want:       "203.0.113.6",
		},
		{
			name:       "loopback with XFF chain returns leftmost",
			remoteAddr: "127.0.0.1:9999",
			xff:        "198.51.100.1, 10.0.0.1, 127.0.0.1",
			want:       "198.51.100.1",
		},
		{
			name:       "loopback with XFF whitespace trimmed",
			remoteAddr: "127.0.0.1:80",
			xff:        "  198.51.100.2 ",
			want:       "198.51.100.2",
		},
		{
			name:       "loopback without XFF returns loopback",
			remoteAddr: "127.0.0.1:80",
			want:       "127.0.0.1",
		},
		{
			name:       "non-loopback ignores XFF",
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.99",
			want:       "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := clientIP(req); got != tt.want {
				t.Errorf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
