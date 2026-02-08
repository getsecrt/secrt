package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"secret/internal/auth"
	"secret/internal/config"
	"secret/internal/ratelimit"
	"secret/internal/secrets"
	"secret/internal/storage"
)

// ── Quota enforcement tests ─────────────────────────────────────────────

func createPublicSecret(t *testing.T, srv *Server, ip string) int {
	t.Helper()

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)
	body, _ := json.Marshal(CreateSecretRequest{
		Envelope:  json.RawMessage(`{"ct":"quota"}`),
		ClaimHash: claimHash,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":1234"
	srv.Handler().ServeHTTP(rec, req)
	return rec.Code
}

func TestCreateSecret_QuotaSecretCountExceeded(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	cfg := config.Config{
		PublicBaseURL:    "https://example.com",
		PublicMaxSecrets: 3,
	}
	srv := NewServer(cfg, secStore, authn)
	// Disable rate limiter for this test.
	srv.publicCreateLimiter = ratelimit.New(1e6, 1000000)

	ip := "10.0.0.1"
	for i := 0; i < 3; i++ {
		code := createPublicSecret(t, srv, ip)
		if code != http.StatusCreated {
			t.Fatalf("create %d: got %d", i, code)
		}
	}

	// 4th should be rejected (at limit).
	code := createPublicSecret(t, srv, ip)
	if code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for count exceeded, got %d", code)
	}
}

func TestCreateSecret_QuotaTotalBytesExceeded(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	cfg := config.Config{
		PublicBaseURL:       "https://example.com",
		PublicMaxSecrets:    100,
		PublicMaxTotalBytes: 100, // very small
	}
	srv := NewServer(cfg, secStore, authn)
	srv.publicCreateLimiter = ratelimit.New(1e6, 1000000)

	ip := "10.0.0.2"

	// First secret should succeed — ~14 bytes envelope.
	code := createPublicSecret(t, srv, ip)
	if code != http.StatusCreated {
		t.Fatalf("first create: got %d", code)
	}

	// Create with large envelope to exceed bytes.
	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)
	bigEnvelope := `{"ct":"` + strings.Repeat("x", 100) + `"}`
	body, _ := json.Marshal(CreateSecretRequest{
		Envelope:  json.RawMessage(bigEnvelope),
		ClaimHash: claimHash,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":1234"
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for bytes exceeded, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateSecret_AuthedQuotaHigherLimits(t *testing.T) {
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
	cfg := config.Config{
		PublicBaseURL:    "https://example.com",
		PublicMaxSecrets: 2,   // very low for public
		AuthedMaxSecrets: 100, // high for authed
	}
	srv := NewServer(cfg, secStore, authn)

	// Create >2 secrets with API key (should succeed because authed limit is 100).
	for i := 0; i < 5; i++ {
		claimToken, _ := randomB64(32)
		claimHash, _ := secrets.HashClaimToken(claimToken)
		body, _ := json.Marshal(CreateSecretRequest{
			Envelope:  json.RawMessage(`{"ct":"authed"}`),
			ClaimHash: claimHash,
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", apiKey)
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("authed create %d: got %d body=%s", i, rec.Code, rec.Body.String())
		}
	}
}

func TestCreateSecret_QuotaGetUsageError(t *testing.T) {
	t.Parallel()

	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	cfg := config.Config{
		PublicBaseURL:    "https://example.com",
		PublicMaxSecrets: 10,
	}
	srv := NewServer(cfg, errSecretsStore{err: context.DeadlineExceeded}, authn)
	srv.publicCreateLimiter = ratelimit.New(1e6, 1000000)

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)
	body, _ := json.Marshal(CreateSecretRequest{
		Envelope:  json.RawMessage(`{"ct":"err"}`),
		ClaimHash: claimHash,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.3:1234"
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for GetUsage error, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateSecret_QuotaResetsAfterClaim(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	cfg := config.Config{
		PublicBaseURL:    "https://example.com",
		PublicMaxSecrets: 2,
	}
	srv := NewServer(cfg, secStore, authn)
	srv.publicCreateLimiter = ratelimit.New(1e6, 1000000)

	ip := "10.0.0.4"

	// Create 2 secrets (at limit).
	var firstID string
	var firstClaimToken string
	for i := 0; i < 2; i++ {
		claimToken, _ := randomB64(32)
		claimHash, _ := secrets.HashClaimToken(claimToken)
		body, _ := json.Marshal(CreateSecretRequest{
			Envelope:  json.RawMessage(`{"ct":"reset"}`),
			ClaimHash: claimHash,
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip + ":1234"
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %d: got %d", i, rec.Code)
		}
		if i == 0 {
			var resp CreateSecretResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &resp)
			firstID = resp.ID
			firstClaimToken = claimToken
		}
	}

	// 3rd should fail.
	code := createPublicSecret(t, srv, ip)
	if code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 at limit, got %d", code)
	}

	// Claim one secret to free quota.
	claimBody, _ := json.Marshal(ClaimSecretRequest{Claim: firstClaimToken})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/"+firstID+"/claim", bytes.NewReader(claimBody))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("claim: got %d", rec.Code)
	}

	// Now creating should succeed again.
	code = createPublicSecret(t, srv, ip)
	if code != http.StatusCreated {
		t.Fatalf("expected 201 after claim, got %d", code)
	}
}

func TestCreateSecret_QuotaZeroMeansUnlimited(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	cfg := config.Config{
		PublicBaseURL:       "https://example.com",
		PublicMaxSecrets:    0, // disabled
		PublicMaxTotalBytes: 0, // disabled
	}
	srv := NewServer(cfg, secStore, authn)
	srv.publicCreateLimiter = ratelimit.New(1e6, 1000000)

	ip := "10.0.0.5"
	for i := 0; i < 20; i++ {
		code := createPublicSecret(t, srv, ip)
		if code != http.StatusCreated {
			t.Fatalf("create %d: got %d (expected unlimited)", i, code)
		}
	}
}
