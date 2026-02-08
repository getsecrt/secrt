package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"secret/internal/auth"
	"secret/internal/config"
	"secret/internal/secrets"
	"secret/internal/storage"
)

// ── End-to-end lifecycle flows ──────────────────────────────────────────

func TestFullLifecycle_CreateClaimVerifyDeletion(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)

	// Create secret.
	createReq, _ := json.Marshal(CreateSecretRequest{
		Envelope:  json.RawMessage(`{"ct":"hello"}`),
		ClaimHash: claimHash,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(createReq))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d body=%s", rec.Code, rec.Body.String())
	}

	var createResp CreateSecretResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &createResp)

	// Claim secret.
	claimBody, _ := json.Marshal(ClaimSecretRequest{Claim: claimToken})
	claimPath := "/api/v1/secrets/" + createResp.ID + "/claim"

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, claimPath, bytes.NewReader(claimBody))
	req2.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("claim: got %d body=%s", rec2.Code, rec2.Body.String())
	}

	// Second claim should fail (secret deleted).
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, claimPath, bytes.NewReader(claimBody))
	req3.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusNotFound {
		t.Fatalf("second claim: expected 404, got %d", rec3.Code)
	}
}

func TestFullLifecycle_AuthedCreateBurnVerify(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	srv, apiKey := newAuthedServer(t, secStore)

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)

	createReq, _ := json.Marshal(CreateSecretRequest{
		Envelope:  json.RawMessage(`{"ct":"burn-me"}`),
		ClaimHash: claimHash,
	})

	// Authed create.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(createReq))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d body=%s", rec.Code, rec.Body.String())
	}

	var createResp CreateSecretResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &createResp)

	// Burn.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/"+createResp.ID+"/burn", nil)
	req2.Header.Set("X-API-Key", apiKey)
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("burn: got %d body=%s", rec2.Code, rec2.Body.String())
	}

	// Claim after burn should 404.
	claimBody, _ := json.Marshal(ClaimSecretRequest{Claim: claimToken})
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/"+createResp.ID+"/claim", bytes.NewReader(claimBody))
	req3.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusNotFound {
		t.Fatalf("claim after burn: expected 404, got %d", rec3.Code)
	}
}

func TestFullLifecycle_WrongClaimTokenReturns404(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)

	createReq, _ := json.Marshal(CreateSecretRequest{
		Envelope:  json.RawMessage(`{"ct":"mine"}`),
		ClaimHash: claimHash,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(createReq))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}

	var createResp CreateSecretResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &createResp)

	// Wrong claim token.
	wrongToken, _ := randomB64(32)
	wrongBody, _ := json.Marshal(ClaimSecretRequest{Claim: wrongToken})

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/"+createResp.ID+"/claim", bytes.NewReader(wrongBody))
	req2.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("wrong token: expected 404, got %d", rec2.Code)
	}

	// Original token should still work.
	rightBody, _ := json.Marshal(ClaimSecretRequest{Claim: claimToken})
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/"+createResp.ID+"/claim", bytes.NewReader(rightBody))
	req3.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("right token: expected 200, got %d body=%s", rec3.Code, rec3.Body.String())
	}
}

func TestClaimPreservesEnvelopeFidelity(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	envelope := json.RawMessage(`{"ct":"dGVzdA","nonce":"AAAAAAAAAAAAAAAAAAAAAA","salt":"c2FsdA","kdf":"argon2id","ops":3,"mem":65536}`)

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)

	createReq, _ := json.Marshal(CreateSecretRequest{
		Envelope:  envelope,
		ClaimHash: claimHash,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(createReq))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}

	var createResp CreateSecretResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &createResp)

	claimBody, _ := json.Marshal(ClaimSecretRequest{Claim: claimToken})
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/"+createResp.ID+"/claim", bytes.NewReader(claimBody))
	req2.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("claim: got %d", rec2.Code)
	}

	var claimResp ClaimSecretResponse
	_ = json.Unmarshal(rec2.Body.Bytes(), &claimResp)

	if !bytes.Equal(claimResp.Envelope, envelope) {
		t.Fatalf("envelope mismatch:\n  got:  %s\n  want: %s", claimResp.Envelope, envelope)
	}
}

func TestSecurityHeaders_OnAllResponses(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	paths := []string{"/healthz", "/", "/api/v1/public/secrets"}
	for _, path := range paths {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		srv.Handler().ServeHTTP(rec, req)

		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q", path, got)
		}
		if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s: Referrer-Policy = %q", path, got)
		}
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("%s: X-Frame-Options = %q", path, got)
		}
	}
}

func TestRequestID_PropagatedOnAllResponses(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	// Without client-supplied request ID, server should generate one.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rid := rec.Header().Get("X-Request-Id"); rid == "" {
		t.Fatal("expected X-Request-Id to be set")
	}

	// With client-supplied ID, it should be echoed back.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req2.Header.Set("X-Request-Id", "test-rid-123")
	srv.Handler().ServeHTTP(rec2, req2)
	if got := rec2.Header().Get("X-Request-Id"); got != "test-rid-123" {
		t.Fatalf("X-Request-Id: got %q want %q", got, "test-rid-123")
	}
}

// ── Concurrency tests (run with go test -race) ─────────────────────────

func TestConcurrentClaim_OnlyOneSucceeds(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)

	createReq, _ := json.Marshal(CreateSecretRequest{
		Envelope:  json.RawMessage(`{"ct":"race"}`),
		ClaimHash: claimHash,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(createReq))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}

	var createResp CreateSecretResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &createResp)

	claimBody, _ := json.Marshal(ClaimSecretRequest{Claim: claimToken})
	claimPath := "/api/v1/secrets/" + createResp.ID + "/claim"

	const goroutines = 50
	var successes int32
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			r := httptest.NewRecorder()
			rq := httptest.NewRequest(http.MethodPost, claimPath, bytes.NewReader(claimBody))
			rq.Header.Set("Content-Type", "application/json")
			srv.Handler().ServeHTTP(r, rq)
			if r.Code == http.StatusOK {
				atomic.AddInt32(&successes, 1)
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("expected exactly 1 success, got %d", successes)
	}
}

func TestConcurrentCreate_UniqueIDs(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	const goroutines = 50
	ids := make([]string, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			claimToken, _ := randomB64(32)
			claimHash, _ := secrets.HashClaimToken(claimToken)
			body, _ := json.Marshal(CreateSecretRequest{
				Envelope:  json.RawMessage(`{"ct":"concurrent"}`),
				ClaimHash: claimHash,
			})
			r := httptest.NewRecorder()
			rq := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(body))
			rq.Header.Set("Content-Type", "application/json")
			srv.Handler().ServeHTTP(r, rq)
			if r.Code == http.StatusCreated {
				var resp CreateSecretResponse
				_ = json.Unmarshal(r.Body.Bytes(), &resp)
				ids[i] = resp.ID
			}
		}()
	}
	wg.Wait()

	seen := make(map[string]struct{})
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate ID: %s", id)
		}
		seen[id] = struct{}{}
	}
}

func TestMemStore_ConcurrentMixedOps(t *testing.T) {
	t.Parallel()

	store := newMemSecretsStore()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	for i := 0; i < goroutines; i++ {
		i := i
		// Create.
		go func() {
			defer wg.Done()
			id := string(rune('a'+i%26)) + "-create"
			_ = store.Create(context.Background(), storage.Secret{
				ID:        id,
				ClaimHash: "hash",
				Envelope:  json.RawMessage(`{"x":"y"}`),
				ExpiresAt: time.Now().Add(time.Hour),
			})
		}()
		// Claim.
		go func() {
			defer wg.Done()
			id := string(rune('a'+i%26)) + "-create"
			_, _ = store.ClaimAndDelete(context.Background(), id, "hash", time.Now())
		}()
		// Burn.
		go func() {
			defer wg.Done()
			id := string(rune('a'+i%26)) + "-create"
			_, _ = store.Burn(context.Background(), id, "")
		}()
	}
	wg.Wait()
}

// ── Boundary / edge cases ───────────────────────────────────────────────

func TestCreateSecret_EnvelopeEdgeCases(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)

	tests := []struct {
		name     string
		envelope string
		wantCode int
	}{
		{"empty object", `{}`, http.StatusCreated},
		{"deeply nested", `{"a":{"b":{"c":{"d":"e"}}}}`, http.StatusCreated},
		{"string not object", `"hello"`, http.StatusBadRequest},
		{"array not object", `[1]`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(CreateSecretRequest{
				Envelope:  json.RawMessage(tt.envelope),
				ClaimHash: claimHash,
			})
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			srv.handleCreateSecret(rec, req, false, "test")
			if rec.Code != tt.wantCode {
				t.Fatalf("envelope %q: got %d want %d body=%s", tt.envelope, rec.Code, tt.wantCode, rec.Body.String())
			}
		})
	}
}

func TestCreateSecret_TTLEdgeCases(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)

	one := int64(1)
	max := int64(secrets.MaxTTL.Seconds())

	tests := []struct {
		name     string
		ttl      *int64
		wantCode int
	}{
		{"minimum 1s", &one, http.StatusCreated},
		{"maximum", &max, http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(CreateSecretRequest{
				Envelope:   json.RawMessage(`{"ct":"ttl"}`),
				ClaimHash:  claimHash,
				TTLSeconds: tt.ttl,
			})
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			srv.handleCreateSecret(rec, req, false, "test")
			if rec.Code != tt.wantCode {
				t.Fatalf("ttl %v: got %d want %d body=%s", tt.ttl, rec.Code, tt.wantCode, rec.Body.String())
			}
		})
	}
}

func TestClaimSecret_ShortClaimToken(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	// 15 bytes (too short — minimum is 16).
	shortToken, _ := randomB64(15)
	body, _ := json.Marshal(ClaimSecretRequest{Claim: shortToken})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/id/claim", bytes.NewReader(body))
	req.SetPathValue("id", "id")
	req.Header.Set("Content-Type", "application/json")
	srv.handleClaimSecret(rec, req)

	// Invalid claims treated as not found.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for short claim token, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateSecret_OversizeBodyRejected(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{
		PublicBaseURL:          "https://example.com",
		PublicMaxEnvelopeBytes: 256 * 1024,
	}, secStore, authn)

	// Build a body larger than MaxBytesReader allows (PublicMaxEnvelopeBytes + 16KB).
	bigPayload := strings.Repeat("x", 256*1024+20*1024)
	body := `{"envelope":{"ct":"` + bigPayload + `"},"claim_hash":"aaa"}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversize body, got %d", rec.Code)
	}
}

func TestCreateSecret_ContentTypeWithCharset(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)
	body, _ := json.Marshal(CreateSecretRequest{
		Envelope:  json.RawMessage(`{"ct":"charset"}`),
		ClaimHash: claimHash,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("content-type with charset: got %d want 201 body=%s", rec.Code, rec.Body.String())
	}
}
