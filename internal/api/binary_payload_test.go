package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"secrt/internal/auth"
	"secrt/internal/config"
	"secrt/internal/secrets"
)

// ── Helpers ─────────────────────────────────────────────────────────────

// createMinimalPNG returns the smallest valid PNG (1x1 transparent pixel).
func createMinimalPNG() []byte {
	// 1x1 transparent PNG — 67 bytes.
	raw, _ := base64.StdEncoding.DecodeString(
		"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIABQABNjN9GQAAAAlwSFlz" +
			"AAAWJQAAFiUBSVIk8AAAAApJREFUCNdjYAAAAAIAAeIhvDMAAAAASUVORK5CYII=")
	return raw
}

// createMinimalJPEG returns a minimal valid JPEG.
func createMinimalJPEG() []byte {
	raw, _ := base64.StdEncoding.DecodeString(
		"/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRof" +
			"Hh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwh" +
			"MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAAR" +
			"CAABAAEDASIAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAA" +
			"AAD/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMR" +
			"AD8AKwA//9k=")
	return raw
}

// createAndClaim creates a secret with the given envelope via the public endpoint
// and claims it, returning the claimed envelope.
func createAndClaim(t *testing.T, srv *Server, envelope json.RawMessage) json.RawMessage {
	t.Helper()

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
		t.Fatalf("create: got %d body=%s", rec.Code, rec.Body.String())
	}

	var createResp CreateSecretResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &createResp)

	claimBody, _ := json.Marshal(ClaimSecretRequest{Claim: claimToken})
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/"+createResp.ID+"/claim", bytes.NewReader(claimBody))
	req2.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("claim: got %d body=%s", rec2.Code, rec2.Body.String())
	}

	var claimResp ClaimSecretResponse
	_ = json.Unmarshal(rec2.Body.Bytes(), &claimResp)
	return claimResp.Envelope
}

func assertEnvelopeEqual(t *testing.T, got, want json.RawMessage) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("envelope mismatch:\n  got:  %s\n  want: %s", got, want)
	}
}

func newTestServer() *Server {
	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	return NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)
}

// ── Binary payload round-trip tests ─────────────────────────────────────

func TestBinaryPayload_SmallPNG(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	png := createMinimalPNG()
	b64 := base64.StdEncoding.EncodeToString(png)

	envelope := json.RawMessage(`{"ct":"` + b64 + `","type":"image/png"}`)
	got := createAndClaim(t, srv, envelope)
	assertEnvelopeEqual(t, got, envelope)

	// Verify we can decode the PNG data back.
	var m map[string]string
	_ = json.Unmarshal(got, &m)
	decoded, err := base64.StdEncoding.DecodeString(m["ct"])
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	// PNG header: 89 50 4E 47
	if len(decoded) < 4 || decoded[0] != 0x89 || decoded[1] != 0x50 {
		t.Fatalf("not a valid PNG header: %x", decoded[:4])
	}
}

func TestBinaryPayload_JPEG(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	jpeg := createMinimalJPEG()
	b64 := base64.StdEncoding.EncodeToString(jpeg)

	envelope := json.RawMessage(`{"ct":"` + b64 + `","type":"image/jpeg"}`)
	got := createAndClaim(t, srv, envelope)
	assertEnvelopeEqual(t, got, envelope)

	var m map[string]string
	_ = json.Unmarshal(got, &m)
	decoded, err := base64.StdEncoding.DecodeString(m["ct"])
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	// JPEG header: FF D8
	if len(decoded) < 2 || decoded[0] != 0xFF || decoded[1] != 0xD8 {
		t.Fatalf("not a valid JPEG header: %x", decoded[:2])
	}
}

func TestBinaryPayload_NearMaxSize(t *testing.T) {
	t.Parallel()

	srv := newTestServer()
	maxEnvelope := srv.cfg.PublicMaxEnvelopeBytes
	if maxEnvelope <= 0 {
		maxEnvelope = secrets.DefaultPublicMaxEnvelopeBytes
	}

	// Use ~75% of limit to stay well within bounds after base64 expansion.
	rawSize := int(maxEnvelope * 3 / 5)
	raw := make([]byte, rawSize)
	for i := range raw {
		raw[i] = byte(i % 256)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)

	envelope := json.RawMessage(`{"ct":"` + b64 + `"}`)
	if int64(len(envelope)) > maxEnvelope {
		t.Skipf("envelope too large for test: %d bytes", len(envelope))
	}

	got := createAndClaim(t, srv, envelope)
	assertEnvelopeEqual(t, got, envelope)
}

func TestBinaryPayload_ExceedsMaxSize(t *testing.T) {
	t.Parallel()

	// Use a small limit to keep the test fast.
	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{
		PublicBaseURL:          "https://example.com",
		PublicMaxEnvelopeBytes: 64 * 1024, // 64 KB for this test
	}, secStore, authn)

	// ~50KB raw binary -> ~67KB after base64 (exceeds 64KB).
	raw := make([]byte, 50*1024)
	for i := range raw {
		raw[i] = byte(i % 256)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)

	envelope := json.RawMessage(`{"ct":"` + b64 + `"}`)
	if int64(len(envelope)) <= 64*1024 {
		t.Skipf("envelope not large enough: %d bytes", len(envelope))
	}

	claimToken, _ := randomB64(32)
	claimHash, _ := secrets.HashClaimToken(claimToken)
	createReq, _ := json.Marshal(CreateSecretRequest{
		Envelope:  envelope,
		ClaimHash: claimHash,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/secrets", bytes.NewReader(createReq))
	req.Header.Set("Content-Type", "application/json")
	srv.handleCreateSecret(rec, req, false, "test")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestBinaryPayload_NullBytes(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	raw := []byte{0x00, 0xFF, 0x00}
	b64 := base64.StdEncoding.EncodeToString(raw)

	envelope := json.RawMessage(`{"ct":"` + b64 + `"}`)
	got := createAndClaim(t, srv, envelope)
	assertEnvelopeEqual(t, got, envelope)

	var m map[string]string
	_ = json.Unmarshal(got, &m)
	decoded, err := base64.StdEncoding.DecodeString(m["ct"])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Fatalf("null bytes round-trip failed: got %x want %x", decoded, raw)
	}
}

func TestBinaryPayload_MultipleFields(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	ct := base64.StdEncoding.EncodeToString([]byte("ciphertext-data"))
	nonce := base64.StdEncoding.EncodeToString([]byte("nonce-12-bytes!!"))
	salt := base64.StdEncoding.EncodeToString([]byte("salt-data"))

	envelope := json.RawMessage(`{"ct":"` + ct + `","nonce":"` + nonce + `","salt":"` + salt + `"}`)
	got := createAndClaim(t, srv, envelope)
	assertEnvelopeEqual(t, got, envelope)
}

func TestBinaryPayload_Base64URLEncoding(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	// Use base64url encoding (+ -> -, / -> _) which is common in web crypto.
	raw := []byte{0xFB, 0xFF, 0xFE} // produces chars that differ between std and url encoding
	b64url := base64.RawURLEncoding.EncodeToString(raw)

	envelope := json.RawMessage(`{"ct":"` + b64url + `","enc":"base64url"}`)
	got := createAndClaim(t, srv, envelope)
	assertEnvelopeEqual(t, got, envelope)

	var m map[string]string
	_ = json.Unmarshal(got, &m)
	decoded, err := base64.RawURLEncoding.DecodeString(m["ct"])
	if err != nil {
		t.Fatalf("decode base64url: %v", err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Fatalf("base64url round-trip failed: got %x want %x", decoded, raw)
	}
}
