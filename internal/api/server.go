package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"secrt/internal/auth"
	"secrt/internal/config"
	"secrt/internal/ratelimit"
	"secrt/internal/secrets"
	"secrt/internal/storage"
	"secrt/web"
)

type Server struct {
	cfg     config.Config
	secrets storage.SecretsStore
	auth    *auth.Authenticator

	publicCreateLimiter *ratelimit.Limiter
	claimLimiter        *ratelimit.Limiter
	apiLimiter          *ratelimit.Limiter

	// ownerHMACKey is a per-process random key used to HMAC-hash client IPs
	// before storing them as owner_key in the database, so raw IPs are never
	// persisted. Generated at startup; quota tracking resets on restart (which
	// is acceptable because secrets expire via TTL anyway).
	ownerHMACKey [32]byte

	generateID func() (string, error)

	mux *http.ServeMux
}

func NewServer(cfg config.Config, secretsStore storage.SecretsStore, authn *auth.Authenticator) *Server {
	mux := http.NewServeMux()

	s := &Server{
		cfg:     cfg,
		secrets: secretsStore,
		auth:    authn,
		// Single-instance rate limits per IP. Tune as needed.
		publicCreateLimiter: ratelimit.New(0.5, 6), // ~30/min burst 6 per IP
		claimLimiter:        ratelimit.New(1.0, 10),
		apiLimiter:          ratelimit.New(2.0, 20),
		generateID:          secrets.GenerateID,
		mux:                 mux,
	}

	// Generate a per-process HMAC key for hashing client IPs in owner_key.
	if _, err := rand.Read(s.ownerHMACKey[:]); err != nil {
		panic("api: crypto/rand failed: " + err.Error())
	}

	// Start GC on rate limiters: sweep every 2 minutes, evict after 10 minutes idle.
	s.publicCreateLimiter.StartGC(2*time.Minute, 10*time.Minute)
	s.claimLimiter.StartGC(2*time.Minute, 10*time.Minute)
	s.apiLimiter.StartGC(2*time.Minute, 10*time.Minute)

	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /s/{id}", s.handleSecretPage)
	mux.HandleFunc("GET /robots.txt", s.handleRobotsTxt)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(web.StaticFS())))

	// Anonymous/public endpoint for the web UI (no API key).
	mux.HandleFunc("POST /api/v1/public/secrets", s.handleCreatePublicSecret)

	// API-key authenticated endpoints for automation.
	mux.HandleFunc("POST /api/v1/secrets", s.handleCreateAuthedSecret)
	mux.HandleFunc("POST /api/v1/secrets/{id}/burn", s.handleBurnAuthedSecret)

	// Claim endpoint (no API key; possession of the URL fragment + optional passphrase should be enough).
	mux.HandleFunc("POST /api/v1/secrets/{id}/claim", s.handleClaimSecret)

	return s
}

func (s *Server) Handler() http.Handler {
	return withMiddleware(s.mux)
}

// Close stops background goroutines (rate limiter GC). Safe to call multiple times.
func (s *Server) Close() {
	s.publicCreateLimiter.Stop()
	s.claimLimiter.Stop()
	s.apiLimiter.Stop()
}

// hashOwnerIP returns an HMAC-SHA256 hex digest of the IP, suitable for use as
// owner_key in the database. This avoids persisting raw IPs while preserving
// per-IP quota enforcement within a process lifetime.
func (s *Server) hashOwnerIP(ip string) string {
	mac := hmac.New(sha256.New, s.ownerHMACKey[:])
	mac.Write([]byte(ip))
	return "ip:" + hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"time": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) handleCreatePublicSecret(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.publicCreateLimiter.Allow(ip) {
		rateLimited(w)
		return
	}

	s.handleCreateSecret(w, r, false, s.hashOwnerIP(ip))
}

func (s *Server) handleCreateAuthedSecret(w http.ResponseWriter, r *http.Request) {
	apiKey, ok := s.requireAPIKey(w, r)
	if !ok {
		return
	}

	if !s.apiLimiter.Allow("apikey:" + apiKey.Prefix) {
		rateLimited(w)
		return
	}

	s.handleCreateSecret(w, r, true, "apikey:"+apiKey.Prefix)
}

func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request, authed bool, ownerKey string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r)
		return
	}
	if !isJSONContentType(r) {
		badRequest(w, "content-type must be application/json")
		return
	}

	var maxEnvelopeBytes int64
	if authed {
		maxEnvelopeBytes = s.cfg.AuthedMaxEnvelopeBytes
	} else {
		maxEnvelopeBytes = s.cfg.PublicMaxEnvelopeBytes
	}
	if maxEnvelopeBytes <= 0 {
		maxEnvelopeBytes = secrets.DefaultAuthedMaxEnvelopeBytes
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxEnvelopeBytes+16*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req CreateSecretRequest
	if err := dec.Decode(&req); err != nil {
		badRequest(w, mapDecodeError(err))
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		badRequest(w, "invalid json")
		return
	}

	if err := secrets.ValidateEnvelope(req.Envelope, maxEnvelopeBytes); err != nil {
		if errors.Is(err, secrets.ErrEnvelopeTooLarge) {
			badRequest(w, fmt.Sprintf("envelope exceeds maximum size (%s)", secrets.FormatBytes(maxEnvelopeBytes)))
			return
		}
		badRequest(w, "invalid envelope")
		return
	}
	if err := secrets.ValidateClaimHash(req.ClaimHash); err != nil {
		badRequest(w, "invalid claim_hash")
		return
	}

	var ttl time.Duration
	var err error
	if authed {
		ttl, err = secrets.NormalizeAuthedTTL(req.TTLSeconds)
	} else {
		ttl, err = secrets.NormalizePublicTTL(req.TTLSeconds)
	}
	if err != nil {
		badRequest(w, "invalid ttl_seconds")
		return
	}

	expiresAt := time.Now().UTC().Add(ttl)

	// Generate a random ID server-side to prevent predictable IDs.
	id, err := s.generateID()
	if err != nil {
		slog.Error("id generation error", "err", err)
		internalServerError(w)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Enforce per-owner storage quotas.
	var maxSecrets, maxBytes int64
	if authed {
		maxSecrets = s.cfg.AuthedMaxSecrets
		maxBytes = s.cfg.AuthedMaxTotalBytes
	} else {
		maxSecrets = s.cfg.PublicMaxSecrets
		maxBytes = s.cfg.PublicMaxTotalBytes
	}
	if maxSecrets > 0 || maxBytes > 0 {
		usage, err := s.secrets.GetUsage(ctx, ownerKey)
		if err != nil {
			slog.Error("get usage error", "err", err)
			internalServerError(w)
			return
		}
		if maxSecrets > 0 && usage.SecretCount >= maxSecrets {
			writeError(w, http.StatusTooManyRequests, fmt.Sprintf("secret limit exceeded (max %d active secrets)", maxSecrets))
			return
		}
		if maxBytes > 0 && usage.TotalBytes+int64(len(req.Envelope)) > maxBytes {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("storage quota exceeded (limit %s)", secrets.FormatBytes(maxBytes)))
			return
		}
	}

	sec := storage.Secret{
		ID:        id,
		ClaimHash: req.ClaimHash,
		Envelope:  req.Envelope,
		ExpiresAt: expiresAt,
		OwnerKey:  ownerKey,
	}

	if err := s.secrets.Create(ctx, sec); err != nil {
		slog.Error("create secret error", "err", err)
		internalServerError(w)
		return
	}

	shareURL := fmt.Sprintf("%s/s/%s", s.cfg.PublicBaseURL, id)
	writeJSON(w, http.StatusCreated, CreateSecretResponse{
		ID:        id,
		ShareURL:  shareURL,
		ExpiresAt: expiresAt,
	})
}

func (s *Server) handleClaimSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r)
		return
	}
	if !s.claimLimiter.Allow(clientIP(r)) {
		rateLimited(w)
		return
	}
	if !isJSONContentType(r) {
		badRequest(w, "content-type must be application/json")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		notFound(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req ClaimSecretRequest
	if err := dec.Decode(&req); err != nil {
		badRequest(w, mapDecodeError(err))
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		badRequest(w, "invalid json")
		return
	}
	if strings.TrimSpace(req.Claim) == "" {
		badRequest(w, "claim is required")
		return
	}

	claimHash, err := secrets.HashClaimToken(req.Claim)
	if err != nil {
		// Treat invalid claims as not found to avoid secret existence leaks.
		notFound(w)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	sec, err := s.secrets.ClaimAndDelete(ctx, id, claimHash, time.Now().UTC())
	if errors.Is(err, storage.ErrNotFound) {
		notFound(w)
		return
	}
	if err != nil {
		slog.Error("claim secret error", "err", err)
		internalServerError(w)
		return
	}

	writeJSON(w, http.StatusOK, ClaimSecretResponse{
		Envelope:  sec.Envelope,
		ExpiresAt: sec.ExpiresAt,
	})
}

func (s *Server) handleBurnAuthedSecret(w http.ResponseWriter, r *http.Request) {
	apiKey, ok := s.requireAPIKey(w, r)
	if !ok {
		return
	}

	if r.Method != http.MethodPost {
		methodNotAllowed(w, r)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		notFound(w)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ownerKey := "apikey:" + apiKey.Prefix
	deleted, err := s.secrets.Burn(ctx, id, ownerKey)
	if err != nil {
		slog.Error("burn secret error", "err", err)
		internalServerError(w)
		return
	}
	if !deleted {
		notFound(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) requireAPIKey(w http.ResponseWriter, r *http.Request) (storage.APIKey, bool) {
	raw := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if raw == "" {
		authz := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			raw = strings.TrimSpace(authz[len("bearer "):])
		}
	}
	if raw == "" {
		unauthorized(w)
		return storage.APIKey{}, false
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	k, err := s.auth.Authenticate(ctx, raw)
	if err != nil {
		unauthorized(w)
		return storage.APIKey{}, false
	}
	return k, true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	// Trust proxy headers only from loopback (nginx/reverse proxy on same host).
	if host == "127.0.0.1" || host == "::1" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Leftmost IP is the original client.
			if i := strings.IndexByte(xff, ','); i > 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}

	return host
}
