package api

import (
	"encoding/json"
	"time"
)

// CreateSecretRequest stores a client-encrypted envelope and metadata needed to enforce one-time retrieval.
//
// The backend must never require access to decryption keys; it stores only ciphertext (the envelope) and a claim hash.
type CreateSecretRequest struct {
	// Envelope is an opaque JSON object produced by the client (ciphertext, nonce, KDF params, etc.).
	Envelope json.RawMessage `json:"envelope"`

	// ClaimHash is the server-stored verifier used to authorize a one-time claim.
	// Recommended format: base64url(sha256(claim_token_bytes)).
	ClaimHash string `json:"claim_hash"`

	// TTLSeconds controls how long the secret should exist for. The server applies caps/allowlists.
	TTLSeconds *int64 `json:"ttl_seconds,omitempty"`
}

type CreateSecretResponse struct {
	ID        string    `json:"id"`
	ShareURL  string    `json:"share_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ClaimSecretRequest authorizes a one-time claim. The client sends the claim token (not the hash).
// The server hashes it and atomically deletes+returns the secret if it matches.
type ClaimSecretRequest struct {
	// Claim is the base64url-encoded claim token bytes.
	Claim string `json:"claim"`
}

type ClaimSecretResponse struct {
	Envelope  json.RawMessage `json:"envelope"`
	ExpiresAt time.Time       `json:"expires_at"`
}

