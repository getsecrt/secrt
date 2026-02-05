# API (v1)

All endpoints are JSON over HTTPS.

The service stores **ciphertext envelopes only**. Decryption keys must never be sent to or stored on the server.

## Content types

- Requests: `Content-Type: application/json`
- Responses: `application/json` (and `Cache-Control: no-store`)

## TTL

- Default: **48 hours**
- Public/anonymous create is restricted to a small allowlist:
  - 10 minutes, 1 hour, 8 hours, 24 hours, 48 hours, 1 week, 1 month
- API-key create allows any TTL in `[10 minutes, 30 days]` (set by `ttl_seconds`).

## Envelope

`envelope` is an opaque JSON object produced by the client (ciphertext, nonce, KDF params, etc.). The backend treats it as a blob and does not inspect its contents beyond basic validation.

## Claim tokens

To claim a secret, the client sends a **claim token**. The server computes:

`claim_hash = base64url( sha256( claim_token_bytes ) )`

The stored `claim_hash` must match for the claim to succeed.

## Endpoints

### Health

`GET /healthz`

### Create (public / anonymous)

`POST /api/v1/public/secrets`

Request:

```json
{
  "envelope": { "ciphertext": "...", "nonce": "...", "kdf": { } },
  "claim_hash": "base64url(sha256(claim_token_bytes))",
  "ttl_seconds": 172800
}
```

Response (`201`):

```json
{
  "id": "…",
  "share_url": "https://secret.fullspec.ca/s/…",
  "expires_at": "2026-02-04T00:00:00Z"
}
```

### Create (API key / automation)

`POST /api/v1/secrets`

Headers:

- `X-API-Key: sk_<prefix>.<secret>` (or `Authorization: Bearer ...`)

Body is the same as the public endpoint.

### Claim (one-time)

`POST /api/v1/secrets/{id}/claim`

Request:

```json
{ "claim": "base64url(claim_token_bytes)" }
```

Response (`200`):

```json
{
  "envelope": { "ciphertext": "...", "nonce": "...", "kdf": { } },
  "expires_at": "2026-02-04T00:00:00Z"
}
```

If the secret is expired, already claimed, or the claim token is wrong, the response is `404`.

### Burn (API key)

`POST /api/v1/secrets/{id}/burn`

Deletes a secret without claiming it (requires API key).
