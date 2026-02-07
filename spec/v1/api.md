# API (v1)

All endpoints are JSON over HTTPS.

The service stores **ciphertext envelopes only**. Decryption keys must never be sent to or stored on the server.

Server-side runtime behavior (atomic claim semantics, reaper cadence, middleware, timeouts) is specified in:

- `/Users/jdlien/code/secret/spec/v1/server.md`

## Content types

- Requests: `Content-Type: application/json`
- Responses: `application/json` (and `Cache-Control: no-store`)

## TTL

- Default: **24 hours** (`86400` seconds) when `ttl_seconds` is omitted.
- API clients MAY set any positive integer `ttl_seconds` up to **1 year** (`31536000` seconds).
- Frontend UI MAY present opinionated presets, but API validation should not be restricted to those preset values.
- The wire contract is integer seconds only; CLI input parsing rules (e.g., `5m`, `2d`, `1w`) are defined in `/Users/jdlien/code/secret/spec/v1/cli.md`.

## Envelope

`envelope` is an opaque JSON object produced by the client (ciphertext, nonce, KDF params, etc.). The backend treats it as a blob and does not inspect its contents beyond basic validation.

Normative envelope format and crypto workflow are defined in:

- `/Users/jdlien/code/secret/spec/v1/envelope.md`

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
  "ttl_seconds": 86400
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
