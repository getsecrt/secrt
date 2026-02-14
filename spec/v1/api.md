# API (v1)

All endpoints are JSON over HTTPS.

The service stores **ciphertext envelopes only**. Decryption keys must never be sent to or stored on the server.

Server-side runtime behavior (atomic claim semantics, reaper cadence, middleware, timeouts) is specified in:

- `spec/v1/server.md`

## Content types

- Requests: `Content-Type: application/json`
- Responses: `application/json` (and `Cache-Control: no-store`)

## TTL

- Default: **24 hours** (`86400` seconds) when `ttl_seconds` is omitted.
- API clients MAY set any positive integer `ttl_seconds` up to **1 year** (`31536000` seconds).
- Frontend UI MAY present opinionated presets, but API validation should not be restricted to those preset values.
- The wire contract is integer seconds only; CLI input parsing rules (e.g., `5m`, `2h`, `2d`, `1w`) are defined in `spec/v1/cli.md`.

## Envelope

`envelope` is an opaque JSON object produced by the client (ciphertext, nonce, KDF params, etc.). The backend treats it as a blob and does not inspect its contents beyond basic validation.

Advisory metadata (`type`, `filename`, `mime`, and similar fields) is encrypted inside the payload frame ciphertext. It MUST NOT be present in plaintext envelope JSON. The server stores the envelope unchanged and cannot read metadata values.

Normative envelope format and crypto workflow are defined in:

- `spec/v1/envelope.md`

## Claim tokens

To claim a secret, the client sends a **claim token**. The server computes:

`claim_hash = base64url( sha256( claim_token_bytes ) )`

The stored `claim_hash` must match for the claim to succeed.

## Authentication and Ownership

Authenticated secret endpoints are API-key based and accept only v2 wire credentials:

- `X-API-Key: ak2_<prefix>.<auth_b64>`
- `Authorization: Bearer ak2_<prefix>.<auth_b64>`

Local key format (client storage only):

- `sk2_<prefix>.<root_b64>`

Derivation contract:

- `ROOT_SALT = SHA256("secrt-apikey-v2-root-salt")`
- `auth_token = HKDF-SHA256(root_key, ROOT_SALT, "secrt-auth", 32)`
- `enc_key = HKDF-SHA256(root_key, ROOT_SALT, "secrt-meta-encrypt", 32)`

Verifier contract:

- `msg = "secrt-apikey-v2-verifier" || u16be(len(prefix)) || prefix_utf8 || auth_token_bytes`
- `auth_hash = hex(HMAC_SHA256(API_KEY_PEPPER, msg))`

Legacy `sk_` credentials are not accepted in v1 runtime.

Ownership is tracked server-side for policy and management actions:

- Public create (`POST /api/v1/public/secrets`) stores an internal owner key derived from client IP.
- Authenticated create (`POST /api/v1/secrets`) stores owner key `apikey:<prefix>`.

Important:

- Ownership metadata is for authorization/rate-limit/quota policy only.
- Ownership does not grant decryption ability. Decryption remains client-side only.

## Policy Tiers

The API uses two policy tiers:

- Public (anonymous): stricter limits.
- Authenticated (API key): higher limits for automation and trusted clients.

Current server defaults are:

- Public max envelope size: `PUBLIC_MAX_ENVELOPE_BYTES` (default `256 KiB`)
- Authenticated max envelope size: `AUTHED_MAX_ENVELOPE_BYTES` (default `1 MiB`)
- Public active-secret cap: `PUBLIC_MAX_SECRETS` (default `10`)
- Public active total bytes cap: `PUBLIC_MAX_TOTAL_BYTES` (default `2 MiB`)
- Authenticated active-secret cap: `AUTHED_MAX_SECRETS` (default `1000`)
- Authenticated active total bytes cap: `AUTHED_MAX_TOTAL_BYTES` (default `20 MiB`)

All limits are configurable per server instance via environment variables.

Quota and size failures:

- `400` with `"envelope exceeds maximum size (<limit>)"` when a single envelope is too large
- `429` with `"secret limit exceeded (max N active secrets)"` when max active secret count is reached
- `413` with `"storage quota exceeded (limit <size>)"` when active total bytes would be exceeded

## Endpoints

### Health

`GET /healthz`

### Server Info

`GET /api/v1/info`

Returns server defaults and per-tier limits. Authentication is optional;
if a valid API key is provided, `authenticated` is `true`.

Caching: `Cache-Control: public, max-age=300`

Response (`200`):

```json
{
  "authenticated": false,
  "ttl": {
    "default_seconds": 86400,
    "max_seconds": 31536000
  },
  "limits": {
    "public": {
      "max_envelope_bytes": 262144,
      "max_secrets": 10,
      "max_total_bytes": 2097152,
      "rate": { "requests_per_second": 0.5, "burst": 6 }
    },
    "authed": {
      "max_envelope_bytes": 1048576,
      "max_secrets": 1000,
      "max_total_bytes": 20971520,
      "rate": { "requests_per_second": 2.0, "burst": 20 }
    }
  },
  "claim_rate": { "requests_per_second": 1.0, "burst": 10 }
}
```

Policy notes:

- No API key required. If provided and valid, `authenticated` is `true`.
- Invalid API key is not an error; `authenticated` is `false`.
- Both tiers are always returned regardless of authentication status.
- Rate-limited via the claim limiter (1 rps, burst 10).

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
  "share_url": "https://secrt.ca/s/…",
  "expires_at": "2026-02-04T00:00:00Z"
}
```

Policy notes:

- No API key required.
- Subject to public rate limits and public quota tier.

### Create (API key / automation)

`POST /api/v1/secrets`

Headers:

- `X-API-Key: ak2_<prefix>.<auth_b64>` (or `Authorization: Bearer ...`)

Body is the same as the public endpoint.

Policy notes:

- Subject to authenticated rate limits and authenticated quota tier.
- Secret ownership is bound to the authenticated API key prefix.

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

Authorization rules:

- The API key MUST own the secret (`owner_key == "apikey:<prefix>"`).
- Missing/invalid API key returns `401`.
- Unknown secret ID or wrong owner returns `404`.

Response (`200`):

```json
{ "ok": true }
```

### Passkey Registration and Login

Passkey endpoints establish a short-lived authenticated browser session used for API-key registration:

- `POST /api/v1/auth/passkeys/register/start`
- `POST /api/v1/auth/passkeys/register/finish`
- `POST /api/v1/auth/passkeys/login/start`
- `POST /api/v1/auth/passkeys/login/finish`
- `GET /api/v1/auth/session`
- `POST /api/v1/auth/logout`

v1 passkey model note:

- v1 does **not** perform WebAuthn cryptographic assertion verification in the `/finish` endpoints.
- The `/start` endpoint issues a random `challenge_id` and opaque `challenge` value.
- The `/finish` endpoint authorizes using a valid, unexpired `challenge_id` plus expected credential linkage.
- Security of this flow depends on `challenge_id` entropy and confidentiality.
- Full WebAuthn signature verification is planned for a future version.

Session bearer token format:

- `Authorization: Bearer uss_<sid>.<secret>`
- Session TTL is fixed at 24h in v1 (no refresh flow).
- `register/finish` and `login/finish` return `session_token`, `display_name`, and `expires_at`.
- `GET /api/v1/auth/session` returns `authenticated`, `display_name`, and `expires_at`.
- Auth/session responses intentionally do **not** expose `user_id`.

### API-Key Registration (Passkey Session Required)

`POST /api/v1/apikeys/register`

Headers:

- `Authorization: Bearer uss_<sid>.<secret>`

Request:

```json
{
  "auth_token": "<base64url 32-byte auth token>",
  "scopes": ""
}
```

Response (`201`):

```json
{
  "prefix": "abcdef",
  "created_at": "2026-02-13T00:00:00Z"
}
```

Policy notes:

- Registration is allowed only for authenticated passkey sessions.
- Quotas are enforced on both dimensions:
  - account: default `5/hour`, `20/day`
  - IP: default `5/hour`, `20/day`
- Quota checks and registration writes execute atomically in one DB transaction.

## Error Semantics

Common responses:

- `400` invalid request JSON, content type, or field validation
- `401` missing or invalid API key/session token (authenticated endpoints)
- `404` not found / expired / already claimed / invalid claim token / burn not owned
- `413` storage quota exceeded
- `429` request rate limited or secret-count quota exceeded
- `500` internal server/storage errors

## Future Authenticated Metadata Endpoints (v1.1 Draft)

Not part of v1 runtime contract yet. Intended for dashboard and automation use:

- `GET /api/v1/secrets`
  - List secrets owned by current API key (metadata only).
- `GET /api/v1/secrets/{id}`
  - Return status/metadata for one owned secret.

Draft response shape for metadata endpoints:

```json
{
  "id": "…",
  "share_url": "https://secrt.ca/s/…",
  "expires_at": "2026-02-04T00:00:00Z",
  "created_at": "2026-02-03T00:00:00Z",
  "state": "active"
}
```

Constraints for these endpoints:

- Must not return plaintext, passphrase material, URL fragment keys, or claim tokens.
- Should not return raw `claim_hash` to clients unless there is a strong operational need.
