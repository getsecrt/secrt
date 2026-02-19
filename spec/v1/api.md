# API (v1)

All endpoints are JSON over HTTPS.

The service stores **ciphertext envelopes only**. Decryption keys must never be sent to or stored on the server.

Server-side runtime behavior (atomic claim semantics, reaper cadence, middleware, timeouts) is specified in:

- `spec/v1/server.md`

## Content types

- Requests with bodies: `Content-Type: application/json`
- Responses: `application/json` (default `Cache-Control: no-store` unless overridden)

## TTL

- Default: **24 hours** (`86400` seconds) when `ttl_seconds` is omitted.
- API clients MAY set any positive integer `ttl_seconds` up to **1 year** (`31536000` seconds).
- Frontend UI MAY present opinionated presets, but API validation is integer seconds, not preset labels.
- CLI input parsing rules (e.g., `5m`, `2h`, `2d`, `1w`) are defined in `spec/v1/cli.md`.

## Envelope

`envelope` is an opaque JSON object produced by the client (ciphertext, nonce, KDF params, etc.). The backend treats it as a blob and does not inspect its contents beyond basic shape/size validation.

Advisory metadata (`type`, `filename`, `mime`, and similar fields) is encrypted inside the payload frame ciphertext. It MUST NOT be present in plaintext envelope JSON. The server stores the envelope unchanged and cannot read metadata values.

Normative envelope format and crypto workflow are defined in:

- `spec/v1/envelope.md`

## Claim tokens

To claim a secret, the client sends a **claim token**. The server computes:

`claim_hash = base64url( sha256( claim_token_bytes ) )`

The stored `claim_hash` must match for the claim to succeed.

## Authentication and Ownership

### API key credentials

v2 wire API keys are accepted via either header:

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

Legacy `sk_` credentials are not accepted in the v1 runtime.

### Session credentials

Passkey auth issues session bearer tokens:

- `Authorization: Bearer uss_<sid>.<secret>`

Session TTL is fixed at 24h in v1 (no refresh flow).

### Owner keys

Ownership is tracked server-side for policy and management actions:

- Public create (`POST /api/v1/public/secrets`) stores owner key derived from client IP (`ip:<hmac>`).
- Session-authenticated create (`POST /api/v1/secrets` with `uss_` token) stores owner key `user:<uuid>`.
- API-key-authenticated create (`POST /api/v1/secrets` with `ak2_`) stores owner key `apikey:<prefix>`.

Important:

- Ownership metadata is for authorization/rate-limit/quota policy only.
- Ownership does not grant decryption ability. Decryption remains client-side only.

## Policy Tiers

The API uses two policy tiers:

- Public (anonymous): stricter limits.
- Authenticated (session or API key): higher limits.

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

Returns server defaults and per-tier limits. Authentication is optional; if a valid API key is provided, `authenticated` is `true`.

Caching: `Cache-Control: public, max-age=300`

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
  "envelope": { "ciphertext": "...", "nonce": "...", "kdf": {} },
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

### Create (authenticated)

`POST /api/v1/secrets`

Accepted auth:

- Session bearer token `uss_<sid>.<secret>`
- API key (`X-API-Key` or `Authorization: Bearer ak2_...`)

Body is the same as the public endpoint.

Auth resolution order in runtime:

1. Session auth is attempted first.
2. If session auth fails, API key auth is attempted.

### List Secrets (metadata)

`GET /api/v1/secrets`

Accepted auth:

- Session bearer token `uss_<sid>.<secret>`
- API key (`X-API-Key` or `Authorization: Bearer ak2_...`)

Query params:

- `limit` (default `50`, clamped to `1..20000`)
- `offset` (default `0`, min `0`)

Response (`200`):

```json
{
  "secrets": [
    {
      "id": "…",
      "share_url": "https://secrt.ca/s/…",
      "expires_at": "2026-02-04T00:00:00Z",
      "created_at": "2026-02-03T00:00:00Z",
      "ciphertext_size": 1234,
      "passphrase_protected": true
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

Session-authenticated listing includes owner keys:

- `user:<session_user_id>`
- `apikey:<prefix>` for each **unrevoked** API key owned by that user

API-key-authenticated listing only includes `apikey:<that_prefix>`.

### Secrets Check (dashboard polling)

`GET /api/v1/secrets/check`

Accepted auth is the same as `GET /api/v1/secrets`.

Purpose: lightweight high-frequency dashboard sync check before refetching full metadata.

Response (`200`):

```json
{
  "count": 12,
  "checksum": "opaque-change-token"
}
```

`checksum` is an opaque server value over currently visible active secret IDs (empty string when count is `0`). Treat it as a change detector, not a cryptographic integrity primitive.

### Claim (one-time)

`POST /api/v1/secrets/{id}/claim`

Request:

```json
{ "claim": "base64url(claim_token_bytes)" }
```

Response (`200`):

```json
{
  "envelope": { "ciphertext": "...", "nonce": "...", "kdf": {} },
  "expires_at": "2026-02-04T00:00:00Z"
}
```

If the secret is expired, already claimed, unknown, or claim token validation fails, response is `404`.

### Burn (delete without claiming)

`POST /api/v1/secrets/{id}/burn`

Accepted auth:

- Session bearer token `uss_<sid>.<secret>`
- API key (`X-API-Key` or `Authorization: Bearer ak2_...`)

Authorization rules:

- API key auth: key must own secret (`owner_key == "apikey:<prefix>"`).
- Session auth: burn is attempted against `user:<id>` and each unrevoked `apikey:<prefix>` for the session user.
- Unknown secret or not owned by caller returns `404`.

Response (`200`):

```json
{ "ok": true }
```

### Passkey Registration and Login

Passkey endpoints establish authenticated browser sessions and account identity:

- `POST /api/v1/auth/passkeys/register/start`
- `POST /api/v1/auth/passkeys/register/finish`
- `POST /api/v1/auth/passkeys/login/start`
- `POST /api/v1/auth/passkeys/login/finish`
- `GET /api/v1/auth/session`
- `POST /api/v1/auth/logout`

v1 passkey model note:

- v1 does **not** perform WebAuthn cryptographic assertion verification in `/finish`.
- `/start` issues random `challenge_id` and opaque `challenge`.
- `/finish` authorizes via valid unexpired `challenge_id` + expected credential linkage.

### Device Authorization (CLI login flow)

Device authorization enables CLI tools to obtain API keys via browser-based approval without exposing the root key to the server. The CLI pre-generates key material and sends only the derived `auth_token` to the server.

#### Start device authorization

`POST /api/v1/auth/device/start`

Unauthenticated. IP rate-limited.

Request:

```json
{
  "auth_token": "<base64url 32-byte auth token>"
}
```

Response (`200`):

```json
{
  "device_code": "<base64url opaque identifier>",
  "user_code": "ABCD-1234",
  "verification_url": "https://secrt.ca/device?code=ABCD-1234",
  "expires_in": 600,
  "interval": 5
}
```

Validation:

- `auth_token` MUST decode as base64url to exactly 32 bytes.
- `device_code` is 32 bytes of random data (base64url encoded), stored as `challenge_id` in the `webauthn_challenges` table with `purpose = "device-auth"` and 10-minute expiry.
- `user_code` is 8 characters from charset `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (no ambiguous `0`, `O`, `I`, `1`), formatted as `XXXX-XXXX`.

#### Poll device authorization status

`POST /api/v1/auth/device/poll`

Unauthenticated. IP rate-limited.

Request:

```json
{
  "device_code": "<base64url>"
}
```

Responses:

- Pending: `200` `{ "status": "authorization_pending" }`
- Approved: `200` `{ "status": "complete", "prefix": "<api_key_prefix>" }` — the challenge is consumed on this response.
- Expired or not found: `400` `{ "error": "expired_token" }`

The CLI constructs the full local key as `sk2_<prefix>.<base64(root_key)>` using the prefix from the response and the locally-held root key.

#### Approve device authorization (session required)

`POST /api/v1/auth/device/approve`

Headers:

- `Authorization: Bearer uss_<sid>.<secret>`

Request:

```json
{
  "user_code": "ABCD-1234"
}
```

Response (`200`):

```json
{ "ok": true }
```

Behavior:

1. Looks up a pending `device-auth` challenge by `user_code` (constant-time comparison).
2. Generates an API key prefix, computes `auth_hash` from the stored `auth_token` + pepper.
3. Registers the API key linked to the session user (reuses existing quota logic from `POST /api/v1/apikeys/register`).
4. Updates challenge status to `"approved"` with the generated prefix.

Other outcomes:

- `400` if `user_code` is not found or challenge is not pending
- `401` if session token is missing or invalid

### API key management (session required)

#### Register API key auth token

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

#### List API keys

`GET /api/v1/apikeys`

Response (`200`):

```json
{
  "api_keys": [
    {
      "prefix": "abcdef",
      "scopes": "",
      "created_at": "2026-02-13T00:00:00Z",
      "revoked_at": null
    }
  ]
}
```

#### Revoke API key

`POST /api/v1/apikeys/{prefix}/revoke`

Response (`200`):

```json
{ "ok": true }
```

Other outcomes:

- `400` if key is already revoked (`"key already revoked"`)
- `404` if key does not exist or is not owned by session user

### Delete account (session required)

`DELETE /api/v1/auth/account`

Deletes the current user account and performs cleanup:

1. Burn secrets for `user:<id>` and **all** API key owner keys for the account (including revoked keys).
2. Revoke all API keys for the account.
3. Delete the user record (cascades passkeys/sessions/challenges).

Response (`200`):

```json
{
  "ok": true,
  "secrets_burned": 2,
  "keys_revoked": 1
}
```

## Error Semantics

Common responses:

- `400` invalid request JSON, content type, field types, or validation
- `401` missing/invalid API key or session token (for protected endpoints)
- `404` not found / expired / already claimed / invalid claim token / not owned by caller
- `405` wrong method
- `413` storage quota exceeded
- `429` request rate limited or secret-count quota exceeded
- `500` internal server/storage errors

## Future Metadata Endpoint (v1.1 Draft)

Not part of current runtime contract yet:

- `GET /api/v1/secrets/{id}` (owned single-secret metadata lookup)

Constraints:

- Must not return plaintext, passphrase material, URL fragment keys, or claim tokens.
- Should not return raw `claim_hash` to clients unless there is a strong operational need.
