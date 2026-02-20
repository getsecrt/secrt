# Server Runtime Specification (v1)

Status: Active for current implementation.

This document describes how the v1 server behaves at runtime. Unlike the API spec, this file covers internal behavior: storage operations, TTL enforcement mechanics, middleware, timeouts, and cleanup loops.

Source-of-truth code paths:

- `crates/secrt-server/src/main.rs`
- `crates/secrt-server/src/http/mod.rs`
- `crates/secrt-server/src/domain/auth.rs`
- `crates/secrt-server/src/storage/postgres.rs`
- `crates/secrt-server/migrations/001_initial.sql`

## 1. Scope

This spec is for server runtime behavior only:

- request handling and middleware
- auth, rate limits, and validation
- persistence and atomic claim semantics
- TTL and cleanup behavior

It is not the client crypto format spec. See:

- `spec/v1/envelope.md`

It is also not the CLI UX/argument spec. See:

- `spec/v1/cli.md`

## 2. Startup and Shutdown

On startup, the server:

1. Creates a root context canceled by `SIGINT` / `SIGTERM`.
2. Loads `.env` automatically when `ENV != production`.
3. Loads config and initializes JSON logging (`tracing`).
4. Opens Postgres and pings it.
5. Runs DB migrations before serving requests.
6. Starts HTTP server.
7. Starts a background expired-row cleanup ticker.

HTTP server timeouts:

- `read_header_timeout`: 5s
- `request_timeout`: 15s
- `write_timeout`: 15s
- `idle_timeout`: 60s

On shutdown, the server performs graceful HTTP shutdown with a 10s timeout.

## 3. Database and Schema

Runtime database is Postgres (via `tokio-postgres` + `deadpool-postgres`).

Connection pool settings (`deadpool-postgres`):

- max size: 10
- conn max lifetime: 30m

Primary tables:

- `secrets(id, claim_hash, envelope, expires_at, created_at, owner_key, meta_key_version SMALLINT, enc_meta JSONB)`
- `api_keys(id, key_prefix, auth_hash, scopes, user_id, created_at, revoked_at)`
- `users(id UUIDv7, display_name, last_active_at DATE, created_at)`
- `passkeys(id, user_id, credential_id, public_key, sign_count, label TEXT DEFAULT '', created_at, revoked_at)`
- `sessions(id, sid, user_id, token_hash, expires_at, created_at, revoked_at)`
- `webauthn_challenges(id, challenge_id, user_id, purpose, challenge_json, expires_at, created_at)`
- `api_key_registrations(id, user_id, ip_hash, created_at)`
- `amk_accounts(user_id UUID PRIMARY KEY, amk_commit, created_at)`
- `amk_wrappers(id, user_id, key_prefix, wrapped_amk, nonce, version SMALLINT, created_at, UNIQUE(user_id, key_prefix))`

AMK table notes:

- `amk_accounts` enforces one commit value per user. All wrappers for a user must share the same `amk_commit`. This prevents accidental overwrites with a different AMK.
- `amk_wrappers` stores one wrapped AMK per API key. The `key_prefix` column has a unique constraint. The wrapping key is derived from the API key's root key; the server never sees the plaintext AMK.

User identifier notes:

- `users.id` is server-generated UUIDv7.
- All auth-linked `user_id` foreign keys (`api_keys`, `passkeys`, `sessions`, `webauthn_challenges`, `api_key_registrations`) are UUID-typed.

Indexes:

- `secrets_expires_at_idx` for expiry-related queries
- `secrets_owner_key_idx` for owner-scoped usage queries
- `passkeys_user_id_idx` on passkeys (user_id, revoked_at)
- `sessions_user_id_idx` on sessions (user_id, expires_at)
- `webauthn_challenges_purpose_idx` on webauthn_challenges (purpose, expires_at)
- `apikey_regs_user_created_idx` for account window quotas
- `apikey_regs_ip_created_idx` for IP window quotas

## 4. Middleware and Request Processing

Middleware stack order (outermost to innermost):

1. privacy log check (advisory, fires once)
2. request logging
3. security headers
4. request ID
5. panic recovery
6. route handler

Security headers set on all responses:

- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `X-Frame-Options: DENY`

JSON responses always set:

- `Content-Type: application/json`
- `Cache-Control: no-store`

Request IDs:

- Uses incoming `X-Request-Id` if provided.
- Otherwise generates 16 random bytes (hex encoded).
- Echoed back in `X-Request-Id` response header.

Logging fields:

- method, path, status, bytes, duration_ms, request_id (if present)

The server trusts `X-Forwarded-For` only when `RemoteAddr` is loopback (`127.0.0.1` or `::1`), extracting the leftmost IP for rate limiting. When not behind a trusted proxy, client identity uses `RemoteAddr` directly.

### 4.1. Privacy Log Header Check

The server checks the `X-Privacy-Log` request header on the first proxied request to verify that the reverse proxy has been configured for privacy-preserving access logging. This is an advisory check — it does not block requests.

**Trigger condition:** The check fires once per process lifetime, on the first request where `X-Forwarded-For` is present (indicating a reverse proxy). Direct connections (no `X-Forwarded-For`) are ignored.

**Header contract:**

| `X-Privacy-Log` value | Behavior |
|---|---|
| `truncated-ip` | `INFO` log confirming privacy-preserving logging is configured |
| (absent) | `WARN` log advising that access logs may contain full client IPs |
| any other value | `WARN` log noting unrecognized value |

**Trust model:** This header is advisory only. An attacker spoofing `X-Privacy-Log: truncated-ip` can only suppress a warning, not gain access or bypass any security control. No loopback restriction is applied.

The header is an internal signal between the reverse proxy and the application and must not be forwarded to clients.

## 5. Route Surface (Current)

- `GET /healthz`
- `GET /`
- `GET /s/{id}`
- `GET /login`
- `GET /register`
- `GET /how-it-works`
- `GET /privacy`
- `GET /dashboard`
- `GET /settings`
- `GET /robots.txt`
- `GET /.well-known/security.txt`
- `GET /static/*` (embedded or filesystem assets)
- `GET /api/v1/info`
- `POST /api/v1/public/secrets`
- `GET /api/v1/secrets/check`
- `GET /api/v1/secrets`
- `GET /api/v1/secrets/{id}`
- `POST /api/v1/secrets`
- `POST /api/v1/secrets/{id}/claim`
- `POST /api/v1/secrets/{id}/burn`
- `POST /api/v1/auth/passkeys/register/start`
- `POST /api/v1/auth/passkeys/register/finish`
- `POST /api/v1/auth/passkeys/login/start`
- `POST /api/v1/auth/passkeys/login/finish`
- `GET /api/v1/auth/session`
- `POST /api/v1/auth/logout`
- `POST /api/v1/apikeys/register`
- `GET /api/v1/apikeys`
- `POST /api/v1/apikeys/{prefix}/revoke`
- `GET /device`
- `POST /api/v1/auth/device/start`
- `POST /api/v1/auth/device/poll`
- `POST /api/v1/auth/device/approve`
- `GET /api/v1/auth/device/challenge`
- `PUT /api/v1/amk/wrapper`
- `GET /api/v1/amk/wrapper`
- `GET /api/v1/amk/wrappers`
- `GET /api/v1/amk/exists`
- `PUT /api/v1/secrets/{id}/meta`
- `GET /api/v1/auth/passkeys`
- `POST /api/v1/auth/passkeys/add/start`
- `POST /api/v1/auth/passkeys/add/finish`
- `PATCH /api/v1/auth/passkeys/{id}`
- `POST /api/v1/auth/passkeys/{id}/revoke`
- `POST /api/v1/amk/commit`
- `PATCH /api/v1/auth/account`
- `DELETE /api/v1/auth/account`

## 6. Auth and Authorization

Authenticated endpoints:

- `GET /api/v1/secrets`
- `GET /api/v1/secrets/{id}` (session or API key)
- `GET /api/v1/secrets/check`
- `POST /api/v1/secrets`
- `POST /api/v1/secrets/{id}/burn`
- `POST /api/v1/apikeys/register` (session-authenticated)
- `GET /api/v1/apikeys` (session-authenticated)
- `POST /api/v1/apikeys/{prefix}/revoke` (session-authenticated)
- `PUT /api/v1/amk/wrapper` (session or API key)
- `GET /api/v1/amk/wrapper` (session or API key)
- `GET /api/v1/amk/wrappers` (session-authenticated)
- `GET /api/v1/amk/exists` (session or API key)
- `PUT /api/v1/secrets/{id}/meta` (session or API key, must own secret)
- `GET /api/v1/auth/device/challenge` (session-authenticated)
- `GET /api/v1/auth/passkeys` (session-authenticated)
- `POST /api/v1/auth/passkeys/add/start` (session-authenticated)
- `POST /api/v1/auth/passkeys/add/finish` (session-authenticated)
- `PATCH /api/v1/auth/passkeys/{id}` (session-authenticated)
- `POST /api/v1/auth/passkeys/{id}/revoke` (session-authenticated)
- `POST /api/v1/amk/commit` (session-authenticated)
- `PATCH /api/v1/auth/account` (session-authenticated)
- `DELETE /api/v1/auth/account` (session-authenticated)

Credential sources:

- `X-API-Key`
- `Authorization: Bearer <key>`

API key format:

- local: `sk2_<prefix>.<root_b64>` (client storage only)
- wire: `ak2_<prefix>.<auth_b64>` (request header value)

Legacy `sk_` credentials are rejected.

Verification model:

1. Parse `ak2_<prefix>.<auth_b64>`.
2. Decode `auth_b64` to 32-byte auth token.
3. Build verifier message:
   - `"secrt-apikey-v2-verifier" || u16be(len(prefix)) || prefix_utf8 || auth_token_bytes`
4. Compute `HMAC-SHA256(API_KEY_PEPPER, message)` (hex encoded).
5. Lookup by prefix.
6. Reject revoked keys.
7. Constant-time compare stored hash vs computed hash.

Notes:

- Missing or invalid keys return `401 unauthorized`.
- If `API_KEY_PEPPER` is unset, API-key auth cannot succeed.
- API key `scopes` are stored but not currently enforced by runtime handlers.
- Passkey session tokens use `Authorization: Bearer uss_<sid>.<secret>` and are valid for 24h.
- Passkey `/finish` handlers in v1 are challenge-id bearer flows: they consume a valid, unexpired `challenge_id` and verify credential linkage, but do not verify WebAuthn signatures.
- `GET/POST /api/v1/secrets` and `GET /api/v1/secrets/check` try session auth first, then API key fallback.
- `POST /api/v1/secrets/{id}/burn` tries API key auth first, then session fallback.

### 6.1. Device Authorization Flow

Device authorization enables CLI tools to obtain API keys via browser-based approval. The root key never leaves the CLI — only the derived `auth_token` is sent to the server.

Storage reuse: device-auth challenges are stored in the `webauthn_challenges` table with `purpose = "device-auth"`. No schema migration is needed.

**`POST /api/v1/auth/device/start`** (unauthenticated, IP rate-limited):

1. Validate `auth_token` decodes as base64url to exactly 32 bytes.
2. Generate `device_code` (32 random bytes, base64url) and `user_code` (8 chars from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, formatted `XXXX-XXXX`).
3. Store challenge: `challenge_id = device_code`, `purpose = "device-auth"`, 10-minute expiry, `challenge_json = { user_code, auth_token_b64, status: "pending", prefix: null, user_id: null }`.
4. Return `{ device_code, user_code, verification_url, expires_in: 600, interval: 5 }`.

**`POST /api/v1/auth/device/poll`** (unauthenticated, IP rate-limited):

1. Look up challenge by `device_code` and `purpose = "device-auth"` (non-consuming read).
2. If pending → return `{ "status": "authorization_pending" }`.
3. If approved → consume the challenge (delete it), return `{ "status": "complete", "prefix": "..." }`.
4. If not found or expired → return `400` `{ "error": "expired_token" }`.

**`POST /api/v1/auth/device/approve`** (requires session auth):

1. Look up a pending `device-auth` challenge by `user_code` (constant-time comparison).
2. Verify challenge status is `"pending"`.
3. Generate API key prefix, compute `auth_hash` from `pepper + prefix + auth_token` (same verifier contract as `POST /api/v1/apikeys/register`).
4. Register API key linked to session user (reuses existing registration quota logic).
5. Update challenge status to `"approved"` with the generated prefix.
6. Return `{ "ok": true }`.

## 7. Ownership and Quota Model

The server tracks an internal `owner_key` for each secret:

- Public create: owner key is `ip:<HMAC-SHA256(client_ip)>`, keyed with a per-process random secret. Raw IPs are **never persisted** to the database.
- Session-authenticated create: owner key is `user:<uuid>`.
- API-key-authenticated create: owner key is `apikey:<prefix>`.

Because the HMAC key is per-process, public quota tracking resets on server restart. This is acceptable because secrets expire via TTL and the reaper deletes them; a brief window of relaxed quotas after restart is not a meaningful abuse vector.

This owner key drives policy only:

- per-owner active-secret quota checks
- per-owner active-byte quota checks
- owner-scoped list/check/burn authorization for authenticated secrets

Ownership metadata does not affect claim/decrypt semantics. Claim remains bearer-by-token.

## 8. Rate Limiting

Limiter implementation is an in-memory token bucket keyed by string.

**Privacy:** Rate limiter keys are HMAC-SHA256 hashed with a per-process random key before use as map keys. Raw client IPs never appear in process memory data structures.

**Garbage collection:** A background Tokio task sweeps stale buckets every 2 minutes, evicting any bucket idle for more than 10 minutes. This bounds memory growth and limits the window during which any IP-derived data exists in memory.

Configured limits:

- Public create: `0.5 rps`, burst `6` (about 30/min, burst 6) keyed by client IP hash.
- Claim: `1.0 rps`, burst `10` keyed by client IP hash.
- Authenticated create: `2.0 rps`, burst `20`, keyed by `user:<id>` (session auth) or `apikey:<prefix>` (API key auth).
- API-key registration: `0.5 rps`, burst `6` keyed by client IP.
- Device auth start/poll: uses public create limiter (`0.5 rps`, burst `6`) keyed by client IP hash.
- Burn: no dedicated limiter in v1 (API key auth + owner checks apply).

Important runtime property:

- This is per-process, not distributed. Multi-instance deployments need a shared/global limiter for strict global limits.

## 9. Input Validation and Limits

Create request (`POST /api/v1/public/secrets`, `POST /api/v1/secrets`):

- Requires `Content-Type: application/json`
- Max body size: per-tier envelope limit + 16KiB overhead
  - Public: `PUBLIC_MAX_ENVELOPE_BYTES + 16KiB` (default `256KiB + 16KiB`)
  - Authenticated: `AUTHED_MAX_ENVELOPE_BYTES + 16KiB` (default `1MiB + 16KiB`)
- JSON unknown fields rejected
- Must contain valid `envelope` object JSON
- Server treats envelope internals as opaque ciphertext and cannot read payload metadata (`type`, `filename`, `mime`), which is encrypted client-side
- Envelope size checked against per-tier limit -> `400` with human-readable limit in message
- Must contain valid `claim_hash` (`base64url(sha256(...))` format)
- `ttl_seconds` rules:
  - default: 24h when omitted
  - accepted: any positive integer seconds up to 31536000 (1 year)
- per-owner quota checks:
  - secret count limit -> `429` (`"secret limit exceeded (max N active secrets)"`)
  - active stored bytes limit -> `413` (`"storage quota exceeded (limit <size>)"`)

All size and quota limits are configurable per server instance via environment variables. See the Policy Tiers section of the API spec.

API-key registration request (`POST /api/v1/apikeys/register`):

- Requires `Authorization: Bearer uss_<sid>.<secret>`
- Requires `Content-Type: application/json`
- Body field `auth_token` MUST decode as base64url to 32 bytes
- Registration quotas are evaluated on both dimensions:
  - account/hour, account/day
  - ip/hour, ip/day
- Quota checks + `api_keys` insert + `api_key_registrations` insert execute atomically in one DB transaction
- Default limits:
  - account: `5/hour`, `20/day`
  - IP: `5/hour`, `20/day`

Device authorization start (`POST /api/v1/auth/device/start`):

- Requires `Content-Type: application/json`
- Body field `auth_token` MUST decode as base64url to exactly 32 bytes
- IP rate-limited

Device authorization poll (`POST /api/v1/auth/device/poll`):

- Requires `Content-Type: application/json`
- Body field `device_code` MUST be a non-empty string
- IP rate-limited

Device authorization approve (`POST /api/v1/auth/device/approve`):

- Requires `Authorization: Bearer uss_<sid>.<secret>`
- Requires `Content-Type: application/json`
- Body field `user_code` MUST be a non-empty string
- User code comparison is constant-time
- Reuses API key registration quota enforcement

List request (`GET /api/v1/secrets`):

- Requires auth (session or API key).
- Query params:
  - `limit` default `50`, clamped to `1..20000`
  - `offset` default `0`, clamped to `>= 0`
- Session auth scope: `user:<id>` plus each unrevoked owned `apikey:<prefix>`.
- API key scope: only `apikey:<prefix>` for that key.

Secrets check request (`GET /api/v1/secrets/check`):

- Requires auth (session or API key).
- No body.
- Same ownership scope rules as `GET /api/v1/secrets`.
- Returns `{count, checksum}` for lightweight dashboard polling.

Claim request (`POST /api/v1/secrets/{id}/claim`):

- Requires `Content-Type: application/json`
- Max body size: 8KiB
- JSON unknown fields rejected
- Requires non-empty `claim`
- Invalid claim token encoding/length is treated as `404` to reduce existence leaks

Burn request (`POST /api/v1/secrets/{id}/burn`):

- Requires auth (session or API key).
- No request body required.
- API key auth burns only `apikey:<prefix>` owned rows.
- Session auth attempts `user:<id>` and each unrevoked owned `apikey:<prefix>`.

Encrypted notes (`PUT /api/v1/secrets/{id}/meta`):

- Requires auth (session or API key).
- Caller must own the secret.
- `enc_meta` is stored as JSONB in the `secrets` table.
- `enc_meta` byte size is included in the owner's active total bytes for quota accounting. This prevents quota bypass via large notes.
- `meta_key_version` is stored alongside and tracks which AMK version encrypted the note.

AMK wrapper endpoints:

- `PUT /api/v1/amk/wrapper`: session or API key auth. API key auth infers `key_prefix` from the authenticated key. Session auth requires `key_prefix` in body. Upserts the wrapper and validates `amk_commit` against existing account commit (409 on mismatch).
- `GET /api/v1/amk/wrapper`: session or API key auth. API key auth returns own wrapper. Session auth requires `?key_prefix=X`.
- `GET /api/v1/amk/wrappers`: session auth only. Returns all wrappers for the user.
- `GET /api/v1/amk/exists`: session or API key auth. Returns `{ exists: bool }`.
- `POST /api/v1/amk/commit`: session auth only. Eagerly commits an AMK hash (first-writer-wins). Returns 409 if a different hash is already committed.

Feature flags:

- `ENCRYPTED_NOTES_ENABLED` (env var, default `true`): when `false`, `PUT /api/v1/secrets/{id}/meta` returns `404` and `enc_meta` is omitted from list responses. The `GET /api/v1/info` response includes `features.encrypted_notes` reflecting this flag.

API key listing/revocation/account management:

- `GET /api/v1/apikeys`, `POST /api/v1/apikeys/{prefix}/revoke`, `PATCH /api/v1/auth/account`, and `DELETE /api/v1/auth/account` require session auth.
- Revoke returns `400` when key is already revoked.

Passkey management:

- `GET /api/v1/auth/passkeys`, `POST .../add/start`, `POST .../add/finish`, `PATCH .../passkeys/{id}`, and `POST .../passkeys/{id}/revoke` require session auth.
- Cannot revoke the last active passkey (returns `400`).
- Labels are trimmed and capped at 100 characters.

## 10. TTL and Expiry Semantics

TTL is enforced in two layers:

1. Logical enforcement on claim path (authoritative):
   - claim query only succeeds when `expires_at > now`
2. Background cleanup for storage hygiene:
   - periodic delete of expired rows

This means expired secrets are not claimable even if cleanup has not run yet.

## 11. Atomic One-Time Claim

One-time semantics are implemented in a single SQL statement:

- `DELETE FROM secrets ... WHERE id=$1 AND claim_hash=$2 AND expires_at>$3 RETURNING ...`

Properties:

- At most one successful claim for a given secret.
- Wrong claim token, expired secret, or already-claimed secret all resolve to not found behavior.
- API returns `404` for all those cases.

## 12. Owner-Scoped Authorization

Burn/list/check authorization uses authenticated owner keys.

- List/check handlers try session auth first, then API key fallback.
- Burn handler tries API key auth first, then session fallback.
- API key path computes owner key `apikey:<prefix>`.
- Session path resolves owner keys as `user:<id>` plus unrevoked owned `apikey:<prefix>` keys.
- Storage delete condition includes both `id` and `owner_key`.

Postgres query shape:

- `DELETE FROM secrets WHERE id=$1 AND owner_key=$2`

Properties:

- API keys can only burn secrets they created.
- Session users can burn/list/check secrets for their user owner key and their unrevoked API key owner keys.
- Missing ID and wrong owner are indistinguishable to clients (`404`).

## 13. Background Expired-Secret Reaper

A best-effort cleanup Tokio task runs every 5 minutes:

- Calls storage `delete_expired(nowUTC)` with a 10s timeout.
- Deletes:
  - expired `secrets`
  - expired `webauthn_challenges`
  - expired or revoked `sessions`
  - `api_key_registrations` older than 24 hours

Important:

- Reaper is not required for correctness of one-time claim behavior.
- Reaper failures are logged and ignored (best-effort housekeeping).

## 14. Error Mapping (Current)

Common responses:

- `400` invalid JSON / field/type/validation issues
- `401` missing or invalid API key/session token
- `404` secret not found, expired, already claimed, wrong/invalid claim token, or owner mismatch
- `405` wrong method
- `413` storage quota exceeded
- `429` rate limited
- `500` unexpected server or storage errors

## 15. Logging and Secret-Safety Notes

Current server logging records metadata (method/path/status/bytes/duration/request_id), not request bodies.

Operational requirement remains:

- Do not add plaintext, passphrases, claim tokens, or envelope payloads to logs.

## 16. Alignment Rule

When this server spec is changed, implementation and tests must be updated in the same change set.
