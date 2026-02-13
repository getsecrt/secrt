# Server Runtime Specification (v1)

Status: Active for current implementation.

This document describes how the v1 server behaves at runtime. Unlike the API spec, this file covers internal behavior: storage operations, TTL enforcement mechanics, middleware, timeouts, and cleanup loops.

Source-of-truth code paths:

- `crates/secrt-server/src/main.rs`
- `crates/secrt-server/src/http/mod.rs`
- `crates/secrt-server/src/domain/auth.rs`
- `crates/secrt-server/src/storage/postgres.rs`
- `crates/secrt-server/migrations/001_initial.sql`
- `crates/secrt-server/migrations/002_auth_apikey_v2.sql`

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

- `ReadHeaderTimeout`: 5s
- `ReadTimeout`: 15s
- `WriteTimeout`: 15s
- `IdleTimeout`: 60s

On shutdown, the server performs graceful HTTP shutdown with a 10s timeout.

## 3. Database and Schema

Runtime database is Postgres (via `tokio-postgres` + `deadpool-postgres`).

Connection pool settings:

- max open conns: 10
- max idle conns: 10
- conn max lifetime: 30m

Primary tables:

- `secrets(id, claim_hash, envelope, expires_at, created_at, owner_key)`
- `api_keys(id, key_prefix, auth_hash, scopes, user_id, created_at, revoked_at)`
- `users(id, handle, display_name, created_at)`
- `passkeys(id, user_id, credential_id, public_key, sign_count, created_at, revoked_at)`
- `sessions(id, sid, user_id, token_hash, expires_at, created_at, revoked_at)`
- `webauthn_challenges(id, challenge_id, user_id, purpose, challenge_json, expires_at, created_at)`
- `api_key_registrations(id, user_id, ip_hash, created_at)`

Indexes:

- `secrets_expires_at_idx` for expiry-related queries
- `secrets_owner_key_idx` for owner-scoped usage queries
- `api_key_registrations_user_created_idx` for account window quotas
- `api_key_registrations_ip_created_idx` for IP window quotas

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
- `GET /robots.txt`
- `POST /api/v1/public/secrets`
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

## 6. Auth and Authorization

Authenticated endpoints:

- `POST /api/v1/secrets`
- `POST /api/v1/secrets/{id}/burn`
- `POST /api/v1/apikeys/register` (session-authenticated)

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
3. Lookup by prefix.
4. Reject revoked keys.
5. Constant-time compare stored hash vs computed hash.

Notes:

- Missing or invalid keys return `401 unauthorized`.
- If `API_KEY_PEPPER` is unset, API-key auth cannot succeed.
- API key `scopes` are stored but not currently enforced by runtime handlers.
- Passkey session tokens use `Authorization: Bearer uss_<sid>.<secret>` and are valid for 24h.

## 7. Ownership and Quota Model

The server tracks an internal `owner_key` for each secret:

- Public create: owner key is `ip:<HMAC-SHA256(client_ip)>`, keyed with a per-process random secret. Raw IPs are **never persisted** to the database.
- Authenticated create: owner key is `apikey:<prefix>`.

Because the HMAC key is per-process, public quota tracking resets on server restart. This is acceptable because secrets expire via TTL and the reaper deletes them; a brief window of relaxed quotas after restart is not a meaningful abuse vector.

This owner key drives policy only:

- per-owner active-secret quota checks
- per-owner active-byte quota checks
- owner-scoped burn authorization for authenticated secrets

Ownership metadata does not affect claim/decrypt semantics. Claim remains bearer-by-token.

## 8. Rate Limiting

Limiter implementation is an in-memory token bucket keyed by string.

**Privacy:** Rate limiter keys are HMAC-SHA256 hashed with a per-process random key before use as map keys. Raw client IPs never appear in process memory data structures.

**Garbage collection:** A background goroutine sweeps stale buckets every 2 minutes, evicting any bucket idle for more than 10 minutes. This bounds memory growth and limits the window during which any IP-derived data exists in memory.

Configured limits:

- Public create: `0.5 rps`, burst `6` (about 30/min, burst 6) keyed by client IP hash.
- Claim: `1.0 rps`, burst `10` keyed by client IP hash.
- Authenticated create: `2.0 rps`, burst `20` keyed by API key prefix.
- API-key registration: `0.5 rps`, burst `6` keyed by client IP.
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

Claim request (`POST /api/v1/secrets/{id}/claim`):

- Requires `Content-Type: application/json`
- Max body size: 8KiB
- JSON unknown fields rejected
- Requires non-empty `claim`
- Invalid claim token encoding/length is treated as `404` to reduce existence leaks

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

## 12. Owner-Scoped Burn

Burn authorization uses authenticated owner keys.

- Handler authenticates API key, computes owner key `apikey:<prefix>`, and passes that to storage.
- Storage delete condition includes both `id` and `owner_key`.

Postgres query shape:

- `DELETE FROM secrets WHERE id=$1 AND owner_key=$2`

Properties:

- API keys can only burn secrets they created.
- Missing ID and wrong owner are indistinguishable to clients (`404`).

## 13. Background Expired-Secret Reaper

A best-effort cleanup goroutine runs every 5 minutes:

- Calls `DeleteExpired(nowUTC)` with a 10s context timeout.
- Deletes rows where `expires_at <= now`.

Important:

- Reaper is not required for correctness of one-time claim behavior.
- Reaper failures are currently ignored (best-effort housekeeping).

## 14. Error Mapping (Current)

Common responses:

- `400` invalid JSON / field/type/validation issues
- `401` missing or invalid API key
- `404` secret not found, expired, already claimed, wrong/invalid claim token, or burn not owned
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
