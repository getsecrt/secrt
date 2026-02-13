# 0.6.0 Implementation Plan: Client-Generated API Root Keys + Passkey-Gated Registration

## Summary
This release hard-cuts API auth from server-generated `sk_` keys to client-generated `sk2_` root keys, where the server only sees derived auth material.  
Execution order is:

1. Update specs (`spec/v1/*`) in place.
2. Implement minimal passkey auth + bearer sessions on server.
3. Implement passkey-authenticated API-key registration with per-account and per-IP caps.
4. Cut server/CLI auth to new key model.
5. Update CLI compatibility for `sk2_`.
6. Bump workspace to `0.6.0` and update changelogs.

Backward compatibility with old API-key format is intentionally not required.

## Locked Product and Security Decisions
1. API namespace stays `/api/v1`.
2. Spec is updated in place under `spec/v1/*`.
3. Local API key format is `sk2_<prefix>.<root_b64>`.
4. Wire API credential format is `ak2_<prefix>.<auth_b64>`.
5. Derived credentials:
   - `ROOT_SALT = SHA256("secrt-apikey-v2-root-salt")`
   - `auth_token = HKDF-SHA256(root_key, ROOT_SALT, "secrt-auth", 32)`
   - `enc_key = HKDF-SHA256(root_key, ROOT_SALT, "secrt-meta-encrypt", 32)`
6. Server verifier uses peppered HMAC, same pattern as current model.
7. API key registration is authenticated by passkey login session only.
8. Session model is bearer token, 24h TTL, re-login after expiry, no refresh flow in 0.6.0.
9. Registration limits are enforced on both account and IP.
10. Defaults are `5/hour` and `20/day` for both account and IP limits.
11. Prefix generation is server-side.
12. `secrt-admin apikey create` is removed.
13. Minimal public auth UI path is included so passkey flow is actually usable/testable.
14. CLI scope is compatibility only (no new key-management commands).

## Public API / Interface Changes

## API Credentials
1. Clients store `sk2_` local key only.
2. Authenticated API requests send derived `ak2_` credential via:
   - `X-API-Key: ak2_<prefix>.<auth_b64>`
   - `Authorization: Bearer ak2_<prefix>.<auth_b64>`
3. Authenticated secret endpoints (`POST /api/v1/secrets`, `POST /api/v1/secrets/{id}/burn`) accept only `ak2_` credentials.

## New Auth Endpoints
1. `POST /api/v1/auth/passkeys/register/start`
2. `POST /api/v1/auth/passkeys/register/finish`
3. `POST /api/v1/auth/passkeys/login/start`
4. `POST /api/v1/auth/passkeys/login/finish`
5. `GET /api/v1/auth/session`
6. `POST /api/v1/auth/logout`

## New API-Key Registration Endpoint
1. `POST /api/v1/apikeys/register` (requires passkey session bearer token)
2. Request body:
```json
{
  "auth_token": "<base64url 32-byte derived token>",
  "scopes": ""
}
```
3. Response body:
```json
{
  "prefix": "<server-generated-prefix>",
  "created_at": "2026-02-13T00:00:00Z"
}
```
4. Client composes local key: `sk2_<prefix>.<root_b64>` (server never sees root).

## Session Bearer Token Format
1. Format: `uss_<sid>.<secret>`
2. Transport: `Authorization: Bearer uss_<sid>.<secret>` for auth/session and registration endpoints only.
3. Session token TTL: 24 hours.

## Metadata Direction in This Release
1. `enc_key` derivation is spec’d now.
2. Runtime metadata list/upsert remains draft/not fully implemented in 0.6.0.
3. Schema support can be added now where low-risk (see DB section), but no full metadata feature rollout in this release.

## Server Configuration Changes
Add these env vars in `crates/secrt-server/src/config.rs`:

1. `SESSION_TOKEN_PEPPER` (required in production).
2. `APIKEY_REGISTER_ACCOUNT_MAX_PER_HOUR` default `5`.
3. `APIKEY_REGISTER_ACCOUNT_MAX_PER_DAY` default `20`.
4. `APIKEY_REGISTER_IP_MAX_PER_HOUR` default `5`.
5. `APIKEY_REGISTER_IP_MAX_PER_DAY` default `20`.
6. `APIKEY_REGISTER_RATE` default `0.5` rps.
7. `APIKEY_REGISTER_BURST` default `6`.

## Database and Storage Changes

## New Migration
Create `crates/secrt-server/migrations/002_auth_apikey_v2.sql` with:

1. `users` table (minimal: id, handle, display_name, created_at).
2. `passkeys` table (id, user_id, credential_id unique, passkey_json, created_at, revoked_at).
3. `sessions` table (id/sid, user_id, token_hash, expires_at, revoked_at, created_at).
4. `webauthn_challenges` table (challenge_id, user_id nullable, purpose, challenge_json, expires_at, created_at).
5. `api_key_registrations` table (id, user_id, ip_hash, created_at).
6. `api_keys` table modifications:
   - rename `key_hash` -> `auth_hash`
   - add `user_id` nullable initially, backfill strategy documented
7. Optional forward-looking columns on `secrets`:
   - `meta_key_version` nullable
   - `enc_meta` nullable jsonb

## Indexes
1. `api_key_registrations(user_id, created_at)`
2. `api_key_registrations(ip_hash, created_at)`
3. `sessions(user_id, expires_at)`
4. `passkeys(user_id, revoked_at)`
5. Unique on `passkeys(credential_id)`

## Server Implementation Plan (File-by-File)

## Domain Auth
Update `crates/secrt-server/src/domain/auth.rs`:

1. Add parser for `ak2_<prefix>.<auth_b64>`.
2. Validate `auth_b64` decodes to 32 bytes.
3. Compute verifier with structured message:
   - `msg = "secrt-apikey-v2-verifier" || u16be(len(prefix)) || prefix_utf8 || auth_token_bytes`
   - `auth_hash = hex(HMAC_SHA256(API_KEY_PEPPER, msg))`
4. Compare against `api_keys.auth_hash` constant-time.
5. Remove legacy `sk_` handling and server-side raw key generation helpers.

## HTTP Router and Handlers
Update `crates/secrt-server/src/http/mod.rs`:

1. Add passkey auth/session endpoints.
2. Add `POST /api/v1/apikeys/register`.
3. Add registration limiter in `AppState`.
4. In registration handler:
   - validate session token and load user
   - validate `auth_token` base64 and length
   - hash IP with existing privacy hasher pattern
   - enforce account/hour + account/day caps via DB query
   - enforce ip/hour + ip/day caps via DB query
   - generate unique prefix server-side
   - compute/store `auth_hash`
   - insert registration event
   - return prefix + timestamp
5. Execute limit check + write operations in one transaction.
6. Keep no-body logging and no secret logging constraints.

## Storage Traits and Postgres
Update:

1. `crates/secrt-server/src/storage/mod.rs`
2. `crates/secrt-server/src/storage/postgres.rs`

Add methods for:

1. user CRUD minimal
2. passkey insert/query/update sign count
3. session create/get/revoke
4. challenge create/get/delete
5. api key insert/get/revoke with `auth_hash`
6. registration count windows (account + IP)
7. registration event insert

## Admin CLI
Update `crates/secrt-server/src/bin/secrt-admin.rs`:

1. Remove `apikey create`.
2. Keep `apikey revoke <prefix>`.
3. Update usage text.
4. Update `crates/secrt-server/tests/admin_cli.rs` accordingly.

## Minimal Public Auth UI
Implement minimal non-polished pages/routes for:

1. passkey register
2. passkey login
3. API key registration call after login

This can live in existing web app route space and only needs enough UX to complete flows and testing.

## CLI Compatibility Plan

## Shared Core Additions
Add to `crates/secrt-core/src/` (new module, e.g. `apikey.rs`), and export in `lib.rs`:

1. `parse_sk2_local_key()`
2. `derive_auth_token_from_root()`
3. `derive_meta_key_from_root()`
4. `format_ak2_wire_credential()`

## API Trait and Types
Update `crates/secrt-core/src/api.rs`:

1. Add register-related request/response structs only if CLI needs compile-time references; keep CLI scope minimal.
2. Keep existing `SecretApi` methods for send/get/burn/info unchanged for this release.

## CLI Client
Update `crates/secrt-cli/src/client.rs`:

1. When `api_key` is present, parse `sk2_`.
2. Derive `auth_token`.
3. Send `ak2_` wire credential for authed calls.
4. Reject malformed keys early with clear message.
5. Do not implement passkey or registration commands.

## CLI Config/Help Text
Update:

1. `crates/secrt-cli/src/config.rs` template (`api_key` example -> `sk2_...`)
2. `crates/secrt-cli/src/cli.rs` help text and docs
3. any README/help snippets referencing `sk_`

## Spec Updates (First Deliverable)
Update in place:

1. `spec/v1/api.md`
2. `spec/v1/server.md`
3. `spec/v1/cli.md`
4. `spec/v1/openapi.yaml`

Also add:
1. `spec/v1/apikey.vectors.json` with deterministic derivation vectors:
   - root key bytes
   - expected auth token
   - expected enc key
   - expected `ak2_` wire credential fragments

## Test Plan

## Server Tests
1. passkey register/login/session happy path.
2. session expiry and logout invalidation.
3. `apikeys/register` success with valid session.
4. register fails without session.
5. register fails with invalid `auth_token` encoding/length.
6. account hourly limit at 6th request fails.
7. account daily limit at 21st request fails.
8. IP hourly limit at 6th request fails.
9. IP daily limit at 21st request fails.
10. auth endpoints and register never log secret material.
11. authed create/burn accepts `ak2_`, rejects legacy `sk_`.
12. `/api/v1/info` `authenticated` true only for valid `ak2_`.

## CLI Tests
1. valid `sk2_` parses and derives stable `ak2_`.
2. `send --api-key sk2_...` hits authenticated create path successfully.
3. `burn --api-key sk2_...` succeeds with owned secrets.
4. `info` with `sk2_` reflects authenticated true.
5. malformed local key format errors cleanly.

## Vector Tests
1. add Rust tests for `apikey.vectors.json` in core and CLI.

## E2E/Integration
1. update existing server integration fixtures that currently mint `sk_`.
2. e2e flow:
   - register/login via passkey
   - register API key (derived auth token)
   - CLI uses composed `sk2_` to send/burn/info.

## Version and Changelog Work
1. bump workspace version in `Cargo.toml` to `0.6.0`.
2. update `secrt-core` dependency versions in:
   - `crates/secrt-cli/Cargo.toml`
   - `crates/secrt-server/Cargo.toml`
3. update changelogs:
   - `CHANGELOG.md`
   - `crates/secrt-cli/CHANGELOG.md`
   - `crates/secrt-core/CHANGELOG.md`
   - `crates/secrt-server/CHANGELOG.md`
4. note breaking auth format change and passkey-gated registration in all relevant entries.

## Acceptance Criteria
1. Specs fully describe `sk2_/ak2_`, passkey sessions, and registration limits.
2. Server never receives root keys and never stores metadata decryption keys.
3. Registration is passkey-authenticated and enforces both account and IP caps with configured defaults.
4. Legacy `sk_` auth path is removed.
5. CLI authenticated workflows work with `sk2_` local keys.
6. All workspace checks pass: fmt, clippy (`-D warnings`), tests.

## Assumptions and Defaults
1. This is alpha and can break old key format.
2. Passkey/session feature is intentionally minimal in 0.6.0.
3. Session tokens are bearer and DB-backed with 24h expiry.
4. Metadata full runtime APIs remain out of 0.6.0 scope; only key-derivation/spec groundwork is required now.
5. Registration defaults: `5/hour`, `20/day` for both account and IP.
