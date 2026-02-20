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
  "auth_token": "<base64url 32-byte auth token>",
  "ecdh_public_key": "<base64url P-256 public key>"
}
```

`ecdh_public_key` is optional. When present, the CLI is advertising its ephemeral ECDH public key for AMK transfer during device approval. The key is stored in the challenge JSON and surfaced via `GET /api/v1/auth/device/challenge`.

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
- Approved: `200` `{ "status": "complete", "prefix": "<api_key_prefix>", "amk_transfer": { "ct": "...", "nonce": "...", "ecdh_public_key": "..." } }` — the challenge is consumed on this response.
- Expired or not found: `400` `{ "error": "expired_token" }`

`amk_transfer` is present only when the approver attached encrypted AMK material during `POST /api/v1/auth/device/approve`. When absent, the device has no AMK and must set one up independently.

The CLI constructs the full local key as `sk2_<prefix>.<base64(root_key)>` using the prefix from the response and the locally-held root key.

#### Get device challenge details

`GET /api/v1/auth/device/challenge`

Session auth required.

Query params:

- `user_code` (required): the user code to look up.

Response (`200`):

```json
{
  "user_code": "ABCD-1234",
  "ecdh_public_key": "<base64url P-256 public key>",
  "status": "pending"
}
```

`ecdh_public_key` is present only if the CLI included one in `/device/start`. The browser uses this to perform ECDH key agreement and encrypt the AMK for transfer.

Returns `404` if the user code is not found or the challenge is not pending.

#### Approve device authorization (session required)

`POST /api/v1/auth/device/approve`

Headers:

- `Authorization: Bearer uss_<sid>.<secret>`

Request:

```json
{
  "user_code": "ABCD-1234",
  "amk_transfer": {
    "ct": "<base64url encrypted AMK>",
    "nonce": "<base64url 12-byte nonce>",
    "ecdh_public_key": "<base64url P-256 public key>"
  }
}
```

`amk_transfer` is optional. When the approver has an AMK and the CLI advertised an ECDH public key, the browser encrypts the AMK using the ECDH shared secret and attaches the ciphertext here.

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

### Passkey management (session required)

These endpoints manage the passkey credentials linked to a user's account. All require session auth.

#### List passkeys

`GET /api/v1/auth/passkeys`

Response (`200`):

```json
{
  "passkeys": [
    {
      "id": 1,
      "label": "MacBook Pro",
      "created_at": "2026-02-13T00:00:00Z"
    }
  ]
}
```

#### Add passkey — start

`POST /api/v1/auth/passkeys/add/start`

No request body required. Returns a challenge for the WebAuthn ceremony.

Response (`200`):

```json
{
  "challenge_id": "<base64url>",
  "challenge": "<base64url 32-byte challenge>",
  "expires_at": "2026-02-13T00:10:00Z"
}
```

Challenge expires after 10 minutes.

#### Add passkey — finish

`POST /api/v1/auth/passkeys/add/finish`

Request:

```json
{
  "challenge_id": "<base64url>",
  "credential_id": "<non-empty string>",
  "public_key": "<non-empty string>"
}
```

Response (`200`):

```json
{
  "ok": true,
  "passkey": {
    "id": 2,
    "label": "",
    "created_at": "2026-02-13T00:00:00Z"
  }
}
```

Other outcomes:

- `400` if `challenge_id` is invalid/expired, or `credential_id`/`public_key` is empty.

#### Rename passkey

`PATCH /api/v1/auth/passkeys/{id}`

Request:

```json
{
  "label": "Work laptop"
}
```

`label` is trimmed and must be 100 characters or fewer. Empty labels are allowed.

Response (`200`):

```json
{ "ok": true }
```

Other outcomes:

- `400` if `label` exceeds 100 characters.
- `404` if passkey ID does not exist or is not owned by the session user.

#### Revoke passkey

`POST /api/v1/auth/passkeys/{id}/revoke`

No request body.

Response (`200`):

```json
{ "ok": true }
```

Other outcomes:

- `400` if the passkey is the user's only active passkey (`"cannot revoke last active passkey"`).
- `404` if passkey ID does not exist or is not owned by the session user.

### Account Master Key (AMK)

The AMK is a client-generated symmetric key used to encrypt per-secret notes. The server stores only wrapped (encrypted) copies of the AMK — one per API key. The wrapping key is derived from the API key's root key. The server never sees the plaintext AMK.

#### Upsert AMK wrapper

`PUT /api/v1/amk/wrapper`

Auth required (session or API key).

Request:

```json
{
  "key_prefix": "abcdef",
  "wrapped_amk": "<base64url>",
  "nonce": "<base64url 12-byte nonce>",
  "amk_commit": "<base64url commit hash>",
  "version": 1
}
```

- API key auth: operates on the caller's own prefix. `key_prefix` is optional (inferred from the authenticated key).
- Session auth: `key_prefix` is required in the body to identify the target API key.

`amk_commit` is a commitment value binding the AMK identity across all wrappers for the same user. The server enforces that all wrappers for a given user share the same `amk_commit`.

Response (`200`):

```json
{ "ok": true }
```

Other outcomes:

- `409` if `amk_commit` does not match the existing commit for the user (prevents accidental overwrites with a different AMK).
- `401` if auth is missing/invalid.

#### Get AMK wrapper

`GET /api/v1/amk/wrapper`

Auth required (session or API key).

- API key auth: returns the wrapper for the authenticated key. No params needed.
- Session auth: requires `?key_prefix=X` query parameter.

Response (`200`):

```json
{
  "user_id": "<uuid>",
  "wrapped_amk": "<base64url>",
  "nonce": "<base64url>",
  "version": 1
}
```

Returns `404` if no wrapper exists for the specified key.

#### List AMK wrappers

`GET /api/v1/amk/wrappers`

Session auth only.

Response (`200`):

```json
{
  "wrappers": [
    {
      "key_prefix": "abcdef",
      "version": 1,
      "created_at": "2026-02-13T00:00:00Z"
    }
  ]
}
```

#### Check AMK existence

`GET /api/v1/amk/exists`

Auth required (session or API key).

Response (`200`):

```json
{ "exists": true }
```

Returns `true` if the authenticated user has at least one AMK wrapper stored.

#### Commit AMK hash

`POST /api/v1/amk/commit`

Session auth only.

Eagerly commits an AMK hash so that other devices can detect an existing key before syncing. Uses first-writer-wins semantics — once a commit is established, subsequent calls with a different hash return `409`.

Request:

```json
{
  "amk_commit": "<base64url 32-byte commitment hash>"
}
```

`amk_commit` must decode to exactly 32 bytes.

Response (`200`):

```json
{ "ok": true }
```

Other outcomes:

- `400` if `amk_commit` is not valid base64url or does not decode to 32 bytes.
- `409` if a different AMK hash is already committed for this account.

### Encrypted Notes

Encrypted notes allow authenticated users to attach a client-encrypted label to a secret they own. Notes are encrypted with a key derived from the AMK and stored server-side as opaque ciphertext.

#### Attach encrypted note

`PUT /api/v1/secrets/{id}/meta`

Auth required (session or API key). Caller must own the secret.

Request:

```json
{
  "enc_meta": {
    "v": 1,
    "note": {
      "ct": "<base64url ciphertext>",
      "nonce": "<base64url 12-byte nonce>",
      "salt": "<base64url HKDF salt>"
    }
  },
  "meta_key_version": 1
}
```

`EncMetaV1` schema:

- `v`: integer, must be `1`.
- `note.ct`: base64url-encoded AES-256-GCM ciphertext of the note text.
- `note.nonce`: base64url-encoded 12-byte GCM nonce.
- `note.salt`: base64url-encoded HKDF salt used to derive the per-note encryption key from the AMK.

Response (`200`):

```json
{ "ok": true }
```

Other outcomes:

- `404` if the secret does not exist or is not owned by the caller.
- `401` if auth is missing/invalid.

#### Notes in list responses

`ListSecretsResponse` items include an optional `enc_meta` field:

```json
{
  "id": "…",
  "share_url": "https://secrt.ca/s/…",
  "expires_at": "2026-02-04T00:00:00Z",
  "created_at": "2026-02-03T00:00:00Z",
  "ciphertext_size": 1234,
  "passphrase_protected": true,
  "enc_meta": {
    "v": 1,
    "note": { "ct": "...", "nonce": "...", "salt": "..." }
  }
}
```

`enc_meta` is `null` or absent when no note has been attached.

#### Feature flag

The `GET /api/v1/info` response `features` object includes:

```json
{
  "features": {
    "encrypted_notes": true
  }
}
```

`encrypted_notes` indicates whether the server supports `PUT /api/v1/secrets/{id}/meta` and returns `enc_meta` in list responses.

### Account management (session required)

#### Update display name

`PATCH /api/v1/auth/account`

Request:

```json
{
  "display_name": "New Name"
}
```

`display_name` is trimmed and must be 1–100 characters.

Response (`200`):

```json
{
  "ok": true,
  "display_name": "New Name"
}
```

Other outcomes:

- `400` if `display_name` is empty after trimming or exceeds 100 characters.

#### Delete account

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

### Get secret metadata (authenticated)

`GET /api/v1/secrets/{id}`

Returns metadata for a single secret owned by the caller. Accepts session or API key auth (session first, API key fallback).

Response (`200`): `SecretMetadataItem` — same schema as items in `ListSecretsResponse`, including optional `enc_meta`.

Errors:

- `401` — missing or invalid credentials.
- `404` — secret not found, expired, or not owned by the caller.

Constraints:

- Must not return plaintext, passphrase material, URL fragment keys, or claim tokens.
- Must not return raw `claim_hash` to clients.
