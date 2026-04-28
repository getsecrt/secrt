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

Returns server defaults, per-tier limits, and CLI version metadata. Authentication is optional; if a valid API key is provided, `authenticated` is `true`.

Caching: `Cache-Control: public, max-age=300`

Policy notes:

- No API key required. If provided and valid, `authenticated` is `true`.
- Invalid API key is not an error; `authenticated` is `false`.
- Both tiers are always returned regardless of authentication status.
- Rate-limited via the claim limiter (1 rps, burst 10).

CLI version fields (advisory; see `spec/v1/cli.md § Update Check and Self-Update` and `spec/v1/server.md § 13.2`):

- `latest_cli_version` (optional, string): the highest non-prerelease CLI semver the server has observed in GitHub Releases. Omitted when the server has not yet completed a successful poll.
- `latest_cli_version_checked_at` (optional, string, RFC 3339): timestamp of the last successful poll. Omitted when never polled successfully. Allows the CLI to distinguish "I have never tried" (both fields absent) from "I tried but the value is stale" (both fields present, timestamp far in the past).
- `min_supported_cli_version` (string, always present): the lowest CLI semver this server is known to be compatible with. Bumped only when a server release introduces a wire-format change. Clients SHOULD warn users running below this version, but MUST NOT block — zero-knowledge claim flows must continue to work for users who received share URLs before they upgraded.
- `server_version` (string, always present on conforming servers): the server build's own semver (`CARGO_PKG_VERSION` at compile time). Lets operators verify deploys without SSH and lets clients record which server version a given response came from. Older servers that pre-date this field omit it; clients MUST treat absence as "unknown" rather than an error.

### CLI Version Advisory Response Headers

To let CLI clients keep their update-check cache warm without dedicated `/api/v1/info` round-trips, conforming servers SHOULD include the same advisory information as response headers on **every** response (authenticated and public, including `/healthz`, error responses, and binary payloads):

- `X-Secrt-Latest-Cli-Version: <semver>` — omitted when the server has not yet completed a successful poll.
- `X-Secrt-Latest-Cli-Version-Checked-At: <RFC 3339>` — omitted when never polled successfully.
- `X-Secrt-Min-Cli-Version: <semver>` — always present (mirrors the `min_supported_cli_version` constant baked into the server build).
- `X-Secrt-Server-Version: <semver>` — always present on conforming servers (mirrors the `server_version` body field; sourced from `CARGO_PKG_VERSION` at compile time). Lets clients record the responding server's version from any request without a dedicated `/api/v1/info` round trip.

The header values mirror the corresponding `/api/v1/info` body fields exactly. The values are public — there is nothing sensitive about emitting them on unauthenticated responses.

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

**WebAuthn verification model.** All `/finish` handlers cryptographically verify the WebAuthn assertion (or, for register/add, the attested credential data) per `spec/v1/server.md` §6.2. ES256 / EC2 P-256 only at v1. Verification failures return opaque `401`.

**Browser → server transport.** The browser surfaces the raw bytes from `navigator.credentials.create()` / `navigator.credentials.get()`:

| Wire field            | Source                                                                                |
| --------------------- | ------------------------------------------------------------------------------------- |
| `authenticator_data`  | base64url of `AuthenticatorAssertionResponse.authenticatorData` (login) or the raw `authData` parsed out of `AuthenticatorAttestationResponse.attestationObject` (register/add). |
| `client_data_json`    | base64url of `*.clientDataJSON` (the literal byte string the browser produced).       |
| `signature`           | base64url of `AuthenticatorAssertionResponse.signature` (login only — DER-encoded ECDSA). |
| `credential_id`       | base64url of the credential ID. The server uses this to look up the stored row.       |

Register/add finish does NOT carry a separate `public_key` field — the COSE_Key is embedded in `authenticator_data`'s attested credential data section and the server extracts it.

#### Register — start

`POST /api/v1/auth/passkeys/register/start`

Unauthenticated. Issues a `challenge_id` + opaque `challenge` for the WebAuthn ceremony.

Request:

```json
{ "display_name": "Alice" }
```

Response (`200`):

```json
{
  "challenge_id": "<base64url>",
  "challenge": "<base64url 32-byte challenge>",
  "expires_at": "2026-04-27T22:40:00Z"
}
```

Challenge expires after 10 minutes.

#### Register — finish

`POST /api/v1/auth/passkeys/register/finish`

Request:

```json
{
  "challenge_id": "<base64url>",
  "credential_id": "<base64url>",
  "authenticator_data": "<base64url, contains attested credential data + COSE_Key>",
  "client_data_json": "<base64url>",
  "prf": { "supported": false, "at_create": false }
}
```

`prf` is optional; see `prf-amk-wrapping.md` for the full semantics.

Response (`200`): same shape as before — session token, user ID, display name, expires_at, optional `prf_cred_salt` / `prf_wrapper`.

Verification (`spec/v1/server.md` §6.2):

- `clientDataJSON.type` must equal `"webauthn.create"`.
- `clientDataJSON.challenge` must equal the issued challenge.
- `clientDataJSON.origin` must equal the configured origin.
- `authenticatorData.rpIdHash` must equal SHA-256 of the configured RP ID.
- `authenticatorData` flags must have UP=1 and AT=1.
- The embedded COSE_Key must be EC2 P-256 ES256 (`kty=2`, `alg=-7`, `crv=1`).

Failures return `401 unauthorized` (no detail). The challenge is consumed regardless.

#### Login — start

`POST /api/v1/auth/passkeys/login/start`

Request:

```json
{ "credential_id": "<base64url>" }
```

Response: same `{ challenge_id, challenge, expires_at }` shape as register/start.

#### Login — finish

`POST /api/v1/auth/passkeys/login/finish`

Request:

```json
{
  "challenge_id": "<base64url>",
  "credential_id": "<base64url>",
  "authenticator_data": "<base64url>",
  "client_data_json": "<base64url>",
  "signature": "<base64url DER ECDSA>",
  "prf": { "supported": false, "at_create": false }
}
```

Response (`200`): unchanged — session token, optional `prf_wrapper` / `prf_cred_salt`. See PRF section for details.

Verification:

- `clientDataJSON.type` = `"webauthn.get"`, challenge / origin match.
- `authenticatorData.rpIdHash` matches; UP flag set.
- New `signCount` strictly greater than stored `sign_count`.
- ECDSA signature verifies with the stored public key over `authenticatorData || SHA-256(clientDataJSON)`.

Failures return `401 unauthorized` with no body detail. The challenge is consumed regardless of outcome to prevent replay.

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

### App Login (desktop app → browser → session token)

App login enables a desktop application (e.g. Tauri) to obtain a session token by opening the user's system browser for passkey authentication. The flow is similar to device authorization, but mints a session token instead of an API key. Optional ECDH key exchange allows the browser to transfer the Account Master Key (AMK) to the app.

#### Start app login

`POST /api/v1/auth/app/start`

Unauthenticated. IP rate-limited.

Request (optional JSON body):

```json
{
  "ecdh_public_key": "<base64url uncompressed P-256 public key, 65 bytes decoded>"
}
```

An empty POST (no body or `Content-Type`) is valid and starts the flow without ECDH. If `Content-Type: application/json` is set, the body is parsed strictly — unknown fields and malformed JSON return `400`.

`ecdh_public_key` validation: must be valid base64url, decoded length exactly 65 bytes (uncompressed P-256: `0x04` prefix + 32 + 32).

Response (`200`):

```json
{
  "app_code": "<base64url opaque identifier>",
  "user_code": "ABCD-1234",
  "verification_url": "https://secrt.ca/app-login?code=ABCD-1234&ek=<base64url>",
  "expires_in": 600,
  "interval": 2
}
```

`verification_url` includes `&ek=<key>` only when `ecdh_public_key` was provided.

#### Poll app login status

`POST /api/v1/auth/app/poll`

Unauthenticated. IP rate-limited.

Request:

```json
{
  "app_code": "<base64url>"
}
```

Responses:

- Pending: `200` `{ "status": "authorization_pending" }`
- Approved: `200` — the challenge is atomically consumed, then a fresh session token is minted:

```json
{
  "status": "complete",
  "session_token": "uss_<sid>.<secret>",
  "user_id": "<uuid>",
  "display_name": "<string>",
  "amk_transfer": {
    "ct": "<base64url 48 bytes>",
    "nonce": "<base64url 12 bytes>",
    "ecdh_public_key": "<base64url 65 bytes>"
  }
}
```

- Expired or already consumed: `400` `{ "error": "expired_token" }`

`amk_transfer` is present only when the approver attached encrypted AMK material. `session_token` is minted at poll time (not stored in the challenge) to avoid persisting raw bearer tokens in the database.

**Concurrency safety:** The challenge is consumed (deleted) atomically before the session token is minted. If two clients poll the same approved challenge concurrently, exactly one will succeed — the other receives `expired_token`. This prevents duplicate session creation.

#### Approve app login (session required)

`POST /api/v1/auth/app/approve`

Headers:

- `Authorization: Bearer uss_<sid>.<secret>`

Request:

```json
{
  "user_code": "ABCD-1234",
  "amk_transfer": {
    "ct": "<base64url 48 bytes: 32-byte AMK + 16-byte GCM tag>",
    "nonce": "<base64url 12 bytes: AES-GCM nonce>",
    "ecdh_public_key": "<base64url 65 bytes: approver's ephemeral P-256 public key>"
  }
}
```

`amk_transfer` is optional. Field validation:

- `ecdh_public_key`: valid base64url, 65 bytes decoded
- `nonce`: valid base64url, 12 bytes decoded
- `ct`: valid base64url, 48 bytes decoded

Response (`200`):

```json
{ "ok": true }
```

Behavior:

1. Validates session auth.
2. Looks up a pending `app-login` challenge by `user_code` (constant-time comparison).
3. Updates challenge status to `"approved"` with the user's `user_id`, `display_name`, and optional `amk_transfer`.
4. Session token is **not** minted here — deferred to poll time.

Other outcomes:

- `400` if `user_code` is not found, challenge is not pending, or `amk_transfer` fields are invalid
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
  "credential_id": "<base64url>",
  "authenticator_data": "<base64url, contains attested credential data + COSE_Key>",
  "client_data_json": "<base64url>",
  "prf": { "supported": false, "at_create": false }
}
```

Verification rules are identical to register/finish (§6.2): the wire shape and acceptance criteria are the same — only the challenge purpose (`"passkey-add"`) and the post-success response shape differ.

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

- `401 unauthorized` if any verification step fails (challenge consumed regardless).

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

The AMK is a client-generated 32-byte symmetric key used to derive per-secret note-encryption keys. The server stores only wrapped (encrypted) copies; the plaintext AMK never leaves clients.

This section defines:

1. **AMK wrapping (normative crypto)** — the byte-exact format every AMK wrapper uses, regardless of how the wrap key was derived.
2. **AMK transport (v1)** — the three v1 mechanisms for moving an AMK to a new device (each produces a wrapper of the shape in §1).
3. **Sync secrets** — the fallback transport layered on top of the standard secret create/claim flow.
4. **Non-goals** — rotation and other out-of-scope concerns.
5. **Endpoints** — `/api/v1/amk/*` and `/api/v1/secrets/{id}/meta`.

#### AMK wrapping (normative crypto)

Constants:

- `AMK_LEN = 32` bytes (raw AMK size)
- `WRAP_KEY_LEN = 32` bytes
- `GCM_NONCE_LEN = 12` bytes
- `GCM_TAG_LEN = 16` bytes
- `HKDF_INFO_AMK_WRAP = "secrt-amk-wrap-v1"` — Transport A info string
- `HKDF_INFO_AMK_WRAP_PRF = "secrt-amk-wrap-prf-v1"` — Transport D info string
- `AMK_COMMIT_DOMAIN_TAG = "secrt-amk-commit-v1"`

##### AAD construction

The AAD binds each wrapper to a specific `(user, binding_id, version)` tuple where `binding_id` is a transport-specific identifier. This prevents cross-replay across accounts, transports, and versions.

```
AAD = info || user_id_uuid || u16be(len(binding_id)) || binding_id || u16be(version)
```

Where:

- `info` is the transport-specific HKDF info string. Transport A: `"secrt-amk-wrap-v1"` (17 bytes). Transport D: `"secrt-amk-wrap-prf-v1"` (21 bytes). Reusing the info string as the AAD prefix binds each wrapper to its wrap path.
- `user_id_uuid` MUST be the 16 raw bytes of the account's UUIDv7 (`users.id`). This is the same UUID returned as a string in `GET /api/v1/info`; clients parse the canonical string form (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) into 16 bytes.
- `binding_id` is the transport-specific binding identifier:
  - Transport A: UTF-8 bytes of the API-key prefix (≥6 chars from `[A-Za-z0-9_-]`).
  - Transport D: raw bytes of the WebAuthn credential ID (base64url-decoded; variable length).
  - Other transports specify their own binding semantics.
- `version` MUST be big-endian u16. In v1, `version = 1`.

**Convention:** fixed-size protocol primitives (UUIDs, the version field) are included verbatim with no length prefix. Variable-length fields (e.g., `binding_id`) are prefixed with a u16 big-endian byte length. This rule applies to every AMK wrap path.

##### Wrap-key derivation

Wrap keys are derived via HKDF-SHA-256. The **IKM source** is transport-dependent; the **info string** and **output length** are fixed for this wrap format.

For the **API-key root transport** (the default v1 path):

```
ROOT_SALT = SHA-256("secrt-apikey-v2-root-salt")         // 32 bytes
wrap_key  = HKDF-SHA-256(
              ikm   = root_key,                          // 32 bytes; client-only
              salt  = ROOT_SALT,
              info  = "secrt-amk-wrap-v1",
              len   = 32,
            )
```

`root_key` is the 32-byte key encoded in the local `sk2_<prefix>.<root_b64>` format. It MUST NOT leave the client. See `cli.md § Authenticated Mode` for the full API-key derivation chain.

Other transports (sync link, ECDH transfer, PRF) derive a 32-byte wrap key via their own mechanisms and then use the same AAD shape (with transport-specific `info` and `binding_id` per §AAD construction), cipher, nonce, and byte layout defined here. See §AMK transport.

##### Sealing

```
nonce = 12 random bytes (fresh per wrap operation)
ct    = AES-256-GCM(wrap_key, nonce, AAD, amk)
```

`ct` MUST be exactly 48 bytes (`AMK_LEN + GCM_TAG_LEN` = 32 + 16). The nonce is generated by the client; the server neither provides nor validates nonces beyond decoding length.

##### AMK commitment

Every wrapper carries a commitment value that the server uses to detect AMK divergence across an account's devices:

```
amk_commit = SHA-256("secrt-amk-commit-v1" || amk)       // 32 bytes
```

Server enforcement (first-writer-wins): all wrappers for a given user MUST share the same `amk_commit`. The first commit stored establishes the account's value; any subsequent `PUT /api/v1/amk/wrapper` or `POST /api/v1/amk/commit` with a different value returns `409 Conflict`.

Security note: `amk_commit` is a deterministic hash — it binds the wrapper to a specific AMK but is not a hiding commitment. Given the AMK is 32 random bytes, this is not a practical concern.

##### Wire format

On `PUT /api/v1/amk/wrapper` and `GET /api/v1/amk/wrapper`:

- `wrapped_amk`: base64url, no padding; MUST decode to 48 bytes.
- `nonce`: base64url, no padding; MUST decode to 12 bytes.
- `amk_commit`: base64url, no padding; MUST decode to 32 bytes.
- `version`: integer; MUST be `1` in v1.

#### AMK transport (v1)

A transport is a mechanism for moving an AMK to a new device without exposing it to the server. All transports produce a wrapper of the shape in §AMK wrapping; they differ only in **where the wrap key is derived from**.

##### Transport A: API-key root wrap (default)

The client holding the AMK derives a wrap key from the local API key's `root_key` and wraps the AMK. One wrapper per API key, uploaded via `PUT /api/v1/amk/wrapper`.

- Use cases: the browser wraps the AMK for each API key the user has registered; a CLI `secrt auth setup` flow wraps the AMK for a newly registered key.
- Revocation: revoking an API key deletes only that key's wrapper. The AMK itself is not rotated.

##### Transport B: Sync link

The browser exports the AMK as a short-lived one-time secret whose plaintext is the raw 32-byte AMK. Another client claims it via the standard claim flow and re-wraps under its own API-key root. See §Sync secrets below.

##### Transport C: ECDH on device-auth and app-login

When a CLI runs `secrt auth login`, or a desktop app runs app-login, the client advertises an ephemeral P-256 public key in `POST /api/v1/auth/device/start` or `POST /api/v1/auth/app/start`. An already-authenticated browser approves the request and, if it holds the AMK, derives an ECDH shared secret with the client, seals the AMK, and returns the sealed blob in the poll response (`amk_transfer`).

ECDH transfer crypto:

- Curve: P-256 (NIST secp256r1).
- Public-key encoding: uncompressed SEC1 (`0x04` || X || Y) — exactly 65 bytes.
- Shared secret: ECDH(private_key, peer_public_key), 32 bytes.
- Transfer key: `HKDF-SHA-256(shared_secret, empty_salt, "secrt-amk-transfer-v1", 32)`.
- Seal: `AES-256-GCM(transfer_key, nonce, empty_aad, amk)` → `ct` is exactly 48 bytes (32 AMK + 16 tag).
- Nonce: 12 random bytes generated by the approver.

The receiving client MUST derive the wrap key for its **own** local API key (per §Wrap-key derivation, Transport A) and re-wrap the AMK for its account, then upload via `PUT /api/v1/amk/wrapper`. The transfer key itself is discarded after use.

**Short Authentication String (SAS):** to detect a MITM during the exchange, clients MAY display a 6-digit code for out-of-band comparison:

```
sas = HKDF-SHA-256(
        shared_secret,
        salt = min(pk_a, pk_b) || max(pk_a, pk_b),         // lex-sorted concatenation
        info = "secrt-amk-sas-v1",
        len  = 3 bytes,
      )
sas_code = ((sas[0] << 16) | (sas[1] << 8) | sas[2]) mod 1_000_000
```

Sorting the public keys lexicographically ensures both sides compute the same code regardless of role.

##### Transport D: PRF wrap

The client derives the wrap key from a WebAuthn PRF extension output, allowing a new device with access to a synced passkey to derive the same wrap key with no bearer-token exchange. Companion design doc: `crates/secrt-server/docs/prf-amk-wrapping.md`.

Crypto:

- IKM: PRF extension output from `navigator.credentials.create/get`'s `extensions.prf.eval.first` — exactly 32 bytes.
- Salt: `cred_salt`, a per-credential 32-byte value generated by the **server** at passkey registration and stored on the credential row. Returned to the client in the register-finish response and surfaced inline in login-finish so a fresh-device client can unwrap immediately.
- Info: `"secrt-amk-wrap-prf-v1"` (21 bytes).
- Wrap-key derivation:

  ```
  wrap_key = HKDF-SHA-256(
               ikm  = prf_output,
               salt = cred_salt,
               info = "secrt-amk-wrap-prf-v1",
               len  = 32,
             )
  ```

- AAD `binding_id`: raw bytes of the WebAuthn credential ID (base64url-decoded; variable length).

The PRF eval salt itself (the input to the authenticator, distinct from `cred_salt`) is a per-RP constant: `PRF_EVAL_SALT = SHA-256("secrt.is/v1/amk-prf-eval-salt")` — 32 bytes. It MUST be stable per RP because synced passkey providers (Apple iCloud Keychain, Google Password Manager) produce deterministic PRF outputs only when the same eval salt is supplied across the synced device set.

PRF wrappers are stored separately from API-key wrappers (see `prf_amk_wrappers` table in the design doc) and keyed by `(user_id, credential_id)`. They share the same AMK and `amk_commit` as all other wrappers for the user, enforced via the standard first-writer-wins commit check.

**Upgrade path for pre-PRF credentials.** A passkey registered before PRF support shipped (or registered on a non-PRF browser and later used on a PRF-capable one) carries `cred_salt = NULL` and `prf_supported = false`. When such a credential is used to log in on a PRF-capable surface, the client SHOULD include a `prf` field on `POST /api/v1/auth/passkeys/login/finish` describing the assertion's PRF state (`{ supported: bool, at_create: bool }`). When `supported = true` and the row has no `cred_salt`, the server generates a fresh 32-byte salt, stamps the row, and returns it as `prf_cred_salt` in the response. The client wraps the AMK (which it already holds — it's logging in on a known device) and calls `PUT /api/v1/auth/passkeys/{cred_id}/prf-wrapper`. Future fresh-device logins with the same credential then enjoy the one-tap unlock path. The `prf` field is also accepted on `POST /api/v1/auth/passkeys/add/finish` to enable PRF on credentials added from settings.

Browser support for the PRF extension is bleeding-edge (Chrome 147+, Safari 18+, Firefox 148+, Chrome on Android+GPM). Clients MUST detect feature availability and fall back to Transport B (sync link) or Transport A (API-key) when PRF is unavailable. iOS Safari + external roaming authenticators do not propagate PRF extension data; this is a documented Apple limitation. Several third-party password manager pickers (Bitwarden, 1Password as of 2026-04) also currently drop the PRF extension at the WebAuthn boundary; users storing their secrt passkey in those managers fall through to the sync-link / API-key paths.

#### Sync secrets

A **sync secret** is a short-lived one-time secret whose plaintext is the raw 32-byte AMK. Sync secrets reuse the standard secret infrastructure; the server makes no protocol-level distinction from any other secret. The "sync" distinction exists entirely at the client layer.

##### Create side (browser)

1. Read the 32-byte AMK from local storage.
2. Seal as a standard envelope per `envelope.md`:
   - Plaintext: the raw 32 AMK bytes.
   - No passphrase (`kdf.name = "none"`).
   - Payload frame metadata: `{ "type": "binary" }`.
3. Create via `POST /api/v1/public/secrets` (or the authenticated endpoint) with a **short TTL — recommended 600 seconds (10 minutes).** The server does not enforce a sync-specific TTL; 10 minutes is a client-side policy convention.
4. Format the share URL using the `/sync/<id>#<url_key_b64>` path instead of `/s/<id>#<url_key_b64>`. This is a UX marker only; the server routes both paths to the same SPA entry point.

##### Consume side (CLI or other client)

1. Parse the URL. A client acting on a sync URL MUST reject `/s/<id>` paths **before** calling claim — claiming a share URL is destructive (one-time claim), so an accidental burn of an unrelated secret must be avoided.
2. Standard claim via `POST /api/v1/secrets/{id}/claim`; decrypt the envelope.
3. The decrypted plaintext MUST be exactly 32 bytes. Any other length is a protocol violation and MUST cause the client to fail without uploading.
4. Resolve the caller's `user_id` from `GET /api/v1/info`. If the API key is not linked to a user, fail — the wrap AAD requires the UUID.
5. Wrap the AMK under the caller's own API-key root (§AMK wrapping, Transport A) and upload via `PUT /api/v1/amk/wrapper`.

##### Threat model

Sync URLs are **bearer tokens equivalent in sensitivity to the AMK itself**. Anyone who observes the full URL before the legitimate recipient claims it can retrieve the AMK and decrypt all future notes for the account.

Built-in mitigations:

- **One-time claim** — the secret is destroyed atomically on first successful claim. An attacker who claims first burns the link, making the compromise visible to the user.
- **Short TTL** — recommended 10 minutes. Clients MUST NOT default to longer.
- **URL fragment** — the `url_key` is in the fragment and not sent in normal HTTP requests. Servers and reverse proxies see only the opaque `id`.

Residual risks clients SHOULD surface to users when presenting a sync URL:

- **Clipboard sync** — Apple Universal Clipboard, Windows Cloud Clipboard, and similar features replicate clipboards across devices and may expose the URL to unintended hosts.
- **Browser history and password managers** — pasting a sync URL into a browser address bar may be captured by history, sync, or URL-grabbing password managers.
- **Terminal logs** — pasting a sync URL into a terminal captures it in shell history and any remote logging.

Treat sync URLs as ephemeral transfer material: consume immediately on the destination device, do not persist or bookmark.

#### AMK — non-goals in v1

- **AMK rotation is not specified.** Once an account's AMK is established (via the first wrapper's `amk_commit`), v1 provides no mechanism to rotate it. Compromise of the AMK therefore compromises every encrypted note ever created under it. The `version` field in wrappers and `meta_key_version` on notes are reserved for a future rotation scheme; in v1 both MUST be `1`.
- **The server is not a cryptographic trust anchor for the AMK.** The server stores wrappers and the commitment but cannot derive or prove correctness of the plaintext AMK. A server that returns a mismatched wrapper causes an AEAD authentication failure on the client; there is no proof beyond that.

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
