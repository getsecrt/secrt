# PRF-Based AMK Wrapping — Design Doc

**Status:** Draft 1 · 2026-04-24
**Owner:** JD
**Scope:** Add WebAuthn PRF extension as a parallel path for AMK wrap-key derivation.
**Tracking:** `.taskmaster/tasks/tasks.json` → task #42.

This is a working-spec, not product-architecture. Register intent here, commit as it gets built. Audience is whoever (human or AI) picks up the implementation — lean on byte-level precision over prose.

---

## 1. Goal & Non-Goals

### Goal
Let a user log into secrt on a new device with only their passkey — no QR code, no sync link, no master password — while preserving zero-knowledge (server never holds decryption material for the AMK).

### Non-goals
- Replace the AMK itself. AMK is still a random 32-byte key living in IndexedDB.
- Replace the envelope encryption layer (`url_key`, passphrases, per-secret keys). PRF is orthogonal.
- Replace the API-key wrap path. That stays as break-glass recovery.
- Replace the sync-link flow. Stays as fallback for non-PRF browsers.
- Introduce a master password. There isn't one and won't be.
- Make the CLI process itself a WebAuthn client. `secrt-cli` does not invoke `navigator.credentials.*`; PRF is browser-only in terms of ceremonies. The CLI does, however, indirectly benefit because its `auth login` command opens a browser tab (§4.7) — that tab runs the same PRF flow as any other logged-out browser entry point.

---

## 2. Current Architecture (verified against code 2026-04-24)

### 2.1 AMK
- Random 32-byte key, generated at first login, stored per-device in IndexedDB (`"secrt-amk"` DB v1, store `"amk"`, keyed by `userId`, raw `Uint8Array`) — `web/src/lib/amk-store.ts:32-34`.
- Never uploaded to server in plaintext.

### 2.2 Existing wrap-key derivation (API-key root)
```rust
// secrt-core/src/amk.rs:66-68
pub fn derive_amk_wrap_key(root_key: &[u8]) -> Result<Vec<u8>, ApiKeyError> {
    derive_from_root(root_key, HKDF_INFO_AMK_WRAP, WRAP_KEY_LEN)
}
// HKDF-SHA256(ikm=root_key, salt=SHA256("secrt-apikey-v2-root-salt"),
//             info="secrt-amk-wrap-v1", len=32)
```

### 2.3 Existing wrapped-AMK wire format
```rust
// secrt-core/src/amk.rs:33-38
pub struct WrappedAmk {
    pub ct: Vec<u8>,     // AES-256-GCM ciphertext+tag, 48 bytes (32-byte AMK + 16-byte tag)
    pub nonce: Vec<u8>,  // 12 bytes
    pub version: u16,
}
```
AAD: `"secrt-amk-wrap-v1" || user_id_uuid(16B) || u16be(len(binding_id)) || binding_id || u16be(version)` (amk.rs:72–97). For the api-key transport `binding_id = key_prefix` UTF-8 bytes; the Rust parameter is currently named `key_prefix` and gets renamed to `binding_id: &[u8]` in Phase B.

Convention (applies to all AMK wrap paths): fixed-size protocol primitives (UUIDs, the version field) are included verbatim with no length prefix. Variable-length fields get a u16 big-endian byte-length prefix. The normative version of this convention lives in `spec/v1/api.md` §"AMK wrapping (normative crypto)".

### 2.4 Existing server schema (relevant tables)
```sql
-- 002_amk_wrappers.sql
CREATE TABLE amk_wrappers (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_prefix TEXT NOT NULL,
    wrapped_amk BYTEA NOT NULL,   -- 48 bytes
    nonce BYTEA NOT NULL,         -- 12 bytes
    version SMALLINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, key_prefix)
);

-- 001_initial.sql + 004_passkey_label.sql
CREATE TABLE passkeys (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,  -- base64url
    public_key TEXT NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    label TEXT NOT NULL DEFAULT ''
);
```

### 2.5 Commitment hash (unchanged by this design)
`amk_commit = SHA256("secrt-amk-commit-v1" || amk)` — `secrt-core/src/amk.rs:50-60`. Referenced for first-writer-wins; PRF wrappers must compute the same commit.

---

## 3. Proposed Design

### 3.1 New wrap-key derivation (parallel to §2.2)

```
prf_output      = WebAuthn PRF result    // 32 bytes from authenticator (HMAC-SHA256 under the hood)
ikm             = prf_output             // treat as IKM, not as a final key
wrap_key        = HKDF-SHA256(
                    ikm   = ikm,
                    salt  = cred_salt,   // 32 random bytes, generated server-side at registration,
                                         // stored in passkeys.cred_salt (new column)
                    info  = "secrt-amk-wrap-prf-v1",
                    len   = 32,
                  )
```

**Why HKDF rather than use `prf_output` directly:** domain separation (Yubico guidance), future rotation (change `info` to `v2`), and consistency with §2.2.

**Why the `cred_salt` is the HKDF salt, not the PRF salt:** the PRF salt is an application-level domain separator passed into the authenticator — it's fine for it to be a fixed per-RP constant (see §3.4). Per-credential randomness belongs in the HKDF step where it serves its cryptographic purpose (breaks same-input cross-credential identity) without confusing the PRF layer.

### 3.2 Wrapped-AMK wire format (refers to normative spec)

Reuses the **normative AMK wrap format** defined in `spec/v1/api.md` §"AMK wrapping (normative crypto)" — same `WrappedAmk { ct, nonce, version }` shape, same AAD layout, same cipher and nonce length. The PRF transport differs only in the per-transport variables documented in §"Transport D: PRF wrap":

- `info` = `"secrt-amk-wrap-prf-v1"` (used both as HKDF info and as AAD prefix)
- `binding_id` = raw bytes of the WebAuthn credential ID (base64url-decoded)
- IKM = PRF extension output (32 bytes)
- HKDF salt = `cred_salt` (per-credential, server-generated; see §3.4)

Concretely:

```
aad = b"secrt-amk-wrap-prf-v1"               // info, 21 bytes
    + user_id_uuid.as_bytes()                // 16 bytes
    + (len(cred_id) as u16_be).to_bytes()    // 2 bytes
    + cred_id_bytes                          // variable
    + (version as u16_be).to_bytes()         // 2 bytes
```

This matches the normative AAD shape with `info = HKDF_INFO_AMK_WRAP_PRF` and
`binding_id = cred_id_bytes`. Implementations MUST NOT introduce a separate AAD format
for PRF; they MUST reuse the same AAD-construction routine used for Transport A,
parameterized by the transport-specific `info` and `binding_id`.

### 3.3 Server schema additions

```sql
-- migrations/NNN_prf_amk_wrappers.sql

ALTER TABLE passkeys
  ADD COLUMN cred_salt       BYTEA,          -- 32 random bytes, NULL for non-PRF credentials
  ADD COLUMN prf_supported   BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN prf_at_create   BOOLEAN NOT NULL DEFAULT false;
  -- prf_supported: authenticator returned non-empty PRF output at some point
  -- prf_at_create: PRF output was available in the registration ceremony (Chrome 147+ Win, Safari 18+, etc.)
  --                vs only available after first auth (older surfaces)

CREATE TABLE prf_amk_wrappers (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_pk BIGINT NOT NULL REFERENCES passkeys(id) ON DELETE CASCADE,
    wrapped_amk BYTEA NOT NULL,        -- 48 bytes
    nonce BYTEA NOT NULL,              -- 12 bytes
    version SMALLINT NOT NULL DEFAULT 1,
    amk_commit BYTEA NOT NULL,         -- 32 bytes, SHA256("secrt-amk-commit-v1" || amk)
                                       -- used to detect AMK divergence / ensure same AMK
                                       -- as api-key-root wrappers
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, credential_pk)
);
CREATE INDEX prf_amk_wrappers_user ON prf_amk_wrappers(user_id);
```

A separate table (not a union column on `amk_wrappers`) so the existing table stays clean and the foreign key to `passkeys.id` is tight. Read cost of checking both tables on login is acceptable (both indexed by `user_id`).

### 3.4 Two distinct salts — be precise about which is which

This design uses two 32-byte salts, with very different roles. Naming them clearly avoids implementation mix-ups.

**`PRF_EVAL_SALT`** — the input passed to the authenticator at `extensions.prf.eval.first` during `navigator.credentials.create/get`.
- Per-RP constant: `PRF_EVAL_SALT = SHA-256("secrt.is/v1/amk-prf-eval-salt")` (computed at build time, hardcoded in client code).
- Stable for the lifetime of the RP. Same value on every device for every credential.
- Why a constant, not per-credential: the PRF salt is an application-level domain separator telling the authenticator "give me the secret for _this purpose_." It does not provide secrecy (attacker sees it in the API call). Per-credential randomness belongs in the HKDF step where it serves its cryptographic purpose. Using the same eval salt across the synced device set is what makes synced-passkey PRF determinism possible — change it and the PRF output changes, breaking new-device unlock.

**`cred_salt`** — the salt passed to HKDF when deriving the wrap key from the PRF output.
- Per-credential, per-account 32-byte random value.
- **Generated server-side** at passkey registration (`handle_passkey_register_finish_entry`) when the registering client reports `prf.supported = true`. Stored on the passkey row (`passkeys.cred_salt`).
- Returned to the client in the register-finish response (`prf_cred_salt` field, base64url) so the client can immediately wrap the AMK and PUT the wrapper.
- Surfaced inline in login-finish responses on subsequent logins so a fresh-device client can unwrap the AMK in one round-trip without a second GET.
- Why server-side: keeps salt issuance single-source-of-truth, prevents client-side bugs that would silently produce a salt mismatch between wrap and unwrap, and makes it auditable when revisiting credentials.

### 3.5 New HTTP routes

```
POST /api/v1/auth/passkeys/{cred_id}/prf-wrapper
    body: { ct, nonce, version, amk_commit }   // all base64url
    auth: session
    response: 204 on first-write, 409 on duplicate (with existing amk_commit)

GET /api/v1/auth/passkeys/{cred_id}/prf-wrapper
    auth: session
    response: { ct, nonce, version, amk_commit }   // base64url, all fields

DELETE /api/v1/auth/passkeys/{cred_id}/prf-wrapper
    auth: session
    response: 204. Used when a PRF credential is revoked.
```

All three should rate-limit tight: login-flow attackers shouldn't be able to enumerate wrappers. `GET` specifically should require a *fresh* session (≤ 60s since last auth), not just any valid session — this is the moment a compromised session could exfiltrate wrap-material.

### 3.6 Relying party (client) API shape

At **registration**:
```ts
// simplified; real code goes through the existing register-start/finish handshake
const createOptions = {
  publicKey: {
    ...standardOptions,
    extensions: {
      prf: {
        eval: { first: PRF_EVAL_SALT },  // PRF-on-create (Chrome 147+ Win, Safari 18+, etc.)
      },
    },
  },
};
const cred = await navigator.credentials.create(createOptions);
const ext = cred.getClientExtensionResults?.().prf;
// ext?.enabled:  boolean — authenticator accepted the extension
// ext?.results?.first: ArrayBuffer(32) — PRF output IF PRF-on-create is supported
```

At **authentication**:
```ts
const getOptions = {
  publicKey: {
    ...standardOptions,
    extensions: {
      prf: { eval: { first: PRF_EVAL_SALT } },
    },
  },
};
const asr = await navigator.credentials.get(getOptions);
const prfOutput = asr.getClientExtensionResults().prf?.results?.first;
// prfOutput: ArrayBuffer(32) | undefined
```

### 3.7 Library choice
No `@simplewebauthn/*` in `package.json` today; registration/login handlers are hand-rolled. Options:
1. **Keep hand-rolled.** Fine — the PRF extension adds ~20 LOC to the existing ceremonies.
2. **Adopt `@simplewebauthn/browser`** for client, `@simplewebauthn/server` for server (Rust equivalent: `webauthn-rs` crate which we may already pull in — verify).

Recommend **stay hand-rolled** for this change. Scope creep risk if we try to swap libraries mid-feature. Revisit independently.

---

## 4. Flows (state diagrams)

Three flows, three failure modes each. Explicit on every branch.

### 4.1 Registration with PRF-on-create available (Chrome 147+ / Windows Hello, Safari 18+, Android+GPM)

```
Client                              Server
  |                                   |
  |-- POST /register/start ---------->|
  |<----- challenge -------------------|
  |                                   |
  | navigator.credentials.create({    |
  |   extensions: { prf: { eval: { first: PRF_EVAL_SALT } } }
  | })                                |
  | → credential + prf.results.first  |
  |                                   |
  | if AMK already exists in IndexedDB:
  |   cred_salt ← crypto.getRandomValues(32)
  |   wrap_key  ← HKDF(prf_out, cred_salt, "secrt-amk-wrap-prf-v1", 32)
  |   nonce     ← crypto.getRandomValues(12)
  |   ct        ← AES-256-GCM(wrap_key, nonce, aad(user_id, cred_id_bytes, 1), amk)
  |   amk_commit← SHA256("secrt-amk-commit-v1" || amk)
  |                                   |
  |-- POST /register/finish --------->|
  |   { cred, prf: { supported: true, at_create: true, cred_salt } }
  |                                   | INSERT passkeys (cred_salt, prf_supported=true, prf_at_create=true)
  |                                   |
  |-- PUT /passkeys/{id}/prf-wrapper->|
  |   { ct, nonce, version: 1, amk_commit }
  |                                   | INSERT prf_amk_wrappers
  |<----- 204 -------------------------|
```

### 4.2 Registration with PRF-on-get only (older surfaces, extension echoed but no `results.first` at create)

```
Client                              Server
  |                                   |
  | Same register/start + create as 4.1
  | But: cred.getClientExtensionResults().prf.enabled === true
  |      cred.getClientExtensionResults().prf.results === undefined
  |                                   |
  |-- POST /register/finish --------->|
  |   { cred, prf: { supported: true, at_create: false } }
  |                                   | INSERT passkeys (cred_salt=random32, prf_supported=true, prf_at_create=false)
  |                                   |
  | Immediately chain into /login/start + /login/finish on same device
  | → obtain prf.results.first at authentication
  | Then:
  |   wrap_key  ← HKDF(prf_out, cred_salt_from_server, ...)
  |   (same wrap + commit as 4.1)
  |                                   |
  |-- PUT /passkeys/{id}/prf-wrapper->|
```

Extra round-trip. Acceptable.

### 4.3 Registration on a surface with no PRF at all (Firefox ≤147, etc.)

```
Client                              Server
  |-- POST /register/start ---------->|
  | (PRF extension requested; cred.getClientExtensionResults().prf === undefined)
  |-- POST /register/finish --------->|
  |   { cred, prf: { supported: false } }
  |                                   | INSERT passkeys (cred_salt=NULL, prf_supported=false)
```

Credential registers successfully but has no PRF wrapper. User will use sync-link flow on new devices using this credential. When they later authenticate on a PRF-capable browser with the same *synced* credential, the client may re-detect PRF support and run the "upgrade path" in §4.5.

### 4.4 New-device login (happy path)

```
Client                              Server
  |-- POST /login/start ------------->|
  |<----- challenge ------------------|
  | navigator.credentials.get({
  |   extensions: { prf: { eval: { first: PRF_EVAL_SALT } } }
  | })                                |
  | → assertion + prf.results.first   |
  |                                   |
  |-- POST /login/finish ------------>|
  |<----- session token --------------|
  |                                   |
  |-- GET /passkeys/{cred_id}/prf-wrapper (fresh session required)
  |<----- { ct, nonce, version, amk_commit } ---|
  |                                   |
  | cred_salt    ← from GET /passkeys/{cred_id} (or embed in above response)
  | wrap_key     ← HKDF(prf_out, cred_salt, "secrt-amk-wrap-prf-v1", 32)
  | amk          ← AES-256-GCM^-1(wrap_key, nonce, aad, ct)
  | verify SHA256("secrt-amk-commit-v1" || amk) === amk_commit  ← MUST PASS
  | storeAmk(user_id, amk)            |
```

### 4.5 Upgrade path — existing credential becomes PRF-capable

Happens when a user registered a passkey on Firefox 146, then later authenticates on Chrome + Windows Hello. Same credential (synced or device-bound), new capability.

```
Login completes normally; after session established:
  asr.getClientExtensionResults().prf.results.first exists BUT
  passkeys.prf_supported = false (or cred_salt is NULL)
  AND user has AMK in IndexedDB (client can prove it by re-deriving commit)

  → offer to enable:
    - generate cred_salt server-side (PATCH /passkeys/{id} to set cred_salt + prf_supported=true)
    - wrap local AMK with HKDF(prf_out, new_cred_salt, ...)
    - PUT /passkeys/{id}/prf-wrapper
    - Now this credential supports passkey-login on new devices
```

### 4.6 CLI bootstrap via `secrt auth login` (browser-mediated ECDH + PRF)

`secrt-cli`'s `auth login` command (`crates/secrt-cli/src/auth.rs:147+`) uses a browser-in-the-middle device-authorization flow: CLI generates ECDH ephemeral keypair, opens a browser to a verification URL, user approves, browser wraps its local AMK with the ECDH shared secret, CLI receives the `amk_transfer` blob and re-wraps under its api-key-root for `amk_wrappers`.

Today this flow implicitly requires the browser tab to **already have AMK in IndexedDB** when the user approves — otherwise there's nothing to ECDH-wrap. That forces a two-step bootstrap on a brand-new browser ("paste API key or run `sync` from another device first, then approve CLI").

PRF composes cleanly with this: the verification-URL page is just another logged-out browser entry point. With Subtasks 3-5 from task #42 landed, that page will automatically trigger the PRF login → fetch wrapped AMK from `GET /passkeys/{cred_id}/prf-wrapper` → unwrap → `storeAmk()` sequence before the user clicks "Approve," turning the bootstrap into a single-tap flow.

```
CLI                          Browser (verification URL)         Server
 |                                      |                           |
 | auth login                           |                           |
 |-- ECDH generate ephemeral keypair    |                           |
 |-- POST /device/start ----------------+-------------------------->|
 |<-- { user_code, verification_url } --|---------------------------|
 |                                      |                           |
 |-- open_browser(verification_url) --->|                           |
 |                                      | (page loads, logged out)  |
 |                                      |-- navigator.credentials.get
 |                                      |     with PRF ext --------->|
 |                                      |<---- assertion + PRF -----|
 |                                      |-- GET /passkeys/{id}/prf-wrapper
 |                                      |<---- wrapped AMK ---------|
 |                                      | unwrap → storeAmk()       |
 |                                      |                           |
 |                                      | user clicks "Approve"     |
 |                                      |-- ECDH(browser_priv, cli_pub)
 |                                      |   → transfer_key          |
 |                                      |   → AES-GCM wrap AMK      |
 |                                      |-- POST /device/approve -->|
 |                                      |   { amk_transfer: {...} } |
 |                                      |                           |
 |-- POST /device/poll ---------------------------------------------- >|
 |<-- { amk_transfer: {...} } ---------------------------------------|
 | ECDH(cli_priv, browser_pub) → transfer_key                        |
 | AES-GCM unwrap → AMK                                              |
 | HKDF(api_key_root, ...) → wrap_key                                |
 | AES-GCM wrap → wrapped_amk                                        |
 |-- PUT /amk-wrappers (existing path) ------------------------------>|
```

**Important implementation note for the verification-URL page:** it must execute the PRF unlock *before* showing the approve button, not lazily-on-click. Otherwise the user taps Approve, the ECDH handoff runs, and the browser has no AMK to wrap → error or incomplete transfer. Order: (1) navigator.credentials.get with PRF → (2) fetch+unwrap AMK → (3) render approve button → (4) on click, do ECDH wrap + POST /device/approve.

**Fallback when PRF unavailable on verification browser** (Firefox ≤147, etc.): the page offers the existing options — "paste API key" or "open sync link from another logged-in device." Same as today's status quo. No regression.

### 4.7 Revocation

Revoking a passkey (`passkeys.revoked_at`) must cascade to `prf_amk_wrappers`. ON DELETE CASCADE via the FK already handles hard deletes. For soft-delete (revoked_at set), the HTTP layer must `DELETE /passkeys/{cred_id}/prf-wrapper` before marking the passkey revoked, so a compromised credential can't exfiltrate its own wrapper.

---

## 5. Fallback & Coexistence (the recovery story)

The "no recovery code" decision rests on these existing paths:

1. **API keys.** Users can generate API keys in Settings; each API key creates an entry in `amk_wrappers` (existing §2.4). An API key printed to paper is a functional recovery token. Advertised explicitly in Settings.
2. **Another still-logged-in device.** Sync-link flow (`POST /api/v1/auth/app/start|approve|poll`) remains. Works for any browser, any credential type.
3. **Multiple passkeys.** Users are nudged at registration to add a second passkey on a different device.

Losing all of (1) + all passkey devices simultaneously = data loss. This is explicit, documented in the UI, and the same guarantee Apple offers for iCloud Keychain. Acceptable.

---

## 6. Threat Model

### Protected against
- **Server compromise:** server holds only `prf_output → HKDF → wrap_key → wrapped_amk` — the PRF output never touches the wire. AMK remains undecryptable.
- **Network observer:** all over TLS; wrapped blobs are opaque.
- **Credential stuffing on the GET endpoint:** fresh-session requirement + rate limiting.
- **Replay across credentials:** AAD binds wrapper to `credential_id`.
- **Replay across users:** AAD binds wrapper to `user_id`.
- **Replay across domains:** `PRF_EVAL_SALT` includes `"secrt.is/v1/..."` prefix; authenticator domain-separates by RP ID anyway.

### Not protected against
- **Malicious client code.** If the attacker replaces our JS, they call `navigator.credentials.get()` legitimately and derive the PRF output themselves. Same failure mode as all browser-crypto; SRI headers and CSP help but aren't sufficient.
- **Malicious browser extension.** Can observe PRF output post-derivation. Inherent limitation.
- **Compromised authenticator.** If the authenticator is actually lying about holding the key, PRF is moot.
- **User losing all credentials and all API keys and all logged-in devices.** Explicit loss (see §5).

---

## 7. Open Questions

1. **Rotation.** If we ever want to rotate the HKDF info label from `v1` to `v2`, do we: (a) re-wrap all PRF wrappers lazily on next login, (b) force all users to re-register, or (c) support both simultaneously via the `version` field? Preferred: (a). Not implementing in v1 but the `version` field in the wrapped-AMK must be respected at decrypt time.
2. **Do we need `prf_at_create` as a column?** Used in §4.1 vs §4.2 flow disambiguation. Low cost; keep it.
3. **What format is `credential_id_bytes` in AAD?** Current `passkeys.credential_id` is TEXT (base64url). AAD should use raw bytes (base64url-decoded). Verify both client and server decode identically. **Land before impl.**
4. **Fresh-session window for GET `/prf-wrapper`.** 60s? 30s? Should we just require re-auth (a new WebAuthn ceremony) instead of relying on session recency? Re-auth is stricter; probably worth it.
5. **Rate-limit tier for `/prf-wrapper` endpoints.** Start with existing authed-create limits (2rps burst 20); may need tightening.
6. **Does `webauthn-rs` (Rust crate) expose PRF extension parsing yet?** Verify before locking the Rust side.

---

## 8. Implementation Plan (by file)

### Rust
- `secrt-core/src/amk.rs`
  - Add `HKDF_INFO_AMK_WRAP_PRF = "secrt-amk-wrap-prf-v1"`.
  - Add `derive_amk_wrap_key_from_prf(prf_output: &[u8], cred_salt: &[u8]) -> Result<Vec<u8>>`.
  - Add AAD builder for PRF path (different layout from §2.3).
  - Tests: round-trip wrap/unwrap using test vectors (§9).
- `secrt-server/src/http/mod.rs`
  - Modify `handle_passkey_register_finish_entry` (line 1597) to accept `prf: { supported, at_create, cred_salt?, wrapper? }` in body.
  - Modify `handle_passkey_login_finish_entry` (line 1722) — no behavior change, but if body asks for wrapper return it in-line to save the extra GET.
  - Add three handlers: `handle_prf_wrapper_put`, `handle_prf_wrapper_get`, `handle_prf_wrapper_delete`.
- `secrt-server/migrations/NNN_prf_amk_wrappers.sql` — schema per §3.3.

### TypeScript
- `web/src/crypto/amk.ts`
  - Add `HKDF_INFO_AMK_WRAP_PRF` and `PRF_EVAL_SALT`.
  - Add `deriveAmkWrapKeyFromPrf(prfOutput, credSalt)`.
  - Add `wrapAmkForPrf(amk, prfOutput, credSalt, credIdBytes, userIdBytes)` and symmetric unwrap.
- `web/src/features/passkeys/register.ts`
  - Add `extensions.prf.eval.first = PRF_EVAL_SALT` to create options.
  - Detect three states post-create (§4.1/4.2/4.3).
  - On success with PRF-on-create and existing AMK: immediate PUT to wrapper endpoint.
- `web/src/features/passkeys/login.ts`
  - Add PRF to get options.
  - On success, if `prf.results.first` present AND no AMK in IndexedDB: fetch wrapper, unwrap, `storeAmk()`.
- `web/src/features/passkeys/upgrade.ts` (new) — §4.5 flow.
- `web/src/features/settings/PasskeysPage.tsx` — per-credential status indicator.

### Spec
- `spec/v1/server.md` — add PRF endpoints to the route table, add §"PRF-based AMK wrapping" subsection.

---

## 9. Test Vectors

Canonical vectors live in `spec/v1/amk.vectors.json` under
`vectors.wrap_unwrap_prf`. Both Rust (`crates/secrt-core/tests/amk_vectors.rs::wrap_unwrap_prf_vector`)
and TypeScript (`web/src/crypto/amk.test.ts::wrap_unwrap_prf`) load the same
JSON and verify byte-identical output for `wrap_key`, `aad`, `ct`, `nonce`,
and `amk_commit`. CI fails if either implementation drifts.

The vector covers:

- HKDF wrap-key derivation from a fixed PRF output and `cred_salt`.
- AAD construction with a 16-byte credential_id as `binding_id`.
- AES-256-GCM seal with a deterministic (fill-byte) nonce.
- AMK commitment matches the api-key transport (same AMK, same commit).

Negative cases live in unit tests inside `crates/secrt-core/src/amk.rs`:

- Wrong credential_id in AAD → `unwrap_amk` fails (`prf_aad_differs_from_apikey_aad`,
  `wrap_unwrap_prf_deterministic_roundtrip`).
- Wrong `cred_salt` produces a different wrap key → unwrap fails.
- Non-32-byte `prf_output` or `cred_salt` rejected at derive time.
- PRF wrap key MUST differ from API-key wrap key even given identical inputs
  (domain separation via different info string).

---

## 11. 2026-04 spike findings

Real-device verification using `web/prototypes/prf-spike/`. Records actual PRF
behavior observed per surface. Update as more devices are tested.

### Observed (so far)

| Surface                                          | PRF-on-create | Login PRF | Notes                                                      |
| ------------------------------------------------ | ------------- | --------- | ---------------------------------------------------------- |
| Chrome on macOS + Apple Passwords (iCloud)       | ✓             |           | fp `ca3f9925 6f5b083c` (single device, single credential)  |
| Safari 18+ on macOS + iCloud Keychain            | ✓             |           | fp `282b9779 0b3c05a9` (different credential than ↑)       |
| Safari on iOS + Apple Passwords (iCloud)         | ✓             | ✓         | fp `150eed07 a4944b7d`. Round-trip OK on same device.      |
| Chrome on Android + Google Password Manager      | ✓             |           | wrap+unwrap OK (fingerprint not recorded)                  |
| Chrome on macOS + Google Password Manager        | ✗             | ✗         | `enabled=false` — see GPM-on-desktop caveat below          |
| Bitwarden as picker (Chrome on macOS)            | ✗             | ✗         | `prf: undefined` — see Bitwarden caveat                    |
| 1Password as picker (Safari on macOS)            | ✗             | ✗         | `prf: undefined` — see 1Password caveat                    |

### iOS Safari naming quirk (not a bug)

At login, iOS Safari returns `enabled=false hasResultsFirst=true`. The `enabled` field is
only meaningfully set at create time; at get time the relevant signal is whether
`results.first` is present. Our spike's `describePrfExt` shows both fields literally; the
correct interpretation is "PRF output present" whenever `hasResultsFirst=true`. The Phase
B and Phase D code should never read `enabled` at get time — only `results.first`.

### 1Password caveat

1Password as a credential picker also returned `prf: undefined` (Safari on macOS, 2026-04
spike). Same root cause class as the Bitwarden caveat — the picker's WebAuthn passthrough
doesn't forward the PRF extension, regardless of whether 1Password's underlying
authenticator could in principle support it.

User impact: same fallback story as Bitwarden — sync-link / API-key path remains the only
new-device unlock for 1Password-stored secrt credentials.

Note on cross-row fingerprint comparison: PRF outputs are per-credential. Different
registrations on different surfaces produce different credentials and therefore different
fingerprints — that's correct, not a bug. Cross-device determinism is only verifiable
when the *same* synced credential is read on two devices (e.g. macOS Safari ↔ iOS Safari
sharing one iCloud Keychain entry).

### GPM-on-desktop caveat (2026-04 spike)

Chrome on macOS storing into Google Password Manager returned `enabled=false` for a
freshly created credential — meaning the API acknowledged the PRF request and explicitly
declined. This contradicts the Corbado April 2026 matrix claim of 100% PRF-on-create
success for GPM. Possible explanations to investigate:

1. GPM PRF-on-create is enabled only on Chrome+Android, not Chrome desktop (the Corbado
   measurement may have been Android-only).
2. macOS Chrome routes GPM through a different code path than Windows/Linux.
3. A recent Chrome desktop update changed GPM's PRF behavior.

Re-test on **Chrome on Android + GPM** before drawing conclusions — that's the surface
that actually matters for our gate (mobile users) and what the matrix in the task
description was based on. If desktop-GPM stays broken but Android-GPM works, the user
impact is "GPM users get PRF unlock on Android but not desktop"; mac users on desktop
who want PRF should use Apple Passwords instead.



### Bitwarden caveat (important for UX docs)

Bitwarden as a credential picker did not propagate the PRF extension to the relying
party in our 2026-04 testing on Chrome/macOS. The `prf` field on
`getClientExtensionResults()` was undefined entirely (not just `enabled=false`).
Bitwarden has shipped PRF for their own E2EE flows, but the browser-WebAuthn
passthrough depends on the picker code path, and as of this spike that path drops the
extension.

For a recommended product like Bitwarden, this is unfortunate. Implication:
1. Users storing their secrt passkey in Bitwarden will not get single-tap new-device unlock.
2. Falls back to the existing sync-link / API-key path — same as Firefox ≤147, external roaming authenticators on iOS Safari, etc.
3. Subtask 6 (UX) must surface this clearly so users can pick where to store their secrt passkey with eyes open.

We should re-test periodically — Bitwarden may add the passthrough in a later release.

### Cross-device determinism — CONFIRMED (2026-04-27)

Registered credential `XZDeAOxyIOZo4DXVnuE9o6_I4bg` on iPhone Safari + iCloud Keychain
(fingerprint `150eed07a4944b7d`). Same credential picked up on macOS Safari via
discoverable login (no `allowCredentials` constraint) — fingerprint matched. Synced
passkeys produce deterministic PRF outputs across devices in the iCloud sync set, as
spec'd. Phase A gate is cleared for the most important surface.

### Still informational, not gating

- Chrome 147+ on Windows 11 + Hello — defer until we have Windows hardware in the loop, or to Subtask 7's CI matrix.
- Firefox 148+ — small user share; defer.
- External YubiKey on iOS Safari — expected fail (hmac-secret returned encrypted; documented Apple WebAuthn limitation, not in scope to fix).

### YubiKey / external roaming authenticators

YubiKey + PRF works on Chrome/Edge/Firefox desktop and on Safari macOS, plus Chrome
Android with NFC. Two implications for secrt's UX (Subtask 6):

1. YubiKey users should register **two physical keys** (primary + backup) because there
   is no Apple/Google recovery layer.
2. The fallback recovery story (API key written down, or a sync-link from another
   device) is load-bearing for this cohort, not optional. Surface this in onboarding
   when a user picks YubiKey as their primary credential.

iOS Safari + external YubiKey remains broken upstream; iOS users with YubiKeys must use
platform passkeys (Apple Passwords) for secrt.

### Cohort summary for product copy

| Cohort                                            | Path                                                          |
| ------------------------------------------------- | ------------------------------------------------------------- |
| Default users (Apple/Google synced passkeys)      | PRF unlock — single-tap on new devices.                       |
| 1Password / Bitwarden / LastPass managers today   | Sync-link or API-key fallback until those add PRF passthrough.|
| Ultra-paranoid (YubiKey)                          | 2× YubiKey + written-down API key, desktop-only PRF.          |

### Gate status: CLEARED for Phase B

---

## 10. References

- WebAuthn Level 3 PRF extension spec: <https://www.w3.org/TR/webauthn-3/#prf-extension>
- Yubico developer guide: <https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html>
- Corbado 2026 state-of-PRF: <https://www.corbado.com/blog/passkeys-prf-webauthn>
- Bitwarden on PRF: <https://bitwarden.com/blog/prf-webauthn-and-its-role-in-passkeys/>
- Firefox PRF meta-bug: <https://bugzilla.mozilla.org/show_bug.cgi?id=1863819>
- Existing AMK impl: `secrt-core/src/amk.rs` + `web/src/crypto/amk.ts`
