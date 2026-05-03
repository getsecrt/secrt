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
  ADD COLUMN cred_salt              BYTEA,          -- 32 random bytes, NULL for non-PRF credentials
  ADD COLUMN prf_supported          BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN prf_at_create          BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN safari_prf_compatible  BOOLEAN;        -- tri-state: TRUE | FALSE | NULL (unclassified)
  -- prf_supported: authenticator returned non-empty PRF output at some point
  -- prf_at_create: PRF output was available in the registration ceremony (Chrome 147+ Win, Safari 18+, etc.)
  --                vs only available after first auth (older surfaces)
  -- safari_prf_compatible: the only server-visible bit added by the credential-metadata work.
  --   Capability-framed (not identity-framed): "this credential can complete PRF unlock on iOS Safari /
  --   any iOS WKWebView browser." TRUE iff iCloud Keychain / Apple-issued credential. FALSE for
  --   non-Apple credentials whose AAGUID is recognized in the client-side lookup. NULL when the
  --   client couldn't classify (e.g. anonymity-stripped attestation, unrecognized AAGUID).
  --   Read at tier-2 (authenticated, AMK not yet available) to render the iPhone-compatibility hint
  --   on the new-device login screen and the tier-2 Settings view, before any encrypted blob can be
  --   decrypted. Brand-level metadata (AAGUID, attestation_fmt, transports, authenticator_attachment)
  --   lives in the AMK-encrypted Preferences blob — see task-37-unified-preferences.md §"Credential
  --   metadata — capture and resolution".

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

### 3.6.1 Credential-metadata capture (registration only)

After `navigator.credentials.create()` returns, the client extracts identification
metadata from the attestation object. This work is owned operationally by
`web/src/lib/credential-capture.ts` (see task-37-unified-preferences.md Phase 3.5)
but the contract is summarized here because it determines the value of
`safari_prf_compatible` that the client sends to the server.

```
1. Parse attestation object:
   - aaguid             = authenticatorData.attestedCredentialData.aaguid (16 raw bytes)
   - attestation_fmt    = outer CBOR "fmt" field ("none" | "packed" | "apple" | "tpm" | ...)
   - transports         = response.getTransports() (e.g. ["usb","nfc"] or ["internal"])
   - attachment         = credential.authenticatorAttachment ("platform" | "cross-platform")
2. Derive safari_prf_compatible (tri-state):
     TRUE   iff attestation_fmt == "apple"
            OR aaguid == adce0002-35bc-c60a-648b-0b25f1f05503  (Apple's published AAGUID)
            OR attachment == "platform" AND attestation_fmt == "apple"
     FALSE  iff aaguid matches a known non-Apple AAGUID (YubiKey models, Windows Hello TPM,
            GPM Android, 1Password, Bitwarden, Feitian, KeePassXC) per the client lookup table
     NULL   otherwise (anonymity-stripped attestation + unrecognized AAGUID)
3. Send safari_prf_compatible to server in register-finish payload:
     POST /api/v1/auth/passkeys/register/finish
       { ..., safari_prf_compatible: true | false | null }
   Server stamps the column. Treat as a UX hint, not a security claim — the actual unlock
   attempt always derives the wrap key, attempts AES-GCM decrypt, and verifies amk_commit.
4. Write rich metadata into the encrypted Preferences blob:
     Preferences.credentials[credential_id] = {
       aaguid, attestation_fmt, transports, authenticator_attachment, capability
     }
   Same write path as any other Preferences mutation (CAS via ETag).
```

The `add-finish` (Settings → Add passkey) and login-finish (PRF-upgrade path
§4.5) handlers also accept and persist `safari_prf_compatible` so credentials
registered or upgraded from those entry points get classified consistently.

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

**Implemented in 0.16.8:** the upgrade is folded into the standard login-finish path rather than a separate PATCH endpoint. The client sends the assertion's PRF state in the `prf` field on `POST /auth/passkeys/login/finish`; when the row predates PRF (`cred_salt = NULL`), the server generates a fresh 32-byte salt, stamps the row with `prf_supported = true`, and returns it as `prf_cred_salt` in the response. The client wraps the AMK (already in IndexedDB on a known device — that's *why* this is the upgrade case rather than a fresh-device login) and `PUT`s the wrapper. Best-effort: failure here is non-fatal, login itself succeeds, and the next login with this credential will retry.

The same `prf` field is accepted on `POST /auth/passkeys/add/finish` so credentials added from Settings get a `cred_salt` and wrapper at create time, mirroring register-finish.

```
Client                                        Server
-------                                       ------
loginPasskeyFinish({
  challenge_id, credential_id,
  prf: { supported: true, at_create: false }
})
                                              looks up passkey row
                                              row.cred_salt is NULL ∧ prf.supported
                                              → cred_salt = randombytes(32)
                                              → set_passkey_prf_state(...)
                                              → respond with prf_cred_salt
loadAmk(user_id) → amk
computeAmkCommit(amk)
wrapAndStorePrfWrapper(...)
                                              upsert_prf_wrapper(...)
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

Real-device verification using `web/prototypes/prf-spike/` and (since
task #62) the in-app diagnostic logging. Records actual PRF behavior
observed per surface. Update as more devices are tested.

> **Captured-trace log:** `prf-cross-device-testing.md` is the empirical
> companion to this section — full per-credential fingerprints, failure
> mode catalog, and methodology. New entries to the table below should be
> backed by a captured trace there.

### Observed (so far)

| Surface                                          | PRF-on-create | Login PRF | Notes                                                      |
| ------------------------------------------------ | ------------- | --------- | ---------------------------------------------------------- |
| Chrome on macOS + Apple Passwords (iCloud)       | ✓             |           | fp `ca3f9925 6f5b083c` (single device, single credential)  |
| Safari 18+ on macOS + iCloud Keychain            | ✓             |           | fp `282b9779 0b3c05a9` (different credential than ↑)       |
| Safari on iOS + Apple Passwords (iCloud)         | ✓             | ✓         | fp `150eed07 a4944b7d`. Round-trip OK on same device.      |
| Chrome on Android + Google Password Manager      | ✓             |           | wrap+unwrap OK (fingerprint not recorded)                  |
| Chrome on macOS + Google Password Manager        | ✗             | ✗         | `enabled=false` — see GPM-on-desktop caveat below          |
| Bitwarden as picker (Chrome on macOS)            | ✓ (with friction) | ✓ (with friction) | 2026-05-02: refined model — Bitwarden gates the WebAuthn UI but does not modify assertion bytes. PRF works when the user navigates through "Use your device or hardware key." Costs ~4 user actions per YubiKey registration vs 2 baseline. See Bitwarden caveat. |
| 1Password as platform passkey provider (Mac Chrome / Safari / Firefox; Windows Chrome / Firefox; iPhone Safari) | ✓ | ✓ | 2026-05-02: same credential `2hX0aGOL` produces byte-identical PRF output `88c149421125d06f` across all six surfaces. End-to-end AMK transfer works on every desktop OS, every major browser including Safari and Firefox, and iOS. PRF returned at create() — single touch at registration. Best cross-platform result we have. See 1Password caveat. |
| YubiKey 5C NFC on Vivaldi ↔ Chrome (macOS)       | ✓             | ✓         | 2026-05-01: AMK transfers cross-browser. Reference fp `ae46d371655a91c5` (localhost) / `7baef9877a382253` (`secrt.is`). |
| YubiKey 5C NFC on **macOS Safari**               | n/a           | ✗ broken  | 2026-05-01: same credential, **different** PRF output (`156c06de00de5149`) than Chromium reading the same key on the same Mac. Apple WebAuthn framework intercepts. See "Apple WebAuthn framework" caveat below. |
| YubiKey 5C NFC on iPhone Safari (any iOS)        | n/a           | ✗ broken  | Auth succeeds, AMK does not transfer — same root cause as macOS Safari above. See "Apple WebAuthn framework" caveat below. |
| YubiKey 5C NFC on **Firefox 150.1** (macOS)      | n/a           | ✗ broken  | 2026-05-02: `prfExtPresent: false` — Firefox strips the PRF extension. Confirmed with and without Bitwarden. **Refined cause (2026-05-02 source investigation, see `firefox-prf-source-investigation.md`):** macOS-specific — Firefox routes USB security keys through Apple's `ASAuthorizationController` and `MacOSWebAuthnService.mm` doesn't wire PRF for the security-key request class. Workaround on this surface: caBLE QR + phone passkey (PRF travels through hybrid). See "Firefox caveat" below. |
| YubiKey on **Firefox 150.1** (Windows)           | n/a           | ✓ confirmed | 2026-05-02 (Round F): same YubiKey, credential `xAvG1eEG` produces `prfOutputFingerprint: 8f5316e83dcd8470` on Firefox/Windows — byte-identical with Chrome/Mac and Chrome/Windows. AMK transfers cleanly Chrome/Windows → Firefox/Windows for credential `d2Bv_6Qz` (`amkFingerprint: 5383cf93d8c11e51`). Routes through `webauthn.dll`'s `WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET`. |
| YubiKey on **Firefox 149.0.2** (Linux)           | n/a           | ✓ confirmed | 2026-05-02 (Round G): same YubiKey, credential `d2Bv_6Qz` produces `prfOutputFingerprint: 50a29d48c9bb78e2` on Firefox/Linux — byte-identical with Chrome/Windows registration and Firefox/Windows sign-in. Cross-OS AMK transfer Chrome/Windows → Firefox/Linux works cleanly (`amkFingerprint: 5383cf93d8c11e51`). Routes through `authrs_bridge` + vendored `authenticator-rs`. PRF working at least since Firefox 149 on Linux. |

### iOS Safari naming quirk (not a bug)

At login, iOS Safari returns `enabled=false hasResultsFirst=true`. The `enabled` field is
only meaningfully set at create time; at get time the relevant signal is whether
`results.first` is present. Our spike's `describePrfExt` shows both fields literally; the
correct interpretation is "PRF output present" whenever `hasResultsFirst=true`. The Phase
B and Phase D code should never read `enabled` at get time — only `results.first`.

### 1Password — confirmed gold standard for cross-ecosystem users (2026-05-02)

Round C in `prf-cross-device-testing.md` captured the same 1Password-stored
credential (`2hX0aGOL`) on six surfaces:

- macOS Chrome (registration)
- macOS Safari (sign-in)
- macOS Firefox (sign-in)
- Windows Chrome (sign-in)
- Windows Firefox (sign-in)
- iPhone Safari (sign-in via 1Password's iOS Credential Provider Extension)

Every surface produced byte-identical PRF output `88c149421125d06f` and
unwrapped the AMK end-to-end. **No surface failed.** Notably:

- **Mac Safari + 1Password works** even though Mac Safari + YubiKey doesn't.
- **iPhone Safari + 1Password works** even though iPhone Safari + YubiKey doesn't.
- **Firefox + 1Password works** even though Firefox + YubiKey doesn't.
- **PRF is returned at create() time** (no double-touch, no fallback ceremony).

#### Why 1Password works where YubiKey doesn't

The mechanism is the `authenticatorAttachment: 'platform'` taxonomy
combined with platform-specific credential-provider APIs:

- **iOS:** 1Password registers via Apple's `ASCredentialProviderExtension`
  (the iOS 17+ third-party passkey provider API). Apple's WebAuthn
  framework treats credentials surfaced through this API the same way
  it treats iCloud Keychain — as a platform credential — and passes PRF
  through unmodified. The Apple framework `hmac-secret` re-wrap behaviour
  (which breaks YubiKey on Safari/iOS) only applies to *external CTAP2
  authenticators* talking via the FIDO2 USB / NFC pathway.
- **macOS / Windows / Linux:** 1Password's browser extension intercepts
  WebAuthn calls and returns a 1Password-managed credential before
  reaching any platform framework. Same passthrough story.
- **Determinism:** 1Password's vault sync carries the cred_salt and
  credential state in a way that makes PRF derivation byte-identical
  across devices. This is the property that lets the AMK unwrap on a
  fresh device.

#### Android caveat

1Password requires **Android 14+** for passkey support — that's when
Android shipped the Credential Manager API for third-party passkey
providers. Earlier Android (Pixel 4a maxes at Android 13, etc.) cannot
do passkeys via 1Password at all. Not a 1Password limitation, an
Android platform one. On Android 14+ the Credential Manager pathway
should behave like the iOS Credential Provider Extension and pass PRF
through cleanly; not yet hardware-verified by us.

#### Trust-model framing for product copy

Recommending 1Password as the cross-ecosystem default is not the same
as recommending it for everyone. The trade-offs:

- **Trust 1Password the company.** Their authenticator implementation,
  their sync infrastructure, their availability. If 1Password's vault
  is compromised (or the user loses access to their 1Password account),
  the credentials are gone.
- **Vs. iCloud Keychain (Apple users only):** trust Apple instead. Tighter
  integration on Apple platforms, no cross-ecosystem reach.
- **Vs. YubiKey:** trust only the device in your hand. Stronger threat
  model. But broken on Safari (any), Firefox, and iPhone — so users with
  any Apple/Firefox surface in their daily life will hit walls
  constantly.

Different cohorts, different recommendations. See "Cohort summary for
product copy" below for the consolidated table.

#### Historical note

The 2026-04 spike's `prf: undefined` reading was Safari/macOS confounding
the test (Safari strips PRF for non-iCloud credentials regardless of
who the picker is). The earlier "1Password drops PRF" claim has been
struck from this doc as of 2026-05-02. Hypothesis H5 in
`prf-cross-device-testing.md` §5 is marked resolved-disproved.

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

**Refined model 2026-05-02 (multiple Round B traces on `secrt.is`):**
Bitwarden's content script (`fido2-page-script.js`) does **not** modify
assertion bytes or strip extensions. What it does is insert a UI gate in
front of every WebAuthn ceremony — its own picker prompt that asks the
user to choose between Bitwarden's stored credentials and "Use your device
or hardware key." When the user navigates through that prompt, the
assertion proceeds normally and the PRF output comes through unchanged.
The `NotAllowedError` we observed on 2026-05-01 was the user dismissing /
timing out the Bitwarden popup — not corruption.

The cost is friction, not breakage. A YubiKey registration with
Bitwarden enabled requires four user actions (Bitwarden popup → tap key
→ second Bitwarden popup for the PRF fallback get() → tap key again)
versus two without the extension. Subsequent sign-ins are similar:
discoverable login completes, but the user has to route through the
Bitwarden picker each time.

Implications:

1. **Bitwarden does not break PRF.** The earlier characterization
   ("Bitwarden silently drops PRF") was wrong for the YubiKey path —
   tied to the 2026-04 spike's testing where Bitwarden was the picker
   *for its own stored credential* (a different code path, where PRF
   genuinely is dropped because Bitwarden's authenticator doesn't
   support it).
2. **Users who store their secrt credential in Bitwarden's vault** still
   lose PRF — Bitwarden's authenticator implementation doesn't forward
   the extension. The 2026-04 finding stands for *this* configuration.
3. **Users with a YubiKey + Bitwarden installed but secrt credential
   not stored in Bitwarden** can use PRF, but pay the friction cost.
   Recommend disabling Bitwarden during initial registration to avoid
   the double-popup; re-enable afterward.
4. **Onboarding copy** should distinguish "Bitwarden as picker for its
   own credential" (PRF dropped, use sync-link) from "Bitwarden present
   but not the credential holder" (PRF works, just clunky UX). These
   are different cohorts with different fallback stories.

We should re-test periodically — Bitwarden may add the PRF passthrough
to its own authenticator in a later release.

### Firefox caveat (confirmed broken on macOS 2026-05-02; refined by source investigation 2026-05-02)

Firefox 150.1 **on macOS** does not return a PRF output for USB
security keys (YubiKey 5C NFC verified). The assertion completes — the
user is signed in — but `getClientExtensionResults()` returns no `prf`
key at all (`prfExtPresent: false` in our logging). Tested with and
without Bitwarden; identical result.

**Mechanism (now verified at the source level — see [`firefox-prf-source-investigation.md`](firefox-prf-source-investigation.md)):**

- Firefox added PRF support in v148 (Mozilla bug 1863819 and follow-ups
  including the macOS-specific 1935280, fixed in Firefox 139).
- The Rust `authenticator-rs` crate that Firefox vendors fully
  supports `hmac-secret`: salt encryption, response decryption, the
  works. So PRF over USB CTAP2 is *not* missing from Firefox-the-product.
- On macOS 13.3+, Firefox routes WebAuthn ceremonies through Apple's
  `ASAuthorizationController` rather than `authenticator-rs`. The
  macOS adapter (`dom/webauthn/MacOSWebAuthnService.mm`) wires PRF
  into the platform-credential request class
  (`ASAuthorizationPlatformPublicKeyCredentialAssertionRequest`) but
  not into the security-key request class
  (`ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest`).
  Both halves of the hypothesis are present: the request never asks
  for PRF, and the response handler never reads it from a security-key
  assertion. (`MacOSWebAuthnService.mm:1276`, `:889`, `:476`.)
- About:config has no `prf`-prefixed preference. SDK status verified
  2026-05-02 against local Xcode SDKs: macOS 15 SDK does *not* expose
  `.prf` on the security-key class; macOS 26.4 SDK *does*
  (`API_AVAILABLE(macos(26.4), ios(26.4))`). So a hypothetical
  small Mozilla patch is shippable for macOS 26.4+ users today.
- **But the framework still re-wraps `hmac-secret` for external
  authenticators on macOS 26.4.1** (empirically reconfirmed in
  Round E, see `prf-cross-device-testing.md`). Apple did not change
  the privacy boundary in the macOS 15 → 26 transition. So Option A
  below would route Firefox through the same wrapped value Safari
  already gets — useful, but not topology-correct.
- No subordinate bug for "USB CTAP2 PRF on macOS" appears under
  meta-bug 1863819 — strongly suggests the gap is unintentional.

**Two candidate Mozilla-side fixes:**

- **Option A — wire `.prf` on the security-key class** in
  `MacOSWebAuthnService.mm`. ~20–40 lines, gated
  `__builtin_available(macos 26.4, *)`. Effective only on macOS 26.4+.
  Yields Safari-equivalent wrapped PRF (Firefox-on-Mac matches
  Safari-on-Mac, but does *not* match Chromium-on-Mac, Firefox/Linux,
  or Firefox/Windows). Useful stopgap but does not deliver
  cross-device determinism.
- **Option B — bypass `ASAuthorizationController` for
  USB-when-PRF-requested**, dispatching to `authrs_bridge` instead.
  ~100–200 lines in `WebAuthnService.cpp` dispatch logic. Effective on
  all macOS versions. Yields raw `hmac-secret`, byte-identical with
  Chromium and Firefox/Linux/Windows. **The only fix that delivers
  cross-device determinism for Firefox/macOS + USB security keys.**

Recommended escalation: file both as Mozilla bugs under 1863819, with
Option B as the primary ask and Option A as a stopgap.

**Cohort consequences:**

1. Firefox/macOS + USB YubiKey: PRF dropped. Sign-in succeeds; AMK
   transfer falls through to sync-link / API-key — same broken-cohort
   bucket as Safari for the YubiKey case. **Workaround:** scan a
   caBLE QR with a phone passkey for the same account (PRF travels
   through the platform request object, which is PRF-wired). Or use
   Chrome / Edge / Vivaldi.
2. Firefox/Linux + USB YubiKey: **confirmed working 2026-05-02
   (Round G).** Routes through `authrs_bridge` (vendored
   `authenticator-rs`). Same credential as Round F produces
   `prfOutputFingerprint: 50a29d48c9bb78e2`, byte-identical with
   Chrome/Windows registration. Cross-OS AMK transfer
   Chrome/Windows → Firefox/Linux works cleanly. Verified on
   Firefox 149.0.2.
3. Firefox/Windows + USB YubiKey: **confirmed working 2026-05-02
   (Round F).** Routes through `webauthn.dll`'s
   `WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET`. Same YubiKey
   credential produces `prfOutputFingerprint: 8f5316e83dcd8470`
   on Firefox/Windows, byte-identical with Chrome/Mac and
   Chrome/Windows. Cross-browser AMK transfer Chrome/Windows ↔
   Firefox/Windows works cleanly.
4. Firefox/anywhere + Apple Passwords or Google Password Manager:
   *may* get PRF (still untested), since those are platform
   credentials. Worth checking before promising it in product copy.
5. Firefox/anywhere + caBLE/hybrid (phone passkey via QR): PRF works,
   empirically confirmed — the platform request path is PRF-wired and
   transports the value through unchanged.

**Right escalation:** file a subordinate Mozilla bug under 1863819
specifically scoped to "USB CTAP2 PRF on macOS — `MacOSWebAuthnService.mm`
security-key class missing PRF wiring." Until Mozilla ships the
patch, document the macOS-specific scoping in product copy and route
Firefox/macOS YubiKey users to the caBLE workaround.


### Cross-device determinism — CONFIRMED (2026-04-27)

Registered credential `XZDeAOxyIOZo4DXVnuE9o6_I4bg` on iPhone Safari + iCloud Keychain
(fingerprint `150eed07a4944b7d`). Same credential picked up on macOS Safari via
discoverable login (no `allowCredentials` constraint) — fingerprint matched. Synced
passkeys produce deterministic PRF outputs across devices in the iCloud sync set, as
spec'd. Phase A gate is cleared for the most important surface.

### Still informational, not gating

- Chrome 147+ on Windows 11 + Hello — defer until we have Windows hardware in the loop, or to Subtask 7's CI matrix. Open hypothesis in `prf-cross-device-testing.md` §H2: Windows may intercept like Apple does, or may pass through like macOS Chrome — captured trace from a real Windows device will resolve this.
- External YubiKey on **any Safari** (macOS or iOS) — confirmed broken (2026-05-01, both surfaces) and now treated as a documented platform limitation rather than a TODO. See "Apple WebAuthn framework caveat" below.
- External YubiKey on **Firefox 150.1 (macOS)** — confirmed broken 2026-05-02. **macOS-specific** per source-level investigation, Round F (Windows), and Round G (Linux) empirical confirmation: Firefox routes USB security keys through Apple's `ASAuthorizationController` and the macOS adapter doesn't wire PRF for the security-key class. **Firefox/Windows and Firefox/Linux both confirmed working 2026-05-02.** See "Firefox caveat" below and [`firefox-prf-source-investigation.md`](firefox-prf-source-investigation.md).

> **YubiKey deep-dive:** for a focused, user-facing explanation of which surfaces work, why the broken ones can't be fixed by Yubico, and recommended setups for YubiKey users (including the trust-model trade-off of pairing a YubiKey with a complementary platform credential), see [`yubikeys.md`](yubikeys.md).

> **Backfilling this table from real captures:** the rows above were collected
> by hand. As of task #62 (`.taskmaster/plans/task-62-prf-amk-diagnostic-logging.md`),
> the web client has gated diagnostic logging behind
> `localStorage.setItem('secrt:debug', '1')` (always on in dev builds). Future
> rows added here should be backed by a captured `[secrt:prf-unwrap]` /
> `[secrt:prf-register-wrap]` console trace — fingerprint + decision branch +
> exception text — rather than speculation about which platform layer
> intercepted the PRF output. The "broken" entries especially deserve a
> captured trace so the failure mode is recorded as observation, not
> hypothesis.

### YubiKey / external roaming authenticators

#### What works (verified 2026-05-01)

Cross-device PRF determinism with the **same YubiKey** between Chromium browsers
(Vivaldi ↔ Chrome on desktop) is confirmed to work end-to-end: register on one
browser, sign in on the other, AMK is unwrapped from the server-stored
`prf_amk_wrappers` row and stored locally with no sync-link / API-key fallback.
Chromium browsers talk to the YubiKey via CTAP HID directly and return the raw
`hmac-secret` value as PRF output, so wrap-key derivation is byte-identical
across machines.

Expected to work on the same basis (not yet hardware-verified): Edge desktop,
Firefox 148+ on **Linux and Windows** (predicted from source investigation
2026-05-02), Chrome on Android with NFC tap. Note: Firefox 148+ on **macOS**
is *not* expected to work for USB security keys — see Firefox caveat above.

#### What breaks: Apple WebAuthn framework (macOS Safari + any iOS browser) with external authenticators

This is a hard upstream limitation, **not a secrt bug**. Mechanism:

- WebAuthn PRF is implemented on top of CTAP2's `hmac-secret` extension.
  Spec-wise, the authenticator returns a value deterministic in
  `(credential, salt)`.
- Chromium and Firefox on desktop forward the raw `hmac-secret` value to
  the relying party as PRF output (they ship their own CTAP HID stacks).
- **Apple's WebAuthn framework** intercepts external-authenticator
  responses and re-wraps `hmac-secret` with an opaque framework-managed key
  before returning to the RP. Output is still 32 bytes and still looks
  valid, but it's `Encrypt(framework_key, real_hmac_secret)` rather than
  the raw value. The framework is used by:
  - **Safari on macOS** (any version, confirmed 2026-05-01 — see
    `prf-cross-device-testing.md` Round A4).
  - **Every browser on iOS** (Safari plus all third-party browsers, since
    iOS forces all browsers through WKWebView).
- Chrome / Vivaldi / Edge on macOS bypass this by talking CTAP HID
  directly. Same Mac, same physical YubiKey, same RP — Chromium gets the
  raw value, Safari gets the framework-wrapped value.

**Important scope note (added 2026-05-02):** the re-wrap behaviour is
specific to *external CTAP2 authenticators* (USB / NFC FIDO2 keys
talking via the platform's HID/NFC pathway). It does **not** apply to
**platform credential providers** that surface credentials through
Apple's `ASCredentialProviderExtension` (iOS 17+ third-party passkey
provider API) or `AuthenticationServices` framework. Round C captured
1Password as a platform credential provider on iPhone Safari and got
clean PRF passthrough — the same credential returned byte-identical PRF
output on iPhone Safari, macOS Safari, and macOS Firefox. So the
"Safari-on-anything is broken for PRF" claim only holds for the
external-authenticator cohort. Software passkey providers that
register via the Credential Provider Extension API are exempt.

Whether the wrap key is per-device, per-Apple-ID, or per-framework-install
is an open question (`prf-cross-device-testing.md` §H1). Either way, two
Apple surfaces using the same external YubiKey on the same RP will not
agree on the PRF output, so cross-Apple-surface AMK transfer doesn't work
even in the friendliest configuration.

Apple's stated rationale is that external authenticators shouldn't expose
raw extension cryptographic material across the platform's privacy
boundary. Yubico's developer guide explicitly calls this out as a known
limitation. There's no signal Apple intends to change it.

**Implication for secrt:** A YubiKey-only user who tries to sign in via
Safari (macOS or iOS) will succeed at *authentication* (the WebAuthn
signature is fine — that path doesn't depend on PRF) but **the AMK will
not transfer**. They'll land on a logged-in but functionally-degraded
session: no encrypted notes accessible, no new notes encrypt-able. Not
silent corruption — just a missing capability. The fallback paths
(sync-link from another device, or API-key unlock) remain available. On
macOS the simplest workaround is "use Chrome / Vivaldi / Edge / Firefox
instead of Safari for sign-in"; on iOS no in-browser workaround exists.

#### UX implications (Subtask 6)

1. YubiKey users should register **two physical keys** (primary + backup) —
   there is no Apple/Google recovery layer. Both wrap the same AMK under
   different `(credential_id, cred_salt)` pairs, so losing one is fully
   recoverable from the other. Verified 2026-05-01: cross-key sync works
   correctly (register both keys on one Chromium browser, use either key on
   another Chromium browser, AMK transfers).
2. The fallback recovery story (written-down API key, or sync-link from another
   logged-in device) is **load-bearing** for this cohort, not optional. Surface
   it in onboarding when a user picks YubiKey as their primary credential.
3. **Surface the broken-cohort caveat at the moment it bites.** When a
   YubiKey user tries to sign in via Safari (macOS or iOS), any iOS
   browser, or Firefox on macOS, expect the AMK unwrap to fail; the UI
   should detect this case (see the failure-mode catalog in
   `prf-cross-device-testing.md` §4) and prompt for sync-link / API-key
   instead of silently leaving them in a degraded session.
   Recommended copy: *"YubiKeys can sign you in here but can't carry
   your encryption key on this browser. On Mac, sign in via Chrome /
   Edge / Vivaldi to get one-tap unlock. On iPhone, use a sync link
   from another logged-in device or paste an API key."* (Note: do
   **not** recommend Firefox in copy — its v148+ PRF support is
   platform-credential-only and does not work for external YubiKeys
   as of 2026-05-02.)
4. Recommend YubiKey users add an iCloud Keychain platform passkey to their
   account specifically for iOS use. Two passkey types on the same account is
   well-supported; on iPhone they get one-tap unlock via the iCloud-synced
   credential, on desktop they keep the YubiKey path. **Honest framing required**
   in the recommendation copy: adding the iCloud Keychain credential widens the
   trust set of the whole account — once any credential can derive the AMK, the
   account's effective security level is the *weakest* enrolled credential
   (OR-of-credentials, not AND). YubiKey-paranoid users who don't model Apple
   as a threat may still want this; users who do should rely on the sync-link /
   API-key fallback on iPhone instead and not add iCloud Keychain at all.

#### Storage and badge UX (cross-reference)

The badge / icon work driven by these constraints lives in
`task-37-unified-preferences.md` (§"Credential metadata — capture and resolution",
Decisions #18–22). Summary of what lands where:

- **One server bit** — `passkeys.safari_prf_compatible` (tri-state). Defined in
  §3.3 above. Capability-framed. Read at tier-2 (no AMK) to render iPhone-compat
  hint before the user has unlocked anything.
- **Rich metadata** — AAGUID, attestation format, transports, authenticator
  attachment, derived capability classification. Lives in the AMK-encrypted
  `Preferences.credentials` map. Server sees opaque bytes only. Resolved to
  brand display name + icon at render time via a static client-side lookup
  table.
- **Padding** — the encrypted Preferences blob is padded to a 4 KB quantum
  before sealing (Decision #18) so credential count / saved-passphrase presence
  can't be inferred from ciphertext length.
- **Server-side label** — `passkeys.label` stays plaintext on the server
  (Decision #21) because revocation and the new-device "which credential do I
  use?" picker must work in the tier-2 state. Encrypting labels would break
  exactly the recovery path that the YubiKey-on-iPhone cohort needs most.

### Cohort summary for product copy

#### TL;DR — which option for which user (2026-05-02)

| If you're… | Use | Why |
|---|---|---|
| **All-Apple, no Android in your life** | **iCloud Passwords / Keychain** | Single-tap on every Apple surface. Works on Windows via QR/hybrid (cumbersome but functional). Doesn't work on Android at all. |
| **Cross-ecosystem with a modern phone (iPhone or Android 14+)** | **1Password — gold standard** | Verified working on every desktop OS, every major browser including Safari and Firefox, plus iOS. Single-tap everywhere. One credential, deterministic PRF, byte-identical across devices. |
| **A Bitwarden user storing your credential there** | Sync-link / API-key fallback | Bitwarden's authenticator doesn't implement PRF. They might add it later; not blocking on it. |
| **A YubiKey-only user (no password manager, no synced platform passkeys)** | YubiKey, but eyes open | Works on Mac/Windows/Linux Chromium. Broken on Safari (any), Firefox, and iPhone. Strong threat model, real compatibility cost. Mitigate by adding a 1Password or iCloud Keychain credential alongside the YubiKey for surfaces where the YubiKey doesn't work. |

In short: **1Password is the gold standard, iCloud is very workable for
all-Apple users, Bitwarden is flawed (for now), and YubiKeys are
semi-broken in half the places.** The detailed matrix below explains
each cohort's behaviour per platform.

#### Detailed cohort matrix

The matrix below assumes the user wants **single-tap unlock on a fresh
device** as the goal (PRF working). Where PRF doesn't work, the
sync-link / API-key fallback is always available — it's just an extra
step the user has to perform.

| Cohort                                            | Desktop                                                       | iPhone / iOS                                                              | Android                                |
| ------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------- | -------------------------------------- |
| **All-Apple users (iCloud Keychain)**             | PRF unlock — single-tap on Apple Passwords across Mac browsers. **On Windows: works only via the CTAP 2.2 hybrid flow** (QR scan + iPhone over Bluetooth + cloud relay) — clunky, requires phone in hand. The iCloud Passwords Chrome extension is **passwords-only, no passkey support** (Apple docs explicit). | PRF unlock — single-tap. | Not applicable (no iCloud on Android). |
| **All-Google users (Google Password Manager)**    | PRF unlock works on Chromium desktop with Android-stored credentials. | Limited — GPM credentials don't sync to iOS Apple Passwords.              | PRF unlock — single-tap (Android 14+). |
| **Cross-ecosystem users → 1Password (gold standard)** | **PRF unlock single-tap on Chrome / Safari / Firefox / Edge / Vivaldi.** Verified Round C 2026-05-02. | **PRF unlock single-tap via Apple Credential Provider Extension.** Verified Round C6. | **Android 14+ required** for 1Password passkeys (Credential Manager API floor). Architecturally expected to work; not yet hardware-verified. |
| Bitwarden storing the secrt credential            | PRF dropped — Bitwarden's authenticator doesn't forward the extension. Sync-link / API-key fallback until Bitwarden ships it. | Same fallback. | Same fallback. |
| Bitwarden installed but credential held elsewhere (e.g. YubiKey) | PRF works, but Bitwarden's picker UI gates every WebAuthn ceremony. ~4 user actions per YubiKey registration vs 2 baseline. Recommend disabling Bitwarden during initial passkey registration. | Same friction pattern if Bitwarden is the iOS picker. | Same friction pattern. |
| **Ultra-paranoid (YubiKey)**                          | PRF unlock works on **Chromium only** (Chrome / Edge / Vivaldi). **Safari and Firefox both broken** on macOS — Safari because Apple's WebAuthn framework re-wraps `hmac-secret` for external CTAP2, Firefox because its v148+ PRF support is platform-credential-only. Recommend 2× YubiKey + written-down API key, and explicitly direct users to a Chromium browser on macOS. | YubiKey signs in but **AMK does not transfer** (same Apple-framework root cause). Sync-link / API-key required, OR add an iCloud Keychain or 1Password passkey for iOS use. | Architecturally expected to work on Chromium (Chrome with NFC tap); not yet hardware-verified. |

**Recommendation defaults to suggest in onboarding copy:**

- *"I'm an Apple user and don't care about other ecosystems"* → iCloud Keychain. Single-tap everywhere Apple, no third-party trust required. If you also use Windows occasionally, expect to scan a QR code with your iPhone for sign-in there.
- *"I use a mix of Apple, Android, Windows, Linux"* → **1Password.** Verified working on every platform we've tested; one credential, byte-identical PRF derivation across all surfaces. Trust set widens to include 1Password the company.
- *"I want hardware-rooted security and don't trust password managers"* → YubiKey. But you'll need to use a Chromium browser on macOS (Safari and Firefox don't work with external authenticators for PRF), and you'll fall back to sync-link / API-key on iPhone. Requires 2× YubiKey for backup.
- *"I currently use Bitwarden as my main vault"* → expect sync-link / API-key fallback for new-device unlock until Bitwarden ships PRF in their authenticator. No PRF-based one-tap path for Bitwarden-stored secrt credentials today.

### Gate status: CLEARED for Phase B

---

## 10. References

- WebAuthn Level 3 PRF extension spec: <https://www.w3.org/TR/webauthn-3/#prf-extension>
- Yubico developer guide: <https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html>
- Corbado 2026 state-of-PRF: <https://www.corbado.com/blog/passkeys-prf-webauthn>
- Bitwarden on PRF: <https://bitwarden.com/blog/prf-webauthn-and-its-role-in-passkeys/>
- Firefox PRF meta-bug: <https://bugzilla.mozilla.org/show_bug.cgi?id=1863819>
- `prf-cross-device-testing.md` — captured-trace log, failure mode catalog, and methodology for empirical PRF testing (companion to §11 of this doc).
- Existing AMK impl: `secrt-core/src/amk.rs` + `web/src/crypto/amk.ts`
- Encrypted Preferences blob (umbrella for credential metadata, saved passphrases, prefs): `.taskmaster/plans/task-37-unified-preferences.md`
