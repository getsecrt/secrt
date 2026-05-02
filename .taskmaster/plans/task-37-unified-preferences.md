# Task 37: Unified Settings + Encrypted Preferences (AMK-wrapped sync)

**Status:** pending — **execution deferred until task #42 (Passkey PRF AMK wrapping) lands**
**Priority:** high (after #42)
**Supersedes / extends:** task #37 (preferences foundation), task #38 (saved passphrases), task #34 (keychain plumbing for passphrases/session)
**Hard prerequisite:** task #42 (Passkey PRF-based AMK wrapping)
**Related but out of scope:** task #40 (Icelandic localization), task #45 (jurisdiction-picker UX), task #49 (multi-profile/custom host)
**Plan version:** v3 — 2026-05-01 (credential metadata + ciphertext padding + label-tier decisions added after PRF cross-device verification on YubiKey)

---

## Goal

Build a single **Settings** route containing per-device user preferences and account-management surfaces, with an end-to-end encrypted preferences blob that syncs across the user's devices using the same AMK-wrapped envelope as encrypted notes. Preferences include both low-stakes UI choices (theme, language, default TTL) and higher-stakes saved passphrases (default send passphrase, list of decryption passphrases to auto-try).

This plan is intentionally cohesive over the *whole* preferences surface — even fields that won't ship initially — so the IA, schema, and storage shape are designed once and don't have to be reworked when we add language, instance picker, profiles, etc.

### Why this is gated on PRF (task #42)

- **PRF unifies AMK acquisition.** With PRF, every login on every device deterministically derives the AMK from the passkey assertion. No password, no device-transfer dance for the common case.
- **PRF lets us safely clear AMK on logout.** Today the AMK persists in IndexedDB (web) and OS keychain (Tauri) across logout — a real defect on shared computers (see Security section). With PRF, "clear AMK on logout" stops being a UX disaster because re-login is one passkey tap that re-derives the AMK instantly.
- **PRF is the right unlock primitive for a saved-passphrase feature.** Saving passphrases stacks more value on the AMK than the existing notes feature; doing this on top of the today's persistent-AMK-with-no-real-logout model would compound an existing weakness.

### Auth-model assumption

This plan assumes **passkey-only authentication** going forward. No password fallback for AMK derivation. The userbase tradeoff (passkey-incapable users excluded) is accepted in exchange for a unified, simpler, phishing-resistant security model.

---

## Non-goals (deferred to other tasks)

- **i18n string extraction & translations** — task #40. The schema includes a `language` field; the actual translation infrastructure is a separate project.
- **Jurisdiction picker UX** — task #45. The schema includes a `preferred_instance` field; the explainer/picker UI is its own task.
- **Multi-profile / custom-host configuration** — task #49. v1 assumes a single instance per user.
- **CLI ↔ AMK-blob sync.** v1 keeps CLI's TOML config local-only. A future task can wire `secrt config` to push/pull the AMK blob using the shared `Preferences` struct.
- **Replacing the existing device-transfer/QR sync flow.** It demotes from "primary onboarding" to "bootstrap second passkey + account recovery + PRF-less authenticator fallback" — but it stays.

---

## Decisions locked in (from design sessions 2026-04-26)

| # | Decision | Rationale |
|---|---|---|
| 1 | **Single `/settings` route** with two sectioned areas: Preferences (always visible) and Account (visible when authenticated). | One nav slot; unauth users get a useful page; section headers do the disambiguation. |
| 2 | **AMK-wrapped, server-synced preferences blob** (single blob, not split). | Same crypto envelope as notes; zero-knowledge; iOS parity. Splitting prefs from passphrases doesn't actually improve confidentiality (same AMK) and the loading-pattern argument is thin. Single blob keeps semantics uniform. |
| 3 | **Saved passphrases ship on both web and Tauri** (gated behind authentication). | Refusing the feature on web would push users to skip passphrase protection entirely, making average security worse. Tauri additionally backs them with the OS keychain + biometric gate. |
| 4 | **Saved passphrases require authentication.** | An unauth user has no AMK; no safe storage exists. Show "Sign in to save passphrases" affordance instead. |
| 5 | **`Cmd+,` / `Ctrl+,` opens `/settings`.** | Native convention; works in both browser and Tauri. |
| 6 | **Dark-mode toggle moves into Settings.** `D` keyboard shortcut preserved. | Frees nav real estate for the language menu, which is more important for accessibility. |
| 7 | **Globe-icon language menu in nav** when 2+ languages live. | A user stranded in a language they don't read needs one click, not three. |
| 8 | **"Use saved default passphrase" checkbox** on Send. Unchecking reveals blank standard passphrase input. No pre-fill of the saved value into the editable input. | Avoids the "I see text in the field, I assume it's mine" footgun. Removes shoulder-surfing exposure of the saved passphrase value. |
| 9 | **Default-checkbox-state is itself a preference.** Default of that meta-setting: checkbox starts *checked* per send. Cautious users can flip a "Always confirm before using saved default passphrase" preference to require per-send opt-in. | Saving a default that requires confirmation every time is mostly pointless ceremony. Cautious users have an escape hatch. |
| 10 | **Auto-decrypt on by default**, with an "Always ask before trying saved passphrases" preference. | The act of saving passphrases is the opt-in. A logged-in browser already exposes higher-value surfaces (banking, password manager) — forcing a passphrase prompt for secrt-specifically is false comfort. |
| 11 | **No count cap on saved passphrases.** Server enforces 64 KB blob size cap. UI warns once the list exceeds ~25 entries. | The auto-try cost is the user's own CPU; the real wall is per-claim latency from KDF work, which UI guidance handles better than a hard count limit. |
| 12 | **Server uses ETag + If-Match (CAS)** for the preferences blob; 409 on stale writes; client retries. Replaces last-write-wins. | LWW silently loses passphrase mutations across devices (e.g. Device A's delete clobbers Device B's add). CAS makes this correct without a second endpoint. |
| 13 | **Tauri biometric gating done through a single gated passphrase provider.** On Tauri, the OS keychain is the **source** for passphrase reads; the AMK blob is the sync/backup material. The provider gates every read with biometric (cached for N minutes). | Biometric on `keyring_get` is theater if passphrases also flow from "decrypted blob → memory" without going through it. One gated provider → biometric actually means something. |
| 14 | **"Clear local data on this device" button** in Account → Danger Zone. Manually triggers `clearAmk` + clears local prefs cache + signs out. | Today there's no user-facing way to clear the AMK without devtools. Cheap fix that gives careful users protection on shared computers immediately. |
| 15 | **Defer "auto-clear AMK on logout" until PRF.** | Today it would break re-login UX (need to re-do device-transfer dance). With PRF, re-login is seamless and clear-on-logout becomes the correct default. |
| 16 | **Cache only ciphertext in localStorage.** | Even though the AMK persists nearby (IndexedDB/keychain), we don't make the localStorage cache *additionally* bad by storing decrypted material. Decrypt happens in memory only. |
| 17 | **`preferences` AAD key prefix is normative.** Spec + vectors written before any TS/Rust code. | Domain-tagged AAD prevents cross-blob misuse; spec-first prevents the two implementations drifting. |
| 18 | **Pad ciphertext to a 4 KB quantum** (round plaintext up to next 4 KB boundary before sealing; cap is still 64 KB plaintext). Padding bytes are zero-filled and stripped at unwrap time using a length prefix or a deterministic schema-driven trim. | Defeats length-based fingerprinting of blob contents (e.g. inferring credential count or whether saved passphrases are present). Quantum chosen to comfortably hold ~10 credentials + prefs + ~25 saved passphrases without bumping a tier. |
| 19 | **Credential metadata folds into the existing `Preferences` blob** as a `credentials: BTreeMap<credential_id, CredentialMetadata>` field — not a separate blob, not a separate table. | Single-blob principle (Decision #2) extends here. The `blob_kind` AAD hook stays reserved for genuinely different blob types; per-credential metadata is just more `Preferences`. Avoids new envelope, new endpoint, new storage table, and the per-blob shape leakage that would come with splitting. |
| 20 | **AAGUID stored raw in the blob; brand display label resolved client-side at render time** via a static lookup table (`web/src/lib/passkey-aaguids.ts`). | Lookup table can evolve — new authenticators recognized, mistakes corrected — without rewriting any user blobs. Pure machine cost; trivial. |
| 21 | **`passkeys.label` remains server-side, plaintext.** Tier-2 (authenticated, AMK-not-available) readability is load-bearing for revoking a lost credential and for the user picking which credential to attempt PRF unlock with on a fresh device. | Encrypting labels would block revocation + recovery flows on the cohort that needs them most (YubiKey-on-iPhone, Bitwarden, anyone in "Sign-in only" land). Empirical privacy cost is small (most labels are device-class names like "YubiKey" / "iPhone"). Optional richer per-credential `private_notes` field can live in the blob in a future version if a real use case emerges. |
| 22 | **Server-visible `passkeys.safari_prf_compatible` tri-state column (NULL = unknown).** Required because it's load-bearing pre-AMK-unlock — used to render iPhone-compatibility hints on the new-device login screen and the tier-2 Settings view, before any blob can be decrypted. Lives in the PRF design doc's schema (`prf-amk-wrapping.md` §3.3); listed here for cross-referencing. | The only new server-visible bit added by the credential-metadata work. Capability-framed, not identity-framed. Anonymity set per state value: many millions of users. |

---

## Naming

- **Route name:** `/settings` (existing path retained — no breaking change to bookmarks).
- **Section headers within the page:**
  - **Preferences** (always visible)
  - **Account** (visible when authenticated)
- **Menu/button labels:**
  - Top-nav avatar dropdown → "Settings" (logged in)
  - Top-nav gear icon → "Settings" (logged out)
  - macOS Tauri menu bar → "Preferences…" (`⌘,`)

We considered renaming "Settings" to "Account" to free the word. Rejected: a unified `/settings` route makes the rename unnecessary — both kinds of options coexist there.

---

## Information architecture

```
/settings
├── Preferences
│   ├── Appearance
│   │   └── Theme (system / light / dark)        [v1]
│   ├── General
│   │   ├── Default TTL                          [v1]
│   │   ├── Auto-copy share link                 [v1]
│   │   └── Update check                         [v1]   (parity with CLI)
│   ├── Language                                 [v1.1, after #40]
│   │   └── UI language (auto / en-CA / is-IS / fr-CA / …)
│   ├── Sending                                  [v1, requires auth]
│   │   ├── Default send passphrase (saved)
│   │   └── "Always confirm before using saved default passphrase"
│   ├── Opening                                  [v1, requires auth]
│   │   ├── Saved passphrases (ordered list)
│   │   └── "Always ask before trying saved passphrases"
│   ├── Device safety                            [v1, requires auth]
│   │   └── (Tauri) "Require biometric to use saved passphrases"
│   │   └── (Tauri) Biometric cache duration
│   └── Instance                                 [later, task #45 / #49]
│       └── Preferred instance / multi-profile
└── Account                                      [requires auth]
    ├── Notes Key (AMK sync)
    ├── API Keys
    ├── Passkeys
    ├── Profile (display name)
    ├── Danger Zone
    │   ├── Clear local data on this device      [v1, NEW]
    │   └── Delete Account
```

### Nav additions

- **Logged-in users:** existing avatar/user-menu route to `/settings`.
- **Logged-out users:** new gear icon in nav routing to `/settings` (Preferences sections render; Account renders "Sign in to manage your account").
- **Globe-icon language menu:** added when `availableLocales.length >= 2`. Shows current locale (`🌐 中文 (繁體) ▾`); dropdown of locales + "More preferences…" link.
- **Dark-mode toggle:** removed from nav. `D` shortcut preserved.

---

## Storage architecture

### Layered model

```
┌─────────────────────────────────────────────────────────────┐
│ In-memory (decrypted Preferences struct, session-scoped)    │
└─────────────────────────────────────────────────────────────┘
            ▲                                ▲
            │ decrypt with AMK               │ encrypt with AMK on save
            ▼                                ▼
┌────────────────────────────┐    ┌────────────────────────────┐
│ Server (when authed)       │    │ localStorage (warm cache)  │
│ AMK-encrypted ciphertext   │◄──►│ AMK-encrypted ciphertext   │
│ (source of truth, ETag)    │    │ (offline / fast-load)      │
└────────────────────────────┘    └────────────────────────────┘

AMK itself (persistent):
  Web:    IndexedDB (web/src/lib/amk-store.ts, raw bytes keyed by user_id)
  Tauri:  OS keychain via keyring_set with `amk:<user_id>` prefix

Saved passphrases on Tauri (additional, defense-in-depth):
  OS keychain entries, gated by single biometric provider
  AMK blob is the sync/backup; keychain is the live source for reads
```

**Rules:**
- **Source of truth** when authenticated: server.
- **localStorage cache** stores *only ciphertext* in the same envelope format.
- **Decrypted blob lives only in memory**, cleared on logout.
- **Unauthenticated users:** `theme` and `language` written to localStorage as plain JSON. On first sign-in, those get migrated into the AMK blob.
- **Tauri passphrase reads** go through the biometric-gated provider, which reads from the OS keychain. The AMK blob is reconciled on app start (blob wins via CAS revision) and on saved-passphrase mutations.

### Sync semantics

- **On login:** fetch ciphertext from server (`GET /api/v1/auth/preferences`). If 404 (first-time user) and local cache has data, push local up. Otherwise server wins; local is overwritten.
- **On change:** read-modify-write the whole blob; PUT with `If-Match: <last-known-etag>`. On 409, refetch, re-apply the diff, retry. Hard-fail after 3 retries (log + surface a toast).
- **On logout:** clear in-memory decrypted blob; **leave** ciphertext cache in localStorage (fast re-login). AMK on web/Tauri also persists today — see the Security section. The "Clear local data on this device" button is the user-driven escape hatch; auto-clear-on-logout lands after PRF (task #15 in Decisions).

---

## Schema

### `Preferences` struct (in `secrt-core`)

```rust
// crates/secrt-core/src/preferences.rs

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Preferences {
    /// Schema version for forward/backward compat.
    pub version: u16,                                   // current: 1

    /// Last-modified timestamp set by the writer (UTC ms).
    /// Inside the ciphertext to detect server replay vs the outer
    /// metadata; outer copy is in the response envelope.
    pub updated_at_ms: u64,

    pub appearance:  AppearancePrefs,
    pub general:     GeneralPrefs,
    pub language:    LanguagePrefs,
    pub passphrases: PassphrasePrefs,
    pub instance:    InstancePrefs,

    /// Per-credential rich metadata, keyed by base64url credential_id.
    /// Captured at register-finish (web/Tauri); CLI never writes this.
    /// BTreeMap (not HashMap) for deterministic serialization → stable
    /// padding boundaries across devices.
    #[serde(default)]
    pub credentials:  BTreeMap<String, CredentialMetadata>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AppearancePrefs {
    /// "system" | "light" | "dark"
    pub theme: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct GeneralPrefs {
    pub default_ttl: Option<String>,                    // CLI grammar
    pub auto_copy_share_link: Option<bool>,
    pub update_check: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct LanguagePrefs {
    pub locale: Option<String>,                         // BCP-47
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PassphrasePrefs {
    pub default_send_passphrase: Option<String>,
    pub decryption_passphrases: Vec<SavedPassphrase>,

    /// If true, the Send page checkbox starts unchecked, requiring
    /// per-send opt-in. Default false (checkbox starts checked).
    pub always_confirm_send_default: bool,

    /// If true, the claim flow always prompts before trying any
    /// saved passphrase. Default false (auto-try is on).
    pub always_ask_before_auto_decrypt: bool,

    /// Tauri-only: require biometric prompt before reading
    /// saved passphrases from the keychain.
    pub require_biometric: bool,

    /// Tauri-only: how long a successful biometric unlock keeps
    /// passphrase reads ungated. 0 = always prompt.
    pub biometric_cache_seconds: u32,                   // default 300
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SavedPassphrase {
    pub label: Option<String>,                          // "work", "personal"
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct InstancePrefs {
    pub preferred_base_url: Option<String>,             // task #45
    pub profiles: Vec<InstanceProfile>,                 // task #49
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct InstanceProfile {
    pub label: String,
    pub base_url: String,
}

/// Per-credential rich metadata. All fields optional so unknown / privacy-
/// stripped values (e.g. iCloud Keychain returning AAGUID = all-zeros under
/// `attestation: "none"`) round-trip cleanly without false-positive labels.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CredentialMetadata {
    /// 16 raw bytes of the AAGUID from the attestation object's
    /// attested-credential-data. All-zeros is a valid value meaning
    /// "authenticator declined to identify itself" — kept as-is.
    pub aaguid: Option<[u8; 16]>,

    /// Attestation format string from the outer CBOR ("none", "packed",
    /// "fido-u2f", "apple", "tpm", "android-key", "android-safetynet").
    pub attestation_fmt: Option<String>,

    /// Transports advertised at registration, e.g. ["usb", "nfc"] or
    /// ["internal"]. Useful tiebreaker when AAGUID is zeros.
    #[serde(default)]
    pub transports: Vec<String>,

    /// "platform" | "cross-platform". Set by the authenticator, not the user.
    pub authenticator_attachment: Option<String>,

    /// Capability classification, derived at capture time. Cached in the
    /// blob (rather than re-derived at render time) so the lookup-table
    /// version that produced it is implicitly captured. Re-derived only
    /// on explicit credential refresh.
    pub capability: Option<CredentialCapability>,

    /// Optional richer per-credential private notes. NOT used in v1; the
    /// field exists so future code can write to it without a schema bump.
    /// `passkeys.label` (server-side, plaintext) is the load-bearing
    /// label for tier-2 (revocation, picker) UX — see Decision #21.
    pub private_notes: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialCapability {
    /// Has a PRF wrapper, works on every platform we ship to.
    /// Examples: iCloud Keychain platform passkeys, GPM-on-Android passkeys.
    FullPortable,
    /// Has a PRF wrapper, works on desktop / Safari macOS / Chromium,
    /// AMK does NOT transfer to iOS Safari (Apple re-wraps hmac-secret).
    /// Examples: YubiKey and other roaming hardware.
    DesktopOnly,
    /// PRF wrapper exists but the credential is bound to a single device
    /// (TPM / Secure Enclave with iCloud Keychain disabled). Cross-device
    /// unlock impossible by design.
    DeviceOnly,
    /// No PRF wrapper. Authentication works, AMK never transfers.
    /// Examples: Bitwarden, 1Password, Firefox ≤147, GPM-on-Chrome-macOS.
    SignInOnly,
    /// Capability not yet classified (e.g. credentials registered before
    /// the metadata-capture feature shipped, or an authenticator we
    /// haven't catalogued).
    Unknown,
}
```

`Option<>` and `Vec<>` are deliberate: distinguishes "user has not set this" from "user set this to false/empty". Defaults come from a single `effective_preferences()` resolver in `secrt-core` shared across CLI / web / Tauri.

### CLI parity mapping (for future CLI ↔ blob sync)

| CLI TOML key | `Preferences` path |
|---|---|
| `passphrase` | `passphrases.default_send_passphrase` |
| `decryption_passphrases` | `passphrases.decryption_passphrases` (each → `SavedPassphrase { label: None, value }`) |
| `default_ttl` | `general.default_ttl` |
| `update_check` | `general.update_check` |
| `auto_copy` | `general.auto_copy_share_link` |
| `base_url` | `instance.preferred_base_url` |
| `use_keychain`, `api_key`, `show_input` | **CLI-only**, not in `Preferences` |
| (none) | `credentials` map — **web/Tauri-only**, populated at WebAuthn register-finish. CLI does not register passkeys (it bootstraps via the browser-mediated ECDH flow), so it has no values to write here. CLI reads of the blob ignore this field. |

---

### Credential metadata — capture and resolution

**Trust-tier split** (the load-bearing principle, repeated explicitly because it governs every rule below):

- **Tier-2 readable** (server, plaintext, no AMK required): `passkeys.label`, `passkeys.safari_prf_compatible`, `passkeys.prf_supported`, the wrapper itself, sign counts, timestamps. Anything required to revoke a credential, render the iPhone-compatibility hint on a fresh-device login, or help a user pick which credential to attempt PRF unlock with.
- **Tier-3 readable** (encrypted blob, AMK required): AAGUID, attestation_fmt, transports, authenticator_attachment, derived capability, brand display label, future private notes. Anything that's nice for management but never required for security operations.

**Capture (at WebAuthn register-finish, web/Tauri only):**

```
1. After navigator.credentials.create() returns, parse the attestation object:
   - Extract AAGUID from authenticatorData → attestedCredentialData.aaguid (16 bytes).
   - Extract attestation format string from the outer CBOR ("apple" / "packed" / etc.).
   - Capture transports[] from getTransports() (or response.getTransports()).
   - Capture authenticatorAttachment from the credential.
2. Derive safari_prf_compatible:
     true   iff attestation_fmt == "apple"
            OR aaguid == adce0002-35bc-c60a-648b-0b25f1f05503  (Apple AAGUID)
     false  iff aaguid matches a known non-Apple-platform value
            (lookup table includes YubiKey AAGUIDs, Windows Hello TPM,
             GPM Android, 1Password, Bitwarden, etc.)
     null   otherwise (unclassified — anonymity-stripped authenticator)
3. Derive capability:
     FullPortable    iff safari_prf_compatible == true && wrapper exists
     DesktopOnly     iff aaguid matches a known roaming-hardware AAGUID
                     OR (authenticator_attachment == "cross-platform" && prf_supported)
     DeviceOnly      iff authenticator_attachment == "platform" && credential is non-syncable
                     (heuristic; rarely hit in practice)
     SignInOnly      iff !prf_supported (no wrapper)
     Unknown         otherwise
4. Send to server (registerPasskeyFinish payload):
     { ..., safari_prf_compatible: <tri-state> }
   Server stores on `passkeys.safari_prf_compatible`.
5. Write to encrypted blob (Preferences.credentials[credential_id]):
     { aaguid, attestation_fmt, transports, authenticator_attachment, capability }
   Same write path as any other Preferences mutation (CAS via ETag, see Sync semantics).
```

**Resolution (at render time):**

- Brand display label + icon: client looks up `aaguid` in `web/src/lib/passkey-aaguids.ts` (static table, see Decision #20). Falls back to attestation_fmt-based inference (`"apple"` → Apple icon, `"tpm"` → Windows Hello icon, etc.) when AAGUID is zeros. Generic passkey icon if neither resolves.
- Capability badge: render directly from `credentials[id].capability`. Pre-AMK-unlock fallback is `passkeys.safari_prf_compatible` for the "iPhone-compatible" hint only.
- Label (tier-2): server-side `passkeys.label`. Always available when authenticated.

**Fallback when blob is unreachable:**

- Tier-2 user (authenticated, no AMK): renders `passkeys.label` + iPhone-compat badge derived from `safari_prf_compatible`. No brand icon, no rich capability. The "Authorize this device" affordance directs them to the unlock path.
- Once AMK is available: blob decrypts, full UI renders.

### Lookup table — `web/src/lib/passkey-aaguids.ts`

Static TS const, shipped with each web build. Source: community-maintained `passkey-authenticator-aaguids` GitHub repo + Yubico's published AAGUIDs + Apple/Microsoft-known values. Resolves AAGUID (32-char hex string) to:

```ts
{
  name: string,           // "YubiKey 5C NFC", "iCloud Keychain", "Windows Hello", ...
  ecosystem: 'apple' | 'google' | 'microsoft' | 'yubico' | 'feitian' | 'manager' | 'unknown',
  iconId: string,         // resolves to an SVG in components/Icons
  capability_hint?: CredentialCapability,   // optional — used as a tiebreaker
}
```

Updates land via re-deploy of the SPA. No migration, no blob rewrite. New AAGUIDs are resolved correctly the next time the user opens Settings on an updated build.

---

## Crypto envelope

Reuse the existing AMK wrap pattern. New domain-tagged AAD prevents cross-blob misuse (a stolen prefs blob can't be misinterpreted as a notes blob).

```
serialized = serde_json::to_vec(&Preferences)            // CBOR also acceptable; pick one in spec
padded     = pad_to_quantum(serialized, 4096)            // see Padding below
ciphertext = AES-256-GCM(
    key   = HKDF(amk, info = "secrt-preferences-v1"),
    nonce = random(12),
    aad   = buildPrefsAad(user_id, blob_kind, version),
    plain = padded
)
```

**Padding** (Decision #18). `pad_to_quantum(bytes, q)`:

```
plaintext_len = bytes.len() as u32                       // ≤ 64 KB
padded_len    = ceil_div(4 + plaintext_len, q) * q
out           = u32_be(plaintext_len) || bytes || zeroes(padded_len - 4 - plaintext_len)
```

The 4-byte length prefix lets the unwrap path trim padding deterministically. Quantum is 4 KB; cap stays at 64 KB plaintext (so worst-case ciphertext = 64 KB + GCM overhead, server-side cap on `ct` becomes 65 KB to allow tag/nonce framing). Padding bytes are zero — no domain separation needed because the AAD already includes user_id and version.

Test vectors must exercise: (a) the 0-byte plaintext (empty Preferences), (b) a plaintext just under a quantum boundary, (c) a plaintext exactly at a quantum boundary, (d) a plaintext just over a quantum boundary, (e) a plaintext near the 64 KB ceiling.

**Normative AAD layout** (matches `buildWrapAad` style):

```
info                    // "secrt-preferences-v1" (UTF-8, 20 bytes)
user_id_uuid            // raw 16 bytes (UUIDv7)
u16 len(blob_kind)
blob_kind               // UTF-8, currently "preferences"
u16 schema_version      // matches Preferences.version
```

`blob_kind` is a forward-compat hook in case we ever need a second AMK-encrypted blob type (e.g. encrypted notes index) — different `blob_kind` strings produce different AAD, preventing substitution.

Spec lives at `spec/v1/preferences.md`; deterministic test vectors at `spec/v1/preferences.vectors.json` (3-5 vectors). Both Rust and TypeScript implementations must pass the same vectors before any UI work.

### Wire format

Server response and request body:

```json
{
  "ct": "base64url",
  "nonce": "base64url",
  "version": 1,
  "updated_at_ms": 1782345678901
}
```

Server supplies `ETag` header on GET responses and accepts `If-Match` on PUT requests.

---

## Server endpoints

| Method | Path | Behavior |
|---|---|---|
| `GET` | `/api/v1/auth/preferences` | Returns the user's encrypted blob + ETag header. 404 if none stored. |
| `PUT` | `/api/v1/auth/preferences` | Replace blob. Requires `If-Match: <etag>` matching current state, **or** `If-None-Match: *` to assert "I expect there to be no existing blob". 409 on mismatch. 412 if `If-Match`/`If-None-Match` is missing entirely (force CAS discipline). |

**No `PATCH`.** The blob is small; always read-modify-write.

**Storage** (new Postgres table):

```sql
CREATE TABLE user_preferences (
    user_id        UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    ct             BYTEA NOT NULL,
    nonce          BYTEA NOT NULL,
    version        SMALLINT NOT NULL,
    updated_at_ms  BIGINT NOT NULL,
    revision       BIGINT NOT NULL,                    -- monotonically incrementing CAS token
    server_updated TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

ETag = `revision` as a quoted string (`"42"`). Server increments `revision` on every successful PUT. Account deletion cascades.

**Server contract:**
- Server never decrypts. Treat blob as opaque.
- Size cap: **64 KB** on `ct`.
- No history beyond current blob.
- Honest note in spec: server rollback to a prior ciphertext is detectable only with a transparency log; not in v1.

---

## UI contracts

### Send-page integration

- When `passphrases.default_send_passphrase` is set, render `[√] Use saved default passphrase` checkbox above the passphrase area.
- **Default state of the checkbox:** depends on `passphrases.always_confirm_send_default` — false (default) means checkbox starts checked, true means starts unchecked.
- Checked: passphrase input is hidden. A compact persistent indicator appears near the Send button: *"Recipient will need the saved default passphrase to open this."* (Exact wording to be workshopped — keep it factual, non-alarming.)
- Unchecked: standard blank passphrase input renders. No pre-filled saved value. To change the saved passphrase itself, user goes to Settings.
- When no default is saved: behaves exactly like today.

### Claim-page integration (multi-phase auto-decrypt)

When claiming a passphrase-protected secret:

1. Try with no passphrase (it might not actually need one).
2. If `passphrases.always_ask_before_auto_decrypt` is **false** (default), try saved passphrases in order: `default_send_passphrase`, then each `decryption_passphrases[*].value`. If any succeeds, decrypt and show.
3. If `always_ask_before_auto_decrypt` is **true**, skip step 2 and go straight to manual prompt.
4. If all auto-tries fail or step 2 is skipped, prompt the user as today.

While trying, show *"Trying saved passphrases…"* status. **Never reveal which passphrase succeeded** — no label flash, no "✓ work" indicator (privacy in shoulder-surfing scenarios).

### Tauri additions

- All passphrase reads on Tauri go through `getPassphrase()` in a single biometric-gated provider:

```ts
// Pseudocode
async function getPassphrase(label: string): Promise<string | null> {
  if (prefs.require_biometric && !biometricCacheValid()) {
    const ok = await invoke('biometric_authenticate', {
      reason: "Use saved passphrase"
    });
    if (!ok) return null;
    refreshBiometricCache(prefs.biometric_cache_seconds);
  }
  return invoke('keyring_get', { key: `passphrase:${label}` });
}
```

- Keychain is the source for passphrase reads on Tauri. AMK blob is sync/backup, reconciled on app startup and on mutations.
- New Tauri command: `biometric_authenticate(reason: string) -> bool`. macOS uses `LAContext.evaluatePolicy`; Windows uses Hello; Linux falls back to "no biometric available" (gate becomes a no-op with a UI note).
- macOS app menu: add `Preferences… ⌘,`.

### `Cmd+,` / `Ctrl+,` global shortcut

In `web/src/lib/shortcuts.ts` (extend whatever module hosts the `D` shortcut). Navigates to `/settings`. Tauri inherits.

### "Authenticated but no AMK" UI state

Three states for the Sending / Opening / Device-safety sections:

| State | Render |
|---|---|
| Signed out | "Sign in to save passphrases" affordance with login link |
| Signed in, AMK present | Full UI |
| Signed in, AMK missing | "Authorize this device to access your saved data" — same affordance pattern already used for unviewable encrypted notes (link to device-transfer/QR flow) |

In a PRF-everywhere world the third state is rare (PRF re-derives AMK at login), but it can still happen during the bootstrap of an additional passkey or after the user explicitly cleared local data.

### "Clear local data on this device" button

Lives in **Account → Danger Zone**, sibling of "Delete Account":

```
[ Clear local data on this device ]
  Removes the saved key used to decrypt your notes and preferences
  on this device, then signs you out. Use this before stepping
  away from a shared computer. You can re-authorize this device
  later by signing in.
```

Triggers: `clearAmk(userId)` → clear localStorage prefs cache → clear session token → navigate to login.

Does **not** delete server-stored data. Distinct from "Delete Account".

---

## Security analysis

### Corrected baseline

The earlier draft of this plan claimed AMK is "re-derived per session and never persisted." **This was wrong.** The AMK is stored at rest:

- **Web:** raw bytes in **IndexedDB** at `web/src/lib/amk-store.ts` (DB `secrt-amk`, store `amk`, keyed by user UUID).
- **Tauri:** OS keychain via `keyring_set` with `amk:<user_id>` prefix.

Logout (today) clears the session token but **does not** call `clearAmk` — see `web/src/lib/auth-context.tsx:117-131`. That means after logout, both the AMK and any AMK-encrypted blobs (notes, future preferences) remain recoverable on the same browser profile.

This is a pre-existing weakness affecting the already-shipped notes feature; saved passphrases meaningfully raise the stakes because their breach exposes many secrets, not one note.

### Mitigations in this plan

- **Manual "Clear local data" button** (decision #14) gives careful users an immediate escape hatch.
- **Auto-clear AMK on logout** is deferred to land alongside PRF (decision #15), where re-login becomes seamless and this stops being a UX disaster.
- **Tauri biometric gate** through a single passphrase provider (decision #13) means even on a compromised local user account, passphrase reads require fresh biometric auth (within cache TTL).
- **`require_biometric`** can be set to true and **`biometric_cache_seconds`** to 0 by users who want every read prompted.

### Threat model

| Threat | Web | Tauri | Mitigation |
|---|---|---|---|
| Passive server compromise | No exposure | No exposure | AMK ciphertext only |
| **Active server compromise (malicious JS)** | **Exposed** (same as notes today) | Not exposed (signed bundle) | CSP, SRI, future Sigstore signing (task #53) |
| At-rest disk forensics | **Exposed** — IndexedDB holds raw AMK; localStorage holds ciphertext blob; both are decryptable together | **Partial** — keychain entries gated by user account perms; on macOS additionally by app identity | "Clear local data" button; auto-clear-on-logout post-PRF |
| Logout-then-walk-away on shared computer | **Exposed** today (pre-existing) | **Exposed** today (pre-existing) | Manual button v1; auto-clear post-PRF |
| XSS in secrt's own code | Reads memory + IndexedDB; same exposure as session token / notes | Same | XSS hygiene; CSP |
| OS-level malware (process access) | Compromised | Compromised + biometric still required for keychain reads on Tauri | Out of scope |

### Honest framing for users

This is **not a full password manager.** It's a sync-and-autofill feature for passphrases bounded by the `Preferences` schema, without a master-password unlock layer. We do not import vault-unlock semantics from Bitwarden / 1Password (master password, auto-lock timeout, vault audit log). The feature relies on:

1. Authentication (passkey + PRF) gating AMK derivation.
2. The AMK gating decryption of the prefs blob.
3. (Tauri only) Biometric prompt gating live passphrase reads from the keychain.

UI caveat (in the Sending / Opening sections, designed not to be visually noisy):

> *"Saved passphrases can open matching protected secrets automatically on this device. Don't enable this on shared or unmanaged computers."*

Plus a similar line near the "Clear local data" button explaining what it does and when to use it.

---

## Implementation phases

**Hard prerequisite for all phases: task #42 (Passkey PRF) merged.**

### Phase 0 — Spec + crypto vectors

- [ ] `spec/v1/preferences.md` — envelope, normative AAD layout, blob_kind enumeration, wire format, CAS semantics, **padding scheme (Decision #18) including the length-prefix format**.
- [ ] `spec/v1/preferences.vectors.json` — 5+ deterministic test vectors covering padding edge cases (empty / sub-quantum / on-quantum / over-quantum / near-cap).
- [ ] Add `Preferences` struct (including `credentials: BTreeMap<String, CredentialMetadata>`), `CredentialMetadata`, `CredentialCapability`, plus `seal_preferences` / `open_preferences` (with padding) in `secrt-core`, with vector-passing tests.
- [ ] Mirror in `web/src/crypto/preferences.ts`, same vectors.

### Phase 1 — Server endpoints

- [ ] `user_preferences` Postgres table + migration (with `revision` column).
- [ ] `GET` and `PUT /api/v1/auth/preferences` handlers in `secrt-server/src/http/`.
- [ ] ETag generation, `If-Match` / `If-None-Match` enforcement, 409 on mismatch, 412 on missing precondition.
- [ ] **`passkeys.safari_prf_compatible BOOLEAN NULL` column** — schema migration owned by the PRF design doc (`prf-amk-wrapping.md` §3.3) but tracked here too. Ensures handler can read it for tier-2 rendering.
- [ ] OpenAPI updates in `spec/v1/openapi.yaml`.
- [ ] Integration tests against `TEST_DATABASE_URL`, including concurrent-write CAS conflict.

### Phase 2 — Client storage + sync

- [ ] `web/src/lib/preferences.ts` — get/set/subscribe API; `usePreference(path)` Preact hook backed by in-memory state.
- [ ] `web/src/lib/preferencesSync.ts` — load on login, write-through with ETag, 409-retry loop (max 3), localStorage ciphertext cache.
- [ ] Tauri-only: `web/src/lib/passphraseProvider.ts` — biometric-gated provider that reads from keychain, reconciles with AMK blob on app start and after mutations.
- [ ] Logout: clear in-memory decrypted blob (do not clear localStorage cache, do not clear AMK).
- [ ] "Authenticated but no AMK" detection used by Settings sections.

### Phase 3 — Settings page restructure

- [ ] Remove `AuthGuard` from `/settings`; render Preferences sections unconditionally.
- [ ] Wrap existing Account sections in auth check; render "Sign in to manage your account" affordance otherwise.
- [ ] Build Appearance, General, Sending, Opening, Device-safety sections.
- [ ] Add Account → Danger Zone → "Clear local data on this device" button.
- [ ] Reuse existing card styling.

### Phase 3.5 — Credential metadata capture + render

- [ ] `web/src/lib/passkey-aaguids.ts` — static AAGUID lookup table sourced from `passkey-authenticator-aaguids` upstream + Yubico published list. Resolver function `resolveAaguid(aaguid: Uint8Array | null) → { name, ecosystem, iconId, capability_hint? } | null`.
- [ ] `web/src/lib/credential-capture.ts` — at register-finish, parse attestation object for AAGUID + attestation_fmt, capture transports + authenticatorAttachment, derive `safari_prf_compatible` (tri-state) and `capability` (enum).
- [ ] Extend `RegisterPage`, `SettingsPage` add-passkey, and (Tauri) the verification-URL page to call the capture function and write to both server (`safari_prf_compatible`) and Preferences blob (`credentials[id]`).
- [ ] Server-side: extend register-finish + add-finish handlers to accept `safari_prf_compatible` and stamp `passkeys.safari_prf_compatible`. PRF-upgrade login path also stamps it when first seen.
- [ ] Settings → Account → Passkeys list rendering: per-row icon (resolved from AAGUID), brand name (resolved from AAGUID), capability badge (`Sign-in only` / `Desktop only` / nothing / `This device only`), tier-2 fallback (label + iPhone-compat hint only).
- [ ] New-device login screen: when server returns the user's credential list (or hint at one via the picker), surface the iPhone-compat badge in advance of the assertion ceremony so users on iPhone can pick the right credential.
- [ ] Spec note in `prf-amk-wrapping.md` §3.6 cross-referencing this plan for capture details.

- [ ] Remove dark-mode toggle from nav (preserve `D` shortcut).
- [ ] Add gear icon in nav for unauth users → `/settings`.
- [ ] Wire `default_ttl` into Send page TTL selector default.
- [ ] Wire `auto_copy_share_link` into post-send share-link flow.
- [ ] Wire default-passphrase checkbox into Send page (per decisions #8/#9).
- [ ] Persistent indicator near Send action when default passphrase is active.
- [ ] Wire multi-phase auto-decrypt into Claim page (per decision #10), respecting `always_ask_before_auto_decrypt`.
- [ ] `Cmd+,` / `Ctrl+,` global shortcut.
- [ ] Tauri: macOS app menu `Preferences… ⌘,`.

### Phase 5 — Tauri biometric gating

- [ ] Tauri command: `biometric_authenticate(reason: string) -> bool`. macOS `LAContext.evaluatePolicy`; Windows Hello; Linux returns false with reason.
- [ ] Wire `passphraseProvider` to call it when `require_biometric` is on.
- [ ] Cache successful auth for `biometric_cache_seconds` (in-memory only).
- [ ] UI for both Device-safety preferences.

### Phase 6 — Auto-clear AMK on logout (after PRF lands)

- [ ] Add `clearAmk(userId)` call to `logout()` in `web/src/lib/auth-context.tsx`.
- [ ] Verify re-login derives AMK via PRF without device-transfer prompt.
- [ ] Update "Clear local data on this device" button copy if redundant.

### Phase 7 — Globe-icon language menu (gated on task #40)

- [ ] When `availableLocales.length >= 2`, render globe menu in nav.
- [ ] Quick-switch sets `language.locale` in the AMK blob.
- [ ] "More preferences…" routes to `/settings#language`.

### Out-of-scope follow-ups (own tasks)

- Passphrase import/export to/from CLI `config.toml` (task #38 subtask 4).
- CLI `secrt config sync` to push/pull the AMK blob.
- iOS app preferences (consume the same `Preferences` struct via shared Rust core or a hand-mirrored Swift type).
- Multi-profile / custom host (task #49).
- Jurisdiction picker explainer (task #45).
- Transparency log / rollback prevention (out of v1; documented limitation).

---

## Files touched (rough map)

| File / area | Change |
|---|---|
| `crates/secrt-core/src/preferences.rs` (**new**) | `Preferences` struct + envelope helpers + AAD builder |
| `crates/secrt-core/src/lib.rs` | Re-export `preferences` |
| `crates/secrt-server/src/http/auth.rs` (or `mod.rs`) | New `/preferences` endpoints with CAS |
| `crates/secrt-server/src/storage/mod.rs` | `user_preferences` table + CRUD + revision |
| `crates/secrt-server/migrations/` (**new file**) | SQL for table |
| `spec/v1/preferences.md` (**new**) | Envelope spec |
| `spec/v1/preferences.vectors.json` (**new**) | Test vectors |
| `spec/v1/openapi.yaml` | Add endpoints, ETag/If-Match |
| `web/src/crypto/preferences.ts` (**new**) | WebCrypto mirror |
| `web/src/lib/preferences.ts` (**new**) | Get/set API + Preact hook |
| `web/src/lib/preferencesSync.ts` (**new**) | Load/save/cache/CAS retry |
| `web/src/lib/passkey-aaguids.ts` (**new**) | Static AAGUID lookup table + resolver |
| `web/src/lib/credential-capture.ts` (**new**) | Parse attestation object, derive `safari_prf_compatible` + `capability`, write split |
| `crates/secrt-server/migrations/` (existing migration set) | Add `passkeys.safari_prf_compatible BOOLEAN NULL` (lives with other PRF schema deltas) |
| `crates/secrt-server/src/http/mod.rs` | register-finish / add-finish: accept and persist `safari_prf_compatible`; login-finish: stamp on PRF upgrade |
| `crates/secrt-server/src/storage/postgres.rs` | passkey CRUD: write/read `safari_prf_compatible` |
| `web/src/lib/passphraseProvider.ts` (**new, Tauri-relevant**) | Single gated provider |
| `web/src/lib/auth-context.tsx` | Phase 6: clear AMK on logout |
| `web/src/features/settings/SettingsPage.tsx` | Add Preferences sections; remove AuthGuard; wrap Account in auth check; add Danger Zone Clear button |
| `web/src/features/settings/Preferences/*.tsx` (**new**) | Section components |
| `web/src/features/send/SendPage.tsx` | Default TTL + checkbox model + auto-copy + indicator |
| `web/src/features/claim/*.tsx` | Multi-phase auto-decrypt |
| `web/src/components/Nav.tsx` | Remove dark-mode toggle; add gear icon for unauth |
| `web/src/components/ThemeToggle.tsx` | Keep `D` shortcut; remove visual button |
| `web/src/lib/shortcuts.ts` (**new or extended**) | `Cmd+,` / `Ctrl+,` |
| `crates/secrt-app/src/lib.rs` | New `biometric_authenticate` Tauri command |
| `crates/secrt-app/tauri.conf.json` | macOS menu `Preferences… ⌘,` |

---

## Open questions to resolve during Phase 0

1. **`updated_at_ms` and clock skew.** Server overwrites with its own clock on PUT (refusing client-claimed timestamps), or trusts client time? Lean: server overwrites the outer envelope timestamp, client-side `Preferences.updated_at_ms` is informational only (used for "last synced" UI text).
2. **Auto-copy on Safari.** Test before shipping; if too unreliable after `await fetch`, fall back to "click to copy" affordance with a small platform-specific notice. Don't gate the whole feature.
3. **Schema migration policy.** v1 ships with `version: 1`. When v2 exists, do v1 clients silently downgrade-on-write (lossy) or refuse to write? Lean: refuse + show "this device needs to be updated."
4. **Quick-settings dropdown.** Defer to v1.1 after dogfooding the full page. Don't gate v1 on it.
5. **PRF and the device-transfer/QR flow.** PRF makes the existing flow rare but not obsolete. It's still required for: bootstrapping a second passkey, account recovery, and PRF-less authenticators (~2-5% of 2026 user base). Demote, don't remove.

---

## Cross-references

- **Design discussion transcripts:** sessions of 2026-04-26 (Claude Code), including Codex review and follow-up triage; session of 2026-05-01 (Claude Code) covering YubiKey cross-device PRF verification, iPhone Safari + external authenticator failure mechanism, badge taxonomy, and credential-metadata folding into this plan.
- **Prior task notes:** task-37 description (in `tasks.json`), task-38, task-34, task-42, task-45, task-49, GitHub issues #28, #29.
- **Related crypto:** `web/src/crypto/amk.ts`, `crates/secrt-core/src/crypto.rs`, `crates/secrt-server/docs/prf-amk-wrapping.md`.
- **AMK persistence layer:** `web/src/lib/amk-store.ts`, `crates/secrt-app/src/lib.rs` (keyring commands).
- **Existing auth flow:** `web/src/lib/auth-context.tsx`, `web/src/features/auth/LoginPage.tsx`, `web/src/features/auth/RegisterPage.tsx`.
- **Existing settings UI:** `web/src/features/settings/SettingsPage.tsx`.
- **Existing CLI config:** `crates/secrt-cli/src/config.rs`.
