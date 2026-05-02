# PRF Cross-Device Testing — Spike Findings & Observational Log

**Companion to:** `prf-amk-wrapping.md` (architecture / design contract).
This file is the empirical evidence backing that doc's §11 matrix. Append
new traces here as devices/browsers are tested; promote conclusions to §11
when stable.

> **How to read this document:** the "Captured traces" section is raw data —
> per-credential fingerprints we've directly observed in console logs. The
> "Failure mode catalog" turns those traces into a Rosetta stone for future
> debugging. The "Open hypotheses" section names what we still need to test
> before promoting conclusions to the architecture doc.

---

## 1. Purpose

WebAuthn PRF behavior in the wild diverges from the spec in ways that aren't
obvious until you see two devices fail to agree on a 32-byte string. This doc
captures those observations with enough fidelity that:

1. A future contributor investigating "why doesn't AMK transfer to platform X"
   can compare against captured traces instead of starting from scratch.
2. Claims about platform behavior in `prf-amk-wrapping.md` §11 are backed by
   observation rather than speculation.
3. The diagnostic-logging changes from
   `.taskmaster/plans/task-62-prf-amk-diagnostic-logging.md` have a place to
   land their output.

---

## 2. Capturing a trace

### Web client

1. **Dev build:** logging is unconditionally on (`import.meta.env.DEV`).
2. **Prod build:** open DevTools console and run:
   ```js
   localStorage.setItem('secrt:debug', '1');
   ```
   then reload.
3. Open DevTools → Console, filter on `[secrt:` to isolate diagnostic lines.
4. Perform the action under test (register, sign in, add passkey from
   Settings, etc.).
5. Copy the relevant `[secrt:...]` lines. The fields to capture per trace:

| Tag | Field that matters most |
|---|---|
| `[secrt:webauthn-create]` | `prfExtPresent`, `prfEnabled`, `prfHasResults`, `prfState.atCreate`, `authenticatorAttachment` |
| `[secrt:webauthn-get]` | `prfExtPresent`, `hasPrfOutput`, `constrained`, `authenticatorAttachment` |
| `[secrt:prf-register-wrap]` | `prfOutputFingerprint` (from `prf-fallback-ceremony` if at-create was false) |
| `[secrt:prf-unwrap]` | `hasWrapper`, `wrapperHasSalt`, `wrapperVersion`, `hasPrfOutput`, `prfOutputFingerprint` |
| `[secrt:prf-fallback-ceremony]` | `prfOutputFingerprint`, `credIdMatch` |
| `[secrt:amk-store]` | `amkFingerprint`, `present` |

**`authenticatorAttachment`** is `'platform'` (iCloud Keychain, Windows Hello,
Android system) or `'cross-platform'` (USB/NFC security key, e.g. YubiKey).
Critical for disambiguating which authenticator the user picked when the
browser offered multiple options — especially on iPhone where the same
credential picker may show both an iCloud-synced credential and a YubiKey-via-
NFC option.

### What to compare

Cross-device determinism is verifiable only across rows that share the
**same credential** (not the same account — same `credentialId`). Resident
YubiKey credentials work for this; per-device platform credentials do not
(those are intentionally device-isolated).

The 8-byte hex fingerprint is `SHA-256(bytes)[0..8]`. Two readings of the
same bytes always produce the same fingerprint; different bytes essentially
never collide.

---

## 3. Captured traces

Each round below is a distinct credential. Within a round, every row should
have the same `prfOutputFingerprint` if PRF determinism holds for the
authenticator across that surface set. Divergence is the interesting signal.

### Round A — YubiKey 5C NFC, 2026-05-01

**Authenticator:** YubiKey 5C NFC, FIDO2 PIN set, USB-C connection.
**RP:** `localhost` (Vite dev server).
**Credential:** `IzbvnR47…` (resident, registered in Chrome incognito).

| # | Browser | OS | Action | `prfOutputFingerprint` | AMK fp | Outcome |
|---|---|---|---|---|---|---|
| A1 | Chrome 147 (incognito, no extensions) | macOS | Register | `ae46d371655a91c5` | `0268912bbf0a1d3d` | ✓ wrap+PUT succeeded |
| A2 | Chrome 147 (regular, with Bitwarden enabled) | macOS | Sign-in | `ae46d371655a91c5` | `0268912bbf0a1d3d` | ✓ unwrap succeeded |
| A3 | Vivaldi (Chromium) | macOS | Sign-in | `ae46d371655a91c5` | `0268912bbf0a1d3d` | ✓ unwrap succeeded |
| A4 | **Safari** | **macOS** | **Sign-in** | **`156c06de00de5149`** | n/a | **✗ unwrap failed (`OperationError`)** |
| A5 | Firefox | macOS | n/a | n/a | n/a | site wouldn't load on `localhost` (Vite/Firefox HMR issue, unrelated; needs prod retest) |

**Round A interpretation.** All Chromium browsers on the same Mac produce the
*identical* PRF output (`ae46d371655a91c5`) for credential `IzbvnR47`, and
unwrap succeeds end-to-end. Safari on the same Mac produces a *different*
output (`156c06de00de5149`) for the same credential, same eval salt, same
authenticator. The unwrap fails with AES-GCM tag failure — exactly what's
expected when the wrap key derived at unwrap time differs from the wrap key
the wrapper was sealed under.

This is direct empirical confirmation that **Apple's WebAuthn framework
re-wraps the `hmac-secret` value for external authenticators on macOS, not
just iOS.** Chromium browsers bypass Apple's framework with their own CTAP
HID stack, so they see the raw value.

### Round B — YubiKey 5C NFC on `secrt.is` (prod), 2026-05-02

**Authenticator:** YubiKey 5C NFC, FIDO2 PIN set, USB-C connection.
**RP:** `https://secrt.is` (prod, post-0.17.5 deploy).
**Credentials:** two registered this round —
  - `WDo5wF7y…` (account #1, registered Chrome with Bitwarden enabled, no popup interaction)
  - `HCiDjl-B…` (account #2, registered Chrome with Bitwarden enabled, popup navigated through "Use your device or Hardware key")

| # | Browser | OS | Action | Credential | `prfOutputFingerprint` | AMK fp | Outcome |
|---|---|---|---|---|---|---|---|
| B1 | Chrome 147 (Bitwarden enabled, popup ignored) | macOS | Register | `WDo5wF7y` | `7baef9877a382253` | `643b887d39635064` | ✓ wrap+PUT succeeded |
| B2 | Chrome 147 (Bitwarden enabled, popup navigated) | macOS | Sign-in (discoverable) | `WDo5wF7y` | `7baef9877a382253` | (existing) | ✓ unwrap skipped — local AMK already present (cross-session determinism confirmed: B2 fingerprint matches B1 byte-for-byte) |
| B3 | Chrome 147 (Bitwarden enabled, popup navigated) | macOS | Register (constrained get() in fallback) | `HCiDjl-B` | `d3185505de174dc5` | `14520ee57c6ea466` | ✓ wrap+PUT succeeded — even on the constrained get() that failed in Round A1 (no extensions) |
| B4 | Firefox 150.1 (Bitwarden enabled) | macOS | Sign-in | `HCiDjl-B` | n/a — `prfExtPresent: false` | n/a | ✗ Firefox stripped the PRF extension entirely |
| B5 | Firefox 150.1 (Bitwarden disabled) | macOS | Sign-in | `HCiDjl-B` | n/a — `prfExtPresent: false` | n/a | ✗ Same as B4 — confirms Firefox itself, not extension |

**Round B interpretation.**

*Cross-session determinism (B1 → B2):* Same credential, separate WebAuthn
ceremonies hours apart, identical fingerprint `7baef9877a382253`. The
YubiKey + Chrome pipe is producing byte-deterministic PRF output across
sessions. Sanity check passed at the most basic level: our wrap math has
no per-ceremony variability sneaking in.

*Bitwarden refinement (B1, B2, B3):* All three Bitwarden-enabled tests
succeeded. Notably B3 is a constrained get() (the PRF-on-get-only
fallback ceremony) — the same shape that *failed* in Round A's
no-extensions-but-localhost case. This contradicts the original
"Bitwarden hooks constrained get() and corrupts" hypothesis. Refined
model: **Bitwarden inserts a UI gate in front of every WebAuthn ceremony
but does not modify assertion bytes.** When the user navigates through
Bitwarden's "Use your device or Hardware key" prompt, the assertion
proceeds normally and PRF is delivered. The yesterday-localhost failure
was almost certainly the user dismissing/timing-out Bitwarden's popup,
which surfaces as `NotAllowedError` from the extension's content script
— not data corruption.

UX cost is real, though: a YubiKey registration with Bitwarden enabled
requires four user actions (Bitwarden popup → tap key → second Bitwarden
popup → tap key again) versus two for a Bitwarden-disabled flow. Many
users will dismiss the second popup not realizing it's a separate
required step.

*Firefox 150.1 (B4, B5):* Both traces show
`prfRequested: true, prfExtPresent: false, hasPrfOutput: false` —
Firefox is not returning the PRF extension at all. Disabling Bitwarden
makes no difference, ruling out extension-side stripping. About:config
search for `prf` returns no existing preferences (the three radio
buttons Firefox shows are the "create new pref" UI, not three existing
prefs). Firefox 150.1 is **post** v148, the version that nominally added
PRF support, so this is not a "browser too old" failure. Combined: the
most plausible explanation is that **Firefox's PRF support is
platform-credential-only and was never extended to external CTAP2
authenticators via USB**. No user-facing workaround exists; would
require Mozilla code change.

### Round C — 1Password as platform passkey provider, 2026-05-02

**Authenticator:** 1Password 8 acting as a platform passkey provider
(via the browser extension on desktop, via Apple's `ASCredentialProviderExtension`
on iOS).
**RP:** `https://secrt.is` (prod).
**Credential:** `2hX0aGOL…` (1Password vault, single credential synced across
all tested devices via 1Password's own sync infrastructure).

| # | Browser | OS | Action | `prfOutputFingerprint` | AMK fp | Outcome |
|---|---|---|---|---|---|---|
| C1 | Chrome | macOS | Register | `88c149421125d06f` | `7b3e927196ba2163` | ✓ wrap+PUT succeeded — **PRF returned at create()** (single touch, no fallback ceremony) |
| C2 | **Safari** | **macOS** | Sign-in | `88c149421125d06f` | `7b3e927196ba2163` | ✓ unwrap succeeded — Apple framework passes platform-provider PRF through |
| C3 | Firefox | macOS | Sign-in | `88c149421125d06f` | `7b3e927196ba2163` | ✓ unwrap succeeded — Firefox's platform-credential PRF support covers third-party providers |
| C4 | Chrome | Windows | Sign-in | `88c149421125d06f` | `7b3e927196ba2163` | ✓ unwrap succeeded |
| C5 | Firefox | Windows | Sign-in | `88c149421125d06f` | `7b3e927196ba2163` | ✓ unwrap succeeded |
| C6 | **Safari** | **iOS (iPhone)** | Sign-in via 1Password Credential Provider Extension | `88c149421125d06f` | `7b3e927196ba2163` | ✓ unwrap succeeded — **iPhone Safari + non-Apple passkey = AMK transferred end-to-end** |
| C7 | Any browser | Android < 14 | n/a | n/a | n/a | ✗ Android Credential Manager API for third-party passkey providers requires Android 14+. 1Password literally cannot do passkeys on older Android (Pixel 4a, etc.). Not a 1Password limitation — an Android platform one. |
| C8 | Any browser | Android 14+ | not yet tested | expected `88c149421125d06f` | expected match | architecturally should work; needs hardware verification |

**Round C interpretation.**

This is the cleanest cross-platform result we have. **One credential, one
PRF output, six confirmed surfaces, end-to-end AMK transfer everywhere
including iPhone Safari.** Notably:

- **Mac Safari + 1Password works** even though Mac Safari + YubiKey doesn't.
- **iPhone Safari + 1Password works** even though iPhone Safari + YubiKey doesn't.
- **Firefox + 1Password works** even though Firefox + YubiKey doesn't.

The mechanism is the `authenticatorAttachment: 'platform'` taxonomy
combined with platform-specific credential-provider APIs:

- On **iOS**, 1Password registers itself via Apple's
  `ASCredentialProviderExtension` (the third-party passkey provider API
  introduced in iOS 17). Apple's WebAuthn framework treats credentials
  surfaced through this API the same way it treats iCloud Keychain — as
  a platform credential — and passes PRF through unmodified. The Apple
  framework re-wrap behaviour (which breaks YubiKey on Safari/iOS) only
  applies to *external CTAP2 authenticators* talking via the
  FIDO2 USB / NFC pathway.
- On **macOS**, the browser extension intercepts WebAuthn calls and
  returns a 1Password-managed credential before reaching Apple's
  framework. Same passthrough story.
- On **Windows / Linux**, same browser-extension mechanism. No platform
  framework involvement at all for software-credential providers.

PRF output `88c149421125d06f` is byte-identical across all tested
surfaces, which means 1Password's vault-level sync carries the
cred_salt and credential state in a way that makes PRF derivation
deterministic across devices. This is the property that lets the AMK
unwrap correctly on a fresh device.

**Practical implication:** 1Password is the cross-ecosystem passkey
recommendation. It works on every desktop OS, every major browser
including Firefox and Safari, and iOS. Android is the only gap, and
it's bounded by the Android version floor (14+), not by 1Password
behaviour.

---

## 4. Failure mode catalog

A reverse index from observed symptom to likely cause.

### `OperationError: The operation failed for an operation-specific reason`

In `[secrt:prf-unwrap]` on the **unwrap** path. AES-GCM tag check failed.
Always means: the wrap key derived from this client's PRF output does not
match the wrap key the wrapper was sealed under.

Common causes (in priority order):

1. **Platform PRF interception.** PRF output for this credential differs
   between the wrapping client and the unwrapping client. Verified by
   comparing `prfOutputFingerprint` across the two `[secrt:prf-unwrap]`
   traces. If they differ, this is the cause and the unwrap will *always*
   fail on this surface.
2. **AAD mismatch.** The AAD bound at wrap time uses
   `(userId, credentialRawId, version)`. Mismatch in any field would also
   produce `OperationError`. Less likely if the credential ID round-trips
   correctly (the `[secrt:webauthn-get]` line shows what the client
   actually presented).
3. **`cred_salt` mismatch.** Wrapper carries its own `cred_salt` so this
   should not normally diverge, but a server bug substituting the salt
   would manifest the same way.

### `Error: The operation either timed out or was not allowed.` from `fido2-page-script.js`

In `[secrt:prf-register-wrap]` or anywhere a WebAuthn ceremony was just
attempted. The stack frame `fido2-page-script.js` is the **content script
injected by a browser extension** intercepting WebAuthn calls — Bitwarden's
extension uses exactly this pattern; 1Password's looks similar.

Refined model (2026-05-02 prod testing): the extension is **not corrupting
or stripping** assertion data — it's gating the WebAuthn flow behind its
own UI prompt. The `NotAllowedError` happens when the user dismisses or
times out the extension's popup. When the user navigates through the
extension's "Use your device or hardware key" option, the assertion
proceeds normally and PRF is delivered intact — even on constrained
get() ceremonies in the PRF-on-get-only fallback path.

Resolution: either dismiss the extension popup is **not** the answer
(it produces this error). Instead, click through the extension's
"Use your device or hardware key" option to route the assertion to the
hardware authenticator. For users who don't want the friction, disable
the extension during initial passkey registration and re-enable
afterward — subsequent sign-ins work cleanly with the extension active
because the discoverable login flow lets the user pick directly through
the extension's UI.

### `[secrt:webauthn-get]` shows `hasPrfOutput: false`

The assertion completed but no PRF output came back. Two distinct
sub-cases distinguished by `prfExtPresent`:

- **`prfExtPresent: false`** — the browser/picker dropped the extension
  entirely from the assertion response. Confirmed cases (2026-05-02):
  Firefox 150.1 with external YubiKey on macOS. Cause appears to be
  Firefox's PRF support being platform-credential-only, not extended to
  external CTAP2 authenticators. No client workaround exists.
- **`prfExtPresent: true, hasPrfOutput: false`** — extension is
  acknowledged but the authenticator declined to evaluate it. Some
  Safari + iCloud configurations do this (`enabled=false` style).

Either way, the PRF unlock path is dead for this credential on this
surface — caller falls through to sync-link / API-key.

### `[secrt:prf-unwrap]` says `'skipping unwrap, local AMK already present'`

Not a failure. The `loadAmk()` call returned a non-null AMK so we
short-circuited rather than re-deriving. Clear IndexedDB (`secrt-amk` DB)
to actually exercise the unwrap path.

### `[secrt:prf-register-wrap]` reports `hasOnCreateOutput: false`

Authenticator (typically YubiKey on Chrome/Edge/Vivaldi) does not return
PRF on create. The fallback ceremony will be invoked — *expect a second
WebAuthn prompt*. This is intrinsic to CTAP2 `hmac-secret` (evaluated only
at assertion time) and not a bug.

### `wrapperHasSalt: false` in `[secrt:prf-unwrap]`

Server returned a `prf_wrapper` object with no `cred_salt` field. This is a
server-side bug — the wrapper schema requires the salt to be embedded so
unwrap clients can derive the wrap key without a separate round trip. The
unwrap will fail with `Error: login-finish prf_wrapper missing cred_salt`
before AES-GCM is even attempted. File against the server, not the client.

(The earlier task #62 trace logged a `hasSalt` field that read the
upgrade-path `finishRes.prf_cred_salt` instead — confusing because that
field is always false on the unwrap branch by design. Renamed to
`wrapperHasSalt` 2026-05-01 to fix this. If you see `hasSalt` in an old
trace, ignore it.)

---

## 5. Open hypotheses

Things we believe but haven't directly verified. Each one names a test that
would resolve it.

### H1 — Apple's `hmac-secret` re-wrap is per-device

We've shown Chrome and Safari on the same Mac produce different PRF outputs
for the same credential. We have *not* shown that two Macs running Safari
with the same iCloud account produce different outputs (which would prove
device-bound), or that they produce the same output (which would prove
account-bound).

**Test:** capture `prfOutputFingerprint` on a second Mac running Safari,
signing in with the same YubiKey credential, same iCloud account. Same
fingerprint as `156c06de00de5149` → account-bound. Different → device-bound.
Either result is interesting.

### H2 — Windows Hello / WebAuthn framework intercepts external authenticators like Apple does

The triggering session for task #62 noted Windows Chrome (regular and
incognito) failing to unwrap against the same YubiKey wrapper that worked
on Mac Chrome. Strong circumstantial evidence of an analogous Windows
mechanism, but we never captured the actual fingerprint.

**Test:** sign in on Windows Chrome with YubiKey credential `IzbvnR47` and
capture `prfOutputFingerprint`. Equals `ae46d371655a91c5` → Windows Chrome
talks CTAP HID directly like macOS Chrome and the prior failure was
something else. Differs → Windows is doing what Apple does, and we've
identified a second platform with the same caveat.

### H3 — Firefox on a real HTTPS origin behaves like Chromium

**RESOLVED — disproved (Round B4, B5, 2026-05-02).** Firefox 150.1 on
prod returns `prfExtPresent: false` for an external YubiKey, with or
without Bitwarden. About:config has no `prf` preference to toggle. Most
plausible explanation: Firefox's PRF support (added in v148) is
platform-credential-only and was never extended to external CTAP2
authenticators. No client-side workaround exists; would require a
Mozilla code change. Tracked upstream via bug 1863819 (PRF meta-bug);
file a follow-up requesting USB CTAP2 PRF if/when we want to push it.

### H4 — The Bitwarden `NotAllowedError` is specific to the get() ceremony, not create()

**RESOLVED — disproved by Round B (2026-05-02).** Refined model:
Bitwarden inserts a UI gate in front of every WebAuthn ceremony but
does not modify assertion bytes. The Round A localhost failure was the
user dismissing/timing-out Bitwarden's popup, surfacing as
`NotAllowedError` from the extension's content script — not data
corruption. When the user navigates through Bitwarden's "Use your
device or Hardware key" prompt, even constrained get() ceremonies
complete normally with PRF output intact. The cost is friction (4 user
actions per YubiKey registration vs 2 baseline), not breakage.

### H5 — 1Password as picker drops PRF

**RESOLVED — disproved (Round C, 2026-05-02).** The 2026-04 spike's
`prf: undefined` reading was Safari/macOS confounding the test, not
1Password's behaviour. Round C captured the same credential
(`2hX0aGOL`) on six different surfaces (Mac Chrome / Safari / Firefox,
Windows Chrome / Firefox, iPhone Safari) and produced a byte-identical
PRF output `88c149421125d06f` every time. End-to-end AMK transfer
worked on every surface.

**1Password is now the strongest cross-platform passkey provider
we've tested** — better than YubiKey on Safari (which is broken),
better than Firefox + external authenticator (broken), better than
Bitwarden's stored-credential case (PRF dropped). Updated cohort
recommendation in `prf-amk-wrapping.md` §11.

### H6 — 1Password works on Android 14+ (Credential Manager API)

**PARTIALLY OPEN.** 1Password requires Android 14+ for passkey
support because that's when Android shipped the Credential Manager
API for third-party passkey providers. Earlier Android (incl. Pixel
4a, which maxes at Android 13) cannot do passkeys via 1Password —
not a configuration issue, an OS API floor. Architecturally, on a
device running Android 14+, the Credential Manager pathway should
behave like Apple's `ASCredentialProviderExtension` and pass PRF
through cleanly.

**Test:** sign in on Android 14+ device with the same credential
`2hX0aGOL`. Expected: `prfOutputFingerprint: 88c149421125d06f`,
unwrap succeeds. Until verified, the cohort table treats this as
"expected to work" rather than "confirmed."

---

## 6. Methodological notes & gotchas

### Resident credentials accumulate on the YubiKey

Each fresh-account registration consumes one resident credential slot
(YubiKey 5C NFC has ~25). After a few rounds of testing, list and delete
old test credentials:

```sh
ykman fido credentials list
ykman fido credentials delete <credential_id>
```

`ykman fido reset` nukes everything FIDO2 on the key — irreversible, only
use on a dedicated test key.

### Browser extensions in incognito

Chrome incognito disables extensions *by default*, but several common
extensions (Bitwarden, 1Password) are toggleable per-extension at
`chrome://extensions` → "Allow in incognito." Confirm those toggles are
**off** before claiming "no extensions" in a captured trace.

### Same credential, different RP origins

PRF outputs are bound to the (credential, eval salt) pair, where eval salt
is itself bound to the RP origin via our `secrt.is/v1/amk-prf-eval-salt`
hash. A YubiKey credential registered against `localhost` will not produce
the same PRF output as the same physical key registered against
`secrt.is`, even though both are computed from the literal string
`secrt.is/v1/amk-prf-eval-salt` — because the *credential itself* is
distinct (different RP IDs produce different credentials on the YubiKey).

For cross-environment comparison (dev → prod), you have to register a new
credential in each environment.

### Which Safari log lines belong to which sign-in

Safari sometimes carries previously-loaded user state and emits
`[secrt:amk-store]` lines for an *unrelated* old user before the active
sign-in starts emitting lines for the new user. The `userId` field
disambiguates — only trust traces where userId matches the account
currently being signed into.

### `[secrt:prf-unwrap]` `userId` field

Identifies the account, not the credential. Two different accounts
registered against the same physical YubiKey will have different `userId`
fields in their traces but may share the same `credIdPrefix` only by
coincidence — credential IDs are 16+ random bytes, so collisions are
effectively zero.

---

## 7. Change log for this document

| Date | Change |
|---|---|
| 2026-05-01 | Initial draft. Round A captured (YubiKey + Mac matrix). Apple WebAuthn macOS Safari interception confirmed. |
| 2026-05-02 | Round B captured on prod (`secrt.is`). H3 (Firefox matches Chromium) disproved — Firefox 150.1 strips PRF entirely for external authenticators. H4 (Bitwarden corrupts) disproved — Bitwarden gates UI but doesn't modify assertion bytes. Refined Bitwarden failure-mode entry; refined `prfExtPresent: false` failure mode with sub-cases. Cross-session determinism (B1 → B2) confirmed on Mac Chrome. |
| 2026-05-02 | Round C captured: 1Password as platform passkey provider, six confirmed surfaces (Mac Chrome / Safari / Firefox, Windows Chrome / Firefox, iPhone Safari). PRF output byte-identical across all (`88c149421125d06f`). Cross-device AMK transfer works end-to-end including iPhone. H5 (1Password drops PRF) disproved positively. H6 added for Android 14+ verification. 1Password promoted to recommended cross-ecosystem option in `prf-amk-wrapping.md` §11. Mechanism note added: platform credential providers are exempt from Apple's `hmac-secret` re-wrap because the framework only intercepts external CTAP2, not `ASCredentialProviderExtension` providers. |
