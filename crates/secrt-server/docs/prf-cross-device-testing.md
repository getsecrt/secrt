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

### Round B — Cross-OS (PENDING)

To be filled when Windows / iPhone testing happens after the next prod
release. Expected fingerprints to capture:

- Windows Chrome + same YubiKey → expected `ae46d371655a91c5` if Windows
  Chrome talks CTAP HID directly (parallel to macOS Chrome). Different
  fingerprint would imply Windows Hello / WebAuthn framework intercepts.
- Windows Edge → same expectation as Windows Chrome (both Chromium).
- iPhone Safari + same YubiKey via NFC → some Apple-framework-wrapped value.
  Whether it equals macOS Safari's `156c06de00de5149` answers an open
  question (see §5): is Apple's wrap device-bound, account-bound, or
  framework-bound?

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

Resolution: disable the extension (or test in incognito with extensions
not granted incognito access) and retry. If the failure goes away, the
extension is the cause. As of 2026-05-01 we've directly observed Bitwarden
intercepting the second ceremony in the PRF-on-get-only fallback path on
Chrome/macOS.

### `[secrt:webauthn-get]` shows `hasPrfOutput: false`

The assertion completed but no PRF output came back. Authenticator or
picker dropped the extension entirely (`prfExtPresent: false`) or the
authenticator declined to evaluate it (`prfExtPresent: true,
hasPrfOutput: false`). Either way, the PRF unlock path is dead for this
credential on this surface — caller falls through to sync-link / API-key.

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

Firefox couldn't load the localhost dev server in Round A. Once we deploy
to a real HTTPS origin, Firefox 148+ should — based on its own CTAP stack —
produce the raw `hmac-secret` and match Chromium's `ae46d371655a91c5`.

**Test:** sign in on Firefox 148+ on prod with the same YubiKey credential
and capture `prfOutputFingerprint`. Equals `ae46d371655a91c5` → Firefox is
in the "works" set with Chromium. Differs → Firefox is doing its own
processing, which would be surprising.

### H4 — The Bitwarden `NotAllowedError` is specific to the get() ceremony, not create()

In Round A, registration with Bitwarden enabled produced a credential
successfully (the `webauthn-create` line completed) but the *second*
ceremony (the fallback get() to obtain PRF output) failed with the
extension-injected error. That suggests Bitwarden hooks `get()` more
aggressively than `create()`, or only intercepts when `allowCredentials`
constrains the picker.

**Test:** ignore for now — we have a workaround (don't register with
extensions on) and Bitwarden's PRF passthrough is a vendor problem to
escalate via their issue tracker, not for us to design around.

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
