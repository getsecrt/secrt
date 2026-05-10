# YubiKey Compatibility with secrt

> **Audience:** project contributors deciding what to recommend in product copy; security-aware users evaluating whether a YubiKey is right for their secrt account.
>
> **Companion docs:**
> - `prf-amk-wrapping.md` — architecture & cohort matrix.
> - `prf-cross-device-testing.md` — empirical traces & methodology.
>
> **TL;DR:** YubiKeys give you the strongest threat model available for secrt, but the WebAuthn ecosystem treats external authenticators as second-class for PRF (the mechanism that lets your encryption key transfer to new devices). YubiKey + secrt works on Chromium browsers on macOS / Windows / Linux. It does **not** work — for the encryption-key-transfer part — on Safari (any), Firefox, or iPhone. None of this is fixable by Yubico or by us; it's platform-policy plus browser-implementation gaps. The practical answer for users who want hardware-rooted security and broad device coverage is to enroll a YubiKey **and** a complementary platform credential (iCloud Keychain or 1Password).

---

## 1. What works

Empirically verified 2026-05-01 with a YubiKey 5C NFC + secrt.is in production. Same physical key, same credential, byte-identical PRF output across all "works" rows:

| Surface | Status | Notes |
|---|---|---|
| macOS Chrome | ✓ | Reference fingerprint captured |
| macOS Vivaldi | ✓ | Same Chromium engine; behaves identically |
| macOS Edge | ✓ expected (untested) | Same Chromium engine |
| Windows Chrome | ✓ confirmed | Round F 2026-05-02: byte-identical raw `hmac-secret` with macOS Chrome for same credential |
| Windows Firefox 150.1 | ✓ confirmed | Round F 2026-05-02: routes through `webauthn.dll`, same raw value as Chromium |
| Windows Edge | ✓ expected (untested) | Same Chromium engine as Chrome/Windows |
| Linux Chrome | ✓ expected (untested) | Same |
| Linux Firefox 149.0.2 | ✓ confirmed | Round G 2026-05-02: routes through `authrs_bridge`; cross-OS AMK transfer with Chrome/Windows verified |
| Chrome on Android (NFC tap) | ✓ expected (untested) | Same |

Why these work: Chromium ships its own CTAP HID stack and forwards the YubiKey's raw `hmac-secret` value to the relying party as PRF output, unmodified. The wrap-key derivation that secrt does is byte-identical across Chromium browsers reading the same physical key, which is the property that lets the encryption key transfer between devices.

## 2. What doesn't work, and why

Three distinct failure modes, each with a different root cause. None of them are bugs in your YubiKey or in secrt — they're decisions made by the platforms / browsers downstream of the key.

### 2.1 Safari, on any Apple OS — Apple framework re-wraps `hmac-secret`

**Confirmed broken:** macOS Safari, iOS Safari, every iOS browser (iOS forces all browsers through WKWebView).

**Mechanism:** Apple's WebAuthn framework intercepts external-authenticator responses and re-wraps `hmac-secret` with an opaque framework-managed key before returning it to the relying party. The output is still 32 bytes and still looks valid, but it's `Encrypt(framework_key, real_hmac_secret)` rather than the raw value. So the wrap key derived on a Mac running Safari doesn't match the wrap key derived on a Mac running Chrome — even though it's the same YubiKey, same credential, same RP.

**Why Apple does this:** anti-tracking. Raw `hmac-secret` is deterministic per `(credential, salt)` — a malicious site could in principle correlate the same user across credentials by inspecting raw PRF outputs. Apple's wrap key prevents that observation from crossing the platform's privacy boundary.

This is documented behaviour, not a bug Apple is going to fix. Yubico's developer guide acknowledges it as a known limitation. Apple has been clear: external authenticators don't get to expose raw extension cryptographic material across the framework.

**Important scope note:** the re-wrap behaviour applies *only* to external CTAP2 authenticators (USB / NFC FIDO2 keys). Software passkey providers that surface credentials through Apple's `ASCredentialProviderExtension` (iOS 17+ third-party passkey provider API) are exempt — which is why 1Password and iCloud Keychain pass PRF through cleanly on iOS. The Apple framework distinguishes between "external hardware key" and "software credential provider" and applies different rules.

### 2.2 Firefox 150.1 on macOS — PRF dropped for USB security keys (macOS-specific)

**Confirmed broken:** Firefox 150.1 on **macOS** with a USB YubiKey (extension stripped entirely, with or without password-manager extensions installed).

**Confirmed working:**
- Firefox 150.1 on **Windows** with a USB YubiKey (Round F, 2026-05-02). Same physical key, same credential, byte-identical raw `hmac-secret` value as Chromium-on-anywhere; full AMK transfer Chrome/Windows ↔ Firefox/Windows works cleanly.
- Firefox 149.0.2 on **Linux** with a USB YubiKey (Round G, 2026-05-02). Same key, same credential, fingerprint matches Chrome/Windows registration; full cross-OS AMK transfer Chrome/Windows → Firefox/Linux works.

So the Firefox/USB-key gap is now empirically locked to **macOS only.** Firefox-the-product handles PRF for USB security keys correctly on every other major desktop OS.

**Mechanism (refined 2026-05-02 by source-level investigation — see [`firefox-prf-source-investigation.md`](firefox-prf-source-investigation.md)):** the gap is *not* that Firefox's PRF support is wholesale-missing for external authenticators. Firefox vendors `authenticator-rs`, which fully supports CTAP2 `hmac-secret` (salt encryption, response decryption, the works). The bug is that on macOS 13.3+, Firefox routes WebAuthn ceremonies through Apple's `ASAuthorizationController` API instead of `authenticator-rs`, and the macOS adapter (`dom/webauthn/MacOSWebAuthnService.mm`) wires PRF only into the platform-credential request class (`ASAuthorizationPlatformPublicKeyCredentialAssertionRequest`), never into the security-key request class (`ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest`). The assertion succeeds, the user signs in, but `getClientExtensionResults()` has no `prf` member.

That's why the same Firefox-on-Mac handles PRF correctly through caBLE/hybrid (a phone passkey scanned via QR) — those go through the platform request object, which *is* PRF-wired. Firefox on Linux/Windows, where Apple's API isn't in the loop, should hit `authrs_bridge` for USB keys and get PRF normally.

About:config has no `prf`-prefixed preference. No subordinate Mozilla bugzilla bug for "USB CTAP2 PRF on macOS" appears under meta-bug 1863819.

**Two candidate Mozilla-side fixes, with different trade-offs (verified against the Apple SDK and empirical re-wrap behavior on macOS 26.4.1, 2026-05-02):**

| Fix | Patch size | OS coverage | Solves cross-device determinism? |
|---|---|---|---|
| **Option A** — wire `.prf` on the security-key class in `MacOSWebAuthnService.mm` | ~20–40 lines of Objective-C++ | macOS 26.4+ only (Apple's `.prf` property is gated `API_AVAILABLE(macos(26.4))`) | **No.** Routes through Apple's framework, which empirically re-wraps `hmac-secret`. Firefox-on-Mac would gain parity with Safari-on-Mac, but values would differ from Chromium-on-Mac, Firefox/Linux, and Firefox/Windows. |
| **Option B** — bypass `ASAuthorizationController` for USB-when-PRF-requested, route to `authrs_bridge` | ~100–200 lines in `WebAuthnService.cpp` dispatch logic | All macOS versions | **Yes.** Raw `hmac-secret`, byte-identical with Chromium and Firefox/Linux/Windows. |

The macOS 15 SDK does **not** expose `.prf` on the security-key class — only platform credentials. The macOS 26.4 SDK adds it (verified in headers locally 2026-05-02). Cross-browser empirical capture on macOS 26.4.1 (`prf-cross-device-testing.md` Round E) confirms Apple still re-wraps `hmac-secret` for external authenticators on the new OS — Apple did not change the framework's privacy boundary in macOS 26. So Option A's value is bounded: it brings Firefox/macOS-26.4+ from "no PRF" to "Safari-equivalent wrapped PRF" — better than today, but not topology-correct.

**Workarounds for users on Firefox/macOS today (in order of recommendability):**

1. **Use Chrome/Edge/Vivaldi for accounts that depend on PRF.** These bypass Apple's framework via CTAP HID directly. No trade-offs.
2. **Scan a QR code with a phone-based passkey for the same account (caBLE).** PRF travels through the platform request path. Requires having a phone-based passkey enrolled.
3. **Power-user workaround — flip `security.webauthn.enable_macos_passkeys` to `false` in `about:config` and restart Firefox.** Empirically validated on Firefox 150.1 / macOS 26.4.1 (Round H, 2026-05-03): this routes USB security keys through `authrs_bridge` and produces working raw `hmac-secret` PRF, byte-identical with Chromium and Firefox/Linux/Windows. **Trade-off:** also disables iCloud Keychain platform-passkey integration in Firefox/macOS. Users with mixed credentials (USB key + iCloud Keychain) will lose iCloud Keychain passkey access in Firefox while gaining USB-key PRF. For users who only use USB security keys, this is a clean fix. Don't enable for daily Firefox use unless you've made the trade explicitly.

### 2.3 The double-touch problem at registration — CTAP2 spec

Even on Chromium browsers where everything works, a YubiKey registration takes **two physical touches** instead of one:

1. Touch #1: the WebAuthn `create()` ceremony to register the credential.
2. Touch #2: an immediate fallback `get()` ceremony to obtain the PRF output, because CTAP2's `hmac-secret` extension only evaluates at assertion time, not at creation time.

This is intrinsic to how `hmac-secret` is specified — it's bound to user verification, which can only happen during an assertion. Yubico is implementing the spec correctly. Apple Passwords / Google Password Manager / 1Password all avoid this because they're software credentials with full control over their own ceremony — they can produce the PRF value at create() time directly.

The user-facing failure mode: many users don't realize the second prompt is part of the same flow, dismiss it, and end up with a "broken" registration where the AMK wrapper was never written. We surface this in the diagnostic logs but the UX cliff is real and is an open task in the project (see task #63 — inter-ceremony status UI).

### 2.4 Bitwarden + YubiKey — friction multiplier

If the user has the Bitwarden browser extension active during a YubiKey registration, the flow becomes:

1. Bitwarden popup → click "Use your device or hardware key"
2. Touch the YubiKey (registration ceremony)
3. Bitwarden popup again → click "Use your device or hardware key" again
4. Touch the YubiKey again (PRF fallback ceremony)

That's four user actions versus two for a Bitwarden-disabled flow. Bitwarden does **not** corrupt the assertion bytes — when the user navigates through correctly, PRF comes through unchanged. But many users will dismiss the second Bitwarden popup not realizing it's a separate required step.

**Workaround:** disable Bitwarden during initial passkey registration, re-enable afterward. Subsequent sign-ins work fine with Bitwarden active because the discoverable login flow lets the user pick the YubiKey through Bitwarden's UI in one click.

## 3. Why none of this is fixable by Yubico (or us)

The instinct is to ask "can a future YubiKey 6 fix this?" The honest answer is **no, mostly, and not in any timeframe that matters.**

| Issue | Whose lap | Yubico can fix? | Realistic timeline |
|---|---|---|---|
| CTAP2 `hmac-secret` is get-only (double-touch problem) | FIDO Alliance spec | No — would need new CTAP version with "PRF on create" support | Multi-year spec process, then hardware revision, then browser support |
| Apple WebAuthn framework re-wraps for external authenticators | Apple, deliberate policy | No — Apple controls the layer between USB and Safari | None foreseeable — Apple has been explicit this is intentional |
| Firefox on macOS routes USB keys through Apple's API, which isn't PRF-wired for the security-key class | Mozilla implementation gap (macOS-specific) | Indirectly (lobby Mozilla; ~20–40 line patch in `MacOSWebAuthnService.mm`) | 1–2 release cycles if Mozilla prioritizes it; no subordinate bug filed under 1863819 yet |

**Yubico is doing the right thing.** They implement CTAP2 correctly. The YubiKey's hardware does exactly what the spec says it should. The downstream platforms/browsers are where the cross-compatibility breaks down.

**A future hardware revision wouldn't help on its own.** Even if Yubico shipped a non-standard extension tomorrow, browsers wouldn't surface it. Even if they implemented Apple's `ASCredentialProviderExtension`, that would require shipping a Yubico app on iOS that holds credentials *and* talks to the YubiKey for unlock — i.e., becoming a software credential provider with a hardware second factor, which is a different product (more like 1Password-with-YubiKey-for-unlock than a pure FIDO2 key). Some YubiKey customers explicitly want "the credential lives on the key, full stop"; that's the trade.

**The contrast with Bitwarden is informative.** Bitwarden's PRF gap is purely a software roadmap decision — they could ship PRF in their authenticator implementation whenever they decide to invest in it. The hardware vendor has the harder path to fixing things than the software vendor here, even though it intuitively feels backwards.

## 4. Recommended setups for YubiKey users

Three patterns, in increasing order of pragmatism:

### 4.1 YubiKey-only, Chromium-only

Two YubiKeys (primary + backup) registered on the account, plus a written-down API key as ultimate recovery. Use only Chrome / Edge / Vivaldi on macOS, Windows, Linux. Avoid Safari and Firefox. Avoid iPhone for secrt entirely.

This is the strongest threat model — only the physical keys in your hand can derive the encryption key. Trust set is just you and your hardware. But it constrains your device choices significantly.

### 4.2 YubiKey + complementary platform credential (recommended for most YubiKey users)

Enroll the YubiKey(s) for primary sign-in, **and** add a second credential of a different type:

- iCloud Keychain passkey for iPhone / iPad use.
- Or 1Password passkey for cross-platform coverage.

Either credential alone can derive the AMK on its respective surfaces. The user gets to use whichever is appropriate for the device in their hand at the moment.

**Trust-model honesty:** adding a second credential widens the trust set of the whole account. The account's effective security level becomes the *weakest* enrolled credential (OR-of-credentials, not AND). YubiKey-paranoid users who don't model Apple or 1Password as a threat may still want this; users who model those vendors as adversaries should rely on the sync-link / API-key fallback on iPhone instead and not enroll a second credential at all.

### 4.3 YubiKey for sign-in, sync-link / API-key for everything else

Enroll the YubiKey(s) only. Accept that on Safari / Firefox / iPhone, sign-in succeeds (the WebAuthn signature is fine — that path doesn't depend on PRF) but the encryption key won't transfer. Use the existing sync-link or API-key flow on those surfaces. This keeps the trust set narrow but adds a manual step every time you use a non-Chromium-non-desktop device.

## 5. UX surface in secrt today (and what's missing)

What's currently in the product:

- **Diagnostic logging** (shipped 0.17.5): `[secrt:webauthn-create]`, `[secrt:webauthn-get]`, `[secrt:prf-unwrap]`, `[secrt:prf-fallback-ceremony]`, etc. See `prf-cross-device-testing.md` §2 for the gating mechanism. Useful for debugging but DevTools-only — not user-facing.
- **"Sign-in only" badge** on passkeys list (shipped 0.16.9): credentials registered as PRF-incapable get a warning badge in Settings.

What's tracked but not yet shipped (see `.taskmaster/tasks/tasks.json`):

- **Task #63** — Inter-ceremony status UI for the YubiKey double-touch. "Tap your security key one more time to enable cross-device unlock" between the two ceremonies. Removes the "why is it asking again?" failure mode without changing the touch count.
- **Task #64** — Detect-and-explain broken cohort at sign-in. When `prfExtPresent: false` (Firefox case) or `OperationError` on unwrap (Safari case), surface an inline message: *"Your encryption key didn't transfer. This is a known limitation of [Firefox / Safari] with hardware security keys. Use a sync link from another browser, or sign in via Chrome / Edge / Vivaldi."* Highest-leverage Tier 1 task because it bridges the broken cohorts directly to actionable guidance.
- **Task #65** — Bitwarden onboarding copy. Plain-language note when we detect a content-script presence: "If you use Bitwarden, expect its prompt twice during setup."
- **Task #66** — AAGUID-based authenticator identification in the passkey list. Display "YubiKey 5C NFC" instead of "passkey #3 created on 2026-04-28" so users can reason about their credential set.
- **Task #67** — PRF-aware confirmation screen after registration: *"This YubiKey gives you single-tap unlock on Chrome, Edge, and Vivaldi — but not Safari, Firefox, or iPhone. Want to add an iCloud Keychain passkey for those?"*

## 6. What it would take to actually fix this

Ordered by likelihood of actually happening:

1. **Mozilla bypasses `ASAuthorizationController` for USB-when-PRF-requested on macOS, routing through `authrs_bridge`** (the only fix that actually solves cross-device determinism — see Option B in §2.2). ~100–200 lines in `WebAuthnService.cpp` dispatch logic. No spec or policy obstacle, but Mozilla may resist losing the native macOS UI affordances of the framework. Effective on all macOS versions. As a stopgap, Mozilla could *also* ship the smaller Option A patch (wire `.prf` on the security-key class for macOS 26.4+) — that brings Firefox/macOS to Safari parity but doesn't reach Chromium parity. Source-level analysis: [`firefox-prf-source-investigation.md`](firefox-prf-source-investigation.md). Note: Firefox on Linux/Windows is predicted to already work for USB+PRF — pending verification.
2. **A new CTAP spec adds "PRF on create" semantics.** Multi-year FIDO Alliance process. Then hardware revision. Then browser support. Then user adoption. Five-year horizon at best.
3. **Apple changes their stance on hmac-secret re-wrap for external keys.** Effectively zero probability — they've been explicit about the privacy rationale.
4. **A new spec mechanism that lets the authenticator declare its PRF output is "non-tracking" in some verifiable way Apple would accept.** Hypothetical, hard to design, no work in progress.
5. **A future YubiKey hardware that registers via Apple's `ASCredentialProviderExtension` API.** Possible but turns the YubiKey into a software credential provider with hardware second factor — different product, different trust model. Some users explicitly don't want that.

The honest forward-looking story is: **YubiKeys will probably remain semi-broken for Safari/iOS for the foreseeable future, and broken on Firefox/macOS until Mozilla wires the security-key adapter.** Mozilla closing their macOS-bridge gap is the most plausible near-term movement (and the patch is small once their priorities allow). Firefox on Linux and Windows is predicted to work today for USB+PRF — pending empirical confirmation. Apple won't budge. The CTAP spec moves slowly.

## 7. References

- **Architecture:** `prf-amk-wrapping.md` — protocol, AAD construction, server endpoints, full cohort matrix.
- **Empirical:** `prf-cross-device-testing.md` — captured traces, failure mode catalog, hypotheses, methodology.
- **Source-level:** `firefox-prf-source-investigation.md` — mozilla-central code paths, dispatch architecture, why Firefox/macOS is the only broken Firefox cohort.
- **WebAuthn PRF spec:** <https://www.w3.org/TR/webauthn-3/#prf-extension>
- **Yubico developer guide on PRF:** <https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html>
- **Apple WebAuthn docs (WKWebView / ASAuthorization):** <https://developer.apple.com/documentation/authenticationservices>
- **Mozilla bug tracking PRF work:** <https://bugzilla.mozilla.org/show_bug.cgi?id=1863819>
- **CTAP 2.2 spec:** <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html>

## 8. Change log for this document

| Date | Change |
|---|---|
| 2026-05-02 | Initial draft. Captures the YubiKey-specific findings from Round A and Round B testing, the discussion of why none of the issues are fixable by Yubico, and the recommended-setups guidance. Cross-references `prf-amk-wrapping.md` §11 cohort matrix and `prf-cross-device-testing.md` for empirical detail. |
| 2026-05-02 (later) | Refined §2.2 Firefox section with source-level investigation findings: the Firefox+USB-key gap is macOS-specific (Apple `ASAuthorizationController` adapter doesn't wire PRF for the security-key class), not a Firefox-wholesale missing feature. Firefox/Linux and Firefox/Windows predicted to work; pending empirical confirmation. Added cross-link to `firefox-prf-source-investigation.md`. |
| 2026-05-02 (later still) | Added Apple SDK findings: macOS 15 SDK does not expose `.prf` on the security-key class; macOS 26.4 SDK does. Empirically reconfirmed Apple's framework re-wrap behavior persists on macOS 26.4.1 (Round E in `prf-cross-device-testing.md`). Reframed the Mozilla fix landscape as Option A (small patch, partial fix — Safari-equivalent wrapped value) vs Option B (heavier `authrs_bridge` bypass, full cross-device determinism). |
| 2026-05-02 (final) | Promoted Firefox/Windows from "predicted" to "confirmed" after Round F: same YubiKey, byte-identical raw `hmac-secret` fingerprint with Chromium, full AMK transfer Chrome/Windows ↔ Firefox/Windows works. Firefox/Linux remains predicted-untested. Updated §1 capability table, §2.2 status header, and references accordingly. |
| 2026-05-02 (final final) | Promoted Firefox/Linux from "predicted" to "confirmed" after Round G: Firefox 149.0.2 on Linux produces matching fingerprint, cross-OS AMK transfer Chrome/Windows → Firefox/Linux verified. Firefox/USB-key gap is now empirically locked to macOS only. |
