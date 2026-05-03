# Firefox WebAuthn PRF Source Investigation

**Date:** 2026-05-02
**Empirical baseline:** Firefox 150.1 on macOS, USB YubiKey 5C NFC over USB-C. Assertion succeeds, `getClientExtensionResults()` contains no `prf` member. Same browser session sees `prf` flow correctly through caBLE/hybrid (Mac scans QR with iPhone iCloud Keychain) and through synced platform passkeys.

**Hypothesis under test:** Firefox's PRF support is asymmetric — PRF travels *through* Firefox but does not *originate* from Firefox-driven roaming USB CTAP2 hardware on macOS. Either (a) the request never includes `hmac-secret` for the USB path, or (b) the response is dropped before reaching `getClientExtensionResults()`.

**Verdict (preview):** Confirmed, via mechanism (a). On macOS, requests against roaming security keys go through Apple's `ASAuthorizationSecurityKey…` API, and Firefox never attaches the PRF input to the security-key request object. The response handler also never reads `prf` from a security-key assertion. The Rust authrs path *does* support PRF, but on macOS it is not the default service for USB authenticators.

---

## Architecture overview: how Firefox dispatches WebAuthn

Firefox 148+ keeps two `nsIWebAuthnService` implementations live and picks one per ceremony.

[`WebAuthnService.h:30-58`](https://searchfox.org/mozilla-central/source/dom/webauthn/WebAuthnService.h) constructs both at startup:

```cpp
WebAuthnService() {
  (void)authrs_service_constructor(getter_AddRefs(mAuthrsService));
#if defined(XP_WIN)
  if (WinWebAuthnService::AreWebAuthNApisAvailable()) {
    mPlatformService = new WinWebAuthnService();
  } else { mPlatformService = mAuthrsService; }
#elif defined(XP_MACOSX)
  if (__builtin_available(macos 13.3, *)) {
    mPlatformService = NewMacOSWebAuthnServiceIfAvailable();
  }
  if (!mPlatformService) { mPlatformService = mAuthrsService; }
#else
  mPlatformService = mAuthrsService;
#endif
}
```

`DefaultService()` returns `mPlatformService` unless the `softtoken` pref overrides ([`WebAuthnService.h:75-82`](https://searchfox.org/mozilla-central/source/dom/webauthn/WebAuthnService.h)). On modern macOS, every ceremony — including those targeting a USB YubiKey — is dispatched to `MacOSWebAuthnService`, which fronts Apple's `ASAuthorizationController` API. The Rust `authrs_bridge` is reachable only via a single narrow fallback in [`WebAuthnService.cpp:165-198`](https://searchfox.org/mozilla-central/source/dom/webauthn/WebAuthnService.cpp): macOS < 14.5, AppID extension present, allow-list non-empty, and no internal/hybrid transports listed. None of that triggers for a normal PRF site like `secrt`.

So on macOS the three transports map as follows:
- **Synced platform passkey (iCloud Keychain on the Mac):** `MacOSWebAuthnService` → `ASAuthorizationPlatformPublicKeyCredential…`.
- **caBLE / hybrid (Mac driving an iPhone via QR):** `MacOSWebAuthnService` → same platform request object, with `shouldShowHybridTransport = YES`.
- **Roaming USB security key (e.g. YubiKey):** `MacOSWebAuthnService` → `ASAuthorizationSecurityKeyPublicKeyCredential…`.

The first two share a code path; the third is a separate request/response object family.

## PRF code paths per transport

### Platform + hybrid (works)

Request side — [`MacOSWebAuthnService.mm:1276-1318`](https://searchfox.org/mozilla-central/source/dom/webauthn/MacOSWebAuthnService.mm):

```objc
if (__builtin_available(macos 15.0, *)) {
  bool requestedPrf;
  (void)aArgs->GetPrf(&requestedPrf);
  if (requestedPrf) {
    // ... build saltInput1, saltInput2, perCredentialInputs ...
    platformAssertionRequest.prf =
        [[ASAuthorizationPublicKeyCredentialPRFAssertionInput alloc]
                 initWithInputValues:prfInputs
            perCredentialInputValues:prfPerCredentialInputs];
  }
}
```

Both the platform request and the hybrid (QR) flow ride on `platformAssertionRequest`, so PRF gets attached for both. The matching response branch — [`MacOSWebAuthnService.mm:439-475`](https://searchfox.org/mozilla-central/source/dom/webauthn/MacOSWebAuthnService.mm) — extracts `platformCredential.prf.first` / `.second` and forwards to `FinishGetAssertion`.

### USB / roaming security key on macOS (broken)

Request side — [`MacOSWebAuthnService.mm:1207-1221`](https://searchfox.org/mozilla-central/source/dom/webauthn/MacOSWebAuthnService.mm) builds a `crossPlatformAssertionRequest`:

```objc
ASAuthorizationSecurityKeyPublicKeyCredentialProvider* crossPlatformProvider =
    [[ASAuthorizationSecurityKeyPublicKeyCredentialProvider alloc]
        initWithRelyingPartyIdentifier:rpIdNS];
ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest*
    crossPlatformAssertionRequest = [crossPlatformProvider
        createCredentialAssertionRequestWithChallenge:challengeNS];
crossPlatformAssertionRequest.allowedCredentials = crossPlatformAllowedCredentials;
if (userVerificationPreference.isSome()) {
  crossPlatformAssertionRequest.userVerificationPreference = *userVerificationPreference;
}
// AppID is set on this object below; PRF is NOT.
```

The PRF block at line 1276 only writes to `platformAssertionRequest`. There is no analogous `crossPlatformAssertionRequest.prf = …`. The same gap exists on the registration side: [`MacOSWebAuthnService.mm:858-893`](https://searchfox.org/mozilla-central/source/dom/webauthn/MacOSWebAuthnService.mm) sets `platformRegistrationRequest.prf` only.

Response side — [`MacOSWebAuthnService.mm:476-488`](https://searchfox.org/mozilla-central/source/dom/webauthn/MacOSWebAuthnService.mm):

```objc
} else if ([credential isKindOfClass:
               [ASAuthorizationSecurityKeyPublicKeyCredentialAssertion class]]) {
  ASAuthorizationSecurityKeyPublicKeyCredentialAssertion* securityKeyCredential =
      (ASAuthorizationSecurityKeyPublicKeyCredentialAssertion*)credential;
  if (__builtin_available(macos 14.5, *)) {
    usedAppId.emplace(securityKeyCredential.appID);
  }
  authenticatorAttachment.emplace(u"cross-platform"_ns);
}
```

Only `appID` and `authenticatorAttachment` are read. `prfFirst`/`prfSecond` remain `Nothing()`, then propagate as such through `FinishGetAssertion` ([`MacOSWebAuthnService.mm:489-492`](https://searchfox.org/mozilla-central/source/dom/webauthn/MacOSWebAuthnService.mm)) into `WebAuthnSignResult`.

Both halves of hypothesis (a) and (b) are present on this path: (a) request never asks, and (b) response handler doesn't read even if Apple were to populate it.

### Rust authrs / authenticator-rs (functional, but not used here)

For the record, the Rust path is fine. [`authrs_bridge/src/lib.rs:1083-1176`](https://searchfox.org/mozilla-central/source/dom/webauthn/authrs_bridge/src/lib.rs) reads `Prf`, `PrfEvalFirst`, `PrfEvalSecond`, `PrfEvalByCredential*` off the args and stuffs them into `SignArgs.extensions.prf`. The vendored `authenticator-rs` crate then converts that to the CTAP2 `hmac-secret` extension at [`third_party/rust/authenticator/src/ctap2/commands/get_assertion.rs:189-272`](https://searchfox.org/mozilla-central/source/third_party/rust/authenticator/src/ctap2/commands/get_assertion.rs), encrypts the salt inputs against the authenticator's shared secret, and decrypts responses (lines 380-425). It has supported PRF since the v0.4.0 upgrade tracked in [bug 1909962](https://bugzilla.mozilla.org/show_bug.cgi?id=1909962).

This is consistent with the empirical observation that PRF works against USB YubiKeys on Firefox/Linux and Firefox/Windows: both reach a stack that knows how to send `hmac-secret`. (Windows uses Microsoft's webauthn.dll wrapper — see [`WinWebAuthnService.cpp:511-544`](https://searchfox.org/mozilla-central/source/dom/webauthn/WinWebAuthnService.cpp), which sets `WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET` directly.)

## Verdict

The asymmetric-support hypothesis is **confirmed for macOS**, with mechanism (a) plus (b) on the same code path. The local CTAP2 stack itself is not the gap — `authenticator-rs` does PRF — but on macOS it is bypassed in favor of `ASAuthorizationController`, and the macOS bridge wires PRF only into the platform/hybrid request and response objects, never into `ASAuthorizationSecurityKey…` objects.

Strictly, this means PRF on Firefox/macOS USB is broken because of an OS-binding gap in `MacOSWebAuthnService.mm`, not because anything in the WebAuthn DOM layer or the IPC layer drops it. `WebAuthnArgs.cpp` plumbs the PRF inputs end-to-end ([lines 337-396](https://searchfox.org/mozilla-central/source/dom/webauthn/WebAuthnArgs.cpp)), and `WebAuthnResult.cpp` carries the outputs back. The bug is purely in the macOS adapter.

## Implications

There are two candidate fixes. Both are Mozilla-side; the choice depends on whether you accept Safari-equivalent behavior or want full cross-device determinism.

### Option A: wire `.prf` on the security-key class (small patch, partial fix)

1. In the assertion request builder ([`MacOSWebAuthnService.mm:1276`](https://searchfox.org/mozilla-central/source/dom/webauthn/MacOSWebAuthnService.mm)), set `crossPlatformAssertionRequest.prf` alongside `platformAssertionRequest.prf` — gated `__builtin_available(macos 26.4, *)`.
2. In the registration request builder ([line 889](https://searchfox.org/mozilla-central/source/dom/webauthn/MacOSWebAuthnService.mm)), do the same for `crossPlatformRegistrationRequest.prf`.
3. In the response handler ([line 476](https://searchfox.org/mozilla-central/source/dom/webauthn/MacOSWebAuthnService.mm)), read `securityKeyCredential.prf.first/.second` (and `.isSupported` on the registration branch) inside the `ASAuthorizationSecurityKey…Assertion` `isKindOfClass:` arm.

Roughly 20–40 lines of Objective-C++. No protocol or IPC changes. **Effective only on macOS 26.4+ (Apple's year-renamed release; see SDK appendix below for verification).**

**Limitation:** this routes Firefox through Apple's `ASAuthorizationController`, which empirically applies the `hmac-secret` re-wrap behavior described in `yubikeys.md` §2.1. Firefox-on-macOS post-patch would receive `Encrypt(framework_key, raw_hmac_secret)` — the same wrapped value Safari already gets. Firefox-on-Mac would gain parity with Safari-on-Mac (incremental UX win), but **would not be byte-identical with Chromium-on-Mac, Firefox/Linux, or Firefox/Windows** — all of which read raw `hmac-secret`. See Round E in [`prf-cross-device-testing.md`](prf-cross-device-testing.md) for the empirical capture.

### Option B: route USB-when-PRF-requested through `authrs_bridge` (heavier patch, full fix)

Extend the dispatch logic in [`WebAuthnService.cpp:165-198`](https://searchfox.org/mozilla-central/source/dom/webauthn/WebAuthnService.cpp) so that when PRF is requested and no platform/hybrid transport is in the allow-list, ceremonies route to `mAuthrsService` instead of `mPlatformService`. The Rust path produces raw `hmac-secret`, byte-identical with Chromium and Firefox/Linux/Windows.

Estimated cost: 100–200 lines, plus design discussion at Mozilla — they may resist losing `ASAuthorizationController`'s native macOS UI affordances (e.g., the system-rendered passkey picker) for the security-key flow when PRF is involved. Effective on **all macOS versions, not just 26.4+**.

This is the only option that delivers cross-device determinism for Firefox/macOS + USB security keys.

### Recommendation

Both. Option A is a useful stopgap because it brings Firefox/macOS-26.4+ to Safari parity (zero PRF → wrapped PRF). Option B is the real fix. Filing them as separate Mozilla bugs lets reviewers evaluate them independently.

## SDK appendix: where Apple exposes `.prf` (verified 2026-05-02 against local Xcode SDKs)

| SDK | Class | Property | Availability |
|---|---|---|---|
| MacOSX15.sdk | `ASAuthorizationPlatformPublicKeyCredentialAssertionRequest` | `.prf` | `macos(15.0)` ✓ |
| MacOSX15.sdk | `ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest` | `.prf` | **absent** ✗ |
| MacOSX15.sdk | `ASAuthorizationSecurityKeyPublicKeyCredentialAssertion` | `.prf` | **absent** ✗ |
| MacOSX15.sdk | `…SecurityKey…RegistrationRequest` / `…Registration` | `.prf` | **absent** ✗ |
| MacOSX26.sdk | `ASAuthorizationPlatformPublicKeyCredentialAssertionRequest` | `.prf` | `macos(15.0)` ✓ |
| MacOSX26.sdk | `ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest` | `.prf` | `macos(26.4), ios(26.4)` ✓ (new) |
| MacOSX26.sdk | `ASAuthorizationSecurityKeyPublicKeyCredentialAssertion` | `.prf` | `macos(26.4), ios(26.4)` ✓ (new) |
| MacOSX26.sdk | `…SecurityKey…RegistrationRequest` / `…Registration` | `.prf` | `macos(26.4), ios(26.4)` ✓ (new) |

Apple shipped `.prf` on the security-key class in the macOS 26.4 / iOS 26.4 SDK. Header path: `…/MacOSX26.sdk/System/Library/Frameworks/AuthenticationServices.framework/Headers/ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest.h` (and the assertion / registration / registration-request siblings). All four use the same `ASAuthorizationPublicKeyCredentialPRFAssertionInput` / `…Output` types (which themselves are `macos(15.0)`).

The headers do not document whether the surfaced PRF value is raw or framework-wrapped. Round E in `prf-cross-device-testing.md` resolves this empirically: Apple still re-wraps. The macOS 26.4 API exposes the same wrapped value Safari has been receiving — it's a public API for what was previously an internal framework path.

## Open questions and ways to close them

- **NFC test:** if NFC against the same YubiKey on Firefox/macOS also lacks PRF in results, that confirms the path is via `ASAuthorizationSecurityKey…` (which lists USB/NFC/BT as transports — see [`MacOSWebAuthnService.mm:84-96`](https://searchfox.org/mozilla-central/source/dom/webauthn/MacOSWebAuthnService.mm)). If NFC happens to work, we'd need to revisit assumptions.
- **Firefox/Windows + USB YubiKey:** ✓ **confirmed 2026-05-02 (Round F).** Same credential produces `prfOutputFingerprint: 8f5316e83dcd8470` on Firefox/Windows, byte-identical with Chrome/Mac (Round E3) and Chrome/Windows. AMK transfer Chrome/Windows ↔ Firefox/Windows works cleanly.
- **Firefox/Linux + USB YubiKey:** ✓ **confirmed 2026-05-02 (Round G).** Firefox 149.0.2 on Linux produces `prfOutputFingerprint: 50a29d48c9bb78e2` for credential `d2Bv_6Qz`, byte-identical with Chrome/Windows registration and Firefox/Windows sign-in. Cross-OS AMK transfer Chrome/Windows → Firefox/Linux works cleanly. Confirms the `authrs_bridge` path produces raw `hmac-secret` as predicted from source.

**The Firefox/USB-key gap is now empirically locked to macOS only.** Three browser+OS combinations on the raw cohort all produce byte-identical PRF output for the same credential; the Firefox/macOS adapter is the lone outlier.
- **softtoken pref:** set `security.webauth.webauthn_enable_softtoken = true` on Firefox/macOS and retry — this routes everything through `mAuthrsService`, which should handle PRF for the YubiKey via CTAP2 directly. Empirically validates the authrs path independent of the macOS bridge, and is the manual equivalent of Option B above for users who can flip the pref.
- **Nightly check:** rebuild with Option A or B applied and try the YubiKey again. Option A would yield a PRF fingerprint matching Safari's wrapped value; Option B would match Chrome's `8f5316e83dcd8470`. The fingerprint match tells you which path is active.

## Bugzilla references

The PRF meta-bug [1863819](https://bugzilla.mozilla.org/show_bug.cgi?id=1863819) is **RESOLVED FIXED** with these dependencies, all closed:

- [1935277](https://bugzilla.mozilla.org/show_bug.cgi?id=1935277) — Baseline support for WebAuthn PRF extension
- [1935278](https://bugzilla.mozilla.org/show_bug.cgi?id=1935278) — Windows support
- [1935280](https://bugzilla.mozilla.org/show_bug.cgi?id=1935280) — macOS support (Firefox 139, requires macOS 15.0+)
- [1958716](https://bugzilla.mozilla.org/show_bug.cgi?id=1958716) — Android support
- [1909962](https://bugzilla.mozilla.org/show_bug.cgi?id=1909962) — authenticator-rs upgrade to v0.4.0
- [1960051](https://bugzilla.mozilla.org/show_bug.cgi?id=1960051), [1960059](https://bugzilla.mozilla.org/show_bug.cgi?id=1960059) — toJSON/`enabled` follow-ups

No subordinate bug specifically scoped to "USB CTAP2 PRF on macOS" appears in this dependency chain, which is consistent with the gap being unintentional. Bugzilla's quicksearch is behind a JS challenge that blocks WebFetch, so a manual search at [bugzilla.mozilla.org/buglist.cgi?quicksearch=hmac-secret](https://bugzilla.mozilla.org/buglist.cgi?quicksearch=hmac-secret) would be needed to rule out a separate filed bug.
