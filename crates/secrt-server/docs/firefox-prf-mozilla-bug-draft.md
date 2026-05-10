# Mozilla Bug Draft — WebAuthn PRF missing for USB security keys on Firefox/macOS

> **Status:** Draft, revised 2026-05-03 after checking Searchfox, Bugzilla, Xcode 26.4.1 SDK headers, and empirically validating Daniel Veditz's pref hypothesis from bug 1985777 comment 4.
>
> **Filing strategy:** file as new bug in `Core :: DOM: Web Authentication`. (Commenting on closed bug 1985777 requires permissions the reporter doesn't have.) **See Also:** 1985777, 1863819, 1935280. Tag :jschanck and :dveditz in the body since they were on 1985777 — Veditz's standing question from comment 4 is answered empirically below in the "Workaround validates dispatch hypothesis" section.
>
> **Suggested metadata:**
> - Component: Core :: DOM: Web Authentication
> - Type: defect
> - OS: macOS
> - Hardware: All
> - Severity: S3
> - See Also: 1985777, 1863819, 1935280

## Title

WebAuthn PRF is not returned for USB security keys on Firefox/macOS

## Summary

When a relying party requests the WebAuthn PRF extension on Firefox/macOS with a roaming USB CTAP2 security key, the WebAuthn assertion succeeds but `PublicKeyCredential.getClientExtensionResults()` does not contain a `prf` result.

The same physical YubiKey and credential return PRF output on Firefox/Windows, Firefox/Linux, and Chromium browsers. Firefox/macOS also returns PRF for platform and hybrid passkeys. The failure appears specific to Firefox's macOS security-key path.

Current Searchfox source points to `dom/webauthn/MacOSWebAuthnService.mm`: PRF is wired for `ASAuthorizationPlatformPublicKeyCredential...` request/result objects, but not for `ASAuthorizationSecurityKeyPublicKeyCredential...` request/result objects.

## Steps to Reproduce

1. Use Firefox on macOS with a CTAP2 security key that supports `hmac-secret` / WebAuthn PRF.
   - Observed: Firefox 150.1, macOS 26.4.1, YubiKey 5C NFC over USB-C.
   - Related prior report: bug 1985777 used Firefox 142 on macOS 15.5-15.6.1 with a YubiKey.
2. Visit a relying party that requests `extensions.prf` during `navigator.credentials.get()`.
   - `https://secrt.is` is a public reproducer. To enable client diagnostics there, run `localStorage.setItem('secrt:debug', '1')` in DevTools and reload.
3. Authenticate with the USB security key.
4. Inspect `credential.getClientExtensionResults()`.

## Actual Results

The assertion succeeds and the user is signed in, but the PRF extension result is absent.

Example diagnostic output from `secrt.is`:

```text
[secrt:webauthn-get] { credIdPrefix: "xAvG1eEG",
  authenticatorAttachment: "cross-platform",
  prfRequested: true,
  prfExtPresent: false,
  hasPrfOutput: false }
```

## Expected Results

`getClientExtensionResults()` should include `prf.results.first` when PRF is requested and the selected authenticator supports CTAP2 `hmac-secret`.

This is the observed behavior for the same YubiKey on Firefox/Windows, Firefox/Linux, and Chromium.

## Affected and Unaffected Configurations

| Configuration                                        | Result | Evidence                                             |
|:-----------------------------------------------------|-------:|:-----------------------------------------------------|
| Firefox 150.1 / macOS 26.4.1 / USB YubiKey           | Broken | `prfExtPresent: false`, `hasPrfOutput: false`        |
| Firefox 150.1 / macOS / hybrid passkey via iPhone QR |  Works | PRF returned through platform/hybrid path            |
| Firefox 150.1 / macOS / synced platform passkey      |  Works | PRF returned through platform path                   |
| Firefox 150.1 / Windows / same USB YubiKey           |  Works | PRF fingerprint matches Chromium for same credential |
| Firefox 149.0.2 / Linux / same USB YubiKey           |  Works | PRF fingerprint matches Firefox/Windows and Chromium |
| Chromium / macOS or Windows / same USB YubiKey       |  Works | PRF output returned                                  |

## Workaround validates the dispatch hypothesis (answers needinfo from bug 1985777 comment 4)

In bug 1985777 comment 4, :dveditz asked the original reporter whether `security.webauthn.enable_macos_passkeys` changes behavior. The reporter went inactive and the bug was auto-closed `RESOLVED INCOMPLETE`. **Empirical answer, captured 2026-05-03:**

| Configuration                                                                | `prfExtPresent` | `prfOutputFingerprint` | Outcome  |
|:-----------------------------------------------------------------------------|:----------------|:-----------------------|:---------|
| Firefox 150.1 / macOS 26.4.1, default pref                                   | `false`         | `null`                 | Bug      |
| Firefox 150.1 / macOS 26.4.1, `security.webauthn.enable_macos_passkeys=false`, **after restart** | `true`          | `50a29d48c9bb78e2`     | ✓ Works  |

Same physical YubiKey, same credential `d2Bv_6Qz`, same RP. The fingerprint `50a29d48c9bb78e2` is **byte-identical** with what Chrome/Windows, Firefox/Windows, Firefox/Linux, and Chrome/macOS produce for the same credential. AMK derived from this PRF unwraps cleanly across all five surfaces.

A live toggle of the pref (without Firefox restart) had no effect — consistent with `WebAuthnService::WebAuthnService()` reading `NewMacOSWebAuthnServiceIfAvailable()` once at service construction.

**Two implications:**

1. **The bug is in Firefox's macOS dispatch / `MacOSWebAuthnService.mm`, not in Firefox's underlying PRF support.** When `MacOSWebAuthnService` is taken out of the path (via the pref), `mAuthrsService` (the Rust `authrs_bridge` + vendored `authenticator-rs` crate) handles the same USB security key correctly and returns raw `hmac-secret` consistent with every other Firefox+OS and Chromium+OS combination.
2. **Apple's framework is wrapping `hmac-secret` regardless** of the new macOS 26.4 SDK property. (Empirically: Safari on macOS 26.4.1 produces a *different* PRF value than Chrome on the same Mac with the same key — `OperationError` on cross-browser unwrap. Round E3 of [`prf-cross-device-testing.md`](https://github.com/getsecrt/secrt/blob/main/crates/secrt-server/docs/prf-cross-device-testing.md).) So merely wiring `.prf` into the `ASAuthorizationSecurityKey…` request/result classes is a partial fix that yields Safari-equivalent wrapped PRF — useful but not interoperable. The full fix is to route USB+PRF through `authrs_bridge`, which is what the pref toggle does globally.

## Source Analysis

Firefox keeps both a platform service and `authrs_bridge` available. On macOS 13.3+, `WebAuthnService` uses `MacOSWebAuthnService` when available:

- [`WebAuthnService.h`](https://searchfox.org/firefox-main/source/dom/webauthn/WebAuthnService.h) constructs `mAuthrsService`, then uses `NewMacOSWebAuthnServiceIfAvailable()` on macOS 13.3+.
- [`WebAuthnService.cpp`](https://searchfox.org/firefox-main/source/dom/webauthn/WebAuthnService.cpp) has a macOS fallback to `AuthrsService()` for AppID on macOS < 14.5 when the allow-list is USB/security-key-only. There is no analogous fallback for PRF.

In the macOS service:

- [`MacOSWebAuthnService.mm`](https://searchfox.org/firefox-main/source/dom/webauthn/MacOSWebAuthnService.mm) extracts PRF results from `ASAuthorizationPlatformPublicKeyCredentialAssertion.prf`, but the `ASAuthorizationSecurityKeyPublicKeyCredentialAssertion` branch only reads AppID and sets `authenticatorAttachment = "cross-platform"`.
- The same file sets `platformAssertionRequest.prf` when PRF is requested, but `crossPlatformAssertionRequest` is built separately and does not receive a PRF input.
- Registration has the same shape: platform credential registration handles PRF, while the security-key registration path does not.

The Rust path already has PRF plumbing:

- [`authrs_bridge/src/lib.rs`](https://searchfox.org/firefox-main/source/dom/webauthn/authrs_bridge/src/lib.rs) reads `GetPrf`, `GetPrfEvalFirst`, `GetPrfEvalSecond`, and per-credential PRF inputs into `AuthenticationExtensionsClientInputs.prf`.
- Firefox/Linux empirical testing is consistent with this path working for USB security keys.

Windows also has explicit PRF wiring:

- [`WinWebAuthnService.cpp`](https://searchfox.org/firefox-main/source/dom/webauthn/WinWebAuthnService.cpp) appends `WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET` when PRF or `hmacCreateSecret` is requested.

## SDK Availability

Local header check with Xcode 26.4.1 (`MacOSX26.4.sdk`) confirms Apple now exposes PRF properties on the security-key classes:

| Class                                                                  | Property availability                   |
|:-----------------------------------------------------------------------|:----------------------------------------|
| `ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest.prf`    | `API_AVAILABLE(macos(26.4), ios(26.4))` |
| `ASAuthorizationSecurityKeyPublicKeyCredentialAssertion.prf`           | `API_AVAILABLE(macos(26.4), ios(26.4))` |
| `ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest.prf` | `API_AVAILABLE(macos(26.4), ios(26.4))` |
| `ASAuthorizationSecurityKeyPublicKeyCredentialRegistration.prf`        | `API_AVAILABLE(macos(26.4), ios(26.4))` |

The platform credential PRF properties remain available from macOS 15.0. This means the direct `MacOSWebAuthnService.mm` wiring fix is available for macOS 26.4+ users, while older macOS versions would need a different path such as `authrs_bridge`.

## Why This Matters

Relying parties use WebAuthn PRF as deterministic input to local key derivation. If the assertion succeeds but PRF output is missing, users can authenticate but cannot decrypt data protected by a PRF-derived key.

For `secrt.is`, the user-visible symptom is: sign-in succeeds, but the account encryption key cannot transfer to the Firefox/macOS session. The same credential works on Firefox/Windows, Firefox/Linux, and Chromium.

## Suggested Fix Direction

There are two related issues for maintainers to consider.

First, `MacOSWebAuthnService.mm` appears to have an internal wiring gap: the platform request/result objects handle PRF, while the security-key request/result objects do not. Since Xcode 26.4.1 exposes PRF on `ASAuthorizationSecurityKeyPublicKeyCredential...`, wiring those request and response properties should make Firefox/macOS return a PRF result for USB security keys on macOS 26.4+.

Second, the most interoperable output is likely the raw CTAP2 `hmac-secret` value returned by Firefox/Windows, Firefox/Linux, and Chromium. If Firefox wants that behavior on macOS, the relevant security-key PRF ceremonies need to route through `authrs_bridge`, similar in spirit to the existing macOS AppID fallback. That path already supports CTAP2 `hmac-secret` and matches Firefox's Linux behavior.

A dispatch fallback is straightforward only when the request is constrained to security keys, for example:

- `aArgs->GetPrf(&prfRequested)` succeeds and `prfRequested == true`
- the allow-list is non-empty
- allow-list transports do not include `internal` or `hybrid`
- then set `guard->ref().service = AuthrsService()`

The `secrt.is` reproducer also covers a discoverable assertion with no allow-list, where the user chooses a resident YubiKey credential from the picker. That case needs a more deliberate design because `MacOSWebAuthnService.mm` currently sends platform and security-key requests together. Routing all PRF discoverable assertions to `authrs_bridge` could regress platform or hybrid passkeys.

Registration has a similar constraint: `makeCredential()` has no positive allow-list. A conservative route-to-authrs condition might use `authenticatorSelection.authenticatorAttachment == "cross-platform"` when PRF is requested, but maintainers will have better context on the UI trade-off.

Whichever path is chosen, the interoperability test should compare PRF bytes for the same credential and salt against Firefox/Windows, Firefox/Linux, or Chromium. Empirical Safari-vs-Chromium testing shows Apple-mediated external-key PRF output may not be byte-identical with the raw CTAP2 value.

## Test Suggestions

- Reproduce with a real CTAP2 security key on Firefox/macOS and confirm `getClientExtensionResults().prf` is present after the fix.
- Compare the PRF output fingerprint for the same credential and salt against Firefox/Windows, Firefox/Linux, or Chromium.
- Verify platform passkeys and hybrid passkeys still return PRF on macOS.
- Verify the existing AppID fallback behavior is unchanged.

## References

- [Bug 1985777](https://bugzilla.mozilla.org/show_bug.cgi?id=1985777) — prior matching report, closed `RESOLVED INCOMPLETE`.
- [Bug 1863819](https://bugzilla.mozilla.org/show_bug.cgi?id=1863819) — WebAuthn PRF meta-bug, `RESOLVED FIXED`.
- [Bug 1935280](https://bugzilla.mozilla.org/show_bug.cgi?id=1935280) — macOS platform PRF support.
- [Bug 1909962](https://bugzilla.mozilla.org/show_bug.cgi?id=1909962) — `authenticator-rs` upgrade.
- [W3C WebAuthn PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension).
- [Yubico Developer Guide to PRF](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html).
- Local supporting notes: [`firefox-prf-source-investigation.md`](firefox-prf-source-investigation.md), [`prf-cross-device-testing.md`](prf-cross-device-testing.md).
