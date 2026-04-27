# PRF Spike

Disposable, local-only prototype for verifying WebAuthn PRF extension behavior on real
authenticators. Not built, not bundled, not deployed. Tracking: task #42, plan phase A.
Design context: `crates/secrt-server/docs/prf-amk-wrapping.md`.

## What it tests

1. PRF extension is honored at `navigator.credentials.create()` (PRF-on-create) — i.e.
   `getClientExtensionResults().prf.results.first` is a 32-byte ArrayBuffer immediately.
2. Fallback: PRF only available at `navigator.credentials.get()` (PRF-on-get-only) on
   older surfaces.
3. Synced passkeys (Apple Passwords, Google Password Manager) produce **identical PRF
   output** for the same `(credential, eval salt)` across devices. Verified by eyeballing
   the SHA-256[0..8] fingerprint shown in the UI on both devices.
4. AES-GCM wrap/unwrap roundtrip with the HKDF-derived wrap key on a single device.

The page never displays the raw PRF output. Only `SHA-256(prf_out)[0..8]` as a fingerprint.

## Running

WebAuthn requires a secure context. `localhost` qualifies; `file://` does not.

```sh
cd web && pnpm dev
# open http://localhost:5173/prototypes/prf-spike/
```

For testing on a phone, expose the dev server on the LAN. Two options:

- `pnpm dev --host` (exposes on LAN), then accept the Chrome/Safari "insecure" prompt
  on the phone — **WebAuthn will refuse** because LAN IPs aren't a secure context. Use a
  tunnel instead.
- `cloudflared tunnel --url http://localhost:5173` or `ngrok http 5173` — this gives an
  https URL the phone can hit. WebAuthn works because the origin is https. The RP ID
  will be the tunnel hostname; that's fine for the spike.

For iCloud Keychain cross-device determinism: register on the macOS Safari side first,
then on iPhone Safari (same iCloud account) hit the same URL and click **Login**. The
PRF fingerprint shown should be identical to the macOS one. If it differs, synced
passkey PRF determinism is broken — stop and re-plan before continuing.

## Test matrix

Record results in `crates/secrt-server/docs/prf-amk-wrapping.md` §11 "2026-04 spike findings."
Note browser version + OS + authenticator type.

| Surface                                       | Register | PRF-on-create | Login PRF | Cross-device fp match |
| --------------------------------------------- | -------- | ------------- | --------- | --------------------- |
| Chrome 147+ on Win 11 + Windows Hello         |          |               |           | (n/a, not synced)     |
| Chrome on macOS + Apple Passwords (iCloud)    | ✓        | ✓             |           | ↓                     |
| Safari 18+ on macOS + iCloud Keychain         | ✓        | ✓             |           | ↓                     |
| Safari 18+ on iOS + iCloud Keychain           | ✓        | ✓             | ✓         | not yet               |
| Chrome on macOS + Google Password Manager     | ✓        | ✗             | ✗         | enabled=false         |
| Chrome on Android + Google Password Manager   | ✓        | ✓             |           | not yet               |
| Firefox 148+ + Windows Hello                  |          |               |           | (n/a)                 |
| Safari 18+ + external YubiKey                 |          |               |           | (expected: fail)      |
| **Bitwarden** (any browser, as picker)        | ✓        | ✗             | ✗         | n/a, prf undefined    |
| **1Password** (Safari on macOS, as picker)    | ✓        | ✗             | ✗         | n/a, prf undefined    |

### Bitwarden caveat

Bitwarden's authenticator returned no PRF extension data at all (`prf: undefined`)
when used as the credential picker on macOS Chrome. Bitwarden has shipped PRF support
for their own E2EE features, but the browser-WebAuthn passthrough depends on which path
the picker takes (browser extension intercept vs. OS credential provider). As of the
2026-04 spike, this path doesn't forward the PRF extension to the relying party.

**User impact:** users who store their secrt passkey in Bitwarden will not get the
single-tap new-device unlock. They fall through to the existing sync-link flow,
exactly as users on Firefox ≤ 147 or external roaming authenticators on iOS Safari do.
Document this in the eventual UX (Subtask 6) so users can make an informed choice.

## Gate

Phase A blocks Phase B until at least Chrome+Hello, Safari+iCloud (both desktop and iOS),
and Chrome+Android+GPM all pass register + login + cross-device fingerprint match.
