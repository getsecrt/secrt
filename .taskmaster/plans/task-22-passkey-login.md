# Task 22: Fix Passkey Login in Tauri Webview

**Status:** pending | **Priority:** high | **Blocks:** authenticated features (dashboard, settings, encrypted notes, device approval)

## Problem

WebAuthn `navigator.credentials.create()` / `.get()` may not work correctly in Tauri's embedded webview (WKWebView on macOS, WebView2 on Windows). If passkeys don't work, users can't log in, which blocks all authenticated features.

## Current Auth Architecture

### Flow
1. User clicks Login -> `LoginPage.tsx` calls `/api/v1/auth/passkeys/login/start` with a stored credential ID
2. Server returns a challenge
3. Frontend calls `navigator.credentials.get()` (in `webauthn.ts`) with the challenge
4. Browser presents platform authenticator (Touch ID, Windows Hello, etc.)
5. Frontend sends assertion to `/api/v1/auth/passkeys/login/finish`
6. Server returns session token, stored in `localStorage`

Registration is similar but uses `navigator.credentials.create()` with `residentKey: 'required'`.

### Key Files

| File | Role |
|------|------|
| `web/src/lib/webauthn.ts` | `createPasskeyCredential()`, `getPasskeyCredential()`, `supportsWebAuthn()` |
| `web/src/lib/auth-context.tsx` | Auth state (Preact Context): `login()`, `logout()`, session token |
| `web/src/lib/session.ts` | localStorage wrapper for session tokens and cached profile |
| `web/src/lib/api.ts` (lines 113-199) | Auth API calls: register start/finish, login start/finish, session, logout, device approve |
| `web/src/features/auth/LoginPage.tsx` | Login UI, 3-step passkey login flow |
| `web/src/features/auth/RegisterPage.tsx` | Registration UI, generates random display name, creates AMK |
| `web/src/features/auth/DevicePage.tsx` | CLI device approval with ECDH key exchange |
| `web/src/lib/config.ts` | `isTauri()` detection, `getApiBase()` returns `https://secrt.ca` for Tauri prod |

### Tauri App Config

- **Tauri conf:** `crates/secrt-app/tauri.conf.json`
- **CSP:** `default-src 'self'; connect-src ipc: http://ipc.localhost https://secrt.ca`
- **No auth plugins** — currently only crypto commands (seal, open, derive_claim_token) in `crates/secrt-app/src/lib.rs`
- **No Tauri auth-specific code yet** — auth pages load identically to browser

### WebAuthn Parameters Used

```typescript
// Registration (webauthn.ts)
navigator.credentials.create({
  publicKey: {
    rp: { name: 'secrt', id: window.location.hostname },
    user: { id, name, displayName },
    pubKeyCredParams: [ES256, RS256],
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'preferred'
    }
  }
})

// Login (webauthn.ts)
navigator.credentials.get({
  publicKey: {
    challenge,
    // No allowCredentials — discoverable/autofill flow
    userVerification: 'preferred'
  }
})
```

## Investigation Plan

### Step 1: Test WebAuthn in WKWebView (macOS)

Build and run the Tauri app, navigate to `/register`, and try creating a passkey. Key questions:
- Does `navigator.credentials` exist in WKWebView?
- Does the platform authenticator (Touch ID) appear?
- Does the RP ID (`secrt.ca`) work from a webview loading from `tauri://localhost`?
- **RP ID mismatch is the most likely blocker** — WebAuthn ties credentials to the RP ID (domain), and Tauri's webview origin won't be `secrt.ca`

### Step 2: Test on WebView2 (Windows)

Same questions for Windows. WebView2 (Chromium-based) may have different behavior.

### Step 3: Design Fallback Strategy

If passkeys don't work (likely due to RP ID mismatch), options:

1. **System browser OAuth-style flow** — Open `https://secrt.ca/login` in the default browser, complete passkey auth there, redirect back to Tauri app via deep link (`secrt://auth-callback?token=...`) or localhost callback. Most reliable but requires deep link support (Task 27).

2. **Email/code login** — Add a new auth method: user enters email, server sends a one-time code, user enters code in app, gets session token. Simple, no WebAuthn needed, but requires server-side email sending.

3. **QR code / device approval** — Show a QR code in the Tauri app, user scans with phone browser where passkeys work, approves the desktop session. Similar to the existing CLI device approval flow.

4. **Proxy auth through Tauri command** — Use a Tauri Rust command to make the WebAuthn calls natively (via platform APIs), bypassing the webview limitation. Complex, platform-specific.

### Step 4: Implement Chosen Solution

Depends on investigation results. The system browser flow (option 1) is probably the best balance of reliability and UX.

### Step 5: Test End-to-End

- Register a new account from the Tauri app
- Log in from the Tauri app
- Verify session persists across app restarts
- Verify logout works
- Test on macOS and Windows

## Dependencies

- None blocking start of investigation
- If system browser flow chosen: Task 27 (deep links) becomes a prerequisite or co-requisite
- Task 34 (keychain storage) would benefit from this — store session tokens securely after auth works

## Notes

- Session tokens are currently stored in `localStorage`, which persists in Tauri's webview
- The `getApiBase()` function already returns `https://secrt.ca` for production Tauri builds
- CSP already allows `connect-src https://secrt.ca`
- The Tauri shell plugin can open URLs in the system browser if needed
