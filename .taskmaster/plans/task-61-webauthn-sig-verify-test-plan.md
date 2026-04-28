# Manual test checklist — v0.17.0 WebAuthn signature verification

Companion to taskmaster task #61. Run against **both** `https://secrt.is`
and `https://secrt.ca` from at least one synced-passkey browser
(iCloud Keychain, Google PM, or 1Password) and ideally one non-PRF
surface (Bitwarden, Firefox).

The fixture set in `spec/v1/webauthn.vectors.json` covers structural
correctness; this checklist covers the things that only show up when a
real browser, real authenticator, and real network are in play.

## 1. First-time registration (happy path)

- [ ] Open the host → "Sign Up"
- [ ] Enter a display name → biometric / PIN prompt
- [ ] Land logged in, header shows display name
- [ ] DevTools network: `POST /api/v1/auth/passkeys/register/finish` →
      **200**. Body has `authenticator_data`, `client_data_json`. No
      `public_key` field.
- [ ] Server logs: no `webauthn verification failed` warnings.

## 2. Log out + log back in

- [ ] Log out
- [ ] "Sign in with Passkey" → completes
- [ ] DevTools network: `/login/finish` → **200**, body has
      `signature`.
- [ ] Server logs still clean.

## 3. Tamper resistance (negative path)

In DevTools, intercept `/login/finish` and flip a byte in `signature`.

- [ ] Server returns **401 unauthorized** with no body detail.
- [ ] Server logs show one `webauthn verification failed` line with
      `error="InvalidSignature"`.
- [ ] No session token issued.

## 4. Sign-count monotonicity

- [ ] Register on Device A.
- [ ] Log in twice on Device A in quick succession — both succeed.
- [ ] Synced-passkey provider: register on Device A, log in on Device B
      (same provider). Apple authenticators emit `sign_count = 0` on
      every assertion; that's allowed only when the stored value is
      also 0. Subsequent logins should keep working.
- [ ] Flag any unexpected 401s after a normal-looking ceremony.

## 5. Add a second passkey (Settings)

- [ ] While logged in, Settings → "Add another passkey".
- [ ] Complete the ceremony with a different authenticator if available
      (e.g. Bitwarden, security key).
- [ ] List shows both passkeys.
- [ ] Log out, sign in with the new passkey → succeeds.

## 6. Encrypted notes (PRF path)

PRF-capable browsers: Chrome+Google PM, Safari+iCloud Keychain,
Firefox 148+.

- [ ] Register, see notes editor work.
- [ ] Set a note, log out, log in on a different device of the same
      provider (e.g. iPhone Safari for an iCloud-synced credential):
      note is visible without sync-link.
- [ ] DevTools network: `prf_wrapper` is inlined on `/login/finish`.

## 7. Cross-host: secrt.ca

Repeat steps 1, 2, 3 against `https://secrt.ca`. Note that `secrt.ca`
and `secrt.is` are separate accounts — passkeys don't carry across
hosts.

## 8. Wildcard subdomain (expected to fail today)

- [ ] Browse `https://my.secrt.is` (or any subdomain). Try to log in.
- [ ] **Expected failure:** `401` because the verifier checks
      `clientDataJSON.origin == "https://secrt.is"`. Subdomain logins
      won't work until task #61.10 lands. If subdomain logins aren't
      a target today, ignore.

## 9. Confirmable from terminal

```sh
curl -sI https://secrt.is/api/v1/info | grep x-secrt-server-version
curl -sI https://secrt.ca/api/v1/info | grep x-secrt-server-version
# Both should report 0.17.0 (or current).
```

## 10. Rollback path (only if something goes wrong)

The 0.17.0 schema migrations are backward-compatible (no destructive
DDL); the empty database is fine for either version. To roll back:

- Either: `ssh <host> "sudo /usr/local/bin/secrt-server-deploy v0.16.9"`
  (confirm the deploy script supports a version arg with `--help`);
- Or: `git checkout server/v0.16.9 && cargo build --release -p
  secrt-server`, copy the binary up, restart `secrt.service`.

## Known follow-ups (taskmaster #61 subtasks)

- **#61.9 single-prompt login UX.** iCloud Passwords prompts for the
  account password on every `navigator.credentials.get()` call, so the
  current two-call login flow is annoying. Fix is the
  discoverable-credential flow (drop `credential_id` from
  `/login/start`, single `navigator.credentials.get()`).
- **#61.10 wildcard subdomain origin allow-list.** `clientDataJSON.origin`
  is checked by string equality against `public_base_url`. Subdomain
  logins fail until the verifier accepts a predicate or allow-list.
- **#61.11 RS256.** Deferred — re-evaluate when a real user reports a
  failed registration.
