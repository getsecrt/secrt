# Task 62: PRF / AMK Diagnostic Logging

**Status:** pending
**Priority:** high — unblocks every future investigation of cross-device PRF and AMK transfer behavior
**Related:** task #42 (PRF AMK wrapping — `crates/secrt-server/docs/prf-amk-wrapping.md`), task #37 (unified preferences — credential metadata folds into the same blob)
**Plan version:** v1 — 2026-05-01

---

## Goal

Replace the silent `} catch {}` blocks in the AMK / PRF flows with **gated diagnostic logging** that:

1. Always logs in dev builds (statically eliminated from prod bundles).
2. Logs in prod **only** when the user explicitly opts in via a localStorage flag.
3. Never sends any data off-device — no telemetry, no analytics, no Sentry. The privacy posture stays intact.
4. Captures structured signal (which branch fired, why, with what fingerprintable inputs) — not just error text — so a single sign-in attempt produces enough information to diagnose where the AMK transfer succeeded or failed.

The bar: **any future "why didn't the AMK sync?" investigation should be answerable from one captured console session, not a day of speculation.**

## Why now (the 2026-05-01 motivation)

Today we hit two PRF determinism walls in a row:

- iPhone Safari + external YubiKey: AMK doesn't transfer. Hypothesized as Apple WebAuthn re-wrapping `hmac-secret` for non-platform authenticators. Plausible mechanism but not directly observed.
- Windows Chrome (regular and incognito) + same YubiKey: AMK also doesn't transfer despite the wrapper being present on the server. Strong circumstantial evidence of Windows-platform interception (analogous to the iOS issue), but again — no direct observation. Three back-to-back diagnostic loops collapsed because the failing code paths swallow their errors.

Each silent catch is an unforced "guess what went wrong" cost we pay every time a real-world surface fails differently than the spec predicts. The browser/authenticator/OS surface area is huge and only growing. We need observability that scales.

Specifically: until this lands, we cannot honestly populate the "still informational, not gating" rows in `prf-amk-wrapping.md` §11 with anything but speculation. The spike findings table currently has gaps that a logging pass would fill in a few sign-ins each.

## Non-goals

- **Telemetry / off-device transmission.** No Sentry, no Datadog, no PostHog, no rollups to the secrt server. Logs stay in the user's local console. The point is observability without privacy compromise — sending crypto error details home would betray the project's stated values.
- **Persistent log storage.** No in-memory ring buffer in v1, no IndexedDB persistence. Console-only. (Future enhancement noted below.)
- **Replace the existing UI fallback paths.** Catch blocks remain; they still let the user fall through to the sync-link / API-key recovery flow. Logging is additive observation, not behavior change.
- **Settings UI for the toggle.** v1 is DevTools-only (`localStorage.setItem('secrt:debug', '1')`). A Settings → Diagnostics toggle is noted as a future enhancement.
- **Server-side logging changes.** Server already logs at info/error level via the `tracing` crate. This task is purely client-side.
- **Anything that changes the cryptographic path.** No new derivations, no different AAD, no schema changes. Pure observation layer.

---

## Decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | **Two-layer gate**: `import.meta.env.DEV` (Vite build-time, statically replaced) **OR** `localStorage.getItem('secrt:debug') === '1'` (runtime opt-in). | Dev builds always log (zero cost in prod since DCE removes the branch). Prod bundles ship the localStorage check so a deployed build can be debugged without rebuilding. No data leaves the device in either case. |
| 2 | **Single helper module** at `web/src/lib/debug-log.ts` exporting `debugLog(label, data)`, `debugError(label, err)`, and `debugInfo(label, data)`. | One import to update if the gate ever changes. Distinct fn names per severity make grep / DevTools-filter usage cleaner than overloading one function. |
| 3 | **Tagged labels** per call site (e.g. `prf-unwrap`, `prf-upgrade`, `prf-register-wrap`, `prf-fallback-ceremony`). Output prefix `[secrt:<label>]`. | Lets you DevTools-filter to a single subsystem in a noisy console. Tag list lives in the helper module's docstring as an enumeration so labels stay consistent across files. |
| 4 | **Log decisions, not just errors.** Every branch in the PRF unwrap / wrap / upgrade flow emits a one-line `debugInfo` describing the path taken (`"PRF wrapper present, no local AMK — attempting unwrap"`). Errors emit additional `debugError`. | Most "why didn't this work?" questions are about *which branch fired*, not "what was the exception text." A successful no-op path is just as informative as a failure when you're trying to understand cross-device behavior. |
| 5 | **Log fingerprints, never secrets.** Approved to log: SHA-256[0..8] hex of inputs (PRF output, wrap key, derived AMK), credential ID prefix (first 8 chars of base64url), AAGUID hex, attestation_fmt string, capability classification, presence/absence of fields. **Forbidden** to log: raw PRF output, raw AMK, raw wrap key, full credential ID, session token, server response bodies in full. | Fingerprints are sufficient for cross-device determinism checks and round-trip verification. Raw values are not — and would be the privacy floor we never want to cross even in opt-in debug mode. |
| 6 | **No persistent storage in v1.** Console-only. | Keeps the surface tiny. Anything logged sticks around as long as the DevTools tab does, which is plenty for an active debug session. Persistent ring buffer is a future enhancement once we know what fields we actually want to retain. |
| 7 | **Gate every helper function internally**, not at each call site. Callers always invoke `debugError(label, err)`; the gate is checked inside. | Removes the temptation to write `if (DEBUG) debugError(...)` boilerplate and ensures consistency. The helper is the single place the gate logic lives. |
| 8 | **Empty-arg-list catches stay forbidden in PRF/AMK paths.** Code review checks: any new `} catch {` (no parameter) inside `web/src/features/auth/`, `web/src/features/settings/`, `web/src/lib/passkey-prf.ts`, `web/src/lib/amk-store.ts` should be flagged. | The whole point of this task is preventing the recurrence of silent failures. Make the rule explicit so it survives future PRs. |

---

## Architecture

### Helper module: `web/src/lib/debug-log.ts`

```ts
/**
 * Gated diagnostic logging for AMK / PRF flows.
 *
 * Dev builds: always log via console (statically replaced; dead-code-eliminated in prod).
 * Prod builds: log only when the user has explicitly opted in via
 *   localStorage.setItem('secrt:debug', '1')
 *
 * No data ever leaves the device. No telemetry, no remote collection.
 *
 * Approved labels (keep in sync with task-62-prf-amk-diagnostic-logging.md):
 *   - 'prf-unwrap'              — login-time PRF unwrap of server wrapper
 *   - 'prf-upgrade'             — login-time PRF wrapper upgrade (existing creds without wrapper)
 *   - 'prf-register-wrap'       — RegisterPage wrap+PUT after fresh registration
 *   - 'prf-settings-wrap'       — SettingsPage add-passkey wrap+PUT
 *   - 'prf-fallback-ceremony'   — passkey-prf.ts second ceremony to obtain PRF on get
 *   - 'amk-store'               — IndexedDB / Tauri keychain reads/writes
 *   - 'amk-transfer-tauri'      — Tauri ECDH-based AMK transfer in app-login flow
 *   - 'webauthn-create'         — registration ceremony observation
 *   - 'webauthn-get'            — assertion ceremony observation
 *   - 'preferences-blob'        — encrypted prefs blob fetch / decrypt / write (post task #37)
 */

const PROD_FLAG = 'secrt:debug';

function enabled(): boolean {
  if (import.meta.env.DEV) return true;
  try {
    return localStorage.getItem(PROD_FLAG) === '1';
  } catch {
    // localStorage unavailable (some private modes, very old browsers)
    return false;
  }
}

export function debugInfo(label: string, data?: unknown): void {
  if (!enabled()) return;
  if (data === undefined) {
    console.info(`[secrt:${label}]`);
  } else {
    console.info(`[secrt:${label}]`, data);
  }
}

export function debugError(label: string, err: unknown, extra?: unknown): void {
  if (!enabled()) return;
  if (extra === undefined) {
    console.error(`[secrt:${label}]`, err);
  } else {
    console.error(`[secrt:${label}]`, err, extra);
  }
}

/**
 * Convenience: stable 8-byte hex fingerprint of any byte sequence.
 * Use for verifying cross-device determinism without exposing raw secrets.
 */
export async function fingerprint(bytes: Uint8Array): Promise<string> {
  if (!enabled()) return ''; // Skip the digest if we won't use it.
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash, 0, 8))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
```

### Where logging goes

#### Currently silent catches that must be wired up

| File | Line(s) | Label | Purpose |
|---|---|---|---|
| `web/src/features/auth/LoginPage.tsx` | ~438 | `prf-unwrap` | PRF wrapper unwrap on fresh-device login |
| `web/src/features/auth/LoginPage.tsx` | ~469 | `prf-upgrade` | PRF wrapper retrofit when known device sees its first cred_salt |
| `web/src/features/auth/LoginPage.tsx` | ~245 | `amk-transfer-tauri` | Tauri ECDH AMK decrypt in app-login flow |
| `web/src/features/auth/LoginPage.tsx` | ~150 | `amk-transfer-tauri` | ECDH keypair generation failure |
| `web/src/features/auth/LoginPage.tsx` | ~177 | `amk-transfer-tauri` | Tauri shell-open failure (less critical, low priority) |
| `web/src/features/auth/RegisterPage.tsx` | ~254 | `prf-register-wrap` | First PRF wrap+PUT after registration |
| `web/src/features/auth/RegisterPage.tsx` | ~260 | `amk-store` | AMK generation/storage at registration |
| `web/src/features/settings/SettingsPage.tsx` | ~401 | `prf-settings-wrap` | Wrap+PUT when adding a passkey from Settings |
| `web/src/lib/passkey-prf.ts` | (any catches in fallback ceremony) | `prf-fallback-ceremony` | Second ceremony when PRF-on-get-only |

For each: keep the existing fall-through behavior (login still succeeds, etc.), but call `debugError(label, err)` *inside* the catch before the existing comment. No behavior change, pure observation.

#### Decision-branch logging to add (new `debugInfo` calls, not in catches)

These are the "which path fired?" markers that turn an opaque flow into a readable trace.

**`LoginPage.tsx` (login flow):**
- After `loginPasskeyFinish` returns:
  - `debugInfo('prf-unwrap', { hasWrapper: !!finishRes.prf_wrapper, hasSalt: !!finishRes.prf_cred_salt, hasPrfOutput: !!assertion.prfOutput, credIdPrefix: assertion.credentialId.slice(0, 8) })`
- Before unwrap branch: `debugInfo('prf-unwrap', 'attempting unwrap, no local AMK')`
- After local-AMK-skip: `debugInfo('prf-unwrap', 'skipping unwrap, local AMK already present')`
- After successful unwrap + commit verify: `debugInfo('prf-unwrap', { result: 'success', amkFingerprint: await fingerprint(amk) })`
- Upgrade branch entry: `debugInfo('prf-upgrade', 'cred_salt present without wrapper, attempting wrap+PUT')`
- After successful PUT: `debugInfo('prf-upgrade', 'wrap+PUT succeeded')`

**`RegisterPage.tsx` (registration flow):**
- After `createPasskeyCredential`: `debugInfo('webauthn-create', { prfState: credential.prfState, credIdPrefix: credential.credentialId.slice(0, 8) })`
- Before wrap+PUT: `debugInfo('prf-register-wrap', { hasOnCreateOutput: !!credential.prfState.onCreateOutput, hasCredSalt: !!finishRes.prf_cred_salt })`
- After wrap+PUT: `debugInfo('prf-register-wrap', 'success')`

**`passkey-prf.ts`:**
- Entry: `debugInfo('prf-fallback-ceremony', { reason: 'no PRF-on-create output, running second assertion' })` when fallback path is taken
- After fallback assertion: `debugInfo('prf-fallback-ceremony', { hasPrfOutput: !!assertion.prfOutput, credIdMatch: assertion.credentialId === credentialId })`

**`amk-store.ts`:**
- Wrap reads/writes with `debugInfo('amk-store', { op: 'load' | 'store' | 'clear', userId, present: ... })` — short, terse.

The quantity of new `debugInfo` calls is intentionally generous in the PRF-touching files and minimal elsewhere. We're optimizing for "first sign-in after enabling debug mode tells you everything."

#### What logged exceptions should look like

A typical AES-GCM tag failure during PRF unwrap should produce something like this in the console:

```
[secrt:prf-unwrap] { hasWrapper: true, hasSalt: true, hasPrfOutput: true, credIdPrefix: 'YGuLNJoO' }
[secrt:prf-unwrap] 'attempting unwrap, no local AMK'
[secrt:prf-unwrap] OperationError: The operation failed for an operation-specific reason
```

That single trace tells you: wrapper was present (server gave us one), salt was present (we have what we need), PRF output was returned by the assertion (the YubiKey/browser produced something), and the AES-GCM decrypt failed — i.e., the wrap key didn't match. From there, the explanation is "the PRF output this client produced doesn't match the PRF output that was used at wrap time," which is the Apple-iOS / Windows-Hello platform-mangling story.

Without the logging: the same scenario produces zero console output and the user has no idea what happened.

---

## Files touched

| File | Change |
|---|---|
| `web/src/lib/debug-log.ts` (**new**) | Helper module per Architecture above. |
| `web/src/features/auth/LoginPage.tsx` | Add `debugInfo` decision markers; replace silent catches with `debugError`. |
| `web/src/features/auth/RegisterPage.tsx` | Same treatment for registration flow. |
| `web/src/features/settings/SettingsPage.tsx` | Same treatment for add-passkey flow. |
| `web/src/lib/passkey-prf.ts` | Wire `debugInfo` / `debugError` into fallback ceremony and existing catches. |
| `web/src/lib/amk-store.ts` | Light `debugInfo` on load/store/clear ops. |
| `web/src/lib/webauthn.ts` | Optional: `debugInfo('webauthn-create', { prfState })` and `debugInfo('webauthn-get', { hasPrfOutput })` after the ceremonies. |
| `crates/secrt-server/docs/prf-amk-wrapping.md` | Add a paragraph in §11 referencing this task and noting that future spike-matrix entries should be backed by captured logs. |
| `web/AGENTS.md` (or `CLAUDE.md` if present in `web/`) | Add a one-liner: *"PRF/AMK code paths must use `debugLog` helpers in catches — never bare `} catch {` (see task-62)."* |

---

## Phases

### Phase 1 — Helper + minimal wiring

- [ ] Create `web/src/lib/debug-log.ts`.
- [ ] Update `LoginPage.tsx` catches at lines ~438 and ~469. Add the decision-branch `debugInfo` markers.
- [ ] Manually verify in dev build: console shows the trace on a sign-in.
- [ ] Manually verify in a prod build (`pnpm build && pnpm preview`): console is silent unless `localStorage.setItem('secrt:debug', '1')` is set.
- [ ] Use this to capture the actual error from the Windows-Chrome incognito case that triggered this task. Update `prf-amk-wrapping.md` §11 with the captured exception text.

This is the immediate-payoff slice and unblocks the YubiKey investigation.

### Phase 2 — Full coverage of PRF / AMK paths

- [ ] Wire up RegisterPage, SettingsPage, passkey-prf.ts, amk-store.ts catches.
- [ ] Add the webauthn ceremony observation lines.
- [ ] Update `web/AGENTS.md` with the no-bare-catch convention.
- [ ] Add a unit test or lint rule that fails the build if a bare `} catch {` is added in any of the PRF/AMK files. (Could be a custom ESLint rule, or just a CI grep.)

### Phase 3 — Tests + docs

- [ ] Document the diagnostic interpretation guide (below) as a section in `prf-amk-wrapping.md` so future-Rachel / future-JD has a Rosetta stone for common console traces.
- [ ] Re-run the spike matrix on every available browser/OS combo with debug logging enabled. Backfill the `prf-amk-wrapping.md` §11 table with captured fingerprints + exception types. This is now the canonical surface-compatibility data, replacing the speculative entries.

### Future (out of v1 scope)

- **Settings → Diagnostics toggle** that writes the localStorage flag from a UI checkbox. Useful for non-dev users helping with bug reports.
- **In-memory ring buffer** of the last N log lines, with a "Copy diagnostics" button that copies them to the clipboard for sharing in support contexts.
- **Server-side request correlation** — emit an opaque request ID in client logs, log the same on the server, so you can grep both sides of a failed flow.
- **Optional `?debug=1` query-param shim** — visiting with the param sets the localStorage flag for that origin. Convenient for sharing debug-enabled links in support threads.

---

## Diagnostic interpretation guide

A non-exhaustive Rosetta stone for console traces. Add to `prf-amk-wrapping.md` after Phase 3.

### Successful PRF unlock on a fresh device

```
[secrt:prf-unwrap] { hasWrapper: true, hasSalt: true, hasPrfOutput: true, credIdPrefix: '...' }
[secrt:prf-unwrap] 'attempting unwrap, no local AMK'
[secrt:prf-unwrap] { result: 'success', amkFingerprint: '...' }
```

### Skipped because already unlocked locally

```
[secrt:prf-unwrap] { hasWrapper: true, hasSalt: true, hasPrfOutput: true, credIdPrefix: '...' }
[secrt:prf-unwrap] 'skipping unwrap, local AMK already present'
```

### Wrapper exists but unwrap fails (the Apple-iOS / Windows-Hello scenario)

```
[secrt:prf-unwrap] { hasWrapper: true, hasSalt: true, hasPrfOutput: true, credIdPrefix: '...' }
[secrt:prf-unwrap] 'attempting unwrap, no local AMK'
[secrt:prf-unwrap] OperationError: The operation failed for an operation-specific reason
```

Interpretation: AES-GCM tag check failed. The wrap key derived on this client doesn't match the wrap key used at wrap time. Almost always: PRF output differs because the platform (iOS Safari, Windows Hello-bridged Chrome) is processing `hmac-secret` for the external authenticator before returning it to the relying party. Compare the SHA-256[0..8] PRF fingerprint via the prf-spike to the fingerprint captured on the device that wrote the wrapper — divergence confirms the hypothesis.

### No wrapper, no upgrade — broken intermediate state

```
[secrt:prf-unwrap] { hasWrapper: false, hasSalt: true, hasPrfOutput: true, credIdPrefix: '...' }
[secrt:prf-upgrade] 'cred_salt present without wrapper, attempting wrap+PUT'
[secrt:prf-upgrade] TypeError: ... (or whatever fails)
```

Interpretation: server has the salt (so the credential is PRF-capable) but no wrapper exists. Upgrade path tried to wrap and PUT, hit some error. The error text tells you whether it's a PUT failure (network, 5xx), a wrap-key derivation failure, or the local AMK was missing.

### PRF extension dropped by the authenticator

```
[secrt:webauthn-get] { hasPrfOutput: false }
[secrt:prf-unwrap] { hasWrapper: true, hasSalt: true, hasPrfOutput: false, credIdPrefix: '...' }
```

Interpretation: the assertion didn't return a PRF output. Authenticator (or picker like Bitwarden / 1Password) declined to produce one. PRF path is dead for this credential on this surface; user falls through to sync-link.

### Tauri AMK transfer failure

```
[secrt:amk-transfer-tauri] OperationError: ...
```

Interpretation: the ECDH-based AMK transfer in the app-login flow failed. Usually means the verification-URL browser tab didn't have an AMK to wrap, or the ECDH/AAD didn't match. Cross-reference with the browser tab's log (which should have a `prf-unwrap` line preceding the approve action).

---

## Privacy posture review

Restating the boundary: nothing logged ever leaves the device. The opt-in flag enables additional console output **on the user's own browser**, not transmission anywhere. There is no Sentry, no analytics endpoint, no `/api/v1/log` ingest. If a future contributor proposes adding remote log transmission "for support purposes," the answer is no — the workflow is "the user copies their console output and pastes it into an email," not "we exfiltrate diagnostic data even with consent."

This matches the project's broader stance (see whitepaper §"Server data minimization" and `task-37-unified-preferences.md` Decision #2): the server is opaque to user activity, and that property does not get diluted for engineering convenience.

What does get logged when debug mode is on:

- Decision-branch traces (which `if` arm fired)
- Field presence/absence (`hasWrapper`, `hasPrfOutput`, etc.)
- Fingerprints (SHA-256[0..8]) of cryptographic inputs/outputs for cross-device determinism comparison
- Exception text from caught errors (which is non-secret JS exception classes + messages)

What does NOT get logged ever, even in debug mode:

- Raw PRF output bytes
- Raw AMK bytes
- Raw wrap key bytes
- Full credential ID (prefix only)
- Session token
- Decrypted note contents
- Decrypted preferences blob contents
- User-set passphrases or labels

The helper exposes no convenience for logging full byte sequences — `fingerprint(bytes)` is the only sanctioned way to surface byte material, and it always reduces to 8 hex chars.

---

## References

- **Triggering session:** 2026-05-01 multi-thread investigation of YubiKey 5C NFC PRF behavior across macOS Vivaldi, macOS Chrome, Windows Chrome (regular + incognito), and iPhone Safari. Findings folded into `prf-amk-wrapping.md` §11.
- **PRF / AMK design:** `crates/secrt-server/docs/prf-amk-wrapping.md`
- **Encrypted preferences design (where credential metadata lives):** `.taskmaster/plans/task-37-unified-preferences.md`
- **PRF spike infrastructure:** `web/prototypes/prf-spike/` — fingerprint comparison tool that complements this logging by isolating the authenticator-determinism layer from the application code path.
- **Vite environment constants:** <https://vite.dev/guide/env-and-mode> — `import.meta.env.DEV` / `.PROD` / `.MODE` semantics.
