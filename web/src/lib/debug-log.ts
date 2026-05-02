/**
 * Gated diagnostic logging for AMK / PRF flows.
 *
 * Dev builds: always log via console (statically replaced; dead-code-eliminated
 *   in prod by Vite when `import.meta.env.DEV` is false).
 * Prod builds: log only when the user has explicitly opted in via
 *   `localStorage.setItem('secrt:debug', '1')`.
 *
 * No data ever leaves the device. No telemetry, no remote collection — see
 * `.taskmaster/plans/task-62-prf-amk-diagnostic-logging.md` for the privacy
 * posture review and the catalogue of what is/isn't loggable.
 *
 * Approved labels (keep this list in sync with the task plan so future
 * contributors don't invent ad-hoc labels that are hard to grep):
 *   - 'prf-unwrap'              — login-time PRF unwrap of server wrapper
 *   - 'prf-upgrade'             — login-time PRF wrapper upgrade (existing creds without wrapper)
 *   - 'prf-register-wrap'       — RegisterPage wrap+PUT after fresh registration
 *   - 'prf-settings-wrap'       — SettingsPage add-passkey wrap+PUT
 *   - 'prf-fallback-ceremony'   — passkey-prf.ts second ceremony to obtain PRF on get
 *   - 'amk-store'               — IndexedDB / Tauri keychain reads/writes
 *   - 'amk-transfer-tauri'      — Tauri ECDH-based AMK transfer in app-login flow
 *   - 'webauthn-create'         — registration ceremony observation
 *   - 'webauthn-get'            — assertion ceremony observation
 *
 * Call style:
 *   debugInfo('prf-unwrap', { hasWrapper: true, credIdPrefix: 'YGuLNJoO' });
 *   debugError('prf-unwrap', err);
 *   const fp = await fingerprint(amk); // 8-byte hex of SHA-256
 */

const PROD_FLAG = 'secrt:debug';

function enabled(): boolean {
  if (import.meta.env.DEV) return true;
  try {
    return (
      typeof localStorage !== 'undefined' &&
      localStorage.getItem(PROD_FLAG) === '1'
    );
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
 * Stable 8-byte hex fingerprint of any byte sequence. Use for verifying
 * cross-device PRF / AMK determinism without exposing raw secrets. Returns
 * an empty string when debug logging is disabled, so the SHA-256 isn't
 * computed in the hot prod path.
 */
export async function fingerprint(bytes: Uint8Array): Promise<string> {
  if (!enabled()) return '';
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash, 0, 8))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
