import { useState, useCallback, useEffect, useRef } from 'preact/hooks';
import { useAuth } from '../../lib/auth-context';
import { supportsWebAuthn, getPasskeyCredential } from '../../lib/webauthn';
import {
  loginPasskeyStart,
  loginPasskeyFinish,
  appLoginStart,
  appLoginPoll,
} from '../../lib/api';
import { base64urlEncode, base64urlDecode } from '../../crypto/encoding';
import {
  generateEcdhKeyPair,
  exportPublicKey,
  performEcdh,
  deriveTransferKey,
  deriveAmkWrapKeyFromPrf,
  buildWrapAadPrf,
  unwrapAmk,
  computeAmkCommit,
} from '../../crypto/amk';
import { loadAmk, storeAmk } from '../../lib/amk-store';
import { wrapAndStorePrfWrapper } from '../../lib/passkey-prf';
import { debugInfo, debugError, fingerprint } from '../../lib/debug-log';
import { navigate } from '../../router';
import { getRedirectParam } from '../../lib/redirect';
import { isTauri, getApiBase } from '../../lib/config';
import { PasskeyIcon, TriangleExclamationIcon } from '../../components/Icons';
import { CardHeading } from '../../components/CardHeading';

type LoginState =
  | { step: 'ready' }
  | { step: 'authenticating' }
  | { step: 'done' }
  | { step: 'error'; message: string }
  | { step: 'unsupported' };

/** Map terse server errors to user-friendly messages. */
function friendlyLoginError(raw: string): string {
  const lower = raw.toLowerCase();
  if (lower.includes('unknown credential'))
    return 'This passkey is not recognized. The account may have been deleted or the passkey is not registered with this server.';
  return raw;
}

/**
 * Derive the AMK wrap key from the PRF output, unwrap the AMK, verify its
 * commitment matches what the server stored, and persist it locally. Used
 * on the new-device login path (the actual UX payoff of WebAuthn PRF).
 *
 * Throws on any verification failure so the caller can fall through to the
 * existing sync-link / API-key flow rather than store a wrong AMK.
 */
async function unwrapAndStorePrfAmk(
  userId: string,
  credentialId: string,
  credentialRawId: Uint8Array,
  prfOutput: Uint8Array,
  wrapper: {
    wrapped_amk: string;
    nonce: string;
    amk_commit: string;
    cred_salt?: string;
    version: number;
  },
): Promise<void> {
  if (wrapper.version !== 1) {
    throw new Error(`unsupported PRF wrapper version: ${wrapper.version}`);
  }
  if (!wrapper.cred_salt) {
    throw new Error('login-finish prf_wrapper missing cred_salt');
  }
  const credSalt = base64urlDecode(wrapper.cred_salt);
  const wrapKey = await deriveAmkWrapKeyFromPrf(prfOutput, credSalt);
  const aad = buildWrapAadPrf(userId, credentialRawId, 1);
  const amk = await unwrapAmk(
    {
      ct: wrapper.wrapped_amk,
      nonce: wrapper.nonce,
      version: wrapper.version,
    },
    wrapKey,
    aad,
  );

  // Verify commitment so we can't be fed a forged or stale wrapper.
  const computedCommit = await computeAmkCommit(amk);
  const expectedCommit = base64urlDecode(wrapper.amk_commit);
  if (
    computedCommit.length !== expectedCommit.length ||
    !computedCommit.every((b, i) => b === expectedCommit[i])
  ) {
    throw new Error('PRF wrapper amk_commit verification failed');
  }
  // Ignore the credentialId variable here intentionally — it's logged by the
  // caller for debugging and isn't needed in the unwrap math (the AAD already
  // binds to credentialRawId).
  void credentialId;

  await storeAmk(userId, amk);
}

/** Validate that a verification URL is HTTPS and matches the API origin. */
export function isAllowedVerificationUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return false;
    const apiBase = getApiBase();
    if (!apiBase) return true; // Dev mode — no origin to check
    return parsed.hostname === new URL(apiBase).hostname;
  } catch {
    return false;
  }
}

// ── Tauri Login Flow ────────────────────────────────────

type TauriLoginState =
  | { step: 'idle' }
  | { step: 'starting' }
  | { step: 'polling'; appCode: string; userCode: string }
  | { step: 'done' }
  | { step: 'error'; message: string };

function TauriLoginFlow() {
  const auth = useAuth();
  const redirectTo = getRedirectParam();
  const [state, setState] = useState<TauriLoginState>({ step: 'idle' });
  const abortRef = useRef<AbortController | null>(null);
  const ecdhPrivateKeyRef = useRef<CryptoKey | null>(null);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  const handleLogin = useCallback(
    async (intent: 'login' | 'register' = 'login') => {
      if (state.step === 'starting' || state.step === 'polling') return;
      setState({ step: 'starting' });

      try {
        // Generate ECDH keypair for AMK transfer
        let ecdhPubKeyB64: string | undefined;
        try {
          const kp = await generateEcdhKeyPair();
          ecdhPrivateKeyRef.current = kp.privateKey;
          const pubBytes = await exportPublicKey(kp.publicKey);
          ecdhPubKeyB64 = base64urlEncode(pubBytes);
        } catch (err) {
          // ECDH generation failure is non-fatal — proceed without AMK transfer
          debugError('amk-transfer-tauri', err, {
            phase: 'ecdh-keypair-generation',
          });
        }

        const res = await appLoginStart(ecdhPubKeyB64);
        setState({
          step: 'polling',
          appCode: res.app_code,
          userCode: res.user_code,
        });

        // Open system browser (only if URL passes origin check).
        // For registration, go directly to /register with the app-login
        // URL as redirect so the user lands on the registration form
        // immediately instead of being routed through the login page.
        let url: string;
        if (intent === 'register') {
          const parsed = new URL(res.verification_url);
          const appLoginPath = `${parsed.pathname}${parsed.search}`;
          url = `${parsed.origin}/register?redirect=${encodeURIComponent(appLoginPath)}`;
        } else {
          url = res.verification_url;
        }
        if (isAllowedVerificationUrl(url)) {
          try {
            const { open } = await import('@tauri-apps/plugin-shell');
            await open(url);
          } catch (err) {
            // If shell plugin fails, the user_code is already displayed for manual entry
            debugError('amk-transfer-tauri', err, { phase: 'shell-open' });
          }
        }

        // Start polling
        const controller = new AbortController();
        abortRef.current = controller;

        const poll = async () => {
          while (!controller.signal.aborted) {
            await new Promise((r) => setTimeout(r, (res.interval ?? 2) * 1000));
            if (controller.signal.aborted) break;

            try {
              const pollRes = await appLoginPoll(
                res.app_code,
                controller.signal,
              );
              if (pollRes.status === 'complete') {
                if (
                  pollRes.session_token &&
                  pollRes.user_id &&
                  pollRes.display_name
                ) {
                  // Decrypt and store AMK if transfer data is present
                  try {
                    const privKey = ecdhPrivateKeyRef.current;
                    debugInfo('amk-transfer-tauri', {
                      hasTransfer: !!pollRes.amk_transfer,
                      hasPrivKey: !!privKey,
                      userId: pollRes.user_id,
                    });
                    if (pollRes.amk_transfer && privKey) {
                      const peerPkBytes = base64urlDecode(
                        pollRes.amk_transfer.ecdh_public_key,
                      );
                      const sharedSecret = await performEcdh(
                        privKey,
                        peerPkBytes,
                      );
                      const transferKey = await deriveTransferKey(sharedSecret);

                      const ct = base64urlDecode(pollRes.amk_transfer.ct);
                      const nonce = base64urlDecode(pollRes.amk_transfer.nonce);
                      const aad = new TextEncoder().encode(
                        'secrt-amk-transfer-v1',
                      );

                      const buf = (a: Uint8Array): ArrayBuffer => {
                        const b = new ArrayBuffer(a.byteLength);
                        new Uint8Array(b).set(a);
                        return b;
                      };

                      const cryptoKey = await crypto.subtle.importKey(
                        'raw',
                        buf(transferKey),
                        'AES-GCM',
                        false,
                        ['decrypt'],
                      );
                      const amkPt = await crypto.subtle.decrypt(
                        {
                          name: 'AES-GCM',
                          iv: buf(nonce),
                          additionalData: buf(aad),
                        },
                        cryptoKey,
                        buf(ct),
                      );
                      const amkBytes = new Uint8Array(amkPt);
                      await storeAmk(pollRes.user_id, amkBytes);
                      debugInfo('amk-transfer-tauri', {
                        result: 'success',
                        amkFingerprint: await fingerprint(amkBytes),
                      });
                    }
                  } catch (err) {
                    // AMK decryption failure is non-fatal — login still succeeds
                    debugError('amk-transfer-tauri', err, {
                      phase: 'decrypt-store',
                    });
                  }
                  ecdhPrivateKeyRef.current = null;

                  auth.login(
                    pollRes.session_token,
                    pollRes.user_id,
                    pollRes.display_name,
                  );
                  setState({ step: 'done' });
                  navigate(redirectTo);
                }
                return;
              }
              // authorization_pending — continue polling
            } catch (err) {
              if (controller.signal.aborted) return;
              const msg =
                err instanceof Error ? err.message : 'Polling failed.';
              if (msg.includes('expired_token')) {
                setState({
                  step: 'error',
                  message: 'Sign-in session expired. Please try again.',
                });
                return;
              }
              // Transient error — keep polling
            }
          }
        };
        poll();
      } catch (err) {
        const message =
          err instanceof Error ? err.message : 'Failed to start login.';
        setState({ step: 'error', message });
      }
    },
    [state.step, auth, redirectTo],
  );

  const handleCancel = useCallback(() => {
    abortRef.current?.abort();
    setState({ step: 'idle' });
  }, []);

  const busy = state.step === 'starting' || state.step === 'polling';

  return (
    <div class="space-y-4">
      <div class="card space-y-6 text-center">
        <CardHeading
          title="Sign In"
          icon={<PasskeyIcon class="size-10" />}
          subtitle="Sign in via your system browser using your passkey."
          class="mb-4"
        />

        {state.step === 'polling' && (
          <div class="space-y-3">
            <p class="text-muted">
              Approve this code in your browser to continue:
            </p>
            <div class="bg-surface-alt mx-auto rounded-lg px-6 py-4 font-mono text-3xl font-bold tracking-[0.3em]">
              {state.userCode}
            </div>
            <p class="text-xs text-faint">Waiting for approval...</p>
          </div>
        )}

        {state.step === 'error' && (
          <div
            role="alert"
            class="alert-error flex items-center justify-center gap-2"
          >
            <TriangleExclamationIcon class="size-5 shrink-0" />
            {state.message}
          </div>
        )}

        {state.step === 'polling' ? (
          <button
            type="button"
            class="btn w-full tracking-wider uppercase"
            onClick={handleCancel}
          >
            Cancel
          </button>
        ) : (
          <button
            type="button"
            class="btn btn-primary w-full tracking-wider uppercase"
            onClick={() => handleLogin()}
            disabled={busy}
          >
            {state.step === 'starting'
              ? 'Starting\u2026'
              : 'Sign in via Browser'}
          </button>
        )}
      </div>

      <p class="text-center text-muted">
        <a
          href="/register"
          class="link"
          onClick={(e: MouseEvent) => {
            e.preventDefault();
            handleLogin('register');
          }}
        >
          Register a New Account
        </a>
      </p>
    </div>
  );
}

// ── Main LoginPage ──────────────────────────────────────

export function LoginPage() {
  const auth = useAuth();
  const redirectTo = getRedirectParam();
  const [state, setState] = useState<LoginState>(() =>
    supportsWebAuthn() ? { step: 'ready' } : { step: 'unsupported' },
  );

  // Redirect if already authenticated
  if (auth.authenticated) {
    navigate(redirectTo);
    return null;
  }

  // In Tauri, use browser-based login flow instead of passkeys
  if (isTauri()) {
    return <TauriLoginFlow />;
  }

  const busy = state.step === 'authenticating';

  const handleLogin = useCallback(async () => {
    if (busy) return;
    setState({ step: 'authenticating' });

    try {
      // Discoverable-credential flow: a single navigator.credentials.get()
      // call. The server issues a fresh challenge with no credential
      // pre-binding; the assertion's signature is what ties the
      // credential to the session. iCloud Passwords prompts for the
      // account password on EVERY get() call, so any second call is a
      // visible UX regression — keep this single-call.
      const startRes = await loginPasskeyStart({});

      const assertion = await getPasskeyCredential(startRes.challenge, {
        enablePrf: true,
      });

      const finishRes = await loginPasskeyFinish({
        challenge_id: startRes.challenge_id,
        credential_id: assertion.credentialId,
        authenticator_data: assertion.authenticatorData,
        client_data_json: assertion.clientDataJSON,
        signature: assertion.signature,
        prf: {
          supported: !!assertion.prfOutput,
          at_create: false,
        },
      });

      // Step 4: Store session
      auth.login(
        finishRes.session_token,
        finishRes.user_id,
        finishRes.display_name,
      );

      // Step 5a: PRF unlock. If the server returned a wrapper inline AND the
      //          assertion produced a PRF output AND we don't already have an
      //          AMK locally, derive the wrap key, unwrap, and store. All-
      //          best-effort: failure here just falls through to the existing
      //          sync-link / API-key path.
      debugInfo('prf-unwrap', {
        hasWrapper: !!finishRes.prf_wrapper,
        wrapperHasSalt: !!finishRes.prf_wrapper?.cred_salt,
        wrapperVersion: finishRes.prf_wrapper?.version ?? null,
        hasPrfOutput: !!assertion.prfOutput,
        prfOutputFingerprint: assertion.prfOutput
          ? await fingerprint(assertion.prfOutput)
          : null,
        credIdPrefix: assertion.credentialId.slice(0, 8),
        userId: finishRes.user_id,
      });
      if (finishRes.prf_wrapper && assertion.prfOutput) {
        try {
          const existing = await loadAmk(finishRes.user_id);
          if (existing) {
            debugInfo(
              'prf-unwrap',
              'skipping unwrap, local AMK already present',
            );
          } else {
            debugInfo('prf-unwrap', 'attempting unwrap, no local AMK');
            await unwrapAndStorePrfAmk(
              finishRes.user_id,
              assertion.credentialId,
              assertion.rawId,
              assertion.prfOutput,
              finishRes.prf_wrapper,
            );
            const stored = await loadAmk(finishRes.user_id);
            debugInfo('prf-unwrap', {
              result: 'success',
              amkFingerprint: stored ? await fingerprint(stored) : null,
            });
          }
        } catch (err) {
          // Non-fatal — login itself succeeded.
          debugError('prf-unwrap', err, {
            credIdPrefix: assertion.credentialId.slice(0, 8),
          });
        }
      }

      // Step 5b: PRF upgrade (§"Transport D" §4.5). Server returned a
      //          cred_salt with no wrapper — this credential is now
      //          PRF-capable but has no wrapper yet. If we have the AMK
      //          loaded (i.e., this is a known device, not a fresh one),
      //          wrap it and PUT so future fresh-device logins get one-tap
      //          unlock. Best-effort: the user is already logged in.
      if (
        finishRes.prf_cred_salt &&
        !finishRes.prf_wrapper &&
        assertion.prfOutput
      ) {
        debugInfo(
          'prf-upgrade',
          'cred_salt present without wrapper, attempting wrap+PUT',
        );
        try {
          const amk = await loadAmk(finishRes.user_id);
          if (!amk) {
            debugInfo(
              'prf-upgrade',
              'skipping upgrade, no local AMK to wrap (fresh device)',
            );
          } else {
            const amkCommit = await computeAmkCommit(amk);
            await wrapAndStorePrfWrapper(
              finishRes.session_token,
              finishRes.user_id,
              assertion.credentialId,
              assertion.rawId,
              finishRes.prf_cred_salt,
              assertion.prfOutput,
              amk,
              amkCommit,
            );
            debugInfo('prf-upgrade', {
              result: 'success',
              amkFingerprint: await fingerprint(amk),
            });
          }
        } catch (err) {
          // Non-fatal — login itself succeeded; upgrade can retry next login.
          debugError('prf-upgrade', err, {
            credIdPrefix: assertion.credentialId.slice(0, 8),
          });
        }
      }

      setState({ step: 'done' });
      navigate(redirectTo);
    } catch (err) {
      if (err instanceof DOMException && err.name === 'NotAllowedError') {
        setState({ step: 'error', message: 'Sign-in was cancelled.' });
      } else {
        const raw = err instanceof Error ? err.message : 'Sign-in failed.';
        setState({ step: 'error', message: friendlyLoginError(raw) });
      }
    }
  }, [busy, auth]);

  if (state.step === 'unsupported') {
    return (
      <div class="card space-y-4 text-center">
        <TriangleExclamationIcon class="text-warning mx-auto size-8" />
        <h2 class="label">Passkeys not supported</h2>
        <p class="text-muted">
          Your browser doesn't support passkeys (WebAuthn). Please use a modern
          browser like Chrome, Safari, or Firefox.
        </p>
      </div>
    );
  }

  return (
    <div class="space-y-4">
      <div class="card space-y-6 text-center">
        <CardHeading
          title="Sign In"
          icon={<PasskeyIcon class="size-10" />}
          subtitle={
            'Use your passkey to sign in anonymously.\nYour browser will show available passkeys.'
          }
          class="mb-4"
        />

        {state.step === 'error' && (
          <div
            role="alert"
            class="alert-error flex items-center justify-center gap-2"
          >
            <TriangleExclamationIcon class="size-5 shrink-0" />
            {state.message}
          </div>
        )}

        <button
          type="button"
          class="btn btn-primary w-full tracking-wider uppercase"
          onClick={handleLogin}
          disabled={busy}
        >
          {busy ? 'Authenticating\u2026' : 'Sign in with Passkey'}
        </button>
      </div>

      <p class="text-center text-muted">
        <a
          href={
            redirectTo === '/'
              ? '/register'
              : `/register?redirect=${encodeURIComponent(redirectTo)}`
          }
          class="link"
          onClick={(e: MouseEvent) => {
            e.preventDefault();
            navigate(
              redirectTo === '/'
                ? '/register'
                : `/register?redirect=${encodeURIComponent(redirectTo)}`,
            );
          }}
        >
          Register a New Account
        </a>
      </p>
    </div>
  );
}
