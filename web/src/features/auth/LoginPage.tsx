import { useState, useCallback, useEffect, useRef } from 'preact/hooks';
import { useAuth } from '../../lib/auth-context';
import { supportsWebAuthn, getPasskeyCredential } from '../../lib/webauthn';
import {
  loginPasskeyStart,
  loginPasskeyFinish,
  appLoginStart,
  appLoginPoll,
} from '../../lib/api';
import { base64urlEncode } from '../../crypto/encoding';
import { navigate } from '../../router';
import { getRedirectParam } from '../../lib/redirect';
import { isTauri } from '../../lib/config';
import {
  PasskeyIcon,
  TriangleExclamationIcon,
} from '../../components/Icons';
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

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  const handleLogin = useCallback(async () => {
    if (state.step === 'starting' || state.step === 'polling') return;
    setState({ step: 'starting' });

    try {
      const res = await appLoginStart();
      setState({
        step: 'polling',
        appCode: res.app_code,
        userCode: res.user_code,
      });

      // Open system browser
      try {
        const { open } = await import('@tauri-apps/plugin-shell');
        await open(res.verification_url);
      } catch {
        // If shell plugin fails, show the URL for manual copy
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
            const msg = err instanceof Error ? err.message : 'Polling failed.';
            if (msg.includes('expired_token')) {
              setState({
                step: 'error',
                message: 'Login session expired. Please try again.',
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
  }, [state.step, auth, redirectTo]);

  const handleCancel = useCallback(() => {
    abortRef.current?.abort();
    setState({ step: 'idle' });
  }, []);

  const busy = state.step === 'starting' || state.step === 'polling';

  return (
    <div class="space-y-4">
      <div class="card space-y-6 text-center">
        <CardHeading
          title="Log In"
          icon={<PasskeyIcon class="size-10" />}
          subtitle="Log in via your system browser using your passkey."
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
            onClick={handleLogin}
            disabled={busy}
          >
            {state.step === 'starting'
              ? 'Starting\u2026'
              : 'Log in via Browser'}
          </button>
        )}
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
      // Step 1: Use a local random challenge just to invoke the passkey picker
      const localChallenge = new Uint8Array(32);
      crypto.getRandomValues(localChallenge);
      const localChallengeB64 = base64urlEncode(localChallenge);

      const pickerResult = await getPasskeyCredential(localChallengeB64);

      // Step 2: Now we have the credential_id, call server login/start
      const startRes = await loginPasskeyStart({
        credential_id: pickerResult.credentialId,
      });

      // Step 3: Complete login with server challenge
      const finishRes = await loginPasskeyFinish({
        challenge_id: startRes.challenge_id,
        credential_id: pickerResult.credentialId,
      });

      // Step 4: Store session
      auth.login(
        finishRes.session_token,
        finishRes.user_id,
        finishRes.display_name,
      );
      setState({ step: 'done' });
      navigate(redirectTo);
    } catch (err) {
      if (err instanceof DOMException && err.name === 'NotAllowedError') {
        setState({ step: 'error', message: 'Login was cancelled.' });
      } else {
        const raw = err instanceof Error ? err.message : 'Login failed.';
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
          title="Log In"
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
          {busy ? 'Authenticating\u2026' : 'Log in with Passkey'}
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
