import { useState, useCallback } from 'preact/hooks';
import { useAuth } from '../../lib/auth-context';
import { supportsWebAuthn, getPasskeyCredential } from '../../lib/webauthn';
import { loginPasskeyStart, loginPasskeyFinish } from '../../lib/api';
import { base64urlEncode } from '../../crypto/encoding';
import { navigate } from '../../router';
import { PasskeyIcon, TriangleExclamationIcon } from '../../components/Icons';

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

export function LoginPage() {
  const auth = useAuth();
  const [state, setState] = useState<LoginState>(() =>
    supportsWebAuthn() ? { step: 'ready' } : { step: 'unsupported' },
  );

  // Redirect if already authenticated
  if (auth.authenticated) {
    navigate('/');
    return null;
  }

  const busy = state.step === 'authenticating';

  const handleLogin = useCallback(async () => {
    if (busy) return;
    setState({ step: 'authenticating' });

    try {
      // 1. Get passkey credential from browser (discoverable — no allowCredentials)
      // We need a challenge first, but for discoverable flow we need the credential_id
      // to start. Use a two-step approach: get credential first with a dummy challenge,
      // then do the server flow.
      // Actually, the server requires credential_id to start login. So we first
      // invoke the browser's passkey picker, then call the server.

      // The server's login/start needs a credential_id. For discoverable credentials,
      // we first need to get the credential_id from the browser. We'll use a preliminary
      // navigator.credentials.get() without a server challenge, then do the full flow.
      // However, WebAuthn requires a challenge. We'll generate a throwaway one locally
      // for the initial credential selection, then do the actual server challenge.

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
      auth.login(finishRes.session_token, finishRes.display_name);
      setState({ step: 'done' });
      navigate('/');
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
        <div>
          <PasskeyIcon class="text-primary mx-auto mb-2 size-10" />
          <h2 class="heading">Log In</h2>
          <p class="mt-1">
            Use your passkey to sign in anonymously.
            <br />
            Your browser will show available passkeys.
          </p>
        </div>

        {state.step === 'error' && (
          <div
            role="alert"
            class="flex items-start gap-2 rounded-md border border-error/30 bg-error/5 px-3 py-2.5 text-left text-error"
          >
            <TriangleExclamationIcon class="mt-0.5 size-4 shrink-0" />
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
          href="/register"
          class="link"
          onClick={(e: MouseEvent) => {
            e.preventDefault();
            navigate('/register');
          }}
        >
          Register a New Account
        </a>
      </p>
    </div>
  );
}
