import { useState, useCallback } from 'preact/hooks';
import { useAuth } from '../../lib/auth-context';
import { supportsWebAuthn, createPasskeyCredential, generateUserId } from '../../lib/webauthn';
import { registerPasskeyStart, registerPasskeyFinish } from '../../lib/api';
import { navigate } from '../../router';
import { FingerprintIcon, TriangleExclamationIcon } from '../../components/Icons';

type RegisterState =
  | { step: 'input' }
  | { step: 'creating' }
  | { step: 'done' }
  | { step: 'error'; message: string }
  | { step: 'unsupported' };

export function RegisterPage() {
  const auth = useAuth();
  const [displayName, setDisplayName] = useState('');
  const [handle, setHandle] = useState('');
  const [state, setState] = useState<RegisterState>(() =>
    supportsWebAuthn() ? { step: 'input' } : { step: 'unsupported' },
  );

  // Redirect if already authenticated
  if (auth.authenticated) {
    navigate('/');
    return null;
  }

  const busy = state.step === 'creating';

  const handleSubmit = useCallback(
    async (e: Event) => {
      e.preventDefault();
      if (!displayName.trim() || busy) return;

      setState({ step: 'creating' });

      try {
        // 1. Start registration — get challenge from server
        const startRes = await registerPasskeyStart({
          display_name: displayName.trim(),
          handle: handle.trim() || undefined,
        });

        // 2. Create passkey credential in browser
        const userId = generateUserId();
        const credential = await createPasskeyCredential(
          startRes.challenge,
          userId,
          handle.trim() || displayName.trim(),
          displayName.trim(),
        );

        // 3. Finish registration — send credential to server
        const finishRes = await registerPasskeyFinish({
          challenge_id: startRes.challenge_id,
          credential_id: credential.credentialId,
          public_key: credential.publicKey,
        });

        // 4. Log in with the returned session
        auth.login(finishRes.session_token, finishRes.user_id, finishRes.handle);
        setState({ step: 'done' });
        navigate('/');
      } catch (err) {
        if (err instanceof DOMException && err.name === 'NotAllowedError') {
          setState({ step: 'error', message: 'Passkey creation was cancelled.' });
        } else {
          setState({
            step: 'error',
            message: err instanceof Error ? err.message : 'Registration failed.',
          });
        }
      }
    },
    [displayName, handle, busy, auth],
  );

  if (state.step === 'unsupported') {
    return (
      <div class="card space-y-4 text-center">
        <TriangleExclamationIcon class="mx-auto size-8 text-warning" />
        <h2 class="label">Passkeys not supported</h2>
        <p class="text-sm text-muted">
          Your browser doesn't support passkeys (WebAuthn). Please use a modern
          browser like Chrome, Safari, or Firefox.
        </p>
      </div>
    );
  }

  return (
    <div class="space-y-4">
      <form class="card space-y-6" onSubmit={handleSubmit}>
        <div class="text-center">
          <FingerprintIcon class="mx-auto mb-2 size-8 text-primary" />
          <h2 class="label">Create an account</h2>
          <p class="mt-1 text-sm text-muted">
            Register with a passkey for higher limits and secret management.
          </p>
        </div>

        <div class="space-y-1">
          <label class="text-sm font-medium text-muted" for="display-name">
            Display Name
          </label>
          <input
            id="display-name"
            type="text"
            class="input"
            placeholder="Your name"
            value={displayName}
            onInput={(e) => setDisplayName((e.target as HTMLInputElement).value)}
            disabled={busy}
            required
            autoFocus
          />
        </div>

        <div class="space-y-1">
          <label class="text-sm font-medium text-muted" for="handle">
            Handle <span class="font-normal text-faint">(optional)</span>
          </label>
          <input
            id="handle"
            type="text"
            class="input"
            placeholder="@handle"
            value={handle}
            onInput={(e) => setHandle((e.target as HTMLInputElement).value)}
            disabled={busy}
          />
        </div>

        {state.step === 'error' && (
          <div
            role="alert"
            class="flex items-start gap-2 rounded-md border border-error/30 bg-error/5 px-3 py-2.5 text-sm text-error"
          >
            <TriangleExclamationIcon class="mt-0.5 size-4 shrink-0" />
            {state.message}
          </div>
        )}

        <button
          type="submit"
          class="btn btn-primary w-full tracking-wider uppercase"
          disabled={!displayName.trim() || busy}
        >
          {busy ? 'Creating passkey\u2026' : 'Register with Passkey'}
        </button>
      </form>

      <p class="text-center text-sm text-muted">
        Already have an account?{' '}
        <a
          href="/login"
          class="link"
          onClick={(e: MouseEvent) => {
            e.preventDefault();
            navigate('/login');
          }}
        >
          Log in
        </a>
      </p>
    </div>
  );
}
