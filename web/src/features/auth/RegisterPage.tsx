import { useState, useCallback } from 'preact/hooks';
import { useAuth } from '../../lib/auth-context';
import {
  supportsWebAuthn,
  createPasskeyCredential,
  generateUserId,
} from '../../lib/webauthn';
import { registerPasskeyStart, registerPasskeyFinish } from '../../lib/api';
import { navigate } from '../../router';
import {
  PasskeyIcon,
  ShuffleIcon,
  TriangleExclamationIcon,
} from '../../components/Icons';
import { CardHeading } from '../../components/CardHeading';

// --- Random display name generator ---
// ~2 500 combinations for privacy-friendly default names.
const ADJECTIVES = [
  'Silent',
  'Hidden',
  'Masked',
  'Covert',
  'Shadow',
  'Ghost',
  'Stealth',
  'Phantom',
  'Veiled',
  'Cryptic',
  'Secret',
  'Cloaked',
  'Guarded',
  'Sealed',
  'Shielded',
  'Obsidian',
  'Onyx',
  'Furtive',
  'Arcane',
  'Nimble',
  'Dusk',
  'Midnight',
  'Ember',
  'Frost',
  'Iron',
  'Ashen',
  'Copper',
  'Misty',
  'Wary',
  'Deft',
  'Keen',
  'Swift',
  'Bold',
  'Clever',
  'Quiet',
  'Sturdy',
  'Vivid',
  'Wispy',
  'Lucid',
  'Stark',
  'Rustic',
  'Lunar',
  'Solar',
  'Coral',
  'Amber',
  'Brisk',
  'Rapid',
  'Steady',
  'Subtle',
  'Dusky',
];
const NOUNS = [
  'Fox',
  'Owl',
  'Wolf',
  'Bear',
  'Hawk',
  'Lynx',
  'Raven',
  'Cobra',
  'Otter',
  'Panda',
  'Heron',
  'Crane',
  'Bison',
  'Moose',
  'Eagle',
  'Viper',
  'Falcon',
  'Badger',
  'Jaguar',
  'Osprey',
  'Wren',
  'Finch',
  'Marten',
  'Ferret',
  'Newt',
  'Stoat',
  'Shrike',
  'Ibis',
  'Gecko',
  'Puma',
  'Egret',
  'Condor',
  'Mink',
  'Coyote',
  'Jackal',
  'Mantis',
  'Parrot',
  'Lemur',
  'Ocelot',
  'Macaw',
  'Quail',
  'Toad',
  'Moth',
  'Beetle',
  'Ermine',
  'Grouse',
  'Marmot',
  'Bobcat',
  'Hare',
  'Wombat',
];

function randomName(): string {
  const adj = ADJECTIVES[Math.floor(Math.random() * ADJECTIVES.length)];
  const noun = NOUNS[Math.floor(Math.random() * NOUNS.length)];
  return `${adj} ${noun}`;
}

type RegisterState =
  | { step: 'input' }
  | { step: 'creating' }
  | { step: 'done' }
  | { step: 'error'; message: string }
  | { step: 'unsupported' };

export function RegisterPage() {
  const auth = useAuth();
  const [displayName, setDisplayName] = useState(randomName);
  const [state, setState] = useState<RegisterState>(() =>
    supportsWebAuthn() ? { step: 'input' } : { step: 'unsupported' },
  );

  // Redirect if already authenticated
  if (auth.authenticated) {
    navigate('/');
    return null;
  }

  const busy = state.step === 'creating';
  const nameError =
    state.step === 'error' && state.message.includes('display name');

  const handleSubmit = useCallback(
    async (e: Event) => {
      e.preventDefault();
      if (busy) return;

      if (!displayName.trim()) {
        setState({
          step: 'error',
          message: 'Please enter a display name.',
        });
        return;
      }

      setState({ step: 'creating' });

      try {
        // 1. Start registration — get challenge from server
        const startRes = await registerPasskeyStart({
          display_name: displayName.trim(),
        });

        // 2. Create passkey credential in browser
        const userId = generateUserId();
        const credential = await createPasskeyCredential(
          startRes.challenge,
          userId,
          displayName.trim(),
          displayName.trim(),
        );

        // 3. Finish registration — send credential to server
        const finishRes = await registerPasskeyFinish({
          challenge_id: startRes.challenge_id,
          credential_id: credential.credentialId,
          public_key: credential.publicKey,
        });

        // 4. Log in with the returned session
        auth.login(finishRes.session_token, finishRes.display_name);
        setState({ step: 'done' });
        navigate('/');
      } catch (err) {
        if (err instanceof DOMException && err.name === 'NotAllowedError') {
          setState({
            step: 'error',
            message: 'Passkey creation was cancelled.',
          });
        } else {
          setState({
            step: 'error',
            message:
              err instanceof Error ? err.message : 'Registration failed.',
          });
        }
      }
    },
    [displayName, busy, auth],
  );

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
      <form class="card space-y-6" onSubmit={handleSubmit}>
        <CardHeading
          title="Log In"
          icon={<PasskeyIcon class="size-10" />}
          subtitle={
            'Register with a passkey for higher limits, larger file uploads, and secret management.'
          }
          class="mb-4"
        />

        <div class="space-y-1.5">
          <label class="block font-medium text-muted" for="display-name">
            Account Nickname
          </label>
          <div class="relative">
            <input
              id="display-name"
              type="text"
              class={`input pr-10 ${nameError ? 'input-error' : ''}`}
              placeholder="Nickname"
              value={displayName}
              onInput={(e) => {
                setDisplayName((e.target as HTMLInputElement).value);
                if (state.step === 'error') setState({ step: 'input' });
              }}
              disabled={busy}
              autoFocus
            />
            <button
              type="button"
              class="absolute top-1/2 right-2 -translate-y-1/2 p-1 text-muted hover:text-text"
              onClick={() => setDisplayName(randomName())}
              aria-label="Generate random name"
              tabIndex={-1}
            >
              <ShuffleIcon class="size-5" />
            </button>
          </div>
          <p class="text-xs text-faint">
            A random name is generated for privacy, but you can change it.
          </p>
        </div>

        {state.step === 'error' && (
          <div
            role="alert"
            class="flex items-start gap-2 rounded-md border border-error/30 bg-error/5 px-3 py-2.5 text-error"
          >
            <TriangleExclamationIcon class="mt-0.5 size-5 shrink-0" />
            {state.message}
          </div>
        )}

        <button
          type="submit"
          class="btn btn-primary w-full tracking-wider uppercase"
          disabled={busy}
        >
          {busy ? 'Creating passkey\u2026' : 'Register with Passkey'}
        </button>
      </form>

      <p class="text-center text-muted">
        Already have an account?
        <br />
        <a
          href="/login"
          class="link"
          onClick={(e: MouseEvent) => {
            e.preventDefault();
            navigate('/login');
          }}
        >
          Log In
        </a>
      </p>
    </div>
  );
}
