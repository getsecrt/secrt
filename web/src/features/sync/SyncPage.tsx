import { useState, useEffect, useRef } from 'preact/hooks';
import { useAuth } from '../../lib/auth-context';
import { navigate } from '../../router';
import { base64urlDecode, base64urlEncode } from '../../crypto/encoding';
import { URL_KEY_LEN } from '../../crypto/constants';
import { open, deriveClaimToken } from '../../crypto/envelope';
import { AMK_LEN } from '../../crypto/amk';
import { claimSecret } from '../../lib/api';
import { storeAmk, loadAmk } from '../../lib/amk-store';
import {
  CheckCircleIcon,
  CircleXmarkIcon,
  TriangleExclamationIcon,
} from '../../components/Icons';
import { CardHeading } from '../../components/CardHeading';

interface SyncPageProps {
  id: string;
}

type SyncStatus =
  | { step: 'init' }
  | { step: 'need-auth' }
  | { step: 'claiming' }
  | { step: 'done' }
  | { step: 'error'; message: string };

export function SyncPage({ id }: SyncPageProps) {
  const auth = useAuth();
  const [status, setStatus] = useState<SyncStatus>({ step: 'init' });
  const abortRef = useRef<AbortController | null>(null);
  const claimedRef = useRef(false);

  // On mount: validate fragment, check auth, then auto-claim
  useEffect(() => {
    return () => {
      abortRef.current?.abort();
      abortRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (auth.loading) return;

    // If not authenticated, redirect to login with full path + hash preserved.
    // Defer via setTimeout so the parent route listener (useRoute in App)
    // has time to attach its popstate handler — child effects fire before
    // parent effects in Preact, so a synchronous navigate() here would be
    // lost on initial page load.
    if (!auth.authenticated) {
      const currentPath = window.location.pathname + window.location.hash;
      setTimeout(
        () => navigate(`/login?redirect=${encodeURIComponent(currentPath)}`),
        0,
      );
      return;
    }

    // Already done or already claiming — don't restart
    if (claimedRef.current) return;

    const fragment = window.location.hash.slice(1);
    if (!fragment) {
      setStatus({
        step: 'error',
        message: 'This sync link is incomplete. The decryption key is missing.',
      });
      return;
    }

    let urlKey: Uint8Array;
    try {
      urlKey = base64urlDecode(fragment);
      if (urlKey.length !== URL_KEY_LEN) throw new Error('bad length');
    } catch {
      setStatus({
        step: 'error',
        message: 'This sync link is malformed. The decryption key is invalid.',
      });
      return;
    }

    // Auto-claim and import AMK
    claimedRef.current = true;
    const controller = new AbortController();
    abortRef.current = controller;

    (async () => {
      setStatus({ step: 'claiming' });

      try {
        // 1. Claim the secret
        const claimToken = await deriveClaimToken(urlKey);
        if (controller.signal.aborted) return;

        const res = await claimSecret(
          id,
          { claim: base64urlEncode(claimToken) },
          controller.signal,
        );

        // 2. Decrypt envelope
        const result = await open(res.envelope, urlKey);
        if (controller.signal.aborted) return;

        // 3. Verify the sync link belongs to the current user
        if (result.meta.userId && result.meta.userId !== auth.userId) {
          setStatus({
            step: 'error',
            message:
              'This sync link belongs to a different account.\nLog in as the correct user and try again.',
          });
          return;
        }

        // 5. Validate AMK (must be exactly 32 bytes)
        if (result.content.length !== AMK_LEN) {
          setStatus({
            step: 'error',
            message: `Invalid notes key: expected ${AMK_LEN} bytes, got ${result.content.length}.`,
          });
          return;
        }

        // 6. Check if we already have an AMK — warn if replacing
        const existing = await loadAmk(auth.userId!);
        if (existing) {
          // Overwrite — the user explicitly chose to sync
        }

        // 7. Store AMK in IndexedDB
        await storeAmk(auth.userId!, result.content);

        setStatus({ step: 'done' });
      } catch (err) {
        if (controller.signal.aborted) return;
        const message =
          err instanceof Error ? err.message : 'Failed to import notes key.';
        // Provide friendly messages for common errors
        if (message.includes('404') || message.includes('not found')) {
          setStatus({
            step: 'error',
            message:
              'This sync link has expired or was already used.\nSync links can only be used once.',
          });
        } else if (message.includes('410') || message.includes('claimed')) {
          setStatus({
            step: 'error',
            message: 'This sync link has already been used.',
          });
        } else {
          setStatus({ step: 'error', message });
        }
      }
    })();
  }, [auth.loading, auth.authenticated, auth.userId, id]);

  // Loading state while auth is resolving
  if (auth.loading || status.step === 'init') {
    return (
      <div class="card space-y-4 text-center">
        <div class="flex justify-center">
          <div class="size-8 animate-spin rounded-full border-2 border-border border-t-accent" />
        </div>
        <p class="text-muted">Preparing&hellip;</p>
      </div>
    );
  }

  // Claiming in progress
  if (status.step === 'claiming') {
    return (
      <div class="card space-y-4 text-center">
        <div class="flex justify-center">
          <div class="size-8 animate-spin rounded-full border-2 border-border border-t-accent" />
        </div>
        <p class="text-muted">Importing notes key&hellip;</p>
      </div>
    );
  }

  // Error
  if (status.step === 'error') {
    return (
      <div class="card space-y-5">
        <CardHeading
          title="Sync Failed"
          icon={<CircleXmarkIcon class="size-10 text-error" />}
        />
        <p class="text-center whitespace-pre-line text-muted">
          {status.message}
        </p>
        <div class="flex flex-col items-center gap-3">
          <a
            href="/dashboard"
            class="link"
            onClick={(e: MouseEvent) => {
              e.preventDefault();
              navigate('/dashboard');
            }}
          >
            Go to Dashboard
          </a>
        </div>
      </div>
    );
  }

  // Success
  return (
    <div class="card space-y-5">
      <CardHeading
        title="Notes Key Synced"
        icon={<CheckCircleIcon class="size-10 text-success" />}
      />
      <p class="text-center text-muted">
        Your notes key has been imported to this browser. You can now view and
        create private notes on your secrets.
      </p>
      <div class="flex flex-col items-center gap-3">
        <a
          href="/dashboard"
          class="link"
          onClick={(e: MouseEvent) => {
            e.preventDefault();
            navigate('/dashboard');
          }}
        >
          Go to Dashboard
        </a>
      </div>
    </div>
  );
}
