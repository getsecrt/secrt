/**
 * PairDisplayPanel — Page A of /pair.
 *
 * This device lacks the AMK. We publish an ephemeral ECDH pubkey at
 * /start, render the user_code + QR + a MM:SS countdown, and poll
 * /poll for the amk_transfer that the keyed device will produce on
 * /approve. The keyed device is the sole actor; this page is purely
 * receive-side.
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'preact/hooks';
import { encode } from 'uqr';
import { useAuth } from '../../lib/auth-context';
import { navigate } from '../../router';
import {
  pairStart,
  pairPoll,
  pairCancel,
  type PairStartResponse,
  type PairPollResponse,
} from '../../lib/api';
import { generateEcdhKeyPair, exportPublicKey } from '../../crypto/amk';
import { base64urlEncode } from '../../crypto/encoding';
import { CardHeading } from '../../components/CardHeading';
import {
  CheckCircleIcon,
  TriangleExclamationIcon,
} from '../../components/Icons';
import { CopyButton } from '../../components/CopyButton';
import {
  decryptAmkFromPeer,
  verifyAndStoreReceivedAmk,
  AmkCommitMismatchError,
} from './pair-crypto';
import { formatPairUrl } from '../../lib/url';
import { usePairPolling } from './use-pair-polling';

type DisplayState =
  | { kind: 'starting' }
  | { kind: 'waiting'; slot: PairStartResponse }
  | { kind: 'expired'; slot: PairStartResponse }
  | { kind: 'success' }
  | { kind: 'cross-account-error' }
  | { kind: 'error'; message: string };

const QR_SIZE_PX = 224;

function QrCanvas({ url }: { url: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const qr = encode(url);
    const modules = qr.size;
    const dpr = window.devicePixelRatio || 1;
    const px = Math.floor((QR_SIZE_PX * dpr) / modules);
    const dim = px * modules;
    canvas.width = dim;
    canvas.height = dim;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const dark = document.documentElement.classList.contains('dark');
    ctx.fillStyle = dark ? '#000' : '#fff';
    ctx.fillRect(0, 0, dim, dim);
    ctx.fillStyle = dark ? '#fff' : '#000';
    for (let y = 0; y < modules; y++) {
      for (let x = 0; x < modules; x++) {
        if (qr.data[y][x]) ctx.fillRect(x * px, y * px, px, px);
      }
    }
  }, [url]);
  return (
    <canvas ref={ref} role="img" aria-label="Pair code QR" class="size-56" />
  );
}

function formatCountdown(remainingMs: number): string {
  const totalSec = Math.max(0, Math.floor(remainingMs / 1000));
  const mm = Math.floor(totalSec / 60)
    .toString()
    .padStart(2, '0');
  const ss = (totalSec % 60).toString().padStart(2, '0');
  return `${mm}:${ss}`;
}

function Countdown({
  expiresAt,
  onExpired,
}: {
  expiresAt: string;
  onExpired: () => void;
}) {
  const target = useMemo(() => Date.parse(expiresAt), [expiresAt]);
  const [remaining, setRemaining] = useState(() =>
    Math.max(0, target - Date.now()),
  );
  useEffect(() => {
    if (Number.isNaN(target)) return;
    const tick = () => {
      const next = Math.max(0, target - Date.now());
      setRemaining(next);
      if (next === 0) onExpired();
    };
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [target, onExpired]);
  return (
    <p class="text-sm text-muted">
      Expires in{' '}
      <span class="font-mono tabular-nums">{formatCountdown(remaining)}</span>
    </p>
  );
}

export function PairDisplayPanel() {
  const auth = useAuth();
  const [state, setState] = useState<DisplayState>({ kind: 'starting' });
  // Holds the ECDH private key (cannot live in state — CryptoKey isn't
  // serializable and must persist across renders without rebuild).
  const privateKeyRef = useRef<CryptoKey | null>(null);

  // Start the slot exactly once.
  useEffect(() => {
    if (!auth.sessionToken) return;
    let cancelled = false;
    (async () => {
      try {
        const kp = await generateEcdhKeyPair();
        privateKeyRef.current = kp.privateKey;
        const pkBytes = await exportPublicKey(kp.publicKey);
        const slot = await pairStart(auth.sessionToken!, {
          ecdh_public_key: base64urlEncode(pkBytes),
        });
        if (cancelled) return;
        setState({ kind: 'waiting', slot });
      } catch (err) {
        if (cancelled) return;
        setState({
          kind: 'error',
          message:
            err instanceof Error ? err.message : 'Failed to start pairing.',
        });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [auth.sessionToken]);

  // Cancel-on-unmount (idempotent on terminal slots). The countdown
  // expiring is a UI state only — the server is authoritative and the
  // reaper handles real expiry. Track the live token in a ref so the
  // cleanup fires once on unmount, not every time `state` flips into
  // a terminal kind (which would otherwise hit /cancel on timer expiry).
  const liveSlotRef = useRef<string | null>(null);
  liveSlotRef.current =
    state.kind === 'waiting' ? state.slot.displayer_poll_token : null;
  useEffect(() => {
    return () => {
      const token = liveSlotRef.current;
      if (token && auth.sessionToken) {
        void pairCancel(auth.sessionToken, token).catch(() => {});
      }
    };
  }, [auth.sessionToken]);

  const handleDelivery = useCallback(
    async (poll: PairPollResponse, signal: AbortSignal): Promise<boolean> => {
      if (!auth.sessionToken || !auth.userId || !poll.amk_transfer)
        return false;
      const priv = privateKeyRef.current;
      if (!priv) {
        setState({
          kind: 'error',
          message: 'Internal error: ECDH key was not generated.',
        });
        return true;
      }
      try {
        const amk = await decryptAmkFromPeer(priv, poll.amk_transfer);
        if (signal.aborted) return true;
        await verifyAndStoreReceivedAmk({
          sessionToken: auth.sessionToken,
          userId: auth.userId,
          amk,
          signal,
        });
        if (signal.aborted) return true;
        setState({ kind: 'success' });
        return true;
      } catch (err) {
        if (err instanceof AmkCommitMismatchError) {
          setState({ kind: 'cross-account-error' });
          return true;
        }
        setState({
          kind: 'error',
          message:
            err instanceof Error
              ? err.message
              : 'Failed to decrypt the transferred key.',
        });
        return true;
      }
    },
    [auth.sessionToken, auth.userId],
  );

  const onPoll = useCallback(
    async (signal: AbortSignal): Promise<boolean> => {
      if (!auth.sessionToken) return true;
      if (state.kind !== 'waiting') return true;
      const slot = state.slot;
      try {
        const res = await pairPoll(
          auth.sessionToken,
          slot.displayer_poll_token,
          signal,
        );
        if (signal.aborted) return true;

        if (res.status === 'cancelled' || res.status === 'expired') {
          setState({
            kind: 'error',
            message:
              res.status === 'cancelled'
                ? 'The pairing was cancelled on the other device.'
                : 'The pairing code expired before it was used.',
          });
          return true;
        }

        if (res.status === 'approved' && res.amk_transfer) {
          return handleDelivery(res, signal);
        }
        // pending — keep polling.
        return false;
      } catch (err) {
        if (signal.aborted) return true;
        const msg = err instanceof Error ? err.message : '';
        if (/401|forbidden|unauthorized/i.test(msg)) {
          setState({ kind: 'error', message: msg });
          return true;
        }
        return false;
      }
    },
    [auth.sessionToken, state, handleDelivery],
  );

  usePairPolling(onPoll, { enabled: state.kind === 'waiting' });

  const handleExpired = useCallback(() => {
    setState((prev) =>
      prev.kind === 'waiting' ? { kind: 'expired', slot: prev.slot } : prev,
    );
  }, []);

  const shareUrl = useMemo(() => {
    if (state.kind !== 'waiting') return '';
    return formatPairUrl(state.slot.user_code);
  }, [state]);

  // ── Render ────────────────────────────────────────────────────────

  if (state.kind === 'starting') {
    return (
      <div class="card text-center">
        <p class="text-muted">Starting pairing…</p>
      </div>
    );
  }

  if (state.kind === 'error') {
    return (
      <div class="card space-y-4 text-center">
        <CardHeading
          title="Pairing failed"
          icon={<TriangleExclamationIcon class="text-warning size-10" />}
        />
        <p class="text-muted">{state.message}</p>
        <button
          type="button"
          class="btn btn-primary tracking-wider uppercase"
          onClick={() => navigate('/dashboard')}
        >
          Back to Dashboard
        </button>
      </div>
    );
  }

  if (state.kind === 'cross-account-error') {
    return (
      <div class="card space-y-4 text-center">
        <CardHeading
          title="Different Account Key"
          icon={<TriangleExclamationIcon class="text-warning size-10" />}
        />
        <p>
          This account key was created for a different account. We won't replace
          your existing key.
        </p>
        <p class="text-sm text-muted">
          If you intended to switch accounts, sign out first, then sign in with
          the other account on this browser.
        </p>
        <button
          type="button"
          class="btn btn-primary tracking-wider uppercase"
          onClick={() => navigate('/dashboard')}
        >
          Back to Dashboard
        </button>
      </div>
    );
  }

  if (state.kind === 'success') {
    return (
      <div class="card space-y-4 text-center">
        <CardHeading
          title="Account Key Received"
          icon={<CheckCircleIcon class="size-10 text-success" />}
        />
        <p class="text-muted">
          This browser can now read your encrypted notes.
        </p>
        <button
          type="button"
          class="btn btn-primary tracking-wider uppercase"
          onClick={() => navigate('/dashboard')}
        >
          Continue
        </button>
      </div>
    );
  }

  if (state.kind === 'expired') {
    return (
      <div class="card space-y-4 text-center">
        <CardHeading
          title="Code expired"
          subtitle="That pairing code is no longer valid."
        />
        <p class="text-muted">Start over to get a fresh code.</p>
        <button
          type="button"
          class="btn btn-primary tracking-wider uppercase"
          onClick={() => window.location.reload()}
        >
          Restart Pairing
        </button>
      </div>
    );
  }

  // state.kind === 'waiting'
  const slot = state.slot;
  return (
    <div class="card space-y-5 text-center">
      <CardHeading
        title="Pair this device"
        subtitle={
          <>
            On a device with your account key, visit
            <p class="my-2 text-base font-semibold text-neutral-700 dark:text-neutral-300">
              {window.location.host}/pair
            </p>
            and enter this code:
          </>
        }
      />

      <div class="bg-surface-alt mx-auto rounded-lg px-6 py-4 font-mono text-3xl font-bold tracking-[0.3em]">
        {slot.user_code}
      </div>

      <div class="flex justify-center">
        <CopyButton text={shareUrl} label="Copy Pairing Link" />
      </div>

      <div class="flex justify-center">
        <QrCanvas url={shareUrl} />
      </div>

      <Countdown expiresAt={slot.expires_at} onExpired={handleExpired} />

      <p class="text-muted">
        Both browsers must be signed in as the same account.
      </p>
    </div>
  );
}
