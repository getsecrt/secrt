/**
 * PairDisplayPanel — the side that shows a code + QR for the other browser
 * to scan/type. Two roles:
 *
 *   role=receive: this browser is new and needs the AMK. Generates an
 *     ephemeral ECDH keypair, posts the pubkey to /start, and polls for an
 *     amk_transfer the joiner-as-sender will produce. Verifies the commit
 *     before storing.
 *
 *   role=send: this browser has the AMK. Posts /start without a pubkey,
 *     waits for a joiner to /claim, then renders an approval screen with
 *     the joiner's UA + timestamp. On approve, encrypts the AMK to the
 *     joiner's pubkey and calls /pair/approve.
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
  pairApprove,
  pairCancel,
  type PairRole,
  type PairStartResponse,
  type PairPollResponse,
} from '../../lib/api';
import { loadAmk } from '../../lib/amk-store';
import { generateEcdhKeyPair, exportPublicKey } from '../../crypto/amk';
import { base64urlEncode } from '../../crypto/encoding';
import { CardHeading } from '../../components/CardHeading';
import {
  CheckCircleIcon,
  TriangleExclamationIcon,
} from '../../components/Icons';
import { CopyButton } from '../../components/CopyButton';
import {
  encryptAmkForPeer,
  decryptAmkFromPeer,
  verifyAndStoreReceivedAmk,
  AmkCommitMismatchError,
} from './pair-crypto';
import { formatPairUrl } from '../../lib/url';
import { usePairPolling } from './use-pair-polling';

interface Props {
  role: PairRole;
  onChooseJoin: () => void;
}

type DisplayState =
  | { kind: 'starting' }
  | { kind: 'waiting'; slot: PairStartResponse }
  | {
      kind: 'review-joiner';
      slot: PairStartResponse;
      joinerUserAgent: string | null;
      joinerSeenAt: string | null;
      peerEcdhPublicKey: string;
    }
  | { kind: 'approving'; slot: PairStartResponse }
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

function describeUa(ua: string | null): string {
  if (!ua) return 'Unknown device';
  // Best-effort tidy-up — UA strings are spoofable advisory copy.
  return ua.length > 80 ? ua.slice(0, 80) + '…' : ua;
}

export function PairDisplayPanel({ role, onChooseJoin }: Props) {
  const auth = useAuth();
  const [state, setState] = useState<DisplayState>({ kind: 'starting' });
  // Holds the ECDH private key for role=receive (cannot live in state — CryptoKey
  // isn't serializable and must persist across renders without rebuild).
  const privateKeyRef = useRef<CryptoKey | null>(null);

  // Start the slot exactly once.
  useEffect(() => {
    if (!auth.sessionToken) return;
    let cancelled = false;
    (async () => {
      try {
        let ecdhPublicKey: string | undefined;
        if (role === 'receive') {
          const kp = await generateEcdhKeyPair();
          privateKeyRef.current = kp.privateKey;
          const pkBytes = await exportPublicKey(kp.publicKey);
          ecdhPublicKey = base64urlEncode(pkBytes);
        }
        const slot = await pairStart(auth.sessionToken!, {
          role,
          ecdh_public_key: ecdhPublicKey,
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
  }, [auth.sessionToken, role]);

  // Cancel-on-unmount (idempotent on terminal slots).
  const slotPollToken =
    state.kind === 'waiting' ||
    state.kind === 'review-joiner' ||
    state.kind === 'approving'
      ? state.slot.displayer_poll_token
      : null;
  useEffect(() => {
    if (!slotPollToken || !auth.sessionToken) return;
    return () => {
      void pairCancel(auth.sessionToken!, slotPollToken).catch(() => {});
    };
  }, [slotPollToken, auth.sessionToken]);

  // Receiver-side: mid-poll AMK delivery, commit verification, store.
  const handleReceiverDelivery = useCallback(
    async (
      slot: PairStartResponse,
      poll: PairPollResponse,
      signal: AbortSignal,
    ): Promise<boolean> => {
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

  // Polling handler. One per render — captures `state` via closure but only
  // dispatches based on the freshly fetched response.
  const onPoll = useCallback(
    async (signal: AbortSignal): Promise<boolean> => {
      if (!auth.sessionToken) return true;
      // Don't poll while we're not in a polling state.
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

        if (role === 'receive') {
          if (res.status === 'approved' && res.amk_transfer) {
            return handleReceiverDelivery(slot, res, signal);
          }
          // pending — keep polling.
          return false;
        }

        // role === 'send'
        if (res.status === 'claimed' && res.peer_ecdh_public_key) {
          setState({
            kind: 'review-joiner',
            slot,
            joinerUserAgent: res.joiner_user_agent ?? null,
            joinerSeenAt: res.joiner_seen_at ?? null,
            peerEcdhPublicKey: res.peer_ecdh_public_key,
          });
          return true;
        }
        if (res.status === 'approved') {
          // Already approved (e.g. tab restored after a prior approve).
          setState({ kind: 'success' });
          return true;
        }
        return false;
      } catch (err) {
        if (signal.aborted) return true;
        // Transient — let the loop retry.
        const msg = err instanceof Error ? err.message : '';
        if (/401|forbidden|unauthorized/i.test(msg)) {
          setState({ kind: 'error', message: msg });
          return true;
        }
        return false;
      }
    },
    [auth.sessionToken, state, role, handleReceiverDelivery],
  );

  usePairPolling(onPoll, { enabled: state.kind === 'waiting' });

  const shareUrl = useMemo(() => {
    if (state.kind === 'starting' || state.kind === 'error') return '';
    const slotState =
      state.kind === 'waiting' ||
      state.kind === 'review-joiner' ||
      state.kind === 'approving'
        ? state.slot
        : null;
    if (!slotState) return '';
    return formatPairUrl(slotState.user_code);
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
          title={
            role === 'receive' ? 'Account Key Received' : 'Account Key Sent'
          }
          icon={<CheckCircleIcon class="size-10 text-success" />}
        />
        <p class="text-muted">
          {role === 'receive'
            ? 'This browser can now read your encrypted notes.'
            : 'The other device now has your account key.'}
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

  if (state.kind === 'review-joiner') {
    const handleApprove = async () => {
      if (!auth.sessionToken || !auth.userId) return;
      setState({ kind: 'approving', slot: state.slot });
      try {
        const amk = await loadAmk(auth.userId);
        if (!amk) {
          setState({
            kind: 'error',
            message:
              'No account key is stored on this browser. Sign in on a device that has it first.',
          });
          return;
        }
        const { amkTransfer } = await encryptAmkForPeer(
          state.peerEcdhPublicKey,
          amk,
        );
        await pairApprove(auth.sessionToken, {
          user_code: state.slot.user_code,
          amk_transfer: amkTransfer,
        });
        setState({ kind: 'success' });
      } catch (err) {
        setState({
          kind: 'error',
          message: err instanceof Error ? err.message : 'Approval failed.',
        });
      }
    };
    const handleReject = async () => {
      if (!auth.sessionToken) return;
      try {
        await pairCancel(auth.sessionToken, state.slot.displayer_poll_token);
      } catch {
        /* idempotent — surface a generic message either way */
      }
      setState({
        kind: 'error',
        message: 'Pairing cancelled.',
      });
    };

    const seenAt = state.joinerSeenAt
      ? new Date(state.joinerSeenAt).toLocaleString()
      : 'just now';
    return (
      <div class="card space-y-4">
        <CardHeading
          title="Approve this device?"
          subtitle="A browser signed into your account is asking for your account key."
        />
        <dl class="space-y-2 text-sm">
          <div>
            <dt class="font-medium text-muted">Device</dt>
            <dd class="break-words">{describeUa(state.joinerUserAgent)}</dd>
          </div>
          <div>
            <dt class="font-medium text-muted">Joined</dt>
            <dd>{seenAt}</dd>
          </div>
        </dl>
        <p class="bg-surface-alt rounded-md border border-border p-3 text-sm text-muted">
          Approve only if you started this on the other device. The label above
          is advisory and can be spoofed.
        </p>
        <div class="flex gap-3">
          <button
            type="button"
            class="btn flex-1 tracking-wider uppercase"
            onClick={handleReject}
          >
            Reject
          </button>
          <button
            type="button"
            class="btn btn-primary flex-1 tracking-wider uppercase"
            onClick={handleApprove}
          >
            Approve
          </button>
        </div>
      </div>
    );
  }

  if (state.kind === 'approving') {
    return (
      <div class="card text-center">
        <p class="text-muted">Sending account key…</p>
      </div>
    );
  }

  // state.kind === 'waiting'
  const slot = state.slot;
  return (
    <div class="card space-y-5 text-center">
      <CardHeading
        title={role === 'receive' ? 'Pair this browser' : 'Pair another device'}
        subtitle={
          role === 'receive'
            ? 'Scan or type this on the browser that already has your account key.'
            : 'Scan or type this on the new browser to send it your account key.'
        }
      />

      <div class="bg-surface-alt mx-auto rounded-lg px-6 py-4 font-mono text-3xl font-bold tracking-[0.3em]">
        {slot.user_code}
      </div>

      <div class="flex justify-center">
        <QrCanvas url={shareUrl} />
      </div>

      <CopyButton text={slot.user_code} label="Copy Code" class="mx-auto" />

      <p class="text-xs text-muted">
        Both browsers must be signed in as the same account.
      </p>

      <button type="button" class="link" onClick={onChooseJoin}>
        Or join a code from another device
      </button>
    </div>
  );
}
