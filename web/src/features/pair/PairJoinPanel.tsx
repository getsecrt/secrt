/**
 * PairJoinPanel — the side that consumes a code from another browser.
 *
 * Two equivalent inputs (scan QR + type code) resolve to the same user_code.
 * `/challenge` then tells us which role the *displayer* is in:
 *
 *   displayer.role=send → joiner is receiver. We /claim with our pubkey and
 *     poll for the amk_transfer the displayer will produce on /approve.
 *
 *   displayer.role=receive → joiner is sender. We confirm intent, then
 *     encrypt our AMK against the displayer's pubkey and /approve directly.
 */

import { useCallback, useEffect, useRef, useState } from 'preact/hooks';
import { useAuth } from '../../lib/auth-context';
import { navigate } from '../../router';
import {
  pairChallenge,
  pairClaim,
  pairApprove,
  pairPoll,
  pairCancel,
  type PairChallengeResult,
  type PairPollResponse,
  type PairClaimResponse,
} from '../../lib/api';
import { loadAmk } from '../../lib/amk-store';
import { generateEcdhKeyPair, exportPublicKey } from '../../crypto/amk';
import { base64urlEncode } from '../../crypto/encoding';
import { CardHeading } from '../../components/CardHeading';
import {
  CheckCircleIcon,
  TriangleExclamationIcon,
} from '../../components/Icons';
import { Modal } from '../../components/Modal';
import {
  encryptAmkForPeer,
  decryptAmkFromPeer,
  verifyAndStoreReceivedAmk,
  AmkCommitMismatchError,
} from './pair-crypto';
import { parsePairUrl } from '../../lib/url';
import { QrScannerView } from './QrScanner';
import { usePairPolling } from './use-pair-polling';

interface Props {
  prefilledCode: string | null;
  onChooseDisplay: () => void;
}

type JoinState =
  | { kind: 'collect-code'; codeInput: string; error: string | null }
  | { kind: 'looking-up'; code: string }
  | {
      kind: 'confirm-send';
      code: string;
      displayerEcdhPublicKey: string;
    }
  | { kind: 'sending'; code: string }
  | { kind: 'claiming'; code: string }
  | {
      kind: 'awaiting-approval';
      code: string;
      claim: PairClaimResponse;
    }
  | { kind: 'success' }
  | { kind: 'cross-account-error' }
  | { kind: 'error'; message: string };

export function PairJoinPanel({ prefilledCode, onChooseDisplay }: Props) {
  const auth = useAuth();
  const [state, setState] = useState<JoinState>(() =>
    prefilledCode
      ? { kind: 'looking-up', code: prefilledCode.toUpperCase() }
      : { kind: 'collect-code', codeInput: '', error: null },
  );
  const [scannerOpen, setScannerOpen] = useState(false);
  // Holds the joiner-as-receiver ECDH private key — see PairDisplayPanel for
  // why this can't live in state.
  const privateKeyRef = useRef<CryptoKey | null>(null);

  // ── Code lookup ─────────────────────────────────────────────────

  const lookupCode = useCallback(
    async (code: string) => {
      if (!auth.sessionToken) return;
      setState({ kind: 'looking-up', code });
      try {
        const res: PairChallengeResult = await pairChallenge(
          auth.sessionToken,
          code,
        );
        if (res.kind === 'not_found') {
          setState({
            kind: 'collect-code',
            codeInput: code,
            error: 'That code is invalid or has expired.',
          });
          return;
        }
        if (res.kind === 'terminal') {
          const map: Record<string, string> = {
            claimed: 'That code is already in use on another browser.',
            approved: 'That pairing was already approved.',
            cancelled: 'That pairing was cancelled.',
          };
          setState({
            kind: 'collect-code',
            codeInput: '',
            error: map[res.state] ?? 'That code is no longer available.',
          });
          return;
        }
        // role is the displayer's role.
        if (res.role === 'receive') {
          // The displayer is receiving. We are the sender.
          if (!res.displayer_ecdh_public_key) {
            setState({
              kind: 'error',
              message:
                'Pairing slot is missing the receiver pubkey — please cancel and start over.',
            });
            return;
          }
          setState({
            kind: 'confirm-send',
            code,
            displayerEcdhPublicKey: res.displayer_ecdh_public_key,
          });
          return;
        }
        // displayer.role === 'send' → we (joiner) are receiver. Claim now.
        setState({ kind: 'claiming', code });
        try {
          const kp = await generateEcdhKeyPair();
          privateKeyRef.current = kp.privateKey;
          const pkBytes = await exportPublicKey(kp.publicKey);
          const claim = await pairClaim(auth.sessionToken, {
            user_code: code,
            ecdh_public_key: base64urlEncode(pkBytes),
          });
          setState({ kind: 'awaiting-approval', code, claim });
        } catch (err) {
          setState({
            kind: 'error',
            message: err instanceof Error ? err.message : 'Claim failed.',
          });
        }
      } catch (err) {
        setState({
          kind: 'error',
          message: err instanceof Error ? err.message : 'Lookup failed.',
        });
      }
    },
    [auth.sessionToken],
  );

  // Auto-trigger lookup when we landed in 'looking-up' (deep-link path).
  const initialLookupRef = useRef(false);
  useEffect(() => {
    if (initialLookupRef.current) return;
    if (state.kind === 'looking-up') {
      initialLookupRef.current = true;
      void lookupCode(state.code);
    }
  }, [state, lookupCode]);

  // Cancel-on-unmount when we have a private joiner_poll_token in flight.
  const liveJoinerToken =
    state.kind === 'awaiting-approval' ? state.claim.joiner_poll_token : null;
  useEffect(() => {
    if (!liveJoinerToken || !auth.sessionToken) return;
    return () => {
      void pairCancel(auth.sessionToken!, liveJoinerToken).catch(() => {});
    };
  }, [liveJoinerToken, auth.sessionToken]);

  // ── Receiver-side polling ───────────────────────────────────────

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
      if (!auth.sessionToken || state.kind !== 'awaiting-approval') return true;
      try {
        const res = await pairPoll(
          auth.sessionToken,
          state.claim.joiner_poll_token,
          signal,
        );
        if (signal.aborted) return true;
        if (res.status === 'cancelled' || res.status === 'expired') {
          setState({
            kind: 'error',
            message:
              res.status === 'cancelled'
                ? 'The pairing was cancelled on the other device.'
                : 'The pairing code expired before it was approved.',
          });
          return true;
        }
        if (res.status === 'approved' && res.amk_transfer) {
          return handleDelivery(res, signal);
        }
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

  usePairPolling(onPoll, { enabled: state.kind === 'awaiting-approval' });

  // ── Render ──────────────────────────────────────────────────────

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
          onClick={() =>
            setState({ kind: 'collect-code', codeInput: '', error: null })
          }
        >
          Try Again
        </button>
      </div>
    );
  }

  if (state.kind === 'looking-up' || state.kind === 'claiming') {
    return (
      <div class="card text-center">
        <p class="text-muted">
          {state.kind === 'looking-up'
            ? 'Looking up code…'
            : 'Connecting to the other device…'}
        </p>
      </div>
    );
  }

  if (state.kind === 'awaiting-approval') {
    const handleCancel = async () => {
      if (!auth.sessionToken) return;
      try {
        await pairCancel(auth.sessionToken, state.claim.joiner_poll_token);
      } catch {
        /* idempotent */
      }
      setState({
        kind: 'error',
        message: 'Pairing cancelled.',
      });
    };
    return (
      <div class="card space-y-4 text-center">
        <CardHeading
          title="Waiting for approval"
          subtitle="Approve this device on the browser that already has your account key."
        />
        <div class="bg-surface-alt mx-auto rounded-lg px-6 py-4 font-mono text-2xl font-bold tracking-[0.3em]">
          {state.code}
        </div>
        <p class="text-sm text-muted">
          We'll switch over automatically once the other browser approves.
        </p>
        <button
          type="button"
          class="btn tracking-wider uppercase"
          onClick={handleCancel}
        >
          Cancel
        </button>
      </div>
    );
  }

  if (state.kind === 'confirm-send') {
    const handleSend = async () => {
      if (!auth.sessionToken || !auth.userId) return;
      setState({ kind: 'sending', code: state.code });
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
          state.displayerEcdhPublicKey,
          amk,
        );
        await pairApprove(auth.sessionToken, {
          user_code: state.code,
          amk_transfer: amkTransfer,
        });
        setState({ kind: 'success' });
      } catch (err) {
        setState({
          kind: 'error',
          message: err instanceof Error ? err.message : 'Send failed.',
        });
      }
    };
    return (
      <div class="card space-y-4">
        <CardHeading
          title="Send your account key?"
          subtitle="The other browser is waiting to receive your account key."
        />
        <p class="bg-surface-alt rounded-md border border-border p-3 text-sm">
          You will send your account key to your other browser. Approve only if
          you started this on that device.
        </p>
        <div class="flex gap-3">
          <button
            type="button"
            class="btn flex-1 tracking-wider uppercase"
            onClick={() =>
              setState({
                kind: 'collect-code',
                codeInput: '',
                error: null,
              })
            }
          >
            Cancel
          </button>
          <button
            type="button"
            class="btn btn-primary flex-1 tracking-wider uppercase"
            onClick={handleSend}
          >
            Send
          </button>
        </div>
      </div>
    );
  }

  if (state.kind === 'sending') {
    return (
      <div class="card text-center">
        <p class="text-muted">Sending account key…</p>
      </div>
    );
  }

  // state.kind === 'collect-code'
  const handleSubmit = (e: Event) => {
    e.preventDefault();
    if (state.kind !== 'collect-code') return;
    const parsed = parsePairUrl(state.codeInput);
    if (!parsed) {
      setState({
        ...state,
        error: 'Enter a code in the form XXXX-XXXX.',
      });
      return;
    }
    void lookupCode(parsed.code);
  };

  return (
    <>
      <div class="card space-y-5">
        <CardHeading
          title="Join a code"
          subtitle="Use a code from the browser that already has your account key."
        />

        <div class="flex flex-col gap-3 sm:flex-row">
          <button
            type="button"
            class="btn btn-primary flex-1 tracking-wider uppercase"
            onClick={() => setScannerOpen(true)}
          >
            Scan QR
          </button>
        </div>

        <form class="space-y-3" onSubmit={handleSubmit}>
          <label class="label" for="pair-code">
            Or type the code
          </label>
          <input
            id="pair-code"
            type="text"
            inputMode="text"
            autoComplete="off"
            autoCapitalize="characters"
            spellcheck={false}
            class="input font-mono tracking-[0.3em] uppercase"
            placeholder="XXXX-XXXX"
            value={state.codeInput}
            maxLength={9}
            onInput={(e) =>
              setState({
                kind: 'collect-code',
                codeInput: (e.target as HTMLInputElement).value,
                error: null,
              })
            }
          />
          {state.error && (
            <p role="alert" class="text-sm text-error">
              {state.error}
            </p>
          )}
          <button type="submit" class="btn w-full tracking-wider uppercase">
            Continue
          </button>
        </form>

        <button
          type="button"
          class="link mx-auto block"
          onClick={onChooseDisplay}
        >
          Or show a code from this device instead
        </button>
      </div>

      <Modal
        open={scannerOpen}
        onClose={() => setScannerOpen(false)}
        class="max-w-md"
      >
        <QrScannerView
          onCode={(code) => {
            setScannerOpen(false);
            void lookupCode(code);
          }}
          onTypeInstead={() => setScannerOpen(false)}
          onClose={() => setScannerOpen(false)}
        />
      </Modal>
    </>
  );
}
