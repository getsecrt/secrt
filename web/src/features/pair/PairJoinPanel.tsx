/**
 * PairJoinPanel — Page B of /pair.
 *
 * This device has the AMK. The user types or scans a code shown on the
 * fresh device and taps "Send Account Key"; /challenge → /approve fire
 * synchronously. There is no joiner-side polling and no interstitial
 * confirm step — the typed code is itself the speed bump.
 */

import { useCallback, useEffect, useRef, useState } from 'preact/hooks';
import { useAuth } from '../../lib/auth-context';
import { navigate } from '../../router';
import {
  pairChallenge,
  pairApprove,
  type PairChallengeResult,
} from '../../lib/api';
import { loadAmk } from '../../lib/amk-store';
import { CardHeading } from '../../components/CardHeading';
import {
  CameraIcon,
  CheckCircleIcon,
  TriangleExclamationIcon,
} from '../../components/Icons';
import { Modal } from '../../components/Modal';
import { encryptAmkForPeer } from './pair-crypto';
import { parsePairUrl } from '../../lib/url';
import { QrScannerView } from './QrScanner';

interface Props {
  prefilledCode: string | null;
}

type JoinState =
  | { kind: 'collect-code'; codeInput: string; error: string | null }
  | { kind: 'sending'; code: string }
  | { kind: 'success' }
  | { kind: 'error'; message: string };

/**
 * Reshape any raw input value (typed char, full paste, pasted URL) into
 * the canonical XXXX-XXXX form. Branches on URL-shape *before* the
 * alphanumeric path so a pasted /pair link doesn't get its scheme
 * mangled into the code buffer.
 *
 * At the 4-chars boundary the displayed hyphen mirrors whatever the raw
 * input contains: typing "K7MQ-" holds the hyphen; backspacing through
 * "K7MQ-" → "K7MQ" drops it. We don't need to compare against the
 * previous value — the browser's edit already tells us which side of
 * the hyphen the cursor is on.
 */
function normalizeCodeInput(raw: string): string {
  const trimmed = raw.trim();
  if (/[/:?]/.test(trimmed)) {
    const parsed = parsePairUrl(trimmed);
    if (parsed) return parsed.code;
    // Fall through if URL-ish but unparseable — the alphanumeric path
    // below produces something the user can see and correct.
  }
  const cleaned = trimmed
    .replace(/[^A-Za-z0-9]/g, '')
    .toUpperCase()
    .slice(0, 8);
  if (cleaned.length < 4) return cleaned;
  if (cleaned.length === 4) {
    return trimmed.includes('-') ? cleaned + '-' : cleaned;
  }
  return cleaned.slice(0, 4) + '-' + cleaned.slice(4);
}

export function PairJoinPanel({ prefilledCode }: Props) {
  const auth = useAuth();
  const [state, setState] = useState<JoinState>(() =>
    prefilledCode
      ? { kind: 'sending', code: prefilledCode.toUpperCase() }
      : { kind: 'collect-code', codeInput: '', error: null },
  );
  const [scannerOpen, setScannerOpen] = useState(false);

  // /challenge → /approve in one go. The interstitial "confirm send" used
  // to live between these two requests; we removed it because the typed
  // 8-char code is itself the speed bump and re-asking adds no defense.
  const sendKey = useCallback(
    async (code: string) => {
      if (!auth.sessionToken || !auth.userId) return;
      setState({ kind: 'sending', code });
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
        if (!res.displayer_ecdh_public_key) {
          setState({
            kind: 'error',
            message:
              'Pairing slot is missing the receiver pubkey — please cancel and start over.',
          });
          return;
        }
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
          res.displayer_ecdh_public_key,
          amk,
        );
        await pairApprove(auth.sessionToken, {
          user_code: code,
          amk_transfer: amkTransfer,
        });
        setState({ kind: 'success' });
      } catch (err) {
        setState({
          kind: 'error',
          message: err instanceof Error ? err.message : 'Send failed.',
        });
      }
    },
    [auth.sessionToken, auth.userId],
  );

  // Auto-send on the deep-link / QR-scan path. Single-fire so re-renders
  // (auth resolving, sendKey identity changing) don't kick a second
  // /challenge.
  const didAutoFireRef = useRef(false);
  useEffect(() => {
    if (didAutoFireRef.current) return;
    if (!prefilledCode) return;
    if (!auth.sessionToken || !auth.userId) return;
    didAutoFireRef.current = true;
    void sendKey(prefilledCode.toUpperCase());
  }, [prefilledCode, auth.sessionToken, auth.userId, sendKey]);

  // ── Render ──────────────────────────────────────────────────────

  if (state.kind === 'success') {
    return (
      <div class="card space-y-4 text-center">
        <CardHeading
          title="Account Key Sent"
          icon={<CheckCircleIcon class="size-10 text-success" />}
        />
        <p class="text-muted">The other device now has your account key.</p>
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
        error: 'Enter an 8-character pairing code or a /pair link.',
      });
      return;
    }
    void sendKey(parsed.code);
  };

  return (
    <>
      <div class="card space-y-5">
        <CardHeading
          title="Pair another device"
          subtitle={
            <>
              On the new device, sign in and visit
              <p class="my-2 text-base font-semibold text-neutral-700 dark:text-neutral-300">
                {window.location.host}/pair
              </p>
              Enter the 8-character code here:
            </>
          }
        />

        <form class="space-y-3" onSubmit={handleSubmit}>
          <div class="flex flex-col gap-4">
            <input
              id="pair-code"
              type="text"
              inputMode="text"
              autoComplete="off"
              autoCapitalize="characters"
              spellcheck={false}
              class="input mx-auto w-52 pl-6 font-mono text-xl font-bold tracking-[0.3em] uppercase"
              placeholder="XXXX-XXXX"
              value={state.codeInput}
              onInput={(e) =>
                setState({
                  kind: 'collect-code',
                  codeInput: normalizeCodeInput(
                    (e.target as HTMLInputElement).value,
                  ),
                  error: null,
                })
              }
            />

            {state.error && (
              <p role="alert" class="text-center text-sm text-error">
                {state.error}
              </p>
            )}

            <button
              type="submit"
              class="btn btn-primary mx-auto w-52 tracking-wider uppercase"
            >
              Send Account Key
            </button>

            <button
              type="button"
              class="btn mx-auto mt-4 w-52 px-4 tracking-wider uppercase"
              aria-label="Scan QR code"
              onClick={() => setScannerOpen(true)}
            >
              <CameraIcon />
              Scan Code
            </button>
          </div>
        </form>

        <p class="text-center text-muted">
          Both browsers must be signed in as the same account.
        </p>
      </div>

      <Modal
        open={scannerOpen}
        onClose={() => setScannerOpen(false)}
        class="max-w-md"
      >
        {scannerOpen && (
          <QrScannerView
            onCode={(code) => {
              setScannerOpen(false);
              void sendKey(code);
            }}
            onTypeInstead={() => setScannerOpen(false)}
            onClose={() => setScannerOpen(false)}
          />
        )}
      </Modal>
    </>
  );
}
