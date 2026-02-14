import { useState, useCallback, useEffect, useRef } from 'preact/hooks';
import { open, deriveClaimToken } from '../../crypto/envelope';
import {
  base64urlEncode,
  base64urlDecode,
  utf8Decode,
} from '../../crypto/encoding';
import { URL_KEY_LEN } from '../../crypto/constants';
import { claimSecret } from '../../lib/api';
import {
  CheckCircleIcon,
  CircleXmarkIcon,
  ClipboardIcon,
  DownloadIcon,
  EyeIcon,
  EyeSlashIcon,
  LockIcon,
  TriangleExclamationIcon,
} from '../../components/Icons';
import { CopyButton } from '../../components/CopyButton';
import { navigate } from '../../router';
import { formatSize } from '../../lib/format';
import { mapClaimError, type ClaimError } from './errors';
import type { EnvelopeJson, PayloadMeta } from '../../types';

interface ClaimPageProps {
  id: string;
}

type ClaimStatus =
  | { step: 'init' }
  | { step: 'claiming' }
  | { step: 'passphrase'; envelope: EnvelopeJson; urlKey: Uint8Array }
  | { step: 'decrypting' }
  | {
      step: 'done';
      content: Uint8Array;
      meta: PayloadMeta;
    }
  | ClaimError;

/** Placeholder dot count shown behind the passphrase modal. */
const PLACEHOLDER_DOTS = 24;

export function ClaimPage({ id }: ClaimPageProps) {
  const [status, setStatus] = useState<ClaimStatus>({ step: 'init' });
  const [passphrase, setPassphrase] = useState('');
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [passphraseError, setPassphraseError] = useState('');
  const [revealed, setRevealed] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const passphraseInputRef = useRef<HTMLInputElement | null>(null);

  // Hold the envelope + urlKey across passphrase retries
  const envelopeRef = useRef<EnvelopeJson | null>(null);
  const urlKeyRef = useRef<Uint8Array | null>(null);

  // Whether this secret requires a passphrase (known after claim response)
  const passphraseRequired =
    envelopeRef.current !== null && envelopeRef.current.kdf.name !== 'none';

  // Refocus passphrase input when returning from a failed attempt
  useEffect(() => {
    if (status.step === 'passphrase') {
      passphraseInputRef.current?.focus();
    }
  }, [status.step]);

  // Parse fragment and initiate claim on mount
  useEffect(() => {
    const controller = new AbortController();
    abortRef.current = controller;

    void (async () => {
      // 1. Parse URL fragment
      const fragment = window.location.hash.slice(1);
      if (!fragment) {
        setStatus({
          step: 'error',
          code: 'no-fragment',
          message:
            'This link is incomplete. The decryption key is missing from the URL.',
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
          code: 'invalid-fragment',
          message:
            'This link is malformed. The decryption key in the URL is invalid.',
        });
        return;
      }

      urlKeyRef.current = urlKey;

      // 2. Derive claim_token and call claim API
      setStatus({ step: 'claiming' });
      try {
        const claimToken = await deriveClaimToken(urlKey);
        if (controller.signal.aborted) return;

        const res = await claimSecret(
          id,
          { claim: base64urlEncode(claimToken) },
          controller.signal,
        );

        envelopeRef.current = res.envelope;

        // 3. Check if passphrase required
        if (res.envelope.kdf.name !== 'none') {
          setStatus({ step: 'passphrase', envelope: res.envelope, urlKey });
          return;
        }

        // 4. Decrypt immediately (no passphrase)
        setStatus({ step: 'decrypting' });
        const result = await open(res.envelope, urlKey);
        if (controller.signal.aborted) return;

        setStatus({ step: 'done', content: result.content, meta: result.meta });
      } catch (err) {
        if (controller.signal.aborted) return;
        setStatus(mapClaimError(err));
      }
    })();

    return () => {
      controller.abort();
      abortRef.current = null;
    };
  }, [id]);

  // Handle passphrase submission
  const handleDecrypt = useCallback(
    async (e: Event) => {
      e.preventDefault();
      const envelope = envelopeRef.current;
      const urlKey = urlKeyRef.current;
      if (!envelope || !urlKey || !passphrase.trim()) return;

      setPassphraseError('');
      setStatus({ step: 'decrypting' });

      try {
        const result = await open(envelope, urlKey, passphrase);
        await new Promise((r) => setTimeout(r, 300));
        setStatus({ step: 'done', content: result.content, meta: result.meta });
      } catch {
        setPassphraseError('Wrong passphrase. Please try again.');
        setStatus({ step: 'passphrase', envelope, urlKey });
      }
    },
    [passphrase],
  );

  // Download file helper
  const handleDownload = useCallback(() => {
    if (status.step !== 'done') return;
    // Copy into a plain ArrayBuffer so TS 5.8's generic Uint8Array is accepted as BlobPart.
    const buf = new ArrayBuffer(status.content.byteLength);
    new Uint8Array(buf).set(status.content);
    const blob = new Blob([buf], {
      type: status.meta.mime ?? 'application/octet-stream',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = status.meta.filename ?? 'secret';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [status]);

  const handleGoHome = useCallback((e: MouseEvent) => {
    e.preventDefault();
    navigate('/');
  }, []);

  // ── Loading / claiming ──
  if (status.step === 'init' || status.step === 'claiming') {
    return (
      <div class="card space-y-4 text-center">
        <div class="flex justify-center">
          <div class="size-8 animate-spin rounded-full border-2 border-border border-t-accent" />
        </div>
        <p class="text-sm text-muted">
          {status.step === 'init'
            ? 'Preparing\u2026'
            : 'Retrieving your secret\u2026'}
        </p>
      </div>
    );
  }

  // ── Auto-decrypting (no passphrase) ──
  if (status.step === 'decrypting' && !passphraseRequired) {
    return (
      <div class="card space-y-4 text-center">
        <div class="flex justify-center">
          <div class="size-8 animate-spin rounded-full border-2 border-border border-t-accent" />
        </div>
        <p class="text-sm text-muted">Decrypting\u2026</p>
      </div>
    );
  }

  // ── Error ──
  if (status.step === 'error') {
    return (
      <div class="card space-y-5">
        <div class="flex flex-col items-center gap-2 text-center">
          <CircleXmarkIcon class="size-10 text-error" />
          <h2 class="text-lg font-semibold">Secret Unavailable</h2>
        </div>

        <p class="text-center text-sm whitespace-pre-line text-muted">
          {status.message}
        </p>

        <a href="/" class="btn w-full text-center" onClick={handleGoHome}>
          Create a new secret
        </a>
      </div>
    );
  }

  // ── Reveal card (passphrase-locked or done) ──
  // Shown when: passphrase prompt, decrypting after passphrase, or done.
  // When locked, a placeholder is shown behind the passphrase modal.
  const isDone = status.step === 'done';
  const isLocked =
    status.step === 'passphrase' ||
    (status.step === 'decrypting' && passphraseRequired);

  const isFile = isDone && status.meta.type === 'file';

  let textContent = '';
  if (isDone && !isFile) {
    try {
      textContent = utf8Decode(status.content);
    } catch {
      textContent = '';
    }
  }

  return (
    <>
      {/* Reveal card — dimmed when locked, interactive when done */}
      <div
        class={`card space-y-5 ${isLocked ? 'pointer-events-none opacity-50 select-none' : ''}`}
      >
        <div class="flex flex-col items-center gap-2 text-center">
          <CheckCircleIcon class="size-10 text-success" />
          <h2 class="text-lg font-semibold">Secret Decrypted</h2>
        </div>

        {isDone && isFile ? (
          /* ── File result ── */
          <div class="space-y-4">
            <div class="flex items-center gap-3 rounded-md border border-border bg-surface-raised px-3 py-3">
              <div class="min-w-0 flex-1">
                <p class="truncate text-sm font-medium">
                  {status.meta.filename ?? 'secret'}
                </p>
                <p class="text-xs text-muted">
                  {formatSize(status.content.length)}
                  {status.meta.mime &&
                  status.meta.mime !== 'application/octet-stream'
                    ? ` \u00B7 ${status.meta.mime}`
                    : ''}
                </p>
              </div>
            </div>

            <button
              type="button"
              class="btn btn-primary w-full"
              onClick={handleDownload}
            >
              <DownloadIcon class="size-5" />
              Download file
            </button>
          </div>
        ) : (
          /* ── Text result (or placeholder when locked) ── */
          <div class="space-y-3">
            <div class="relative rounded-md border border-border bg-surface px-3 py-2.5 inset-shadow-sm">
              {isDone && revealed ? (
                <pre class="font-mono text-sm break-all whitespace-pre-wrap">
                  {textContent}
                </pre>
              ) : (
                <p class="cursor-pointer font-mono text-sm tracking-wider text-muted select-none">
                  {'\u25CF'.repeat(
                    isDone
                      ? Math.min(textContent.length || 12, 40)
                      : PLACEHOLDER_DOTS,
                  )}
                </p>
              )}
              {isDone && (
                <button
                  type="button"
                  class="absolute top-2 right-2 p-1 text-muted hover:text-text"
                  onClick={() => setRevealed((r) => !r)}
                  aria-label={revealed ? 'Hide secret' : 'Show secret'}
                >
                  {revealed ? (
                    <EyeSlashIcon class="size-4" />
                  ) : (
                    <EyeIcon class="size-4" />
                  )}
                </button>
              )}
            </div>

            {isDone && (
              <CopyButton
                text={textContent}
                class="btn-primary w-full tracking-wider uppercase"
                label="Copy secret"
                icon={<ClipboardIcon class="size-5" />}
              />
            )}
          </div>
        )}

        <p class="text-center text-xs text-muted">
          This secret has been permanently deleted from the server.
        </p>

        <a href="/" class="btn w-full text-center" onClick={handleGoHome}>
          Create a new secret
        </a>
      </div>

      {/* ── Passphrase modal overlay ── */}
      {isLocked && (
        <div class="fixed inset-0 z-50 flex items-start justify-center bg-black/30 px-4 pt-32">
          <form class="card w-full max-w-sm space-y-6" onSubmit={handleDecrypt}>
            <div class="flex flex-col items-center gap-2 text-center">
              <LockIcon class="size-10 text-accent" />
              <h2 class="text-lg font-semibold">Passphrase Required</h2>
              <p class="text-sm text-muted">
                This secret is protected with a passphrase.
                <br />
                Enter it below to decrypt.
              </p>
            </div>

            <div class="space-y-1">
              <label
                class="flex items-center gap-1.5 text-sm font-medium text-muted"
                for="claim-passphrase"
              >
                <LockIcon class="size-4" />
                Passphrase
              </label>
              <div class="relative">
                <input
                  id="claim-passphrase"
                  type={showPassphrase ? 'text' : 'password'}
                  class="input pr-10"
                  value={passphrase}
                  onInput={(e) =>
                    setPassphrase((e.target as HTMLInputElement).value)
                  }
                  autocomplete="off"
                  autofocus
                  disabled={status.step === 'decrypting'}
                />
                <button
                  type="button"
                  class="absolute top-1/2 right-2 -translate-y-1/2 p-1 text-muted hover:text-text"
                  onClick={() => setShowPassphrase((s) => !s)}
                  aria-label={
                    showPassphrase ? 'Hide passphrase' : 'Show passphrase'
                  }
                  tabIndex={-1}
                >
                  {showPassphrase ? (
                    <EyeSlashIcon class="size-4" />
                  ) : (
                    <EyeIcon class="size-4" />
                  )}
                </button>
              </div>
            </div>

            {passphraseError && (
              <div
                role="alert"
                class="flex items-start gap-2 rounded-md border border-error/30 bg-error/5 px-3 py-2.5 text-sm text-error"
              >
                <TriangleExclamationIcon class="mt-0.5 size-4 shrink-0" />
                {passphraseError}
              </div>
            )}

            <button
              type="submit"
              class="btn btn-primary w-full tracking-wider uppercase"
              disabled={!passphrase.trim() || status.step === 'decrypting'}
            >
              {status.step === 'decrypting' ? 'Decrypting\u2026' : 'Decrypt'}
            </button>
          </form>
        </div>
      )}
    </>
  );
}
