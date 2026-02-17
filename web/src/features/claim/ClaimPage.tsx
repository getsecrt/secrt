import { useState, useCallback, useEffect, useRef } from 'preact/hooks';
import {
  open,
  deriveClaimToken,
  preloadPassphraseKdf,
} from '../../crypto/envelope';
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
import { Modal } from '../../components/Modal';
import { navigate } from '../../router';
import { formatSize } from '../../lib/format';
import { mapClaimError, type ClaimError } from './errors';
import type { EnvelopeJson, PayloadMeta } from '../../types';

interface ClaimPageProps {
  id: string;
}

type ClaimStatus =
  | { step: 'init' }
  | { step: 'confirm' }
  | { step: 'claiming' }
  | { step: 'passphrase'; envelope: EnvelopeJson; urlKey: Uint8Array }
  | { step: 'decrypting' }
  | {
      step: 'done';
      content: Uint8Array;
      meta: PayloadMeta;
    }
  | ClaimError;

/** Placeholder dot count shown behind modals. */
const PLACEHOLDER_DOTS = 24;

export function ClaimPage({ id }: ClaimPageProps) {
  const [status, setStatus] = useState<ClaimStatus>({ step: 'init' });
  const [passphrase, setPassphrase] = useState('');
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [passphraseError, setPassphraseError] = useState('');
  const abortRef = useRef<AbortController | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
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
      passphraseInputRef.current?.select();
    }
  }, [status.step]);

  // Auto-size textarea for browsers without field-sizing: content (Safari)
  useEffect(() => {
    const ta = textareaRef.current;
    if (!ta || status.step !== 'done') return;
    if (CSS.supports('field-sizing', 'content')) return;
    ta.style.height = 'auto';
    ta.style.height = `${Math.min(ta.scrollHeight, 256)}px`;
  }, [status.step]);

  // Validate fragment on mount — stop at confirm screen, don't claim yet
  useEffect(() => {
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
    setStatus({ step: 'confirm' });

    return () => {
      abortRef.current?.abort();
      abortRef.current = null;
    };
  }, [id]);

  // Claim and decrypt — triggered by the "View Secret" button
  const handleClaim = useCallback(async () => {
    const urlKey = urlKeyRef.current;
    if (!urlKey) return;

    const controller = new AbortController();
    abortRef.current = controller;

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

      // Check if passphrase required
      if (res.envelope.kdf.name !== 'none') {
        void preloadPassphraseKdf().catch(() => {
          // Surface load errors when user attempts decrypt.
        });
        setStatus({ step: 'passphrase', envelope: res.envelope, urlKey });
        return;
      }

      // Decrypt immediately (no passphrase)
      setStatus({ step: 'decrypting' });
      const result = await open(res.envelope, urlKey);
      if (controller.signal.aborted) return;

      setStatus({ step: 'done', content: result.content, meta: result.meta });
    } catch (err) {
      if (controller.signal.aborted) return;
      setStatus(mapClaimError(err));
    }
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
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.toLowerCase().includes('argon2id module failed to load')) {
          setPassphraseError(msg);
        } else {
          setPassphraseError('Wrong passphrase. Please try again.');
        }
        setStatus({ step: 'passphrase', envelope, urlKey });
      }
    },
    [passphrase],
  );

  // Download file helper
  const handleDownload = useCallback(() => {
    if (status.step !== 'done') return;
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

  // ── Pure loading: validating fragment ──
  if (status.step === 'init') {
    return (
      <div class="card space-y-4 text-center">
        <div class="flex justify-center">
          <div class="size-8 animate-spin rounded-full border-2 border-border border-t-accent" />
        </div>
        <p class="text-muted">Preparing&hellip;</p>
      </div>
    );
  }

  // ── Error ──
  if (status.step === 'error') {
    return (
      <div class="card space-y-5">
        <div class="flex flex-col items-center gap-2 text-center">
          <CircleXmarkIcon class="size-10 text-error" />
          <h2 class="text-xl font-semibold">Secret Unavailable</h2>
        </div>

        <p class="text-center whitespace-pre-line text-muted">
          {status.message}
        </p>

        <div class="text-center">
          <a href="/" class="link" onClick={handleGoHome}>
            Create a New Secret
          </a>
        </div>
      </div>
    );
  }

  // ── Main card: always rendered once we have a valid fragment ──
  // Shows placeholder dots when locked, real content when done.
  const isDone = status.step === 'done';
  const isLocked = !isDone;
  const isPassphraseStep =
    status.step === 'passphrase' ||
    (status.step === 'decrypting' && passphraseRequired);
  const isBusy = status.step === 'claiming' || status.step === 'decrypting';
  const modalOpen =
    status.step === 'confirm' || isBusy || status.step === 'passphrase';

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
      {/* Main reveal card — dimmed when locked, interactive when done */}
      <div
        class={`card space-y-5 ${isLocked ? 'pointer-events-none opacity-50 select-none' : ''}`}
      >
        <div class="flex flex-col items-center gap-2 text-center">
          {isLocked ? (
            <>
              <LockIcon class="size-10 text-muted" />
              <h2 class="text-xl font-semibold">Secret Ready</h2>
            </>
          ) : (
            <>
              <CheckCircleIcon class="size-10 text-success" />
              <h2 class="text-xl font-semibold">Secret Decrypted</h2>
            </>
          )}
        </div>

        {isDone && isFile ? (
          /* ── File result ── */
          <div class="space-y-4">
            <div class="flex items-center gap-3 rounded-md border border-border bg-surface-raised px-3 py-3">
              <div class="min-w-0 flex-1">
                <p class="truncate font-medium">
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
            <textarea
              ref={isDone ? textareaRef : undefined}
              readOnly
              disabled={!isDone}
              tabIndex={isDone ? undefined : -1}
              class="input [field-sizing:content] max-h-64 w-full resize-y font-mono text-sm break-all whitespace-pre-wrap"
              value={isDone ? textContent : '\u25CF'.repeat(PLACEHOLDER_DOTS)}
            />

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

        <p class="text-center text-sm text-muted">
          {isDone
            ? 'This secret has been permanently deleted from the server.'
            : 'This secret will be permanently deleted from the server.'}
        </p>
        <div class="text-center">
          <a href="/" class="link" onClick={handleGoHome}>
            Create a New Secret
          </a>
        </div>
      </div>

      {/* ── Claim modal — confirm or passphrase ── */}
      <Modal
        open={modalOpen}
        dismissible={false}
        asForm={isPassphraseStep}
        onSubmit={isPassphraseStep ? handleDecrypt : undefined}
      >
        {isPassphraseStep ? (
          <>
            <div class="flex flex-col items-center gap-2 text-center">
              <LockIcon class="size-10 text-accent" />
              <h2 class="mb-2 text-xl font-semibold">Passphrase Required</h2>
              <p class="text-muted">
                This secret is protected with a passphrase.
                <br />
                Enter it below to decrypt.
              </p>
            </div>

            <div class="space-y-1">
              <label
                class="flex items-center gap-1.5 font-medium text-muted"
                for="claim-passphrase"
              >
                <LockIcon class="size-4" />
                Passphrase
              </label>
              <div class="relative">
                <input
                  ref={passphraseInputRef}
                  id="claim-passphrase"
                  type={showPassphrase ? 'text' : 'password'}
                  class="input pr-10"
                  value={passphrase}
                  onInput={(e) => {
                    const value = (e.target as HTMLInputElement).value;
                    setPassphrase(value);
                    if (value) {
                      void preloadPassphraseKdf().catch(() => {
                        // Surface load errors when decrypt is submitted.
                      });
                    }
                  }}
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
              <div role="alert" class="alert-error flex items-center gap-2">
                <TriangleExclamationIcon class="size-5 shrink-0" />
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
          </>
        ) : (
          <>
            <div class="flex flex-col items-center gap-2 text-center">
              <LockIcon class="size-10 text-accent" />
              <h2 class="mb-2 text-xl font-semibold">
                Someone Sent You a Secret
              </h2>
              <p>This secret can only be viewed once.</p>
              <p class="mt-4 text-sm text-muted">
                Be ready to save it and ensure no one else can see your screen.
              </p>
            </div>

            <button
              type="button"
              class="btn btn-primary w-full tracking-wider uppercase"
              onClick={handleClaim}
              disabled={isBusy}
            >
              {isBusy ? 'Retrieving\u2026' : 'View Secret'}
            </button>
          </>
        )}
      </Modal>
    </>
  );
}
