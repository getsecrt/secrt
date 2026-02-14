import { useState, useCallback, useEffect, useRef } from 'preact/hooks';
import { seal, open } from '../../crypto/envelope';
import { utf8Encode, utf8Decode } from '../../crypto/encoding';
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
import type { EnvelopeJson, PayloadMeta } from '../../types';

/* ── Types ── */

type TestStatus =
  | { step: 'pick' }
  | { step: 'sealing' }
  | { step: 'claiming' }
  | { step: 'passphrase'; envelope: EnvelopeJson; urlKey: Uint8Array }
  | { step: 'decrypting' }
  | { step: 'done'; content: Uint8Array; meta: PayloadMeta }
  | { step: 'error'; message: string };

/** Placeholder dot count shown behind the passphrase modal. */
const PLACEHOLDER_DOTS = 24;

/* ── Helpers ── */

/** Simulate a short network delay. */
const delay = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/* ── Component ── */

export function TestClaimPage() {
  const [status, setStatus] = useState<TestStatus>({ step: 'pick' });
  const [passphrase, setPassphrase] = useState('');
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [passphraseError, setPassphraseError] = useState('');
  const [revealed, setRevealed] = useState(false);

  const passphraseInputRef = useRef<HTMLInputElement | null>(null);

  const envelopeRef = useRef<EnvelopeJson | null>(null);
  const urlKeyRef = useRef<Uint8Array | null>(null);

  const passphraseRequired =
    envelopeRef.current !== null && envelopeRef.current.kdf.name !== 'none';

  // Refocus passphrase input when returning from a failed attempt
  useEffect(() => {
    if (status.step === 'passphrase') {
      passphraseInputRef.current?.focus();
    }
  }, [status.step]);

  const reset = useCallback(() => {
    setStatus({ step: 'pick' });
    setPassphrase('');
    setShowPassphrase(false);
    setPassphraseError('');
    setRevealed(false);
    envelopeRef.current = null;
    urlKeyRef.current = null;
  }, []);

  /** Seal content, simulate claim delay, then decrypt. */
  const runScenario = useCallback(
    async (
      content: Uint8Array,
      meta: PayloadMeta,
      opts?: { passphrase?: string },
    ) => {
      reset();

      // 1. Seal
      setStatus({ step: 'sealing' });
      const sealOpts = opts?.passphrase
        ? { passphrase: opts.passphrase }
        : undefined;
      const { envelope, urlKey } = await seal(content, meta, sealOpts);
      envelopeRef.current = envelope;
      urlKeyRef.current = urlKey;

      // 2. Simulate network claim
      setStatus({ step: 'claiming' });
      await delay(600);

      // 3. Check if passphrase required
      if (envelope.kdf.name !== 'none') {
        setStatus({ step: 'passphrase', envelope, urlKey });
        return;
      }

      // 4. Decrypt directly
      setStatus({ step: 'decrypting' });
      const result = await open(envelope, urlKey);
      setStatus({ step: 'done', content: result.content, meta: result.meta });
    },
    [reset],
  );

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

  /* ── Scenario picker ── */
  if (status.step === 'pick') {
    return (
      <div class="space-y-6">
        <div class="card space-y-4">
          <h2 class="heading text-center">Claim Page Test Scenarios</h2>
          <p class="text-sm text-muted">
            Each scenario seals a test secret client-side, simulates the claim
            API delay, then exercises the real decrypt and reveal UI.
          </p>

          <div class="space-y-2">
            <button
              class="btn w-full text-left"
              onClick={() =>
                runScenario(
                  utf8Encode('Hello from secrt! This is a test secret.'),
                  { type: 'text' },
                )
              }
            >
              1. Text secret (no passphrase)
            </button>

            <button
              class="btn w-full text-left"
              onClick={() =>
                runScenario(
                  utf8Encode('Protected secret content.\nLine two.'),
                  { type: 'text' },
                  { passphrase: 'hunter2' },
                )
              }
            >
              2. Text secret (passphrase: <code class="text-xs">hunter2</code>)
            </button>

            <button
              class="btn w-full text-left"
              onClick={() =>
                runScenario(utf8Encode('{ "api_key": "sk_test_abc123" }'), {
                  type: 'file',
                  filename: 'credentials.json',
                  mime: 'application/json',
                })
              }
            >
              3. File secret (credentials.json)
            </button>

            <button
              class="btn w-full text-left"
              onClick={() =>
                runScenario(
                  new Uint8Array([
                    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00,
                  ]),
                  {
                    type: 'file',
                    filename: 'image.png',
                    mime: 'image/png',
                  },
                )
              }
            >
              4. Binary file secret (image.png, 10 bytes)
            </button>

            <button
              class="btn w-full text-left"
              onClick={() =>
                setStatus({
                  step: 'error',
                  message:
                    'This secret is no longer available.\nIt may have already been viewed or expired.',
                })
              }
            >
              5. Error: secret unavailable (404)
            </button>

            <button
              class="btn w-full text-left"
              onClick={() =>
                setStatus({
                  step: 'error',
                  message:
                    'This link is incomplete. The decryption key is missing from the URL.',
                })
              }
            >
              6. Error: missing fragment
            </button>

            <button
              class="btn w-full text-left"
              onClick={() =>
                runScenario(utf8Encode('A'.repeat(500)), { type: 'text' })
              }
            >
              7. Long text secret (500 chars)
            </button>
          </div>
        </div>

        <a href="/" class="btn w-full text-center" onClick={handleGoHome}>
          Back to home
        </a>
      </div>
    );
  }

  /* ── Loading states ── */
  if (status.step === 'sealing' || status.step === 'claiming') {
    return (
      <div class="card space-y-4 text-center">
        <div class="flex justify-center">
          <div class="size-8 animate-spin rounded-full border-2 border-border border-t-accent" />
        </div>
        <p class="text-sm text-muted">
          {status.step === 'sealing'
            ? 'Encrypting test secret\u2026'
            : 'Retrieving your secret\u2026'}
        </p>
      </div>
    );
  }

  /* ── Auto-decrypting (no passphrase) ── */
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

  /* ── Error ── */
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

        <button type="button" class="btn w-full" onClick={reset}>
          Back to scenarios
        </button>
      </div>
    );
  }

  /* ── Reveal card (passphrase-locked or done) ── */
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
          {isLocked ? (
            <>
              <CircleXmarkIcon class="size-10 text-muted" />
              <h2 class="text-lg font-semibold">Secret Protected</h2>
            </>
          ) : (
            <>
              <CheckCircleIcon class="size-10 text-success" />
              <h2 class="text-lg font-semibold">Secret Decrypted</h2>
            </>
          )}
        </div>

        {isDone && isFile ? (
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
          <div class="space-y-3">
            <div class="relative rounded-md border border-border bg-surface px-3 py-2.5 inset-shadow-sm">
              {isDone && revealed ? (
                <pre class="font-mono text-sm break-all whitespace-pre-wrap">
                  {textContent}
                </pre>
              ) : (
                <p class="cursor-pointer font-mono text-sm tracking-wider text-muted select-none">
                  {'\u25CF'.repeat(PLACEHOLDER_DOTS)}
                </p>
              )}
              <button
                type="button"
                class="absolute top-2 right-2 p-1 text-muted hover:text-text"
                onClick={() => setRevealed((r) => !r)}
                aria-label={revealed ? 'Hide secret' : 'Show secret'}
                disabled={!isDone}
              >
                <EyeIcon class="size-4" />
              </button>
            </div>

            <CopyButton
              text={textContent}
              class="btn-primary w-full tracking-wider uppercase"
              label="Copy secret"
              icon={<ClipboardIcon class="size-5" />}
            />
          </div>
        )}

        <p class="text-center text-xs text-muted">
          This secret has been permanently deleted from the server.
        </p>

        <button type="button" class="btn w-full" onClick={reset}>
          Back to scenarios
        </button>
      </div>

      {/* ── Passphrase modal overlay ── */}
      {isLocked && (
        <div class="fixed inset-0 z-50 flex items-start justify-center bg-black/30 px-4 pt-32">
          <form class="card w-full max-w-sm space-y-6" onSubmit={handleDecrypt}>
            <div class="flex flex-col items-center gap-2 text-center">
              <LockIcon class="size-10 text-amber-500" />
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
                for="test-passphrase"
              >
                <LockIcon class="size-4" />
                Passphrase
              </label>
              <div class="relative">
                <input
                  ref={passphraseInputRef}
                  id="test-passphrase"
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
