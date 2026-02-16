import { useState, useCallback, useEffect, useRef } from 'preact/hooks';
import { seal } from '../../crypto/envelope';
import { utf8Encode } from '../../crypto/encoding';
import { buildFrame } from '../../crypto/frame';
import { ensureCompressor, compress } from '../../crypto/compress';
import { CODEC_ZSTD } from '../../crypto/constants';
import { createSecret, fetchInfo } from '../../lib/api';
import {
  checkEnvelopeSize,
  estimateEnvelopeSize,
  frameSizeError,
} from '../../lib/envelope-size';
import { formatShareLink } from '../../lib/url';
import { copyToClipboard } from '../../lib/clipboard';
import { TTL_DEFAULT, isValidTtl } from '../../lib/ttl';
import {
  EyeIcon,
  EyeSlashIcon,
  GearIcon,
  KeyIcon,
  LockIcon,
  NoteIcon,
  TriangleExclamationIcon,
  UploadIcon,
} from '../../components/Icons';
import type { ApiInfo, PayloadMeta } from '../../types';
import { FileDropZone } from './FileDropZone';
import { TtlSelector } from './TtlSelector';
import { ShareResult } from './ShareResult';
import { HowItWorks } from '../../components/HowItWorks';
import { useAuth } from '../../lib/auth-context';
import { mapError } from './errors';
import {
  DEFAULT_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  generatePassword,
} from './password-generator';

/** Skip compression if raw file size exceeds this multiple of the server limit. */
const COMPRESS_SKIP_FACTOR = 40;

type SendStatus =
  | { step: 'input' }
  | { step: 'encrypting' }
  | { step: 'sending' }
  | { step: 'done'; shareUrl: string; expiresAt: string }
  | { step: 'error'; message: string };

export function SendPage() {
  const auth = useAuth();
  const [mode, setMode] = useState<'text' | 'file'>('text');
  const [text, setText] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [ttlSeconds, setTtlSeconds] = useState(TTL_DEFAULT);
  const [status, setStatus] = useState<SendStatus>({ step: 'input' });
  const [cachedFrame, setCachedFrame] = useState<Uint8Array | null>(null);
  const [passwordCopied, setPasswordCopied] = useState(false);
  const [passwordModalOpen, setPasswordModalOpen] = useState(false);
  const [passwordLengthInput, setPasswordLengthInput] = useState(
    String(DEFAULT_PASSWORD_LENGTH),
  );
  const [passwordGrouped, setPasswordGrouped] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const passwordCopiedTimerRef = useRef<number | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [serverInfo, setServerInfo] = useState<ApiInfo | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    fetchInfo(controller.signal)
      .then(setServerInfo)
      .catch(() => {
        /* best-effort; server will still enforce limits */
      });
    return () => {
      controller.abort();
      abortRef.current?.abort();
      if (passwordCopiedTimerRef.current !== null) {
        window.clearTimeout(passwordCopiedTimerRef.current);
      }
    };
  }, []);

  // Page-level drag listener to switch to file mode
  const handlePageDragOver = useCallback((e: DragEvent) => {
    if (e.dataTransfer?.types.includes('Files')) {
      e.preventDefault();
      setMode('file');
    }
  }, []);

  const handleFileSelect = useCallback(
    async (f: File) => {
      setFile(f);
      setMode('file');
      setCachedFrame(null);

      // Clear previous error
      setStatus((prev) => (prev.step === 'error' ? { step: 'input' } : prev));

      // Quick-reject: if raw file size is 10x the server limit, no point compressing
      if (serverInfo) {
        const tier = auth.authenticated
          ? serverInfo.limits.authed
          : serverInfo.limits.public;
        if (f.size > tier.max_envelope_bytes * COMPRESS_SKIP_FACTOR) {
          setStatus({
            step: 'error',
            message: frameSizeError(
              estimateEnvelopeSize(f.size),
              tier.max_envelope_bytes,
            ),
          });
          return;
        }
      }

      // Build frame with compression for accurate size check
      try {
        await ensureCompressor();

        const bytes = new Uint8Array(await f.arrayBuffer());
        const meta: PayloadMeta = {
          type: 'file',
          filename: f.name,
          mime: f.type || 'application/octet-stream',
        };
        const frame = buildFrame(meta, bytes, compress);

        // Check estimated envelope size against server limit
        if (serverInfo) {
          const tier = auth.authenticated
            ? serverInfo.limits.authed
            : serverInfo.limits.public;
          const estimated = estimateEnvelopeSize(frame.length);
          if (estimated > tier.max_envelope_bytes) {
            const wasCompressed = frame[5] === CODEC_ZSTD;
            setStatus({
              step: 'error',
              message: frameSizeError(
                estimated,
                tier.max_envelope_bytes,
                wasCompressed,
              ),
            });
            return;
          }
        }

        setCachedFrame(frame);
      } catch {
        // If compression init fails, fall back to raw size check
        if (serverInfo) {
          const tier = auth.authenticated
            ? serverInfo.limits.authed
            : serverInfo.limits.public;
          const estimated = estimateEnvelopeSize(f.size);
          if (estimated > tier.max_envelope_bytes) {
            setStatus({
              step: 'error',
              message: frameSizeError(estimated, tier.max_envelope_bytes),
            });
            return;
          }
        }
      }
    },
    [serverInfo, auth.authenticated],
  );

  const handleFileClear = useCallback(() => {
    setFile(null);
    setCachedFrame(null);
    setMode('text');
    if (status.step === 'error') setStatus({ step: 'input' });
  }, [status.step]);

  const handleReset = useCallback(() => {
    setMode('text');
    setText('');
    setFile(null);
    setCachedFrame(null);
    setPassphrase('');
    setShowPassphrase(false);
    setTtlSeconds(TTL_DEFAULT);
    setPasswordCopied(false);
    setPasswordModalOpen(false);
    setPasswordLengthInput(String(DEFAULT_PASSWORD_LENGTH));
    setPasswordGrouped(false);
    setStatus({ step: 'input' });
    if (passwordCopiedTimerRef.current !== null) {
      window.clearTimeout(passwordCopiedTimerRef.current);
      passwordCopiedTimerRef.current = null;
    }
  }, []);

  const showCopiedFeedback = useCallback(() => {
    setPasswordCopied(true);
    if (passwordCopiedTimerRef.current !== null) {
      window.clearTimeout(passwordCopiedTimerRef.current);
    }
    passwordCopiedTimerRef.current = window.setTimeout(() => {
      setPasswordCopied(false);
      passwordCopiedTimerRef.current = null;
    }, 2000);
  }, []);

  const busy = status.step === 'encrypting' || status.step === 'sending';
  const hasContent = mode === 'text' ? text.trim().length > 0 : file !== null;
  const contentError =
    status.step === 'error' &&
    (status.message.includes('too large') || !hasContent);
  const passwordLength = Number(passwordLengthInput);
  const passwordLengthValid =
    Number.isInteger(passwordLength) && passwordLength >= MIN_PASSWORD_LENGTH;

  const generateAndCopyPassword = useCallback(
    async (options: { length: number; grouped: boolean }) => {
      try {
        const generated = generatePassword(options);
        setText(generated);
        setMode('text');
        setFile(null);
        setCachedFrame(null);
        setStatus((prev) => (prev.step === 'error' ? { step: 'input' } : prev));

        const copied = await copyToClipboard(generated);
        if (copied) {
          showCopiedFeedback();
        }
      } catch (err) {
        const message =
          err instanceof Error ? err.message : 'Failed to generate password.';
        setStatus({ step: 'error', message });
      }
    },
    [showCopiedFeedback],
  );

  const handleGenerateDefaultPassword = useCallback(() => {
    void generateAndCopyPassword({
      length: DEFAULT_PASSWORD_LENGTH,
      grouped: false,
    });
  }, [generateAndCopyPassword]);

  const handleGeneratePasswordFromModal = useCallback(
    (e: Event) => {
      e.preventDefault();
      if (!passwordLengthValid) return;
      setPasswordModalOpen(false);
      void generateAndCopyPassword({
        length: passwordLength,
        grouped: passwordGrouped,
      });
    },
    [passwordLengthValid, passwordLength, passwordGrouped, generateAndCopyPassword],
  );

  const handleSubmit = useCallback(
    async (e: Event) => {
      e.preventDefault();
      if (busy) return;
      if (!hasContent) {
        setStatus({
          step: 'error',
          message:
            mode === 'text'
              ? 'Enter a secret message first.'
              : 'Choose a file first.',
        });
        return;
      }
      if (!isValidTtl(ttlSeconds)) {
        setStatus({ step: 'error', message: 'Invalid expiry time.' });
        return;
      }

      const controller = new AbortController();
      abortRef.current = controller;

      try {
        // Build content + meta
        let content: Uint8Array;
        let meta: PayloadMeta;

        if (mode === 'file' && file) {
          content = new Uint8Array(await file.arrayBuffer());
          meta = {
            type: 'file',
            filename: file.name,
            mime: file.type || 'application/octet-stream',
          };
        } else {
          content = utf8Encode(text);
          meta = { type: 'text' };
        }

        // Encrypt — reuse cached frame for files, compress on the fly for text
        setStatus({ step: 'encrypting' });

        await ensureCompressor();

        let sealOpts: Parameters<typeof seal>[2];
        if (mode === 'file' && cachedFrame) {
          sealOpts = passphrase
            ? { passphrase, prebuiltFrame: cachedFrame }
            : { prebuiltFrame: cachedFrame };
        } else {
          sealOpts = passphrase ? { passphrase, compress } : { compress };
        }

        const { envelope, urlKey, claimHash } = await seal(
          content,
          meta,
          sealOpts,
        );

        if (controller.signal.aborted) return;

        // Check envelope size against server limit
        const sizeError = checkEnvelopeSize(
          envelope,
          serverInfo,
          auth.authenticated,
        );
        if (sizeError) {
          setStatus({ step: 'error', message: sizeError });
          return;
        }

        // Send to server
        setStatus({ step: 'sending' });
        const res = await createSecret(
          { envelope, claim_hash: claimHash, ttl_seconds: ttlSeconds },
          auth.sessionToken ?? undefined,
          controller.signal,
        );

        // Build share URL
        const shareUrl = formatShareLink(res.id, urlKey);

        setStatus({ step: 'done', shareUrl, expiresAt: res.expires_at });
      } catch (err) {
        if (controller.signal.aborted) return;
        setStatus({ step: 'error', message: mapError(err) });
      }
    },
    [
      mode,
      text,
      file,
      passphrase,
      ttlSeconds,
      hasContent,
      busy,
      serverInfo,
      cachedFrame,
      auth.authenticated,
      auth.sessionToken,
    ],
  );

  // Done — show result
  if (status.step === 'done') {
    return (
      <ShareResult
        shareUrl={status.shareUrl}
        expiresAt={status.expiresAt}
        onReset={handleReset}
      />
    );
  }

  const buttonLabel =
    status.step === 'encrypting'
      ? 'Encrypting\u2026'
      : status.step === 'sending'
        ? 'Sending\u2026'
        : 'Create secret';

  return (
    <div class="max-w-xl space-y-4">
      <form
        class="card space-y-6"
        onSubmit={handleSubmit}
        onDragOver={handlePageDragOver}
      >
        <p class="text-center text-sm text-muted">
          Add secret data to encrypt in your browser.
          <br />
          The server never sees the original text or file.
        </p>

        {/* Content input */}
        <div class="space-y-1">
          <div class="flex items-center justify-between gap-2">
            <label class="flex items-center gap-1.5 font-medium text-muted">
              {mode === 'text' ? (
                <>
                  <NoteIcon class="size-4" /> Secret Message
                </>
              ) : (
                <>
                  <UploadIcon class="size-4" /> Secret File
                </>
              )}
            </label>
            {mode === 'text' && (
              <div class="flex items-center gap-1">
                <button
                  type="button"
                  class="link text-xs"
                  onClick={handleGenerateDefaultPassword}
                  disabled={busy}
                >
                  {passwordCopied ? 'copied!' : 'Generate Password'}
                </button>
                <button
                  type="button"
                  class="rounded p-1 text-muted transition-colors hover:text-text"
                  onClick={() => setPasswordModalOpen(true)}
                  aria-label="Password generator settings"
                  disabled={busy}
                >
                  <GearIcon class="size-4" />
                </button>
              </div>
            )}
          </div>
          {/* Grid stack: textarea sets the height, drop zone overlays it */}
          <div class="grid">
            <textarea
              class={`textarea mb-0 [grid-area:1/1] ${mode === 'file' ? 'invisible' : ''} ${contentError && mode === 'text' ? 'input-error' : ''}`}
              rows={5}
              placeholder="Enter your secret..."
              value={text}
              onInput={(e) => {
                setText((e.target as HTMLTextAreaElement).value);
                setPasswordCopied(false);
                if (status.step === 'error') setStatus({ step: 'input' });
              }}
              disabled={busy || mode === 'file'}
            />
            {mode === 'file' && (
              <FileDropZone
                file={file}
                onFileSelect={handleFileSelect}
                onFileClear={handleFileClear}
                disabled={busy}
                className={`[grid-area:1/1] ${contentError ? 'border-error' : ''}`}
              />
            )}
          </div>
          <p class="text-center text-xs text-faint">
            {mode === 'text' ? (
              <>
                <button
                  type="button"
                  class="link"
                  onClick={() => fileInputRef.current?.click()}
                >
                  Choose a file
                </button>{' '}
                or drag one onto this page to upload
                <input
                  ref={fileInputRef}
                  type="file"
                  class="hidden"
                  onChange={(e) => {
                    const f = (e.target as HTMLInputElement).files?.[0];
                    if (f) handleFileSelect(f);
                  }}
                />
              </>
            ) : (
              <>
                Max size{' '}
                {serverInfo
                  ? `${Math.floor((auth.authenticated ? serverInfo.limits.authed : serverInfo.limits.public).max_envelope_bytes / 1024)} KB`
                  : '256 KB'}
              </>
            )}
          </p>
        </div>

        {/* Passphrase */}
        <div class="space-y-1">
          <label
            class="flex items-center gap-1.5 font-medium text-muted"
            for="passphrase"
          >
            <LockIcon class="size-4" />
            Passphrase <span class="font-normal text-faint">(optional)</span>
          </label>
          <div class="relative">
            <input
              id="passphrase"
              type={showPassphrase ? 'text' : 'password'}
              class="input pr-10"
              placeholder=""
              value={passphrase}
              onInput={(e) =>
                setPassphrase((e.target as HTMLInputElement).value)
              }
              disabled={busy}
              autocomplete="off"
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
          <p class="text-center text-xs text-faint">
            {passphrase ? 'The recipient must enter this password' : '\u00A0'}
          </p>
        </div>

        {/* TTL */}
        <TtlSelector
          value={ttlSeconds}
          onChange={setTtlSeconds}
          disabled={busy}
        />

        {/* Submit */}
        <button
          type="submit"
          class="btn btn-primary mt-3 w-full tracking-wider uppercase"
          disabled={busy}
        >
          {buttonLabel}
        </button>

        {/* Error */}
        {status.step === 'error' && (
          <div
            role="alert"
            class="flex items-start gap-2 rounded-md border border-error/30 bg-error/5 px-3 py-2.5 text-error"
          >
            <TriangleExclamationIcon class="mt-0.5 size-5 shrink-0" />
            <span>
              {status.message.split('\n').map((line, i, arr) => (
                <>
                  {line}
                  {i < arr.length - 1 && <br />}
                </>
              ))}
            </span>
          </div>
        )}
      </form>

      {/* Password generator modal */}
      {passwordModalOpen && (
        <div class="fixed inset-0 z-50 flex items-start justify-center bg-black/30 px-4 pt-32">
          <form
            class="card w-full max-w-sm space-y-6"
            onSubmit={handleGeneratePasswordFromModal}
          >
            <div class="flex flex-col items-center gap-2 text-center">
              <KeyIcon class="size-10 text-accent" />
              <h2 class="mb-2 text-xl font-semibold">Generate Password</h2>
              <p class="text-muted">
                Replace the message with a random password and copy it to your
                clipboard.
              </p>
            </div>

            <div class="space-y-1">
              <label
                class="flex items-center gap-1.5 font-medium text-muted"
                for="password-generator-length"
              >
                Length
              </label>
              <input
                id="password-generator-length"
                type="number"
                class="input"
                min={MIN_PASSWORD_LENGTH}
                step={1}
                value={passwordLengthInput}
                onInput={(e) =>
                  setPasswordLengthInput((e.target as HTMLInputElement).value)
                }
                autofocus
              />
              <p class="text-xs text-faint">
                Minimum {MIN_PASSWORD_LENGTH}. Default {DEFAULT_PASSWORD_LENGTH}.
              </p>
            </div>

            <label class="flex items-center gap-2 text-sm text-muted">
              <input
                type="checkbox"
                class="size-4 accent-accent"
                checked={passwordGrouped}
                onChange={(e) =>
                  setPasswordGrouped((e.target as HTMLInputElement).checked)
                }
              />
              Group characters by type
            </label>

            {!passwordLengthValid && (
              <div
                role="alert"
                class="rounded-md border border-error/30 bg-error/5 px-3 py-2 text-sm text-error"
              >
                Length must be at least {MIN_PASSWORD_LENGTH}.
              </div>
            )}

            <div class="flex gap-2">
              <button
                type="button"
                class="btn btn-secondary w-full"
                onClick={() => setPasswordModalOpen(false)}
              >
                Cancel
              </button>
              <button
                type="submit"
                class="btn btn-primary w-full tracking-wider uppercase"
                disabled={!passwordLengthValid}
              >
                Generate &amp; copy
              </button>
            </div>
          </form>
        </div>
      )}

      <HowItWorks />
    </div>
  );
}
