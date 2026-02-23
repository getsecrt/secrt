import { useState, useCallback, useEffect, useRef } from 'preact/hooks';
import { seal, preloadPassphraseKdf } from '../../crypto/envelope';
import { utf8Encode } from '../../crypto/encoding';
import { buildFrame } from '../../crypto/frame';
import { ensureCompressor, compress } from '../../crypto/compress';
import { CODEC_ZSTD } from '../../crypto/constants';
import { encryptNote, generateAmk, computeAmkCommit } from '../../crypto/amk';
import { base64urlEncode } from '../../crypto/encoding';
import {
  createSecret,
  fetchInfo,
  updateSecretMeta,
  amkExists,
  commitAmk,
} from '../../lib/api';
import { loadAmk, storeAmk } from '../../lib/amk-store';
import {
  checkEnvelopeSize,
  estimateEnvelopeSize,
  frameSizeError,
} from '../../lib/envelope-size';
import { formatShareLink, parseShareUrl } from '../../lib/url';
import { copyToClipboard } from '../../lib/clipboard';
import { TTL_DEFAULT, isValidTtl } from '../../lib/ttl';
import {
  getSendPasswordGeneratorSettings,
  setSendPasswordGeneratorSettings,
} from '../../lib/theme';
import {
  DocumentIcon,
  EyeIcon,
  EyeSlashIcon,
  GearIcon,
  KeyIcon,
  LinkIcon,
  LockIcon,
  NoteIcon,
  TriangleExclamationIcon,
  UploadIcon,
  XMarkIcon,
} from '../../components/Icons';
import type { ApiInfo, PayloadMeta, EncMetaV1 } from '../../types';
import { CardHeading } from '../../components/CardHeading';
import { Modal } from '../../components/Modal';
import { FileDropZone } from './FileDropZone';
import { TtlSelector } from './TtlSelector';
import { ShareResult } from './ShareResult';
import { navigate } from '../../router';
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

function GetSecretForm() {
  const [getUrl, setGetUrl] = useState('');
  const [getError, setGetError] = useState('');

  const handleGet = useCallback(() => {
    const parsed = parseShareUrl(getUrl.trim());
    if (!parsed) {
      setGetError(
        'Please enter a valid secrt link (e.g. https://secrt.ca/s/abc123#key)',
      );
      return;
    }
    setGetError('');
    const fragment = base64urlEncode(parsed.urlKey);
    navigate(`/s/${parsed.id}#${fragment}`);
  }, [getUrl]);

  const handleSubmit = useCallback(
    (e: Event) => {
      e.preventDefault();
      handleGet();
    },
    [handleGet],
  );

  return (
    <form onSubmit={handleSubmit} role="tabpanel" class="space-y-6">
      <p class="text-center text-sm text-muted">
        Paste a secrt link to view the secret.
      </p>
      <div class="space-y-2">
        <label class="label" for="get-url">
          <LinkIcon class="size-4 opacity-60" /> Secret Link
        </label>
        <input
          id="get-url"
          type="text"
          class={`input ${getError ? 'input-error' : ''}`}
          placeholder="https://secrt.ca/s/abc123#..."
          value={getUrl}
          onInput={(e) => {
            setGetUrl((e.target as HTMLInputElement).value);
            if (getError) setGetError('');
          }}
          autoFocus
        />
        {getError ? (
          <p class="text-sm text-red-600">{getError}</p>
        ) : (
          <p class="text-center text-sm text-muted">&nbsp;</p>
        )}
      </div>
      <button
        type="submit"
        class="btn btn-primary w-full tracking-wider uppercase"
        disabled={!getUrl.trim()}
      >
        View Secret
      </button>
    </form>
  );
}

export function SendPage() {
  const auth = useAuth();
  const [tab, setTab] = useState<'send' | 'get'>(() =>
    window.location.hash === '#get' ? 'get' : 'send',
  );
  const [mode, setMode] = useState<'text' | 'file'>('text');
  const [text, setText] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [note, setNote] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [ttlSeconds, setTtlSeconds] = useState(TTL_DEFAULT);
  const [status, setStatus] = useState<SendStatus>({ step: 'input' });
  const [cachedFrame, setCachedFrame] = useState<Uint8Array | null>(null);
  const [initialPasswordSettings] = useState(() =>
    getSendPasswordGeneratorSettings(
      DEFAULT_PASSWORD_LENGTH,
      MIN_PASSWORD_LENGTH,
    ),
  );
  const [passwordCopied, setPasswordCopied] = useState(false);
  const [passwordModalOpen, setPasswordModalOpen] = useState(false);
  const [passwordLengthInput, setPasswordLengthInput] = useState(
    String(initialPasswordSettings.length),
  );
  const [passwordGrouped, setPasswordGrouped] = useState(
    initialPasswordSettings.grouped,
  );
  const abortRef = useRef<AbortController | null>(null);
  const passwordCopiedTimerRef = useRef<number | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [noteStatus, setNoteStatus] = useState<
    'checking' | 'available' | 'needs-sync'
  >('checking');
  const [serverInfo, setServerInfo] = useState<ApiInfo | null>(() => {
    try {
      const cached = sessionStorage.getItem('server_info');
      return cached ? (JSON.parse(cached) as ApiInfo) : null;
    } catch {
      return null;
    }
  });

  useEffect(() => {
    const controller = new AbortController();
    fetchInfo(controller.signal)
      .then((info) => {
        setServerInfo(info);
        try {
          sessionStorage.setItem('server_info', JSON.stringify(info));
        } catch {
          /* best-effort */
        }
      })
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

  // Check AMK status for note availability on second-browser scenario
  useEffect(() => {
    if (
      !auth.authenticated ||
      !auth.userId ||
      !serverInfo?.features?.encrypted_notes
    ) {
      setNoteStatus('available');
      return;
    }
    let cancelled = false;
    loadAmk(auth.userId)
      .then(async (amk) => {
        if (cancelled) return;
        if (amk) {
          setNoteStatus('available');
          return;
        }
        // No local AMK — check if one is committed on the server
        try {
          const { exists } = await amkExists(auth.sessionToken!);
          if (!cancelled) setNoteStatus(exists ? 'needs-sync' : 'available');
        } catch {
          if (!cancelled) setNoteStatus('available');
        }
      })
      .catch(() => {
        if (!cancelled) setNoteStatus('available');
      });
    return () => {
      cancelled = true;
    };
  }, [auth.authenticated, auth.userId, auth.sessionToken, serverInfo]);

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
    setNote('');
    setPassphrase('');
    setShowPassphrase(false);
    setTtlSeconds(TTL_DEFAULT);
    setPasswordCopied(false);
    setPasswordModalOpen(false);
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
    }, 1000);
  }, []);

  const busy = status.step === 'encrypting' || status.step === 'sending';
  const notesAvailable =
    auth.authenticated && !!serverInfo?.features?.encrypted_notes;
  const hasContent = mode === 'text' ? text.trim().length > 0 : file !== null;
  const contentError =
    status.step === 'error' &&
    (status.message.includes('too large') || !hasContent);
  const passwordLength = Number(passwordLengthInput);
  const passwordLengthValid =
    Number.isInteger(passwordLength) && passwordLength >= MIN_PASSWORD_LENGTH;

  useEffect(() => {
    if (!passwordLengthValid) return;
    setSendPasswordGeneratorSettings(passwordLength, passwordGrouped);
  }, [passwordLengthValid, passwordLength, passwordGrouped]);

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
    const saved = getSendPasswordGeneratorSettings(
      DEFAULT_PASSWORD_LENGTH,
      MIN_PASSWORD_LENGTH,
    );
    void generateAndCopyPassword(saved);
  }, [generateAndCopyPassword]);

  const handleGeneratePasswordFromModal = useCallback(
    (e: Event) => {
      e.preventDefault();
      if (!passwordLengthValid) return;
      void generateAndCopyPassword({
        length: passwordLength,
        grouped: passwordGrouped,
      });
    },
    [
      passwordLengthValid,
      passwordLength,
      passwordGrouped,
      generateAndCopyPassword,
    ],
  );

  const handlePasswordPreviewInput = useCallback((e: Event) => {
    setText((e.target as HTMLInputElement).value);
    setMode('text');
    setFile(null);
    setCachedFrame(null);
    setPasswordCopied(false);
    setStatus((prev) => (prev.step === 'error' ? { step: 'input' } : prev));
  }, []);

  const handlePassphraseInput = useCallback((e: Event) => {
    const value = (e.target as HTMLInputElement).value;
    setPassphrase(value);
    if (value) {
      void preloadPassphraseKdf().catch(() => {
        // Surface load errors on submit/decrypt; do not block typing.
      });
    }
  }, []);

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

        // Attach encrypted note if provided
        if (note.trim() && auth.sessionToken && auth.userId) {
          try {
            let amk = await loadAmk(auth.userId);
            if (!amk) {
              // First note: generate AMK and store locally.
              amk = generateAmk();
              await storeAmk(auth.userId, amk);
              // Commit to server (first-writer-wins; throws on 409 mismatch)
              const commit = await computeAmkCommit(amk);
              await commitAmk(auth.sessionToken, base64urlEncode(commit));
            }
            const encrypted = await encryptNote(amk, res.id, utf8Encode(note));
            const encMeta: EncMetaV1 = {
              v: 1,
              note: {
                ct: encrypted.ct,
                nonce: encrypted.nonce,
                salt: encrypted.salt,
              },
            };
            await updateSecretMeta(
              auth.sessionToken,
              res.id,
              encMeta,
              1,
              controller.signal,
            );
          } catch (noteErr) {
            // Non-fatal: secret was created, but note couldn't be attached
            console.error('[secrt] failed to attach note:', noteErr);
          }
        }

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
      note,
      passphrase,
      ttlSeconds,
      hasContent,
      busy,
      serverInfo,
      cachedFrame,
      auth.authenticated,
      auth.sessionToken,
      auth.userId,
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
    <div class="space-y-4">
      <div class="card space-y-6">
        {/* Send / Get tab switcher */}
        <div class="-mt-1.5 flex gap-2" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'send'}
            class={`flex-1 border-b-2 px-4 pb-1.5 text-center font-semibold tracking-wider uppercase transition-colors ${
              tab === 'send'
                ? 'border-accent-hover text-black dark:border-accent dark:text-white'
                : 'border-neutral-200 text-muted hover:border-neutral-400 hover:text-neutral-800 dark:border-neutral-600 dark:hover:border-neutral-400 dark:hover:text-neutral-300'
            }`}
            onClick={() => setTab('send')}
          >
            Send Secret
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'get'}
            class={`flex-1 border-b-2 px-4 pb-1.5 text-center font-semibold tracking-wider uppercase transition-colors ${
              tab === 'get'
                ? 'border-accent-hover text-black dark:border-accent dark:text-white'
                : 'border-neutral-200 text-muted hover:border-neutral-400 hover:text-neutral-800 dark:border-neutral-600 dark:hover:border-neutral-400 dark:hover:text-neutral-300'
            }`}
            onClick={() => setTab('get')}
          >
            Get Secret
          </button>
        </div>

        {tab === 'get' && <GetSecretForm />}

        {/* Send tab content */}
        {tab === 'send' && (
          <form
            class="space-y-6"
            onSubmit={handleSubmit}
            onDragOver={handlePageDragOver}
          >
            <p class="text-center text-sm text-muted">
              The server never sees the original text or file.
            </p>
            {/* Content input */}
            <div class="space-y-1">
              <div class="flex items-center justify-between gap-2">
                <label class="label">
                  {mode === 'text' ? (
                    <>
                      <DocumentIcon
                        class="size-4 opacity-60"
                        aria-hidden="true"
                      />{' '}
                      Secret Message
                    </>
                  ) : (
                    <>
                      <UploadIcon
                        class="size-4 opacity-60"
                        aria-hidden="true"
                      />{' '}
                      Secret File
                    </>
                  )}
                </label>
                {mode === 'text' && (
                  <div class="flex items-center gap-1">
                    <button
                      type="button"
                      class="link"
                      onClick={handleGenerateDefaultPassword}
                      disabled={busy}
                    >
                      {passwordCopied ? (
                        'Copied to Clipboard!'
                      ) : (
                        <>
                          <span class="xs:hidden">Generate</span>
                          <span class="hidden xs:inline">
                            Generate a Password
                          </span>
                        </>
                      )}
                    </button>
                    <button
                      type="button"
                      class="rounded p-1 transition-colors hover:text-text"
                      onClick={() => setPasswordModalOpen(true)}
                      aria-label="Password generator settings"
                      disabled={busy}
                    >
                      <GearIcon class="label size-4 hover:text-black dark:hover:text-white" />
                    </button>
                  </div>
                )}
              </div>
              {/* Grid stack: textarea sets the height, drop zone overlays it */}
              <div class="grid">
                <textarea
                  class={`textarea mb-0 [grid-area:1/1] ${mode === 'file' ? 'invisible' : ''} ${contentError && mode === 'text' ? 'input-error' : ''}`}
                  rows={5}
                  placeholder="Enter your secret or drag a file here..."
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
              <p class="text-center text-sm">
                {mode === 'text' ? (
                  <>
                    <button
                      type="button"
                      class="link"
                      onClick={() => fileInputRef.current?.click()}
                    >
                      Choose a File
                    </button>{' '}
                    {/*or drag one here to upload*/}
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
              <label class="label" for="passphrase">
                <LockIcon class="size-4 opacity-60" aria-hidden="true" />
                <span class="flex items-baseline gap-2">
                  Passphrase{' '}
                  <span class="text-sm font-normal text-faint">optional</span>
                </span>
              </label>
              <div class="relative">
                <input
                  id="passphrase"
                  type={showPassphrase ? 'text' : 'password'}
                  class="input pr-10"
                  placeholder=""
                  value={passphrase}
                  onInput={handlePassphraseInput}
                  disabled={busy}
                  autocomplete="off"
                />
                <button
                  type="button"
                  class="absolute top-1/2 right-2 -translate-y-1/2 p-1 hover:text-text"
                  onClick={() => setShowPassphrase((s) => !s)}
                  aria-label={
                    showPassphrase ? 'Hide passphrase' : 'Show passphrase'
                  }
                >
                  {showPassphrase ? (
                    <EyeSlashIcon class="label size-4 hover:text-black dark:hover:text-white" />
                  ) : (
                    <EyeIcon class="label size-4 hover:text-black dark:hover:text-white" />
                  )}
                </button>
              </div>
              <p class="text-center text-sm text-muted">
                {passphrase
                  ? 'The recipient must enter this password'
                  : '\u00A0'}
              </p>
            </div>

            {/* Private note (only shown when authenticated + feature enabled) */}
            {notesAvailable && noteStatus === 'available' && (
              <div class="space-y-1">
                <label class="label" for="note">
                  <NoteIcon class="size-4 opacity-60" aria-hidden="true" />
                  <span class="flex items-baseline gap-2">
                    Private Note{' '}
                    <span class="text-sm font-normal text-faint">optional</span>
                  </span>
                </label>
                <input
                  id="note"
                  type="text"
                  class="input"
                  placeholder="Description"
                  value={note}
                  onInput={(e) => setNote((e.target as HTMLInputElement).value)}
                  disabled={busy}
                  maxLength={500}
                  autocomplete="off"
                />
                <p class="text-center text-sm text-muted">
                  Only visible to you on your dashboard
                </p>
              </div>
            )}
            {notesAvailable && noteStatus === 'needs-sync' && (
              <div class="space-y-1">
                <label class="label" for="note">
                  <NoteIcon class="size-4 opacity-60" aria-hidden="true" />
                  <span class="flex items-baseline gap-2">
                    Private Note{' '}
                    <span class="text-sm font-normal text-faint">optional</span>
                  </span>
                </label>
                <input
                  disabled
                  class="input border-yellow-600 text-center dark:border-yellow-500/50"
                  value="Notes Unavailable: No Notes Key"
                />
                <p class="text-center text-sm">
                  Sync Notes Key from an authenticated device to add notes.
                </p>
              </div>
            )}

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
              aria-busy={busy}
              aria-describedby={
                status.step === 'error' ? 'send-error' : undefined
              }
            >
              {buttonLabel}
            </button>

            {/* Error */}
            {status.step === 'error' && (
              <div
                id="send-error"
                role="alert"
                class="alert-error flex items-center gap-2"
              >
                <TriangleExclamationIcon
                  class="size-5 shrink-0"
                  aria-hidden="true"
                />
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
        )}
      </div>

      {/* Password generator modal */}
      <Modal
        open={passwordModalOpen}
        onClose={() => setPasswordModalOpen(false)}
        dismissible
        asForm
        onSubmit={handleGeneratePasswordFromModal}
        aria-label="Password generator"
        data-testid="password-generator-backdrop"
      >
        <button
          type="button"
          class="absolute top-3 right-3 rounded p-1 text-muted transition-colors hover:text-text"
          onClick={() => setPasswordModalOpen(false)}
          aria-label="Close password generator"
        >
          <XMarkIcon class="size-5" />
        </button>

        <div class="flex flex-col items-center gap-2 text-center">
          <CardHeading
            icon={<KeyIcon class="size-10" />}
            title="Generate Password"
            subtitle={
              'Replace the message with a random password\nand copies it directly to your clipboard.'
            }
          />
        </div>

        <div class="space-y-1">
          <label class="label text-muted" for="password-generator-preview">
            Password Preview
          </label>
          <input
            id="password-generator-preview"
            type="text"
            class="input font-mono"
            value={text}
            onInput={handlePasswordPreviewInput}
            autocomplete="off"
          />
          <p class="text-sm text-muted">
            Edit this value directly. It stays synced with Secret Message.
          </p>
        </div>

        <div class="space-y-1">
          <label class="label text-muted" for="password-generator-length">
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
          <p class="text-sm text-muted">
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
          Group characters for easier entry
        </label>

        {!passwordLengthValid && (
          <div role="alert" class="alert-error text-sm">
            Length must be at least {MIN_PASSWORD_LENGTH}.
          </div>
        )}

        <button
          type="submit"
          class="btn btn-primary w-full tracking-wider uppercase"
          disabled={!passwordLengthValid}
        >
          Generate &amp; copy
        </button>
      </Modal>
    </div>
  );
}
