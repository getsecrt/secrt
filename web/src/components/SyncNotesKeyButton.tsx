import { useState, useCallback, useRef, useEffect } from 'preact/hooks';
import { useAuth } from '../lib/auth-context';
import { seal, deriveClaimHash } from '../crypto/envelope';
import { createSecret } from '../lib/api';
import { loadAmk } from '../lib/amk-store';
import { formatSyncLink } from '../lib/url';
import { ShareResult } from '../features/send/ShareResult';
import { Modal } from './Modal';
import { TriangleExclamationIcon, XMarkIcon } from './Icons';

type SyncState =
  | { step: 'idle' }
  | { step: 'creating' }
  | { step: 'done'; shareUrl: string; expiresAt: string }
  | { step: 'error'; message: string };

/** Short TTL for sync links: 10 minutes. */
const SYNC_TTL_SECONDS = 600;

export function SyncNotesKeyButton() {
  const auth = useAuth();
  const [state, setState] = useState<SyncState>({ step: 'idle' });
  const [modalOpen, setModalOpen] = useState(false);
  const [hasAmk, setHasAmk] = useState<boolean | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  // Check whether this browser has a notes key stored
  useEffect(() => {
    if (!auth.userId) return;
    loadAmk(auth.userId).then((amk) => setHasAmk(amk !== null));
  }, [auth.userId]);

  const handleSync = useCallback(async () => {
    if (!auth.sessionToken || !auth.userId) return;

    const controller = new AbortController();
    abortRef.current = controller;

    setState({ step: 'creating' });
    setModalOpen(true);

    try {
      // 1. Load AMK from IndexedDB
      const amk = await loadAmk(auth.userId);
      if (!amk) throw new Error('Notes key not found.');

      // 2. Seal the AMK as a secret (no passphrase, binary payload)
      const { envelope, urlKey, claimHash } = await seal(amk, {
        type: 'binary',
      });

      if (controller.signal.aborted) return;

      // 3. Create the secret on the server with a short TTL
      const res = await createSecret(
        {
          envelope,
          claim_hash: claimHash,
          ttl_seconds: SYNC_TTL_SECONDS,
        },
        auth.sessionToken,
        controller.signal,
      );

      // 4. Build sync link (uses /sync/ prefix)
      const shareUrl = formatSyncLink(res.id, urlKey);

      setState({ step: 'done', shareUrl, expiresAt: res.expires_at });
    } catch (err) {
      if (controller.signal.aborted) return;
      setState({
        step: 'error',
        message:
          err instanceof Error ? err.message : 'Failed to create sync link.',
      });
    }
  }, [auth.sessionToken, auth.userId]);

  const handleClose = useCallback(() => {
    abortRef.current?.abort();
    setModalOpen(false);
    setState({ step: 'idle' });
  }, []);

  // Hide entirely if no AMK in this browser (or still checking)
  if (!hasAmk) return null;

  return (
    <>
      <button
        type="button"
        class="link"
        onClick={handleSync}
        disabled={state.step === 'creating'}
      >
        Sync Notes Key to Another Browser
      </button>

      <Modal open={modalOpen} onClose={handleClose} class="max-w-md">
        <button
          type="button"
          class="btn-icon absolute top-3 right-3"
          onClick={handleClose}
          aria-label="Close"
        >
          <XMarkIcon class="size-5" />
        </button>

        {state.step === 'creating' && (
          <p class="py-4 text-center text-muted">Creating sync link…</p>
        )}

        {state.step === 'done' && (
          <ShareResult
            shareUrl={state.shareUrl}
            expiresAt={state.expiresAt}
            title="Notes Key Link"
            subtitle="Open link in the browser you want to sync."
            bare
          />
        )}

        {state.step === 'error' && (
          <div class="space-y-4">
            <div role="alert" class="alert-error flex items-center gap-2">
              <TriangleExclamationIcon class="size-5 shrink-0" />
              {state.message}
            </div>
          </div>
        )}
      </Modal>
    </>
  );
}
