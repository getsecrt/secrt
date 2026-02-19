import {
  useState,
  useEffect,
  useLayoutEffect,
  useCallback,
  useRef,
  useMemo,
} from 'preact/hooks';
import { AuthGuard } from '../../components/AuthGuard';
import { useAuth } from '../../lib/auth-context';
import { listSecrets, checkSecrets, burnSecretAuthed } from '../../lib/api';
import { decryptNote } from '../../crypto/amk';
import { utf8Decode } from '../../crypto/encoding';
import { loadAmk } from '../../lib/amk-store';
import {
  FireIcon,
  LockIcon,
  NoteIcon,
  ClipboardIcon,
  XMarkIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ChevronDownIcon,
  ChevronUpIcon,
} from '../../components/Icons';
import { CardHeading } from '../../components/CardHeading';
import { CopyButton } from '../../components/CopyButton';
import { Modal } from '../../components/Modal';
import { SyncNotesKeyButton } from '../../components/SyncNotesKeyButton';
import { navigate } from '../../router';
import type { SecretMetadata } from '../../types';

const PAGE_SIZE = 10;
const FETCH_LIMIT = 20_000;

type SortColumn = 'created_at' | 'expires_at' | 'ciphertext_size';
type SortOrder = 'asc' | 'desc';

const pad = (n: number) => String(n).padStart(2, '0');

function timeRemaining(expiresAt: string, now: number) {
  const ms = new Date(expiresAt).getTime() - now;
  if (ms <= 0) return 'Expired';
  const totalSecs = Math.floor(ms / 1000);
  const secs = totalSecs % 60;
  const mins = Math.floor(totalSecs / 60) % 60;
  const hrs = Math.floor(totalSecs / 3600) % 24;
  const days = Math.floor(totalSecs / 86400);
  const ss = <span class="text-[0.85em] opacity-50">:{pad(secs)}</span>;
  if (days > 0)
    return (
      <>
        {days}d {pad(hrs)}:{pad(mins)}
        {ss}
      </>
    );
  return (
    <>
      {hrs}:{pad(mins)}
      {ss}
    </>
  );
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function SortIndicator({
  column,
  sortBy,
  sortOrder,
}: {
  column: SortColumn;
  sortBy: SortColumn;
  sortOrder: SortOrder;
}) {
  if (column !== sortBy) return null;
  return sortOrder === 'asc' ? (
    <ChevronUpIcon class="ml-0.5 inline size-3" />
  ) : (
    <ChevronDownIcon class="ml-0.5 inline size-3" />
  );
}

function BurnPopover({
  id,
  burning,
  onBurn,
}: {
  id: string;
  burning: boolean;
  onBurn: (id: string) => void;
}) {
  const triggerRef = useRef<HTMLButtonElement>(null);
  const [open, setOpen] = useState(false);
  const popoverRef = useRef<HTMLDivElement>(null);

  // Position and show the popover before first paint
  useLayoutEffect(() => {
    const popover = popoverRef.current;
    const trigger = triggerRef.current;
    if (!open || !popover || !trigger) return;

    popover.setAttribute('popover', 'auto');

    const rect = trigger.getBoundingClientRect();
    popover.style.position = 'fixed';
    popover.style.top = `${rect.bottom + 4}px`;
    popover.style.right = `${window.innerWidth - rect.right}px`;
    popover.style.left = 'auto';
    popover.style.margin = '0';

    popover.showPopover();

    const onToggle = () => {
      if (!popover.matches(':popover-open')) setOpen(false);
    };
    popover.addEventListener('toggle', onToggle);
    return () => popover.removeEventListener('toggle', onToggle);
  }, [open]);

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        class="btn-destructive-subtle"
        onClick={() => setOpen(true)}
      >
        <FireIcon class="size-4 text-error" />
        <span class="hidden sm:inline">Burn</span>
      </button>
      {open && (
        <div
          ref={popoverRef}
          id={`burn-${id}`}
          class="rounded-lg border border-border/90 bg-surface-raised/80 p-2 text-text shadow-lg backdrop-blur"
        >
          <p class="mb-2 text-center text-sm">Burn this secret?</p>
          <div class="flex gap-4">
            <button
              type="button"
              class="btn btn-danger p-1 py-0.5 text-xs"
              disabled={burning}
              onClick={() => {
                onBurn(id);
                setOpen(false);
              }}
            >
              {burning ? 'Burning...' : 'Yes, burn'}
            </button>
            <button
              type="button"
              class="btn p-1 py-0.5 text-xs"
              onClick={() => setOpen(false)}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </>
  );
}

function DashboardContent() {
  const auth = useAuth();
  const [allSecrets, setAllSecrets] = useState<SecretMetadata[]>([]);
  const [serverTotal, setServerTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [burning, setBurning] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());
  const [sortBy, setSortBy] = useState<SortColumn>('created_at');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [page, setPage] = useState(0);
  const [decryptedNotes, setDecryptedNotes] = useState<Record<string, string>>(
    {},
  );
  const [selectedSecret, setSelectedSecret] = useState<SecretMetadata | null>(
    null,
  );
  const amkRef = useRef<Uint8Array | null>(null);
  const [hasAmk, setHasAmk] = useState(false);

  // Load AMK from IndexedDB on mount
  useEffect(() => {
    if (!auth.userId) return;
    loadAmk(auth.userId)
      .then((amk) => {
        amkRef.current = amk;
        setHasAmk(amk !== null);
      })
      .catch(() => {
        /* AMK unavailable */
      });
  }, [auth.userId]);

  // Decrypt notes when secrets change
  useEffect(() => {
    const amk = amkRef.current;
    if (!amk) return;

    const secretsWithNotes = allSecrets.filter((s) => s.enc_meta?.note);
    if (secretsWithNotes.length === 0) return;

    let cancelled = false;
    (async () => {
      const notes: Record<string, string> = {};
      for (const s of secretsWithNotes) {
        if (cancelled) return;
        try {
          const pt = await decryptNote(amk, s.id, s.enc_meta!.note);
          notes[s.id] = utf8Decode(pt);
        } catch {
          notes[s.id] = '\u26A0 Unable to decrypt note';
        }
      }
      if (!cancelled) setDecryptedNotes(notes);
    })();
    return () => {
      cancelled = true;
    };
  }, [allSecrets]);

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const fetchSecrets = useCallback(async () => {
    if (!auth.sessionToken) return;
    setLoading(true);
    setError(null);
    try {
      const res = await listSecrets(auth.sessionToken, FETCH_LIMIT, 0);
      setAllSecrets(res.secrets);
      setServerTotal(res.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load secrets');
    } finally {
      setLoading(false);
    }
  }, [auth.sessionToken]);

  useEffect(() => {
    fetchSecrets();
  }, [fetchSecrets]);

  // Poll for changes via lightweight checksum endpoint
  const lastChecksum = useRef<string>('');
  useEffect(() => {
    if (!auth.sessionToken) return;
    const controller = new AbortController();
    const id = setInterval(async () => {
      if (loading) return;
      try {
        const res = await checkSecrets(auth.sessionToken!, controller.signal);
        if (res.checksum !== lastChecksum.current) {
          lastChecksum.current = res.checksum;
          fetchSecrets();
        }
      } catch {
        // Silently ignore poll errors (network blips, unmount abort)
      }
    }, 4000);
    return () => {
      clearInterval(id);
      controller.abort();
    };
  }, [auth.sessionToken, loading, fetchSecrets]);

  const sorted = useMemo(() => {
    const copy = [...allSecrets];
    const dir = sortOrder === 'asc' ? 1 : -1;
    copy.sort((a, b) => {
      if (sortBy === 'ciphertext_size') {
        return (a.ciphertext_size - b.ciphertext_size) * dir;
      }
      // String compare for date ISO strings (lexicographic = chronological)
      const av = a[sortBy];
      const bv = b[sortBy];
      return av < bv ? -dir : av > bv ? dir : 0;
    });
    return copy;
  }, [allSecrets, sortBy, sortOrder]);

  const total = allSecrets.length;
  const totalPages = Math.ceil(total / PAGE_SIZE);
  const pageSecrets = sorted.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const toggleSort = (column: SortColumn) => {
    if (sortBy === column) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(column);
      setSortOrder('desc');
    }
    setPage(0);
  };

  const handleBurn = useCallback(
    async (id: string) => {
      if (!auth.sessionToken) return;
      setBurning(id);
      try {
        await burnSecretAuthed(auth.sessionToken, id);
        setAllSecrets((prev) => prev.filter((s) => s.id !== id));
        setServerTotal((prev) => prev - 1);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to burn secret');
      } finally {
        setBurning(null);
      }
    },
    [auth.sessionToken],
  );

  const thSortable = 'cursor-pointer select-none';

  return (
    <div class="">
      <CardHeading title="Your Secrets" class="mb-4" />

      {error && (
        <div role="alert" class="alert-error mb-4">
          {error}
        </div>
      )}

      {loading && allSecrets.length === 0 ? (
        <p class="text-muted">Loading...</p>
      ) : allSecrets.length === 0 ? (
        <div class="text-center">
          <p class="mb-4 text-muted">You have no active secrets.</p>
        </div>
      ) : (
        <>
          {serverTotal > allSecrets.length && (
            <p class="mb-2 text-sm text-muted">
              Showing {allSecrets.length} of {serverTotal} secrets
            </p>
          )}

          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-border text-left">
                  <th class="pr-3 pb-2 font-medium">ID</th>
                  <th
                    class={`pr-3 pb-2 font-medium ${thSortable}`}
                    onClick={() => toggleSort('created_at')}
                  >
                    Created
                    <SortIndicator
                      column="created_at"
                      sortBy={sortBy}
                      sortOrder={sortOrder}
                    />
                  </th>
                  <th
                    class={`hidden pr-3 pb-2 font-medium sm:table-cell ${thSortable}`}
                    onClick={() => toggleSort('ciphertext_size')}
                  >
                    Size
                    <SortIndicator
                      column="ciphertext_size"
                      sortBy={sortBy}
                      sortOrder={sortOrder}
                    />
                  </th>
                  <th class="hidden pr-3 pb-2 font-medium md:table-cell">
                    <NoteIcon class="size-3.5" />
                  </th>
                  <th class="pr-3 pb-2 font-medium">
                    <LockIcon class="size-3.5" />
                  </th>
                  <th
                    class={`w-[119px] pr-3 pb-2 font-medium ${thSortable}`}
                    onClick={() => toggleSort('expires_at')}
                  >
                    Remaining
                    <SortIndicator
                      column="expires_at"
                      sortBy={sortBy}
                      sortOrder={sortOrder}
                    />
                  </th>
                  <th class="pb-2 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {pageSecrets.map((s) => (
                  <tr key={s.id} class="border-b border-border/50">
                    <td
                      class="link-subtle max-w-[8rem] cursor-pointer truncate py-2 pr-3 font-mono text-xs hover:text-accent sm:max-w-[12rem] md:max-w-[18rem] lg:max-w-none"
                      onClick={() => setSelectedSecret(s)}
                    >
                      {s.id}
                    </td>
                    <td class="py-2 pr-3 whitespace-nowrap">
                      {formatDate(s.created_at)}
                    </td>
                    <td class="hidden py-2 pr-3 whitespace-nowrap sm:table-cell">
                      {formatSize(s.ciphertext_size)}
                    </td>
                    <td
                      class={`hidden max-w-[12rem] truncate py-2 pr-3 text-xs md:table-cell ${
                        decryptedNotes[s.id] || s.enc_meta?.note
                          ? 'link-subtle cursor-pointer text-muted hover:text-accent'
                          : 'text-muted'
                      }`}
                      title={
                        decryptedNotes[s.id] ??
                        (s.enc_meta?.note ? 'Encrypted' : '')
                      }
                      onClick={() =>
                        (decryptedNotes[s.id] || s.enc_meta?.note) &&
                        setSelectedSecret(s)
                      }
                    >
                      {decryptedNotes[s.id] ?? (
                        s.enc_meta?.note ? (
                          <span class="italic opacity-60">Encrypted</span>
                        ) : (
                          ''
                        )
                      )}
                    </td>
                    <td class="py-2 pr-3">
                      {s.passphrase_protected && (
                        <LockIcon
                          class="size-4 text-muted"
                          title="Passphrase protected"
                        />
                      )}
                    </td>
                    <td class="py-2 pr-3 whitespace-nowrap">
                      {timeRemaining(s.expires_at, now)}
                    </td>
                    <td class="py-2 text-right">
                      <BurnPopover
                        id={s.id}
                        burning={burning === s.id}
                        onBurn={handleBurn}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {total > PAGE_SIZE && (
            <div class="mt-4 flex items-center justify-between">
              <button
                type="button"
                class="btn btn-sm"
                disabled={page === 0 || loading}
                onClick={() => setPage((p) => p - 1)}
              >
                <ChevronLeftIcon class="size-4" />
                Prev
              </button>
              <span class="text-sm text-muted">
                {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)}{' '}
                <span class="text-faint">of</span> {total}
              </span>
              <button
                type="button"
                class="btn btn-sm"
                disabled={page + 1 >= totalPages || loading}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
                <ChevronRightIcon class="size-4" />
              </button>
            </div>
          )}
        </>
      )}

      <div class="mt-6 flex flex-col items-center gap-4">
        <a
          href="/"
          class="link"
          onClick={(e: MouseEvent) => {
            e.preventDefault();
            navigate('/');
          }}
        >
          Send a New Secret
        </a>

        <a
          href="/settings"
          class="link"
          onClick={(e: MouseEvent) => {
            e.preventDefault();
            navigate('/settings');
          }}
        >
          API Keys & Account Settings
        </a>

        <SyncNotesKeyButton />
      </div>

      {/* Secret detail modal */}
      <Modal
        open={selectedSecret !== null}
        onClose={() => setSelectedSecret(null)}
        dismissible
      >
        {selectedSecret && (
          <>
            <button
              type="button"
              class="absolute top-3 right-3 rounded p-1 text-muted transition-colors hover:text-text"
              onClick={() => setSelectedSecret(null)}
              aria-label="Close"
            >
              <XMarkIcon class="size-5" />
            </button>

            <CardHeading title="Secret Details" />

            <dl class="space-y-4 text-sm">
              <div>
                <dt class="font-medium text-muted">ID</dt>
                <dd class="mt-0.5 font-mono text-xs break-all">
                  {selectedSecret.id}
                </dd>
              </div>
              <div>
                <dt class="font-medium text-muted">Created</dt>
                <dd class="mt-0.5">{formatDate(selectedSecret.created_at)}</dd>
              </div>
              <div>
                <dt class="font-medium text-muted">Remaining</dt>
                <dd class="mt-0.5">
                  {timeRemaining(selectedSecret.expires_at, now)}
                </dd>
              </div>
              <div>
                <dt class="font-medium text-muted">Envelope Size</dt>
                <dd class="mt-0.5">
                  {formatSize(selectedSecret.ciphertext_size)}
                </dd>
              </div>
              {selectedSecret.passphrase_protected && (
                <div>
                  <dt class="font-medium text-muted">Protection</dt>
                  <dd class="mt-0.5 flex items-center gap-1">
                    <LockIcon class="size-3.5" /> Passphrase protected
                  </dd>
                </div>
              )}
              {decryptedNotes[selectedSecret.id] ? (
                <div>
                  <dt class="font-medium text-muted">Note</dt>
                  <dd class="mt-0.5 whitespace-pre-wrap">
                    {decryptedNotes[selectedSecret.id]}
                  </dd>
                </div>
              ) : (
                selectedSecret.enc_meta?.note && (
                  <div>
                    <dt class="font-medium text-muted">Note</dt>
                    <dd class="mt-0.5 italic text-muted">
                      {hasAmk
                        ? 'Unable to decrypt note'
                        : 'Sync your notes key from another browser to view this note.'}
                    </dd>
                  </div>
                )
              )}
            </dl>
          </>
        )}
      </Modal>
    </div>
  );
}

export function DashboardPage() {
  return (
    <AuthGuard>
      <DashboardContent />
    </AuthGuard>
  );
}
