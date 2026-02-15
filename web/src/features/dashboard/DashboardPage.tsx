import { useState, useEffect, useCallback, useRef } from 'preact/hooks';
import { AuthGuard } from '../../components/AuthGuard';
import { useAuth } from '../../lib/auth-context';
import { listSecrets, burnSecretAuthed } from '../../lib/api';
import { FireIcon } from '../../components/Icons';
import { navigate } from '../../router';
import type { SecretMetadata } from '../../types';

const PAGE_SIZE = 50;

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
  if (hrs > 0)
    return (
      <>
        {hrs}:{pad(mins)}
        {ss}
      </>
    );
  if (mins > 0)
    return (
      <>
        {mins}:{pad(secs)}
      </>
    );
  return <>0:{pad(secs)}</>;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
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
  const popoverRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const trigger = triggerRef.current;
    const popover = popoverRef.current;
    if (!trigger || !popover) return;

    popover.setAttribute('popover', 'auto');
    trigger.setAttribute('popovertarget', popover.id);

    const onToggle = () => {
      if (popover.matches(':popover-open')) {
        const rect = trigger.getBoundingClientRect();
        popover.style.position = 'fixed';
        popover.style.top = `${rect.bottom + 4}px`;
        popover.style.right = `${window.innerWidth - rect.right}px`;
        popover.style.left = 'auto';
        popover.style.margin = '0';
      }
    };

    popover.addEventListener('toggle', onToggle);
    return () => popover.removeEventListener('toggle', onToggle);
  }, []);

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        class="flex items-center gap-1 rounded-md border border-transparent px-1 py-0.5 text-error/50 hover:border-error hover:bg-error/10 hover:text-error"
      >
        <FireIcon class="size-4" />
        <span class="hidden sm:inline">Burn</span>
      </button>
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
              popoverRef.current?.hidePopover();
            }}
          >
            {burning ? 'Burning...' : 'Yes, burn'}
          </button>
          <button
            type="button"
            class="btn p-1 py-0.5 text-xs"
            onClick={() => popoverRef.current?.hidePopover()}
          >
            Cancel
          </button>
        </div>
      </div>
    </>
  );
}

function DashboardContent() {
  const auth = useAuth();
  const [secrets, setSecrets] = useState<SecretMetadata[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [burning, setBurning] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const fetchSecrets = useCallback(
    async (newOffset: number) => {
      if (!auth.sessionToken) return;
      setLoading(true);
      setError(null);
      try {
        const res = await listSecrets(auth.sessionToken, PAGE_SIZE, newOffset);
        setSecrets(res.secrets);
        setTotal(res.total);
        setOffset(newOffset);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load secrets');
      } finally {
        setLoading(false);
      }
    },
    [auth.sessionToken],
  );

  useEffect(() => {
    fetchSecrets(0);
  }, [fetchSecrets]);

  const handleBurn = useCallback(
    async (id: string) => {
      if (!auth.sessionToken) return;
      setBurning(id);
      try {
        await burnSecretAuthed(auth.sessionToken, id);
        setSecrets((prev) => prev.filter((s) => s.id !== id));
        setTotal((prev) => prev - 1);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to burn secret');
      } finally {
        setBurning(null);
      }
    },
    [auth.sessionToken],
  );

  return (
    <div class="">
      <h2 class="heading text-center">Your Secrets</h2>

      {error && (
        <div
          role="alert"
          class="mb-4 rounded-md bg-red-100 px-3 py-2 text-sm text-red-700 dark:bg-red-900/30 dark:text-red-400"
        >
          {error}
        </div>
      )}

      {loading && secrets.length === 0 ? (
        <p class="text-sm text-muted">Loading...</p>
      ) : secrets.length === 0 ? (
        <div class="text-center">
          <p class="mb-4 text-sm text-muted">You have no active secrets.</p>
          <button type="button" class="link" onClick={() => navigate('/')}>
            Create a Secret
          </button>
        </div>
      ) : (
        <>
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-border text-left">
                  <th class="pr-3 pb-2 font-medium">ID</th>
                  <th class="pr-3 pb-2 font-medium">Created</th>
                  <th class="w-[119px] pr-3 pb-2 font-medium">
                    <span class="flex items-center gap-1">
                      {/*<ClockIcon class="size-3.5" />*/}
                      Remaining
                    </span>
                  </th>
                  <th class="pb-2 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {secrets.map((s) => (
                  <tr key={s.id} class="border-b border-border/50">
                    <td class="max-w-[8rem] truncate py-2 pr-3 font-mono text-xs sm:max-w-[12rem] md:max-w-[18rem] lg:max-w-none">
                      {s.id}
                    </td>
                    <td class="py-2 pr-3 whitespace-nowrap">
                      {formatDate(s.created_at)}
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
                class="text-sm text-muted hover:text-text disabled:opacity-50"
                disabled={offset === 0 || loading}
                onClick={() => fetchSecrets(Math.max(0, offset - PAGE_SIZE))}
              >
                Previous
              </button>
              <span class="text-xs text-muted">
                {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
              </span>
              <button
                type="button"
                class="text-sm text-muted hover:text-text disabled:opacity-50"
                disabled={offset + PAGE_SIZE >= total || loading}
                onClick={() => fetchSecrets(offset + PAGE_SIZE)}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}

      <div class="mt-6 flex flex-col justify-center gap-4">
        <button type="button" class="link" onClick={() => navigate('/')}>
          Send A New Secret
        </button>

        <button
          type="button"
          class="link"
          onClick={() => navigate('/settings')}
        >
          Manage API Keys & Account Settings
        </button>
      </div>
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
