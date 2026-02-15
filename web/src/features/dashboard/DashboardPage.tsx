import { useState, useEffect, useCallback } from 'preact/hooks';
import { AuthGuard } from '../../components/AuthGuard';
import { useAuth } from '../../lib/auth-context';
import { listSecrets, burnSecretAuthed } from '../../lib/api';
import { FireIcon, ClockIcon } from '../../components/Icons';
import { navigate } from '../../router';
import type { SecretMetadata } from '../../types';

const PAGE_SIZE = 50;

function timeRemaining(expiresAt: string): string {
  const ms = new Date(expiresAt).getTime() - Date.now();
  if (ms <= 0) return 'Expired';
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ${mins % 60}m`;
  const days = Math.floor(hrs / 24);
  return `${days}d ${hrs % 24}h`;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function DashboardContent() {
  const auth = useAuth();
  const [secrets, setSecrets] = useState<SecretMetadata[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [burning, setBurning] = useState<string | null>(null);
  const [confirmBurn, setConfirmBurn] = useState<string | null>(null);

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
        setConfirmBurn(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to burn secret');
      } finally {
        setBurning(null);
      }
    },
    [auth.sessionToken],
  );

  return (
    <div class="card">
      <h2 class="label mb-4">Your Secrets</h2>

      {error && (
        <div role="alert" class="mb-4 rounded-md bg-red-100 px-3 py-2 text-sm text-red-700 dark:bg-red-900/30 dark:text-red-400">
          {error}
        </div>
      )}

      {loading && secrets.length === 0 ? (
        <p class="text-sm text-muted">Loading...</p>
      ) : secrets.length === 0 ? (
        <div class="text-center">
          <p class="text-sm text-muted mb-3">No active secrets.</p>
          <button
            type="button"
            class="btn btn-primary text-sm"
            onClick={() => navigate('/')}
          >
            Create a Secret
          </button>
        </div>
      ) : (
        <>
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-border text-left text-muted">
                  <th class="pb-2 pr-3 font-medium">ID</th>
                  <th class="pb-2 pr-3 font-medium">Created</th>
                  <th class="pb-2 pr-3 font-medium">
                    <span class="flex items-center gap-1">
                      <ClockIcon class="size-3.5" />
                      Remaining
                    </span>
                  </th>
                  <th class="pb-2 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {secrets.map((s) => (
                  <tr key={s.id} class="border-b border-border/50">
                    <td class="py-2 pr-3 font-mono text-xs">
                      {s.id.slice(0, 12)}...
                    </td>
                    <td class="py-2 pr-3 whitespace-nowrap">
                      {formatDate(s.created_at)}
                    </td>
                    <td class="py-2 pr-3 whitespace-nowrap">
                      {timeRemaining(s.expires_at)}
                    </td>
                    <td class="py-2 text-right">
                      {confirmBurn === s.id ? (
                        <span class="inline-flex items-center gap-2">
                          <span class="text-xs text-muted">Sure?</span>
                          <button
                            type="button"
                            class="text-xs text-red-600 hover:text-red-700 dark:text-red-400"
                            disabled={burning === s.id}
                            onClick={() => handleBurn(s.id)}
                          >
                            {burning === s.id ? 'Burning...' : 'Yes, burn'}
                          </button>
                          <button
                            type="button"
                            class="text-xs text-muted hover:text-text"
                            onClick={() => setConfirmBurn(null)}
                          >
                            Cancel
                          </button>
                        </span>
                      ) : (
                        <button
                          type="button"
                          class="inline-flex items-center gap-1 text-xs text-muted hover:text-red-600 dark:hover:text-red-400"
                          onClick={() => setConfirmBurn(s.id)}
                        >
                          <FireIcon class="size-3.5" />
                          Burn
                        </button>
                      )}
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

      <div class="mt-6 text-center">
        <button
          type="button"
          class="text-sm text-muted hover:text-text"
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
