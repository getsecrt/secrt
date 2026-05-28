/**
 * SyncLandingPage — bare `/sync` (no ID).
 *
 * Reached when someone arrives at `/sync` without the `/<id>#<key>` tail
 * — usually a truncated paste, a stale bookmark, or a hand-typed URL.
 * Rather than showing a generic 404 we:
 *
 * 1. Redirect to `/login?redirect=/sync` if the user isn't signed in, so
 *    the user can at least authenticate before we explain what went wrong.
 *    The redirect-back lands them here again, now authed, where step 2
 *    takes over.
 * 2. If the user is signed in, render a friendly "the sync link is
 *    incomplete" message and point at `/pair`, the modern path.
 */

import { useEffect } from 'preact/hooks';
import { useAuth } from '../../lib/auth-context';
import { navigate } from '../../router';
import { CardHeading } from '../../components/CardHeading';
import { TriangleExclamationIcon } from '../../components/Icons';

export function SyncLandingPage() {
  const auth = useAuth();

  useEffect(() => {
    if (auth.loading) return;
    if (auth.authenticated) return;
    // Same defer-with-setTimeout pattern as SyncPage / DevicePage: in
    // Preact, child useEffect fires before parent useEffect, so a
    // synchronous navigate() here would dispatch a popstate before the
    // root router's listener is attached. See commit 34074da.
    setTimeout(() => navigate('/login?redirect=/sync'), 0);
  }, [auth.loading, auth.authenticated]);

  if (auth.loading || !auth.authenticated) {
    return (
      <div class="card text-center">
        <p class="text-muted">Signing in…</p>
      </div>
    );
  }

  return (
    <div class="card space-y-4 text-center">
      <CardHeading
        title="Sync link is incomplete"
        icon={<TriangleExclamationIcon class="text-warning size-10" />}
      />
      <p class="text-muted">
        This URL is missing the secret ID and decryption key — your link
        may have been truncated when it was copied.
      </p>
      <p class="text-muted">
        If you have access to another signed-in device, you can pair it
        directly instead — no link required.
      </p>
      <button
        type="button"
        class="btn btn-primary tracking-wider uppercase"
        onClick={() => navigate('/pair')}
      >
        Pair Another Device
      </button>
    </div>
  );
}
