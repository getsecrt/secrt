/**
 * /pair — browser-to-browser AMK transfer entry point.
 *
 * Mode is derived from local state, not query params:
 *
 *   - No AMK on this device  → Page A (display a code + QR + countdown).
 *   - AMK present, no ?code= → Page B (type or scan a code).
 *   - AMK present, ?code=…   → Page B prefilled (deep-link path).
 *   - No AMK + ?code=…       → Page A (this device can't send; ignore code).
 *
 * Both browsers must already be signed in as the same account; the server
 * enforces same-user-binding on every pair endpoint.
 */

import { useEffect, useState } from 'preact/hooks';
import { useAuth } from '../../lib/auth-context';
import { navigate } from '../../router';
import { loadAmk } from '../../lib/amk-store';
import { PairDisplayPanel } from './PairDisplayPanel';
import { PairJoinPanel } from './PairJoinPanel';

type AmkState = 'loading' | 'absent' | 'present';

function readCodeFromUrl(): string | null {
  const params = new URLSearchParams(window.location.search);
  const raw = params.get('code');
  return raw ? raw.toUpperCase() : null;
}

export function PairPage() {
  const auth = useAuth();
  const [amk, setAmk] = useState<AmkState>('loading');
  const [code, setCode] = useState<string | null>(() => readCodeFromUrl());

  // Same setTimeout(fn, 0) workaround as DevicePage — child effects fire
  // before parent route popstate listener attaches on initial mount. See
  // MEMORY.md "Preact Effect Ordering Bug".
  useEffect(() => {
    if (!auth.loading && !auth.authenticated) {
      const returnUrl = `/pair${window.location.search}`;
      setTimeout(
        () => navigate(`/login?redirect=${encodeURIComponent(returnUrl)}`),
        0,
      );
    }
  }, [auth.loading, auth.authenticated]);

  // Load AMK state once we know who the user is.
  useEffect(() => {
    if (!auth.userId) return;
    let cancelled = false;
    setAmk('loading');
    (async () => {
      const result = await loadAmk(auth.userId!);
      if (cancelled) return;
      setAmk(result ? 'present' : 'absent');
    })();
    return () => {
      cancelled = true;
    };
  }, [auth.userId]);

  // Same-instance URL reactivity. PairPage parses `?code=` once at mount;
  // re-derive it on popstate so a navigate() inside the page (e.g. typing
  // a code on Page B that updates the URL) still flips into the prefilled
  // path. PairPage may also re-render in-place if the router preserves the
  // same instance across same-route navigations.
  useEffect(() => {
    const onPop = () => setCode(readCodeFromUrl());
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  if (auth.loading || amk === 'loading') {
    return (
      <div class="card text-center">
        <p class="text-muted">Preparing…</p>
      </div>
    );
  }
  if (!auth.authenticated) return null;

  if (amk === 'absent') {
    return <PairDisplayPanel />;
  }

  return <PairJoinPanel prefilledCode={code} />;
}
