/**
 * /pair — browser-to-browser AMK transfer entry point.
 *
 * Two inner panels (display, join) selected via the `mode` query param,
 * with `role` selecting which side the displayer represents (send vs
 * receive) and `code` deep-linking the join panel from a QR scan.
 *
 * Both browsers must already be signed in as the same account; the server
 * enforces same-user-binding on every pair endpoint.
 */

import { useState, useEffect } from 'preact/hooks';
import { useAuth } from '../../lib/auth-context';
import { navigate } from '../../router';
import { CardHeading } from '../../components/CardHeading';
import { PairDisplayPanel } from './PairDisplayPanel';
import { PairJoinPanel } from './PairJoinPanel';
import type { PairRole } from '../../lib/api';

type Mode = 'display' | 'join' | 'pick';

interface PairParams {
  mode: Mode;
  role: PairRole;
  code: string | null;
}

function parsePairParams(): PairParams {
  const params = new URLSearchParams(window.location.search);
  const rawMode = params.get('mode');
  const rawRole = params.get('role');
  const code = params.get('code');

  const mode: Mode =
    rawMode === 'display' ? 'display' : rawMode === 'join' ? 'join' : 'pick';
  const role: PairRole = rawRole === 'send' ? 'send' : 'receive';

  return { mode, role, code };
}

export function PairPage() {
  const auth = useAuth();
  const [params, setParams] = useState<PairParams>(parsePairParams);

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

  if (auth.loading) {
    return (
      <div class="card text-center">
        <p class="text-muted">Loading...</p>
      </div>
    );
  }
  if (!auth.authenticated) return null;

  if (params.mode === 'display') {
    return (
      <PairDisplayPanel
        role={params.role}
        onChooseJoin={() =>
          setParams({ mode: 'join', role: params.role, code: null })
        }
      />
    );
  }

  if (params.mode === 'join') {
    return (
      <PairJoinPanel
        prefilledCode={params.code}
        onChooseDisplay={() =>
          setParams({ mode: 'display', role: params.role, code: null })
        }
      />
    );
  }

  // Picker — landed on bare /pair without a mode hint.
  return (
    <div class="card space-y-6">
      <CardHeading
        title="Pair Another Device"
        subtitle="Move your account key to another browser without using a sync link."
      />

      <div class="space-y-3">
        <button
          type="button"
          class="btn btn-primary w-full tracking-wider uppercase"
          onClick={() =>
            setParams({ mode: 'display', role: 'receive', code: null })
          }
        >
          This browser is new — show a code to receive my key
        </button>

        <button
          type="button"
          class="btn w-full tracking-wider uppercase"
          onClick={() =>
            setParams({ mode: 'display', role: 'send', code: null })
          }
        >
          This browser has my key — show a code to send to a new device
        </button>

        <button
          type="button"
          class="btn w-full tracking-wider uppercase"
          onClick={() =>
            setParams({ mode: 'join', role: 'receive', code: null })
          }
        >
          I see a code on another device — join it
        </button>
      </div>

      <p class="text-center text-xs text-muted">
        Both browsers must be signed in as the same account.
      </p>
    </div>
  );
}
