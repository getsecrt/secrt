import { useState, useEffect } from 'preact/hooks';
import { useAuth } from '../../lib/auth-context';
import { navigate } from '../../router';
import { appLoginApprove } from '../../lib/api';
import {
  CheckCircleIcon,
  TriangleExclamationIcon,
} from '../../components/Icons';
import { CardHeading } from '../../components/CardHeading';

type AppLoginState =
  | { step: 'confirm' }
  | { step: 'approving' }
  | { step: 'done' }
  | { step: 'error'; message: string }
  | { step: 'no-code' };

function parseUserCode(): string | null {
  const params = new URLSearchParams(window.location.search);
  return params.get('code');
}

export function AppLoginPage() {
  const auth = useAuth();
  const [userCode] = useState(() => parseUserCode() ?? '');
  const [state, setState] = useState<AppLoginState>(() =>
    userCode ? { step: 'confirm' } : { step: 'no-code' },
  );

  // Redirect to login if not authenticated (preserve redirect back).
  useEffect(() => {
    if (!auth.loading && !auth.authenticated) {
      const returnUrl = `/app-login${window.location.search}`;
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

  if (!auth.authenticated) {
    return null;
  }

  if (state.step === 'no-code') {
    return (
      <div class="card space-y-4 text-center">
        <TriangleExclamationIcon class="text-warning mx-auto size-8" />
        <h2 class="label">Missing Code</h2>
        <p class="text-muted">
          No authorization code found. Please use the link shown in your desktop
          app.
        </p>
      </div>
    );
  }

  if (state.step === 'done') {
    return (
      <div class="card space-y-4 text-center">
        <CardHeading
          title="App Authorized"
          icon={<CheckCircleIcon class="size-10 text-success" />}
        />
        <p class="text-muted">
          Your desktop app is now logged in. You can close this tab.
        </p>
      </div>
    );
  }

  const handleApprove = async () => {
    if (!auth.sessionToken) return;
    setState({ step: 'approving' });

    try {
      await appLoginApprove(auth.sessionToken, userCode);
      setState({ step: 'done' });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Approval failed.';
      setState({ step: 'error', message });
    }
  };

  const handleCancel = () => {
    navigate('/');
  };

  const busy = state.step === 'approving';

  return (
    <div class="card text-center">
      <CardHeading
        title="Authorize Desktop App"
        subtitle="A desktop app is requesting access to your account."
        class="mb-4"
      />

      <div class="my-6">
        <p>Confirm this code matches your desktop app:</p>

        <div class="bg-surface-alt mx-auto rounded-lg px-6 py-4 font-mono text-3xl font-bold tracking-[0.3em]">
          {userCode}
        </div>

        {state.step === 'error' && (
          <div
            role="alert"
            class="alert-error mt-4 flex items-center gap-2 text-left"
          >
            <TriangleExclamationIcon class="size-5 shrink-0" />
            {state.message}
          </div>
        )}
      </div>

      <div class="flex gap-3">
        <button
          type="button"
          class="btn flex-1 tracking-wider uppercase"
          onClick={handleCancel}
          disabled={busy}
        >
          Cancel
        </button>
        <button
          type="button"
          class="btn btn-primary flex-1 tracking-wider uppercase"
          onClick={handleApprove}
          disabled={busy}
        >
          {busy ? 'Authorizing\u2026' : 'Approve'}
        </button>
      </div>
    </div>
  );
}
