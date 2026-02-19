import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';
import { AuthProvider, useAuth } from './auth-context';

// Mock api module
vi.mock('./api', () => ({
  fetchSession: vi.fn(),
  logout: vi.fn(),
}));

import { fetchSession, logout as apiLogout } from './api';

function AuthConsumer() {
  const auth = useAuth();
  return (
    <div>
      <span data-testid="loading">{String(auth.loading)}</span>
      <span data-testid="authenticated">{String(auth.authenticated)}</span>
      <span data-testid="displayName">{String(auth.displayName)}</span>
      <span data-testid="sessionToken">{String(auth.sessionToken)}</span>
      <button
        data-testid="login-btn"
        onClick={() => auth.login('tok_new', 'uid_alice', 'alice')}
      >
        Login
      </button>
      <button data-testid="logout-btn" onClick={() => auth.logout()}>
        Logout
      </button>
    </div>
  );
}

describe('AuthProvider', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.mocked(fetchSession).mockReset();
    vi.mocked(apiLogout).mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it('shows loading=false and unauthenticated when no stored token', async () => {
    render(
      <AuthProvider>
        <AuthConsumer />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false');
    });
    expect(screen.getByTestId('authenticated').textContent).toBe('false');
  });

  it('restores session from localStorage on mount', async () => {
    localStorage.setItem('session_token', 'uss_stored.secret');
    vi.mocked(fetchSession).mockResolvedValue({
      authenticated: true,
      user_id: 'test-uid',
      display_name: 'bob',
      expires_at: '2026-12-31T00:00:00Z',
    });

    render(
      <AuthProvider>
        <AuthConsumer />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false');
    });
    expect(screen.getByTestId('authenticated').textContent).toBe('true');
    expect(screen.getByTestId('displayName').textContent).toBe('bob');
    expect(screen.getByTestId('sessionToken').textContent).toBe(
      'uss_stored.secret',
    );
  });

  it('clears stored token when session validation returns unauthenticated', async () => {
    localStorage.setItem('session_token', 'uss_expired.tok');
    vi.mocked(fetchSession).mockResolvedValue({
      authenticated: false,
      user_id: null,
      display_name: null,
      expires_at: null,
    });

    render(
      <AuthProvider>
        <AuthConsumer />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false');
    });
    expect(screen.getByTestId('authenticated').textContent).toBe('false');
    expect(localStorage.getItem('session_token')).toBeNull();
  });

  it('keeps stored token when session validation fails with network error', async () => {
    localStorage.setItem('session_token', 'uss_bad.tok');
    vi.mocked(fetchSession).mockRejectedValue(new Error('network'));

    render(
      <AuthProvider>
        <AuthConsumer />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false');
    });
    expect(screen.getByTestId('authenticated').textContent).toBe('false');
    expect(localStorage.getItem('session_token')).toBe('uss_bad.tok');
  });

  it('login() stores token and updates state', async () => {
    const user = userEvent.setup();

    render(
      <AuthProvider>
        <AuthConsumer />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false');
    });

    await user.click(screen.getByTestId('login-btn'));

    expect(screen.getByTestId('authenticated').textContent).toBe('true');
    expect(screen.getByTestId('displayName').textContent).toBe('alice');
    expect(localStorage.getItem('session_token')).toBe('tok_new');
  });

  it('logout() calls API, clears state and localStorage', async () => {
    const user = userEvent.setup();
    vi.mocked(apiLogout).mockResolvedValue(undefined);

    render(
      <AuthProvider>
        <AuthConsumer />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false');
    });

    // Login first
    await user.click(screen.getByTestId('login-btn'));
    expect(screen.getByTestId('authenticated').textContent).toBe('true');

    // Now logout
    await user.click(screen.getByTestId('logout-btn'));

    expect(screen.getByTestId('authenticated').textContent).toBe('false');
    expect(localStorage.getItem('session_token')).toBeNull();
  });

  it('logout() still clears state when API call fails', async () => {
    const user = userEvent.setup();
    vi.mocked(apiLogout).mockRejectedValue(new Error('network'));

    render(
      <AuthProvider>
        <AuthConsumer />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false');
    });

    await user.click(screen.getByTestId('login-btn'));
    await user.click(screen.getByTestId('logout-btn'));

    expect(screen.getByTestId('authenticated').textContent).toBe('false');
  });

  it('useAuth() outside provider exposes safe no-op handlers', async () => {
    const user = userEvent.setup();
    let completed = false;

    function BareConsumer() {
      const auth = useAuth();
      return (
        <button
          data-testid="bare-auth-btn"
          onClick={async () => {
            auth.login('tok_any', 'uid_anon', 'anon');
            await auth.logout();
            completed = true;
          }}
        >
          Run
        </button>
      );
    }

    render(<BareConsumer />);
    await user.click(screen.getByTestId('bare-auth-btn'));
    expect(completed).toBe(true);
  });
});
