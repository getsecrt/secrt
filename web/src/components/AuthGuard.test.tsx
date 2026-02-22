import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';

// Mock dependencies
const mockAuth = {
  loading: false,
  authenticated: false,
  displayName: null,
  sessionToken: null,
  login: vi.fn(),
  logout: vi.fn(),
};
vi.mock('../lib/auth-context', () => ({
  useAuth: () => mockAuth,
}));

const mockNavigate = vi.fn();
vi.mock('../router', () => ({
  navigate: (...args: unknown[]) => mockNavigate(...args),
}));

import { AuthGuard } from './AuthGuard';

describe('AuthGuard', () => {
  beforeEach(() => {
    mockAuth.loading = false;
    mockAuth.authenticated = false;
    mockNavigate.mockClear();
  });

  afterEach(() => {
    cleanup();
  });

  it('shows loading state while auth is loading', () => {
    mockAuth.loading = true;
    render(
      <AuthGuard>
        <p>Protected content</p>
      </AuthGuard>,
    );
    expect(screen.getByText('Loading...')).toBeInTheDocument();
    expect(screen.queryByText('Protected content')).toBeNull();
  });

  it('redirects to /login when not authenticated', async () => {
    mockAuth.loading = false;
    mockAuth.authenticated = false;
    render(
      <AuthGuard>
        <p>Protected content</p>
      </AuthGuard>,
    );
    await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith('/login'));
  });

  it('does not render children when unauthenticated', () => {
    mockAuth.loading = false;
    mockAuth.authenticated = false;
    render(
      <AuthGuard>
        <p>Protected content</p>
      </AuthGuard>,
    );
    expect(screen.queryByText('Protected content')).toBeNull();
  });

  it('renders children when authenticated', () => {
    mockAuth.loading = false;
    mockAuth.authenticated = true;
    render(
      <AuthGuard>
        <p>Protected content</p>
      </AuthGuard>,
    );
    expect(screen.getByText('Protected content')).toBeInTheDocument();
    expect(mockNavigate).not.toHaveBeenCalled();
  });
});
