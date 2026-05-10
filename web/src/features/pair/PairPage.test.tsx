import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';

const mockAuth: {
  loading: boolean;
  authenticated: boolean;
  userId: string | null;
  sessionToken: string | null;
  displayName: string | null;
} = {
  loading: false,
  authenticated: true,
  userId: 'u1',
  sessionToken: 'tok',
  displayName: null,
};
vi.mock('../../lib/auth-context', () => ({
  useAuth: () => mockAuth,
}));

const mockNavigate = vi.fn();
vi.mock('../../router', () => ({
  navigate: (...args: unknown[]) => mockNavigate(...args),
}));

// PairPage delegates to two heavy panels — stub them so we can observe
// which mode/role got dispatched without standing up the whole flow.
vi.mock('./PairDisplayPanel', () => ({
  PairDisplayPanel: (props: { role: string }) => (
    <div data-testid="display-panel" data-role={props.role}>
      Display
    </div>
  ),
}));
vi.mock('./PairJoinPanel', () => ({
  PairJoinPanel: (props: { prefilledCode: string | null }) => (
    <div data-testid="join-panel" data-code={props.prefilledCode ?? ''}>
      Join
    </div>
  ),
}));

import { PairPage } from './PairPage';

function setSearch(search: string) {
  window.history.replaceState({}, '', `/pair${search}`);
}

describe('PairPage', () => {
  beforeEach(() => {
    mockAuth.loading = false;
    mockAuth.authenticated = true;
    mockAuth.userId = 'u1';
    mockAuth.sessionToken = 'tok';
    mockNavigate.mockClear();
    setSearch('');
  });
  afterEach(() => {
    cleanup();
    setSearch('');
  });

  it('shows the picker on bare /pair', () => {
    render(<PairPage />);
    expect(
      screen.getByText(/show a code to receive my key/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/show a code to send to a new device/i),
    ).toBeInTheDocument();
  });

  it('renders the display panel with role=receive when ?mode=display&role=receive', () => {
    setSearch('?mode=display&role=receive');
    render(<PairPage />);
    const panel = screen.getByTestId('display-panel');
    expect(panel).toHaveAttribute('data-role', 'receive');
  });

  it('renders the display panel with role=send when ?mode=display&role=send', () => {
    setSearch('?mode=display&role=send');
    render(<PairPage />);
    expect(screen.getByTestId('display-panel')).toHaveAttribute(
      'data-role',
      'send',
    );
  });

  it('renders the join panel with the deep-linked code', () => {
    setSearch('?mode=join&code=K7MQ-3F2A');
    render(<PairPage />);
    const panel = screen.getByTestId('join-panel');
    expect(panel).toHaveAttribute('data-code', 'K7MQ-3F2A');
  });

  it('redirects to /login when unauthenticated', async () => {
    mockAuth.authenticated = false;
    setSearch('?mode=display&role=receive');
    render(<PairPage />);
    await waitFor(() =>
      expect(mockNavigate).toHaveBeenCalledWith(
        expect.stringMatching(/^\/login\?redirect=/),
      ),
    );
  });

  it('renders nothing protected while auth is loading', () => {
    mockAuth.loading = true;
    setSearch('?mode=display&role=receive');
    render(<PairPage />);
    expect(screen.queryByTestId('display-panel')).toBeNull();
    expect(screen.getByText(/Loading/i)).toBeInTheDocument();
  });
});
