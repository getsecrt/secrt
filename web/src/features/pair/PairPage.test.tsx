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

const mockLoadAmk = vi.fn<(userId: string) => Promise<Uint8Array | null>>();
vi.mock('../../lib/amk-store', () => ({
  loadAmk: (userId: string) => mockLoadAmk(userId),
}));

// PairPage delegates to two heavy panels — stub them so we can observe
// which mode got dispatched without standing up the whole flow.
vi.mock('./PairDisplayPanel', () => ({
  PairDisplayPanel: () => <div data-testid="display-panel">Display</div>,
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
    mockLoadAmk.mockReset();
    setSearch('');
  });
  afterEach(() => {
    cleanup();
    setSearch('');
  });

  it('renders Page A (display) when this device has no AMK', async () => {
    mockLoadAmk.mockResolvedValue(null);
    render(<PairPage />);
    await waitFor(() =>
      expect(screen.getByTestId('display-panel')).toBeInTheDocument(),
    );
    expect(screen.queryByTestId('join-panel')).toBeNull();
  });

  it('renders Page B (join) with no prefill when this device has the AMK', async () => {
    mockLoadAmk.mockResolvedValue(new Uint8Array(32));
    render(<PairPage />);
    await waitFor(() =>
      expect(screen.getByTestId('join-panel')).toBeInTheDocument(),
    );
    expect(screen.getByTestId('join-panel')).toHaveAttribute('data-code', '');
  });

  it('renders Page B prefilled with ?code= when AMK is present', async () => {
    mockLoadAmk.mockResolvedValue(new Uint8Array(32));
    setSearch('?code=K7MQ-3F2A');
    render(<PairPage />);
    await waitFor(() =>
      expect(screen.getByTestId('join-panel')).toHaveAttribute(
        'data-code',
        'K7MQ-3F2A',
      ),
    );
  });

  it('uppercases lowercase ?code= input', async () => {
    mockLoadAmk.mockResolvedValue(new Uint8Array(32));
    setSearch('?code=k7mq-3f2a');
    render(<PairPage />);
    await waitFor(() =>
      expect(screen.getByTestId('join-panel')).toHaveAttribute(
        'data-code',
        'K7MQ-3F2A',
      ),
    );
  });

  it('falls back to Page A when AMK is absent even with ?code= present', async () => {
    mockLoadAmk.mockResolvedValue(null);
    setSearch('?code=K7MQ-3F2A');
    render(<PairPage />);
    await waitFor(() =>
      expect(screen.getByTestId('display-panel')).toBeInTheDocument(),
    );
  });

  it('redirects to /login when unauthenticated', async () => {
    mockAuth.authenticated = false;
    mockLoadAmk.mockResolvedValue(null);
    render(<PairPage />);
    await waitFor(() =>
      expect(mockNavigate).toHaveBeenCalledWith(
        expect.stringMatching(/^\/login\?redirect=/),
      ),
    );
  });

  it('shows a placeholder while auth is loading', () => {
    mockAuth.loading = true;
    mockLoadAmk.mockResolvedValue(null);
    render(<PairPage />);
    expect(screen.queryByTestId('display-panel')).toBeNull();
    expect(screen.queryByTestId('join-panel')).toBeNull();
    expect(screen.getByText(/Preparing/i)).toBeInTheDocument();
  });

  it('shows a placeholder while AMK is loading', () => {
    let resolveAmk: (v: Uint8Array | null) => void = () => {};
    mockLoadAmk.mockReturnValue(
      new Promise<Uint8Array | null>((r) => {
        resolveAmk = r;
      }),
    );
    render(<PairPage />);
    expect(screen.queryByTestId('display-panel')).toBeNull();
    expect(screen.queryByTestId('join-panel')).toBeNull();
    expect(screen.getByText(/Preparing/i)).toBeInTheDocument();
    resolveAmk(null);
  });
});
