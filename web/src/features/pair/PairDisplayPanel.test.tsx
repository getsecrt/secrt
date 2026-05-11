import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  render,
  screen,
  cleanup,
  waitFor,
  fireEvent,
  act,
} from '@testing-library/preact';

const mockAuth = {
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

const mockPairStart = vi.fn();
const mockPairCancel = vi.fn();
const mockPairPoll = vi.fn();
vi.mock('../../lib/api', () => ({
  pairStart: (...args: unknown[]) => mockPairStart(...args),
  pairCancel: (...args: unknown[]) => mockPairCancel(...args),
  pairPoll: (...args: unknown[]) => mockPairPoll(...args),
}));

vi.mock('../../crypto/amk', () => ({
  generateEcdhKeyPair: async () => ({
    privateKey: 'priv' as unknown as CryptoKey,
    publicKey: 'pub' as unknown as CryptoKey,
  }),
  exportPublicKey: async () => new Uint8Array(65),
}));

vi.mock('./pair-crypto', () => ({
  decryptAmkFromPeer: vi.fn(),
  verifyAndStoreReceivedAmk: vi.fn(),
  AmkCommitMismatchError: class extends Error {},
}));

// Don't spin the real polling loop in countdown/expiry tests.
vi.mock('./use-pair-polling', () => ({
  usePairPolling: () => {},
}));

import { PairDisplayPanel } from './PairDisplayPanel';

describe('PairDisplayPanel (Page A)', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mockNavigate.mockClear();
    mockPairStart.mockReset();
    mockPairCancel.mockReset();
    mockPairCancel.mockResolvedValue({ ok: true });
    mockPairPoll.mockReset();
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it('renders the code, copy buttons, QR, and countdown after /start', async () => {
    const expiresAt = new Date(
      Date.now() + 9 * 60 * 1000 + 42 * 1000,
    ).toISOString();
    mockPairStart.mockResolvedValue({
      user_code: 'K7MQ-3F2A',
      displayer_poll_token: 'tok',
      expires_at: expiresAt,
    });

    render(<PairDisplayPanel />);

    await waitFor(() =>
      expect(screen.getByText('K7MQ-3F2A')).toBeInTheDocument(),
    );
    expect(
      screen.getByRole('button', { name: /Copy Pairing Link/i }),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Copy Code/i })).toBeNull();
    expect(
      screen.getByRole('img', { name: /Pair code QR/i }),
    ).toBeInTheDocument();
    // Countdown should show 09:42 (or 09:41 depending on tick boundary).
    expect(screen.getByText(/0?9:(41|42)/)).toBeInTheDocument();
  });

  it('counts down to 0 and switches to the expired UI without calling /cancel', async () => {
    const expiresAt = new Date(Date.now() + 2_000).toISOString();
    mockPairStart.mockResolvedValue({
      user_code: 'K7MQ-3F2A',
      displayer_poll_token: 'tok',
      expires_at: expiresAt,
    });

    render(<PairDisplayPanel />);
    await waitFor(() =>
      expect(screen.getByText('K7MQ-3F2A')).toBeInTheDocument(),
    );

    // Advance past expiry. Component switches into 'expired' state.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3_500);
    });

    await waitFor(() =>
      expect(screen.getByText(/Code expired/i)).toBeInTheDocument(),
    );
    expect(
      screen.getByRole('button', { name: /Restart Pairing/i }),
    ).toBeInTheDocument();

    // Timer-driven expiry must NOT call /cancel — only user-cancel or
    // component unmount fire that. Cancel-on-unmount will still fire when
    // the component leaves the DOM in cleanup; this assertion only proves
    // that *transitioning to the expired UI* didn't fire it.
    expect(mockPairCancel).not.toHaveBeenCalled();
  });

  it('shows "Restart Pairing" CTA on expiry that triggers reload', async () => {
    const reloadSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...window.location, reload: reloadSpy },
    });

    const expiresAt = new Date(Date.now() + 1_000).toISOString();
    mockPairStart.mockResolvedValue({
      user_code: 'AAAA-BBBB',
      displayer_poll_token: 'tok',
      expires_at: expiresAt,
    });

    render(<PairDisplayPanel />);
    await waitFor(() =>
      expect(screen.getByText('AAAA-BBBB')).toBeInTheDocument(),
    );

    await act(async () => {
      await vi.advanceTimersByTimeAsync(2_000);
    });

    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: /Restart Pairing/i }),
      ).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole('button', { name: /Restart Pairing/i }));
    expect(reloadSpy).toHaveBeenCalled();
  });
});
