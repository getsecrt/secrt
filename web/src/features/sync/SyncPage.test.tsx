import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';

// ── Mocks ──

const mockAuth = {
  loading: false,
  authenticated: true,
  displayName: 'alice',
  userId: 'user-abc',
  sessionToken: 'uss_test.tok',
  login: vi.fn(),
  logout: vi.fn(),
};
vi.mock('../../lib/auth-context', () => ({
  useAuth: () => mockAuth,
}));

const mockNavigate = vi.fn();
vi.mock('../../router', () => ({
  navigate: (...args: unknown[]) => mockNavigate(...args),
}));

vi.mock('../../crypto/constants', () => ({
  URL_KEY_LEN: 32,
}));

vi.mock('../../crypto/amk', () => ({
  AMK_LEN: 32,
}));

const mockBase64urlDecode = vi.fn();
const mockBase64urlEncode = vi.fn();
vi.mock('../../crypto/encoding', () => ({
  base64urlDecode: (...args: unknown[]) => mockBase64urlDecode(...args),
  base64urlEncode: (...args: unknown[]) => mockBase64urlEncode(...args),
}));

const mockOpen = vi.fn();
const mockDeriveClaimToken = vi.fn();
vi.mock('../../crypto/envelope', () => ({
  open: (...args: unknown[]) => mockOpen(...args),
  deriveClaimToken: (...args: unknown[]) => mockDeriveClaimToken(...args),
}));

const mockClaimSecret = vi.fn();
vi.mock('../../lib/api', () => ({
  claimSecret: (...args: unknown[]) => mockClaimSecret(...args),
}));

const mockStoreAmk = vi.fn();
const mockLoadAmk = vi.fn();
vi.mock('../../lib/amk-store', () => ({
  storeAmk: (...args: unknown[]) => mockStoreAmk(...args),
  loadAmk: (...args: unknown[]) => mockLoadAmk(...args),
}));

import { SyncPage } from './SyncPage';

/** Override window.location for tests. */
function setLocation(opts: { hash?: string; pathname?: string }) {
  Object.defineProperty(window, 'location', {
    writable: true,
    value: {
      ...window.location,
      hash: opts.hash ?? '',
      pathname: opts.pathname ?? '/sync/test-id',
    },
  });
}

describe('SyncPage', () => {
  beforeEach(() => {
    mockAuth.loading = false;
    mockAuth.authenticated = true;
    mockAuth.userId = 'user-abc';
    mockAuth.sessionToken = 'uss_test.tok';
    mockNavigate.mockClear();
    mockBase64urlDecode.mockReset();
    mockBase64urlEncode.mockReset();
    mockOpen.mockReset();
    mockDeriveClaimToken.mockReset();
    mockClaimSecret.mockReset();
    mockStoreAmk.mockReset().mockResolvedValue(undefined);
    mockLoadAmk.mockReset().mockResolvedValue(null);
  });

  afterEach(() => {
    cleanup();
    setLocation({ hash: '' });
  });

  it('redirects to login when not authenticated', () => {
    mockAuth.authenticated = false;
    setLocation({ hash: '#' + 'A'.repeat(43) });

    render(<SyncPage id="test-id" />);

    expect(mockNavigate).toHaveBeenCalledWith(
      expect.stringContaining('/login?redirect='),
    );
  });

  it('shows error when fragment is missing', async () => {
    setLocation({ hash: '' });

    render(<SyncPage id="test-id" />);

    await waitFor(() => {
      expect(screen.getByText('Sync Failed')).toBeInTheDocument();
    });
    expect(
      screen.getByText(/decryption key is missing/),
    ).toBeInTheDocument();
  });

  it('shows error when url_key is wrong length', async () => {
    setLocation({ hash: '#badkey' });
    mockBase64urlDecode.mockReturnValue(new Uint8Array(16)); // wrong: not 32

    render(<SyncPage id="test-id" />);

    await waitFor(() => {
      expect(screen.getByText('Sync Failed')).toBeInTheDocument();
    });
    expect(screen.getByText(/malformed/)).toBeInTheDocument();
  });

  it('auto-claim succeeds and shows success state', async () => {
    const fakeUrlKey = new Uint8Array(32).fill(0xaa);
    const fakeClaimToken = new Uint8Array(32).fill(0xbb);
    const fakeAmk = new Uint8Array(32).fill(0xcc);

    setLocation({ hash: '#' + 'A'.repeat(43) });
    mockBase64urlDecode.mockReturnValue(fakeUrlKey);
    mockBase64urlEncode.mockReturnValue('encoded-claim-token');
    mockDeriveClaimToken.mockResolvedValue(fakeClaimToken);
    mockClaimSecret.mockResolvedValue({
      envelope: { v: 1 },
      expires_at: '2099-12-31T23:59:59Z',
    });
    mockOpen.mockResolvedValue({
      content: fakeAmk,
      meta: { type: 'binary' },
    });

    render(<SyncPage id="test-id" />);

    await waitFor(() => {
      expect(screen.getByText('Notes Key Synced')).toBeInTheDocument();
    });
    expect(mockClaimSecret).toHaveBeenCalledWith(
      'test-id',
      { claim: 'encoded-claim-token' },
      expect.any(AbortSignal),
    );
    expect(mockStoreAmk).toHaveBeenCalledWith('user-abc', fakeAmk);
  });

  it('shows error when claim fails with 404', async () => {
    const fakeUrlKey = new Uint8Array(32).fill(0xaa);

    setLocation({ hash: '#' + 'A'.repeat(43) });
    mockBase64urlDecode.mockReturnValue(fakeUrlKey);
    mockBase64urlEncode.mockReturnValue('encoded');
    mockDeriveClaimToken.mockResolvedValue(new Uint8Array(32));
    mockClaimSecret.mockRejectedValue(new Error('404 not found'));

    render(<SyncPage id="test-id" />);

    await waitFor(() => {
      expect(screen.getByText('Sync Failed')).toBeInTheDocument();
    });
    expect(
      screen.getByText(/expired or was already used/),
    ).toBeInTheDocument();
  });

  it('shows error when decrypted AMK has wrong length', async () => {
    const fakeUrlKey = new Uint8Array(32).fill(0xaa);

    setLocation({ hash: '#' + 'A'.repeat(43) });
    mockBase64urlDecode.mockReturnValue(fakeUrlKey);
    mockBase64urlEncode.mockReturnValue('encoded');
    mockDeriveClaimToken.mockResolvedValue(new Uint8Array(32));
    mockClaimSecret.mockResolvedValue({
      envelope: { v: 1 },
      expires_at: '2099-12-31T23:59:59Z',
    });
    mockOpen.mockResolvedValue({
      content: new Uint8Array(16), // wrong: not 32
      meta: { type: 'binary' },
    });

    render(<SyncPage id="test-id" />);

    await waitFor(() => {
      expect(screen.getByText('Sync Failed')).toBeInTheDocument();
    });
    expect(screen.getByText(/Invalid notes key/)).toBeInTheDocument();
  });

  it('shows error when claim returns 410 (already claimed)', async () => {
    const fakeUrlKey = new Uint8Array(32).fill(0xaa);

    setLocation({ hash: '#' + 'A'.repeat(43) });
    mockBase64urlDecode.mockReturnValue(fakeUrlKey);
    mockBase64urlEncode.mockReturnValue('encoded');
    mockDeriveClaimToken.mockResolvedValue(new Uint8Array(32));
    mockClaimSecret.mockRejectedValue(new Error('410 claimed'));

    render(<SyncPage id="test-id" />);

    await waitFor(() => {
      expect(screen.getByText('Sync Failed')).toBeInTheDocument();
    });
    expect(
      screen.getByText(/already been used/),
    ).toBeInTheDocument();
  });
});
