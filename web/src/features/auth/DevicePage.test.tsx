import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';

// Mock dependencies
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

const mockDeviceApprove = vi.fn();
const mockGetDeviceChallenge = vi.fn();
vi.mock('../../lib/api', () => ({
  deviceApprove: (...args: unknown[]) => mockDeviceApprove(...args),
  getDeviceChallenge: (...args: unknown[]) => mockGetDeviceChallenge(...args),
}));

// Mock amk-store (no AMK available in tests by default)
vi.mock('../../lib/amk-store', () => ({
  loadAmk: vi.fn().mockResolvedValue(null),
}));

// Mock crypto/amk (not exercised when no AMK is loaded)
vi.mock('../../crypto/amk', () => ({
  generateEcdhKeyPair: vi.fn(),
  exportPublicKey: vi.fn(),
  performEcdh: vi.fn(),
  deriveTransferKey: vi.fn(),
  computeSas: vi.fn(),
}));

// Mock crypto/encoding
vi.mock('../../crypto/encoding', () => ({
  base64urlEncode: vi.fn((b: Uint8Array) => btoa(String.fromCharCode(...b))),
  base64urlDecode: vi.fn((s: string) => new Uint8Array([...atob(s)].map(c => c.charCodeAt(0)))),
}));

import { DevicePage } from './DevicePage';

/** Set window.location.search for the test. */
function setSearchParams(params: string) {
  Object.defineProperty(window, 'location', {
    writable: true,
    value: { ...window.location, search: params },
  });
}

describe('DevicePage', () => {
  beforeEach(() => {
    mockAuth.loading = false;
    mockAuth.authenticated = true;
    mockAuth.sessionToken = 'uss_test.tok';
    mockAuth.userId = 'user-abc';
    mockNavigate.mockClear();
    mockDeviceApprove.mockClear();
    mockGetDeviceChallenge.mockClear();
    // Default: challenge returns no ECDH key (no AMK transfer)
    mockGetDeviceChallenge.mockResolvedValue({
      user_code: 'ABCD-1234',
      status: 'pending',
    });
    setSearchParams('?code=ABCD-1234');
  });

  afterEach(() => {
    cleanup();
    setSearchParams('');
  });

  it('renders confirm state with user code from query', () => {
    render(<DevicePage />);
    expect(screen.getByText('Authorize Device')).toBeInTheDocument();
    expect(screen.getByText('ABCD-1234')).toBeInTheDocument();
    expect(screen.getByText('Approve')).toBeInTheDocument();
    expect(screen.getByText('Cancel')).toBeInTheDocument();
  });

  it('shows missing code message when no code param', () => {
    setSearchParams('');
    render(<DevicePage />);
    expect(screen.getByText('Missing Device Code')).toBeInTheDocument();
  });

  it('redirects to login when not authenticated', () => {
    mockAuth.authenticated = false;
    mockAuth.loading = false;
    render(<DevicePage />);
    expect(mockNavigate).toHaveBeenCalledWith(
      expect.stringContaining('/login?redirect='),
    );
  });

  it('shows loading state while auth is loading', () => {
    mockAuth.loading = true;
    mockAuth.authenticated = false;
    render(<DevicePage />);
    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  it('calls deviceApprove and shows success on approve click', async () => {
    const user = userEvent.setup();
    mockDeviceApprove.mockResolvedValue({ ok: true });

    render(<DevicePage />);
    await user.click(screen.getByText('Approve'));

    // deviceApprove is called with token, code, and optional amkTransfer (undefined when no ECDH)
    expect(mockDeviceApprove).toHaveBeenCalledWith(
      'uss_test.tok',
      'ABCD-1234',
      undefined,
    );

    await waitFor(() => {
      expect(screen.getByText('Device Authorized')).toBeInTheDocument();
    });
  });

  it('shows error state when approval fails', async () => {
    const user = userEvent.setup();
    mockDeviceApprove.mockRejectedValue(new Error('Challenge expired'));

    render(<DevicePage />);
    await user.click(screen.getByText('Approve'));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Challenge expired');
    });
  });

  it('navigates home on cancel click', async () => {
    const user = userEvent.setup();
    render(<DevicePage />);
    await user.click(screen.getByText('Cancel'));
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('shows generic error for non-Error rejection', async () => {
    const user = userEvent.setup();
    mockDeviceApprove.mockRejectedValue('unknown');

    render(<DevicePage />);
    await user.click(screen.getByText('Approve'));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Approval failed');
    });
  });
});
