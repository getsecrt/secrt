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
const mockLoadAmk = vi.fn().mockResolvedValue(null);
vi.mock('../../lib/amk-store', () => ({
  loadAmk: (...args: unknown[]) => mockLoadAmk(...args),
}));

// Mock crypto/amk (not exercised when no AMK is loaded)
const mockGenerateEcdhKeyPair = vi.fn();
const mockExportPublicKey = vi.fn();
const mockPerformEcdh = vi.fn();
const mockDeriveTransferKey = vi.fn();
const mockComputeSas = vi.fn();
vi.mock('../../crypto/amk', () => ({
  generateEcdhKeyPair: (...args: unknown[]) => mockGenerateEcdhKeyPair(...args),
  exportPublicKey: (...args: unknown[]) => mockExportPublicKey(...args),
  performEcdh: (...args: unknown[]) => mockPerformEcdh(...args),
  deriveTransferKey: (...args: unknown[]) => mockDeriveTransferKey(...args),
  computeSas: (...args: unknown[]) => mockComputeSas(...args),
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
    mockLoadAmk.mockReset().mockResolvedValue(null);
    mockGenerateEcdhKeyPair.mockReset();
    mockExportPublicKey.mockReset();
    mockPerformEcdh.mockReset();
    mockDeriveTransferKey.mockReset();
    mockComputeSas.mockReset();
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

  it('calls deviceApprove and shows success on approve click (no AMK)', async () => {
    const user = userEvent.setup();
    mockDeviceApprove.mockResolvedValue({ ok: true });

    render(<DevicePage />);
    await user.click(screen.getByText('Approve'));

    // deviceApprove is called with token and code only (no amkTransfer)
    expect(mockDeviceApprove).toHaveBeenCalledWith(
      'uss_test.tok',
      'ABCD-1234',
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

  describe('SAS verification flow', () => {
    const fakeAmk = new Uint8Array(32).fill(0xaa);
    const fakeBrowserPk = new Uint8Array(65).fill(0xbb);
    const fakeSharedSecret = new Uint8Array(32).fill(0xcc);
    const fakeTransferKey = new Uint8Array(32).fill(0xdd);

    beforeEach(() => {
      // Challenge includes CLI's ECDH public key
      mockGetDeviceChallenge.mockResolvedValue({
        user_code: 'ABCD-1234',
        status: 'pending',
        ecdh_public_key: btoa(String.fromCharCode(...new Uint8Array(65).fill(0x11))),
      });
      // AMK is available
      mockLoadAmk.mockResolvedValue(fakeAmk);
      // ECDH mocks
      mockGenerateEcdhKeyPair.mockResolvedValue({
        publicKey: 'mock-public',
        privateKey: 'mock-private',
      });
      mockExportPublicKey.mockResolvedValue(fakeBrowserPk);
      mockPerformEcdh.mockResolvedValue(fakeSharedSecret);
      mockDeriveTransferKey.mockResolvedValue(fakeTransferKey);
      mockComputeSas.mockResolvedValue(123456);

      // Mock WebCrypto for AMK encryption
      const mockCryptoKey = {};
      vi.spyOn(crypto.subtle, 'importKey').mockResolvedValue(mockCryptoKey as CryptoKey);
      vi.spyOn(crypto.subtle, 'encrypt').mockResolvedValue(new Uint8Array(48).buffer);
    });

    it('shows SAS verification screen before approving when AMK transfer is available', async () => {
      const user = userEvent.setup();
      render(<DevicePage />);
      await user.click(screen.getByText('Approve'));

      await waitFor(() => {
        expect(screen.getByText('Verify Security Code')).toBeInTheDocument();
      });
      expect(screen.getByText('123456')).toBeInTheDocument();
      expect(screen.getByText('Confirm & Approve')).toBeInTheDocument();
      expect(screen.getByText('Skip Transfer')).toBeInTheDocument();

      // deviceApprove should NOT have been called yet
      expect(mockDeviceApprove).not.toHaveBeenCalled();
    });

    it('sends approval with AMK transfer after SAS confirmation', async () => {
      const user = userEvent.setup();
      mockDeviceApprove.mockResolvedValue({ ok: true });

      render(<DevicePage />);
      await user.click(screen.getByText('Approve'));

      await waitFor(() => {
        expect(screen.getByText('Verify Security Code')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Confirm & Approve'));

      await waitFor(() => {
        expect(screen.getByText('Device Authorized')).toBeInTheDocument();
      });

      // deviceApprove called with amkTransfer
      expect(mockDeviceApprove).toHaveBeenCalledWith(
        'uss_test.tok',
        'ABCD-1234',
        expect.objectContaining({
          ct: expect.any(String),
          nonce: expect.any(String),
          ecdh_public_key: expect.any(String),
        }),
      );
    });

    it('keeps SAS visible on done screen after confirmation', async () => {
      const user = userEvent.setup();
      mockDeviceApprove.mockResolvedValue({ ok: true });

      render(<DevicePage />);
      await user.click(screen.getByText('Approve'));

      await waitFor(() => {
        expect(screen.getByText('Verify Security Code')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Confirm & Approve'));

      await waitFor(() => {
        expect(screen.getByText('Device Authorized')).toBeInTheDocument();
      });

      // SAS code should still be visible
      expect(screen.getByText('123456')).toBeInTheDocument();
    });

    it('approves without AMK transfer when user clicks Skip Transfer', async () => {
      const user = userEvent.setup();
      mockDeviceApprove.mockResolvedValue({ ok: true });

      render(<DevicePage />);
      await user.click(screen.getByText('Approve'));

      await waitFor(() => {
        expect(screen.getByText('Verify Security Code')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Skip Transfer'));

      await waitFor(() => {
        expect(screen.getByText('Device Authorized')).toBeInTheDocument();
      });

      // deviceApprove called WITHOUT amkTransfer
      expect(mockDeviceApprove).toHaveBeenCalledWith(
        'uss_test.tok',
        'ABCD-1234',
      );
    });

    it('does not show SAS on done screen when transfer was skipped', async () => {
      const user = userEvent.setup();
      mockDeviceApprove.mockResolvedValue({ ok: true });

      render(<DevicePage />);
      await user.click(screen.getByText('Approve'));

      await waitFor(() => {
        expect(screen.getByText('Verify Security Code')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Skip Transfer'));

      await waitFor(() => {
        expect(screen.getByText('Device Authorized')).toBeInTheDocument();
      });

      expect(screen.queryByText('123456')).not.toBeInTheDocument();
    });

    it('falls through to direct approval when ECDH fails', async () => {
      const user = userEvent.setup();
      mockDeviceApprove.mockResolvedValue({ ok: true });
      // Make ECDH fail
      mockPerformEcdh.mockRejectedValue(new Error('ECDH failed'));

      render(<DevicePage />);
      await user.click(screen.getByText('Approve'));

      // Should skip SAS screen and go directly to done
      await waitFor(() => {
        expect(screen.getByText('Device Authorized')).toBeInTheDocument();
      });

      // deviceApprove called without amkTransfer
      expect(mockDeviceApprove).toHaveBeenCalledWith(
        'uss_test.tok',
        'ABCD-1234',
      );
    });
  });
});
