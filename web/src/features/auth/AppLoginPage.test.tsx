import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';

// Mock dependencies
const mockAuth = {
  loading: false,
  authenticated: true,
  userId: 'uid-123',
  displayName: 'alice',
  sessionToken: 'uss_test.secret',
  login: vi.fn(),
  logout: vi.fn(),
  setDisplayName: vi.fn(),
};
vi.mock('../../lib/auth-context', () => ({
  useAuth: () => mockAuth,
}));

const mockNavigate = vi.fn();
vi.mock('../../router', () => ({
  navigate: (...args: unknown[]) => mockNavigate(...args),
}));

vi.mock('../../lib/api', () => ({
  appLoginApprove: vi.fn(),
}));

vi.mock('../../lib/amk-store', () => ({
  loadAmk: vi.fn(),
}));

vi.mock('../../crypto/amk', () => ({
  generateEcdhKeyPair: vi.fn(),
  exportPublicKey: vi.fn(),
  performEcdh: vi.fn(),
  deriveTransferKey: vi.fn(),
}));

vi.mock('../../crypto/encoding', () => ({
  base64urlEncode: vi.fn().mockReturnValue('cmFuZG9t'),
  base64urlDecode: vi.fn().mockReturnValue(new Uint8Array(65)),
}));

import { AppLoginPage } from './AppLoginPage';
import { appLoginApprove } from '../../lib/api';
import { loadAmk } from '../../lib/amk-store';

function setUrlParams(params: string) {
  Object.defineProperty(window, 'location', {
    value: { ...window.location, search: params },
    writable: true,
  });
}

describe('AppLoginPage', () => {
  beforeEach(() => {
    mockAuth.authenticated = true;
    mockAuth.loading = false;
    mockAuth.sessionToken = 'uss_test.secret';
    mockAuth.userId = 'uid-123';
    mockNavigate.mockClear();
    vi.mocked(appLoginApprove).mockReset();
    vi.mocked(loadAmk).mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it('shows no-code message when no code param', () => {
    setUrlParams('');
    render(<AppLoginPage />);
    expect(screen.getByText('Missing Code')).toBeInTheDocument();
  });

  it('shows confirmation UI with user code', () => {
    setUrlParams('?code=ABCD-1234');
    render(<AppLoginPage />);
    expect(screen.getByText('ABCD-1234')).toBeInTheDocument();
    expect(screen.getByText('Approve')).toBeInTheDocument();
    expect(screen.getByText('Cancel')).toBeInTheDocument();
  });

  it('approves without AMK transfer when no ek param', async () => {
    setUrlParams('?code=ABCD-1234');
    vi.mocked(appLoginApprove).mockResolvedValue({ ok: true });
    vi.mocked(loadAmk).mockResolvedValue(null);

    const user = userEvent.setup();
    render(<AppLoginPage />);
    await user.click(screen.getByText('Approve'));

    await waitFor(() => {
      expect(appLoginApprove).toHaveBeenCalledWith(
        'uss_test.secret',
        'ABCD-1234',
        undefined,
      );
    });
    expect(screen.getByText('App Authorized')).toBeInTheDocument();
  });

  it('shows error on approve failure', async () => {
    setUrlParams('?code=ABCD-1234');
    vi.mocked(appLoginApprove).mockRejectedValue(new Error('server error'));

    const user = userEvent.setup();
    render(<AppLoginPage />);
    await user.click(screen.getByText('Approve'));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('server error');
    });
  });

  it('cancel navigates home', async () => {
    setUrlParams('?code=ABCD-1234');
    const user = userEvent.setup();
    render(<AppLoginPage />);
    await user.click(screen.getByText('Cancel'));
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('redirects to login when not authenticated', async () => {
    mockAuth.authenticated = false;
    mockAuth.loading = false;
    setUrlParams('?code=ABCD-1234');
    render(<AppLoginPage />);

    // Should redirect to login with redirect param
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith(
        expect.stringContaining('/login?redirect='),
      );
    });
  });
});
