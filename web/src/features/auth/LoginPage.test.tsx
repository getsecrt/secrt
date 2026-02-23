import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';

// Mock dependencies
const mockAuth = {
  loading: false,
  authenticated: false,
  displayName: null,
  sessionToken: null,
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

vi.mock('../../lib/webauthn', () => ({
  supportsWebAuthn: vi.fn().mockReturnValue(true),
  getPasskeyCredential: vi.fn(),
}));

vi.mock('../../lib/api', () => ({
  loginPasskeyStart: vi.fn(),
  loginPasskeyFinish: vi.fn(),
  appLoginStart: vi.fn(),
  appLoginPoll: vi.fn(),
}));

vi.mock('../../crypto/encoding', () => ({
  base64urlEncode: vi.fn().mockReturnValue('cmFuZG9t'),
  base64urlDecode: vi.fn().mockReturnValue(new Uint8Array(65)),
}));

vi.mock('../../crypto/amk', () => ({
  generateEcdhKeyPair: vi.fn().mockRejectedValue(new Error('not in test')),
  exportPublicKey: vi.fn(),
  performEcdh: vi.fn(),
  deriveTransferKey: vi.fn(),
}));

vi.mock('../../lib/amk-store', () => ({
  storeAmk: vi.fn(),
}));

const mockIsTauri = vi.fn().mockReturnValue(false);
vi.mock('../../lib/config', () => ({
  isTauri: (...args: unknown[]) => mockIsTauri(...args),
  getApiBase: () => '',
}));

const mockShellOpen = vi.fn();
vi.mock('@tauri-apps/plugin-shell', () => ({
  open: (...args: unknown[]) => mockShellOpen(...args),
}));

import { LoginPage, isAllowedVerificationUrl } from './LoginPage';
import { supportsWebAuthn, getPasskeyCredential } from '../../lib/webauthn';
import { loginPasskeyStart, loginPasskeyFinish, appLoginStart } from '../../lib/api';

describe('LoginPage', () => {
  beforeEach(() => {
    mockAuth.authenticated = false;
    mockAuth.login.mockClear();
    mockNavigate.mockClear();
    mockIsTauri.mockReturnValue(false);
    mockShellOpen.mockClear();
    vi.mocked(supportsWebAuthn).mockReturnValue(true);
  });

  afterEach(() => {
    cleanup();
  });

  it('renders login page', () => {
    render(<LoginPage />);
    expect(screen.getByText('Log In')).toBeInTheDocument();
    expect(screen.getByText('Log in with Passkey')).toBeInTheDocument();
  });

  it('redirects when already authenticated', () => {
    mockAuth.authenticated = true;
    render(<LoginPage />);
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('shows unsupported message when WebAuthn unavailable', () => {
    vi.mocked(supportsWebAuthn).mockReturnValue(false);
    render(<LoginPage />);
    expect(screen.getByText('Passkeys not supported')).toBeInTheDocument();
  });

  it('runs full login flow on button click', async () => {
    const user = userEvent.setup();
    vi.mocked(getPasskeyCredential).mockResolvedValue({
      credentialId: 'cred_login',
    });
    vi.mocked(loginPasskeyStart).mockResolvedValue({
      challenge_id: 'ch_login',
      challenge: 'Y2hhbA',
      expires_at: '2026-12-31T00:00:00Z',
    });
    vi.mocked(loginPasskeyFinish).mockResolvedValue({
      session_token: 'uss_login.tok',
      user_id: '00000000-0000-0000-0000-000000000001',
      display_name: 'dave',
      expires_at: '2026-12-31T00:00:00Z',
    });

    render(<LoginPage />);
    await user.click(screen.getByText('Log in with Passkey'));

    expect(loginPasskeyStart).toHaveBeenCalledWith({
      credential_id: 'cred_login',
    });
    expect(loginPasskeyFinish).toHaveBeenCalledWith({
      challenge_id: 'ch_login',
      credential_id: 'cred_login',
    });
    expect(mockAuth.login).toHaveBeenCalledWith('uss_login.tok', '00000000-0000-0000-0000-000000000001', 'dave');
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('shows friendly error for unknown credential', async () => {
    const user = userEvent.setup();
    vi.mocked(getPasskeyCredential).mockRejectedValue(
      new Error('unknown credential'),
    );

    render(<LoginPage />);
    await user.click(screen.getByText('Log in with Passkey'));

    expect(screen.getByRole('alert')).toHaveTextContent(
      'This passkey is not recognized',
    );
  });

  it('shows raw error for other failures', async () => {
    const user = userEvent.setup();
    vi.mocked(getPasskeyCredential).mockRejectedValue(
      new Error('network error'),
    );

    render(<LoginPage />);
    await user.click(screen.getByText('Log in with Passkey'));

    expect(screen.getByRole('alert')).toHaveTextContent('network error');
  });

  it('shows cancelled message on NotAllowedError', async () => {
    const user = userEvent.setup();
    const err = new DOMException('User cancelled', 'NotAllowedError');
    vi.mocked(getPasskeyCredential).mockRejectedValue(err);

    render(<LoginPage />);
    await user.click(screen.getByText('Log in with Passkey'));

    expect(screen.getByRole('alert')).toHaveTextContent('Login was cancelled');
  });

  it('has link to register page', async () => {
    const user = userEvent.setup();
    render(<LoginPage />);
    await user.click(screen.getByText('Register a New Account'));
    expect(mockNavigate).toHaveBeenCalledWith('/register');
  });

  describe('TauriLoginFlow', () => {
    beforeEach(() => {
      mockIsTauri.mockReturnValue(true);
      mockShellOpen.mockResolvedValue(undefined);
      vi.mocked(appLoginStart).mockReset();
    });

    it('login opens browser without intent param', async () => {
      vi.mocked(appLoginStart).mockResolvedValue({
        app_code: 'app_123',
        user_code: 'ABCD-1234',
        verification_url: 'https://secrt.ca/app-login?code=ABCD-1234&ek=abc',
        interval: 2,
        expires_in: 600,
      });

      const user = userEvent.setup();
      render(<LoginPage />);
      await user.click(screen.getByText('Log in via Browser'));

      await waitFor(() => {
        expect(appLoginStart).toHaveBeenCalled();
      });
      await waitFor(() => {
        expect(mockShellOpen).toHaveBeenCalledWith(
          'https://secrt.ca/app-login?code=ABCD-1234&ek=abc',
        );
      });
    });

    it('register opens browser directly to /register with app-login redirect', async () => {
      vi.mocked(appLoginStart).mockResolvedValue({
        app_code: 'app_456',
        user_code: 'EFGH-5678',
        verification_url: 'https://secrt.ca/app-login?code=EFGH-5678&ek=xyz',
        interval: 2,
        expires_in: 600,
      });

      const user = userEvent.setup();
      render(<LoginPage />);
      await user.click(screen.getByText('Register a New Account'));

      await waitFor(() => {
        expect(appLoginStart).toHaveBeenCalled();
      });
      await waitFor(() => {
        expect(mockShellOpen).toHaveBeenCalledWith(
          `https://secrt.ca/register?redirect=${encodeURIComponent('/app-login?code=EFGH-5678&ek=xyz')}`,
        );
      });
    });

    it('shows user code while polling', async () => {
      vi.mocked(appLoginStart).mockResolvedValue({
        app_code: 'app_789',
        user_code: 'WXYZ-9999',
        verification_url: 'https://secrt.ca/app-login?code=WXYZ-9999&ek=def',
        interval: 2,
        expires_in: 600,
      });

      const user = userEvent.setup();
      render(<LoginPage />);
      await user.click(screen.getByText('Log in via Browser'));

      await waitFor(() => {
        expect(screen.getByText('WXYZ-9999')).toBeInTheDocument();
      });
    });
  });
});

describe('isAllowedVerificationUrl', () => {
  it('rejects non-https URLs', () => {
    expect(isAllowedVerificationUrl('http://secrt.ca/app-login?code=ABCD-1234')).toBe(false);
  });

  it('rejects invalid URLs', () => {
    expect(isAllowedVerificationUrl('not-a-url')).toBe(false);
    expect(isAllowedVerificationUrl('')).toBe(false);
  });

  it('accepts https URLs in dev mode (getApiBase returns empty)', () => {
    // In test env, isTauri() is false and getApiBase() returns ''
    expect(isAllowedVerificationUrl('https://secrt.ca/app-login?code=ABCD-1234')).toBe(true);
    expect(isAllowedVerificationUrl('https://any-host.com/path')).toBe(true);
  });

  it('rejects javascript: protocol', () => {
    expect(isAllowedVerificationUrl('javascript:alert(1)')).toBe(false);
  });

  it('rejects data: protocol', () => {
    expect(isAllowedVerificationUrl('data:text/html,<h1>hi</h1>')).toBe(false);
  });
});
