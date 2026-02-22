import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/preact';
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
}));

vi.mock('../../crypto/encoding', () => ({
  base64urlEncode: vi.fn().mockReturnValue('cmFuZG9t'),
}));

import { LoginPage, isAllowedVerificationUrl } from './LoginPage';
import { supportsWebAuthn, getPasskeyCredential } from '../../lib/webauthn';
import { loginPasskeyStart, loginPasskeyFinish } from '../../lib/api';

describe('LoginPage', () => {
  beforeEach(() => {
    mockAuth.authenticated = false;
    mockAuth.login.mockClear();
    mockNavigate.mockClear();
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
