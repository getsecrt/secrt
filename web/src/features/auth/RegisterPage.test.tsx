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
  createPasskeyCredential: vi.fn(),
  generateUserId: vi.fn().mockReturnValue('dXNlci1pZA'),
}));

vi.mock('../../lib/api', () => ({
  registerPasskeyStart: vi.fn(),
  registerPasskeyFinish: vi.fn(),
}));

import { RegisterPage } from './RegisterPage';
import { supportsWebAuthn, createPasskeyCredential } from '../../lib/webauthn';
import { registerPasskeyStart, registerPasskeyFinish } from '../../lib/api';

describe('RegisterPage', () => {
  beforeEach(() => {
    mockAuth.authenticated = false;
    mockAuth.login.mockClear();
    mockNavigate.mockClear();
    vi.mocked(supportsWebAuthn).mockReturnValue(true);
  });

  afterEach(() => {
    cleanup();
  });

  it('renders registration form', () => {
    render(<RegisterPage />);
    expect(screen.getByText('Create an Account')).toBeInTheDocument();
    expect(screen.getByLabelText('Account Nickname')).toBeInTheDocument();
    expect(screen.getByText('Register with Passkey')).toBeInTheDocument();
  });

  it('redirects when already authenticated', () => {
    mockAuth.authenticated = true;
    render(<RegisterPage />);
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('shows unsupported message when WebAuthn unavailable', () => {
    vi.mocked(supportsWebAuthn).mockReturnValue(false);
    render(<RegisterPage />);
    expect(screen.getByText('Passkeys not supported')).toBeInTheDocument();
  });

  it('shows error when display name is empty on submit', async () => {
    const user = userEvent.setup();
    render(<RegisterPage />);
    // Clear the pre-filled random name
    const input = screen.getByLabelText('Account Nickname');
    await user.clear(input);
    await user.click(screen.getByText('Register with Passkey'));
    expect(screen.getByRole('alert')).toHaveTextContent('Please enter a display name');
  });

  it('submit button is enabled with pre-filled name', () => {
    render(<RegisterPage />);
    expect(screen.getByText('Register with Passkey')).not.toBeDisabled();
  });

  it('runs full registration flow on submit', async () => {
    const user = userEvent.setup();
    vi.mocked(registerPasskeyStart).mockResolvedValue({
      challenge_id: 'ch_1',
      challenge: 'Y2hhbGxlbmdl',
      expires_at: '2026-12-31T00:00:00Z',
    });
    vi.mocked(createPasskeyCredential).mockResolvedValue({
      credentialId: 'cred_abc',
      publicKey: 'pk_xyz',
    });
    vi.mocked(registerPasskeyFinish).mockResolvedValue({
      session_token: 'uss_new.tok',
      display_name: 'alice',
      expires_at: '2026-12-31T00:00:00Z',
    });

    render(<RegisterPage />);
    // Clear pre-filled name and type a specific one
    const input = screen.getByLabelText('Account Nickname');
    await user.clear(input);
    await user.type(input, 'Alice');
    await user.click(screen.getByText('Register with Passkey'));

    expect(registerPasskeyStart).toHaveBeenCalledWith({
      display_name: 'Alice',
    });
    expect(mockAuth.login).toHaveBeenCalledWith('uss_new.tok', 'alice');
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('shows error when registration fails', async () => {
    const user = userEvent.setup();
    vi.mocked(registerPasskeyStart).mockRejectedValue(
      new Error('server down'),
    );

    render(<RegisterPage />);
    await user.type(screen.getByLabelText('Account Nickname'), 'Bob');
    await user.click(screen.getByText('Register with Passkey'));

    expect(screen.getByRole('alert')).toHaveTextContent('server down');
  });

  it('shows cancelled message on NotAllowedError', async () => {
    const user = userEvent.setup();
    vi.mocked(registerPasskeyStart).mockResolvedValue({
      challenge_id: 'ch_2',
      challenge: 'Y2hhbA',
      expires_at: '2026-12-31T00:00:00Z',
    });
    const err = new DOMException('User cancelled', 'NotAllowedError');
    vi.mocked(createPasskeyCredential).mockRejectedValue(err);

    render(<RegisterPage />);
    await user.type(screen.getByLabelText('Account Nickname'), 'Carol');
    await user.click(screen.getByText('Register with Passkey'));

    expect(screen.getByRole('alert')).toHaveTextContent(
      'Passkey creation was cancelled',
    );
  });

  it('has link to login page', async () => {
    const user = userEvent.setup();
    render(<RegisterPage />);
    await user.click(screen.getByText('Log In'));
    expect(mockNavigate).toHaveBeenCalledWith('/login');
  });
});
