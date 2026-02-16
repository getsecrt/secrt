import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';

// Mock auth context
const mockAuth = {
  loading: false,
  authenticated: true,
  displayName: 'alice',
  sessionToken: 'uss_test.secret',
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

vi.mock('../../lib/api', () => ({
  listSecrets: vi.fn(),
  checkSecrets: vi.fn(),
  burnSecretAuthed: vi.fn(),
}));

import { DashboardPage } from './DashboardPage';
import { listSecrets, checkSecrets, burnSecretAuthed } from '../../lib/api';

const futureDate = new Date(Date.now() + 3600000).toISOString();

function makeSecret(overrides: Partial<{
  id: string;
  share_url: string;
  expires_at: string;
  created_at: string;
  state: string;
  ciphertext_size: number;
  passphrase_protected: boolean;
}> = {}) {
  return {
    id: 'abc123def456gh',
    share_url: 'https://secrt.ca/s/abc123def456gh#key',
    expires_at: futureDate,
    created_at: '2026-01-15T10:00:00Z',
    state: 'active',
    ciphertext_size: 1024,
    passphrase_protected: false,
    ...overrides,
  };
}

describe('DashboardPage', () => {
  beforeEach(() => {
    mockAuth.loading = false;
    mockAuth.authenticated = true;
    mockAuth.displayName = 'alice';
    mockAuth.sessionToken = 'uss_test.secret';
    mockAuth.login.mockClear();
    mockAuth.logout.mockClear();
    mockNavigate.mockClear();
    vi.mocked(listSecrets).mockReset();
    vi.mocked(checkSecrets).mockResolvedValue({ count: 0, checksum: 'steady' });
    vi.mocked(burnSecretAuthed).mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it('redirects unauthenticated users to /login', () => {
    mockAuth.authenticated = false;
    mockAuth.loading = false;
    render(<DashboardPage />);
    expect(mockNavigate).toHaveBeenCalledWith('/login');
  });

  it('shows loading state while fetching secrets', () => {
    // listSecrets returns a promise that never resolves
    vi.mocked(listSecrets).mockReturnValue(new Promise(() => {}));
    render(<DashboardPage />);
    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  it('shows empty state when API returns zero secrets', async () => {
    vi.mocked(listSecrets).mockResolvedValue({
      secrets: [],
      total: 0,
      limit: 50,
      offset: 0,
    });

    render(<DashboardPage />);
    expect(await screen.findByText('You have no active secrets.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Send a New Secret' })).toBeInTheDocument();
  });

  it('renders secrets list with correct metadata', async () => {
    const s1 = makeSecret({ id: 'aaaa1111bbbb2222', created_at: '2026-01-15T10:00:00Z' });
    const s2 = makeSecret({ id: 'cccc3333dddd4444', created_at: '2026-01-15T10:00:00Z' });

    vi.mocked(listSecrets).mockResolvedValue({
      secrets: [s1, s2],
      total: 2,
      limit: 50,
      offset: 0,
    });

    render(<DashboardPage />);

    // IDs should appear
    expect(await screen.findByText('aaaa1111bbbb2222')).toBeInTheDocument();
    expect(screen.getByText('cccc3333dddd4444')).toBeInTheDocument();

    // The "Remaining" column header should appear
    expect(screen.getByText('Remaining')).toBeInTheDocument();

    // Burn buttons for each secret
    const burnButtons = screen.getAllByText('Burn');
    expect(burnButtons).toHaveLength(2);
  });

  it('shows confirmation before calling burn API', async () => {
    const user = userEvent.setup();
    const secret = makeSecret({ id: 'aaaa1111bbbb2222' });

    vi.mocked(listSecrets).mockResolvedValue({
      secrets: [secret],
      total: 1,
      limit: 50,
      offset: 0,
    });

    render(<DashboardPage />);

    // Wait for the secret to appear
    await screen.findByText('aaaa1111bbbb2222');

    // Click the Burn button
    await user.click(screen.getByText('Burn'));

    // Should show confirmation UI, not call the API yet
    expect(screen.getByText('Burn this secret?')).toBeInTheDocument();
    expect(screen.getByText('Yes, burn')).toBeInTheDocument();
    expect(screen.getByText('Cancel')).toBeInTheDocument();
    expect(burnSecretAuthed).not.toHaveBeenCalled();
  });

  it('successful burn removes the secret from the list', async () => {
    const user = userEvent.setup();
    const secret = makeSecret({ id: 'aaaa1111bbbb2222' });

    vi.mocked(listSecrets).mockResolvedValue({
      secrets: [secret],
      total: 1,
      limit: 50,
      offset: 0,
    });
    vi.mocked(burnSecretAuthed).mockResolvedValue(undefined);

    render(<DashboardPage />);

    // Wait for the secret to appear
    await screen.findByText('aaaa1111bbbb2222');

    // Click Burn, then confirm
    await user.click(screen.getByText('Burn'));
    await user.click(screen.getByText('Yes, burn'));

    expect(burnSecretAuthed).toHaveBeenCalledWith('uss_test.secret', 'aaaa1111bbbb2222');

    // Secret should be removed, empty state should appear
    await waitFor(() => {
      expect(screen.queryByText('aaaa1111bbbb2222')).toBeNull();
    });
    expect(screen.getByText('You have no active secrets.')).toBeInTheDocument();
  });

  it('displays error message on API error during fetch', async () => {
    vi.mocked(listSecrets).mockRejectedValue(new Error('Network failure'));

    render(<DashboardPage />);

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Network failure');
  });

  it('displays error message on burn failure', async () => {
    const user = userEvent.setup();
    const secret = makeSecret({ id: 'aaaa1111bbbb2222' });

    vi.mocked(listSecrets).mockResolvedValue({
      secrets: [secret],
      total: 1,
      limit: 50,
      offset: 0,
    });
    vi.mocked(burnSecretAuthed).mockRejectedValue(new Error('Burn denied'));

    render(<DashboardPage />);

    await screen.findByText('aaaa1111bbbb2222');
    await user.click(screen.getByText('Burn'));
    await user.click(screen.getByText('Yes, burn'));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Burn denied');
  });
});
