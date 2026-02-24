import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';

// Mock auth context
const mockAuth: {
  loading: boolean;
  authenticated: boolean;
  userId: string | null;
  displayName: string | null;
  sessionToken: string | null;
  login: ReturnType<typeof vi.fn>;
  logout: ReturnType<typeof vi.fn>;
  setDisplayName: ReturnType<typeof vi.fn>;
} = {
  loading: false,
  authenticated: true,
  userId: 'user-1',
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
  listSecrets: vi.fn(),
  checkSecrets: vi.fn(),
  burnSecretAuthed: vi.fn(),
}));

vi.mock('../../lib/amk-store', () => ({
  loadAmk: vi.fn(),
}));

vi.mock('../../crypto/amk', () => ({
  decryptNote: vi.fn(),
}));

import { DashboardPage } from './DashboardPage';
import { listSecrets, checkSecrets, burnSecretAuthed } from '../../lib/api';
import { loadAmk } from '../../lib/amk-store';
import { decryptNote } from '../../crypto/amk';

const futureDate = new Date(Date.now() + 3600000).toISOString();

function makeSecret(
  overrides: Partial<{
    id: string;
    share_url: string;
    expires_at: string;
    created_at: string;
    state: string;
    ciphertext_size: number;
    passphrase_protected: boolean;
    enc_meta: { v: 1; note: { ct: string; nonce: string; salt: string } };
  }> = {},
) {
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
    mockAuth.userId = 'user-1';
    mockAuth.displayName = 'alice';
    mockAuth.sessionToken = 'uss_test.secret';
    mockAuth.login.mockClear();
    mockAuth.logout.mockClear();
    mockNavigate.mockClear();
    vi.mocked(listSecrets).mockReset();
    vi.mocked(checkSecrets).mockResolvedValue({ count: 0, checksum: 'steady' });
    vi.mocked(burnSecretAuthed).mockReset();
    vi.mocked(loadAmk).mockReset();
    vi.mocked(loadAmk).mockResolvedValue(null);
    vi.mocked(decryptNote).mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it('redirects unauthenticated users to /login', async () => {
    mockAuth.authenticated = false;
    mockAuth.loading = false;
    render(<DashboardPage />);
    await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith('/login'));
  });

  it('shows loading state while fetching secrets', () => {
    // listSecrets returns a promise that never resolves
    vi.mocked(listSecrets).mockReturnValue(new Promise(() => {}));
    render(<DashboardPage />);
    expect(screen.getByText('Loading secrets...')).toBeInTheDocument();
  });

  it('shows empty state when API returns zero secrets', async () => {
    vi.mocked(listSecrets).mockResolvedValue({
      secrets: [],
      total: 0,
      limit: 50,
      offset: 0,
    });

    render(<DashboardPage />);
    expect(
      await screen.findByText('You have no active secrets.'),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: 'Send a New Secret' }),
    ).toBeInTheDocument();
  });

  it('renders secrets list with correct metadata', async () => {
    const s1 = makeSecret({
      id: 'aaaa1111bbbb2222',
      created_at: '2026-01-15T10:00:00Z',
    });
    const s2 = makeSecret({
      id: 'cccc3333dddd4444',
      created_at: '2026-01-15T10:00:00Z',
    });

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
    expect(screen.getByText('Burn it')).toBeInTheDocument();
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
    await user.click(screen.getByText('Burn it'));

    expect(burnSecretAuthed).toHaveBeenCalledWith(
      'uss_test.secret',
      'aaaa1111bbbb2222',
    );

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
    await user.click(screen.getByText('Burn it'));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Burn denied');
  });

  it('decrypts notes when AMK loads after secrets (race condition)', async () => {
    // Prevent polling from causing incidental refetches.
    vi.mocked(checkSecrets).mockReturnValue(new Promise(() => {}));

    // Simulate AMK loading slower than secrets (IndexedDB vs API race)
    let resolveAmk!: (amk: Uint8Array | null) => void;
    vi.mocked(loadAmk).mockReturnValue(
      new Promise((r) => {
        resolveAmk = r;
      }),
    );

    vi.mocked(decryptNote).mockResolvedValue(
      new TextEncoder().encode('my secret note'),
    );

    const secret = makeSecret({
      id: 'aaaa1111bbbb2222',
      enc_meta: {
        v: 1,
        note: { ct: 'fakect', nonce: 'fakenonce', salt: 'fakesalt' },
      },
    });

    // listSecrets resolves immediately — secrets arrive before AMK
    vi.mocked(listSecrets).mockResolvedValue({
      secrets: [secret],
      total: 1,
      limit: 50,
      offset: 0,
    });

    render(<DashboardPage />);

    // Secrets load first — note should show as "Encrypted" (AMK not ready)
    await screen.findByText('aaaa1111bbbb2222');
    expect(screen.getByText('Encrypted')).toBeInTheDocument();
    expect(decryptNote).not.toHaveBeenCalled();

    // Now AMK arrives from IndexedDB
    resolveAmk(new Uint8Array(32));

    // hasAmk in the decrypt effect deps ensures it reruns when AMK appears
    await waitFor(() => {
      expect(screen.getByText('my secret note')).toBeInTheDocument();
    });
    expect(decryptNote).toHaveBeenCalled();
  });

  it('decrypts notes immediately when AMK is already loaded', async () => {
    // AMK resolves instantly (already cached)
    vi.mocked(loadAmk).mockResolvedValue(new Uint8Array(32));
    vi.mocked(decryptNote).mockResolvedValue(
      new TextEncoder().encode('instant note'),
    );

    const secret = makeSecret({
      id: 'aaaa1111bbbb2222',
      enc_meta: {
        v: 1,
        note: { ct: 'fakect', nonce: 'fakenonce', salt: 'fakesalt' },
      },
    });

    vi.mocked(listSecrets).mockResolvedValue({
      secrets: [secret],
      total: 1,
      limit: 50,
      offset: 0,
    });

    render(<DashboardPage />);

    // Should eventually show decrypted note
    await waitFor(() => {
      expect(screen.getByText('instant note')).toBeInTheDocument();
    });
    expect(decryptNote).toHaveBeenCalled();
  });
});
