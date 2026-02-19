import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';

/* ---------- mocks (must precede component import) ---------- */

const mockAuth = {
  loading: false,
  authenticated: true,
  userId: 'test-uid',
  displayName: 'alice',
  sessionToken: 'uss_test.secret',
  login: vi.fn(),
  logout: vi.fn().mockResolvedValue(undefined),
};
vi.mock('../../lib/auth-context', () => ({
  useAuth: () => mockAuth,
}));

const mockNavigate = vi.fn();
vi.mock('../../router', () => ({
  navigate: (...args: unknown[]) => mockNavigate(...args),
}));

vi.mock('../../lib/api', () => ({
  listApiKeys: vi.fn(),
  revokeApiKey: vi.fn(),
  registerApiKey: vi.fn(),
  deleteAccount: vi.fn(),
  upsertAmkWrapper: vi.fn().mockResolvedValue({ ok: true }),
  fetchInfo: vi.fn().mockResolvedValue({ features: { encrypted_notes: false } }),
}));

vi.mock('../../crypto/apikey', () => ({
  generateApiKeyMaterial: vi.fn(),
  formatWireApiKey: vi.fn(),
}));

vi.mock('../../crypto/amk', () => ({
  generateAmk: vi.fn(() => new Uint8Array(32)),
  computeAmkCommit: vi.fn().mockResolvedValue(new Uint8Array(32)),
  deriveAmkWrapKey: vi.fn().mockResolvedValue(new Uint8Array(32)),
  buildWrapAad: vi.fn(() => new Uint8Array(0)),
  wrapAmk: vi.fn().mockResolvedValue({ ct: 'ct', nonce: 'nonce', version: 1 }),
}));

vi.mock('../../crypto/encoding', () => ({
  base64urlEncode: vi.fn(() => 'encoded'),
}));

vi.mock('../../lib/amk-store', () => ({
  storeAmk: vi.fn().mockResolvedValue(undefined),
  loadAmk: vi.fn().mockResolvedValue(null),
  clearAmk: vi.fn().mockResolvedValue(undefined),
}));

/* ---------- imports (after vi.mock) ---------- */

import { SettingsPage } from './SettingsPage';
import {
  listApiKeys,
  revokeApiKey,
  registerApiKey,
  deleteAccount,
} from '../../lib/api';
import { generateApiKeyMaterial, formatWireApiKey } from '../../crypto/apikey';

/* ---------- helpers ---------- */

const mockedListApiKeys = vi.mocked(listApiKeys);
const mockedRevokeApiKey = vi.mocked(revokeApiKey);
const mockedRegisterApiKey = vi.mocked(registerApiKey);
const mockedDeleteAccount = vi.mocked(deleteAccount);
const mockedGenerateApiKeyMaterial = vi.mocked(generateApiKeyMaterial);
const mockedFormatWireApiKey = vi.mocked(formatWireApiKey);

/* ---------- suite ---------- */

describe('SettingsPage', () => {
  beforeEach(() => {
    // Reset auth to authenticated defaults before each test
    mockAuth.loading = false;
    mockAuth.authenticated = true;
    mockAuth.userId = 'test-uid';
    mockAuth.displayName = 'alice';
    mockAuth.sessionToken = 'uss_test.secret';
    mockAuth.logout.mockResolvedValue(undefined);

    // Default: listApiKeys resolves to empty list so the page renders
    mockedListApiKeys.mockResolvedValue({ api_keys: [] });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  /* ---- 1. Redirect unauthenticated users ---- */

  it('redirects unauthenticated users to /login', () => {
    mockAuth.authenticated = false;
    mockAuth.loading = false;

    render(<SettingsPage />);

    expect(mockNavigate).toHaveBeenCalledWith('/login');
  });

  /* ---- 2. Renders API key list ---- */

  it('renders API key list with prefix, date, and status badge', async () => {
    mockedListApiKeys.mockResolvedValue({
      api_keys: [
        {
          prefix: 'abc123',
          scopes: 'full',
          created_at: '2025-06-15T10:00:00Z',
          revoked_at: null,
        },
        {
          prefix: 'xyz789',
          scopes: 'full',
          created_at: '2025-05-01T08:00:00Z',
          revoked_at: '2025-05-20T12:00:00Z',
        },
      ],
    });

    render(<SettingsPage />);

    // Wait for the keys to load
    expect(await screen.findByText('abc123')).toBeTruthy();
    expect(screen.getByText('xyz789')).toBeTruthy();

    // Status badges
    expect(screen.getByText('Active')).toBeTruthy();
    expect(screen.getByText('Revoked')).toBeTruthy();

    // Revoke button only for active key
    const revokeButtons = screen.getAllByText('Revoke');
    expect(revokeButtons).toHaveLength(1);
  });

  /* ---- 3. Revoke button calls API with correct prefix ---- */

  it('revoke button calls revokeApiKey with the correct prefix', async () => {
    const user = userEvent.setup();

    mockedListApiKeys.mockResolvedValue({
      api_keys: [
        {
          prefix: 'abc123',
          scopes: 'full',
          created_at: '2025-06-15T10:00:00Z',
          revoked_at: null,
        },
      ],
    });
    mockedRevokeApiKey.mockResolvedValue(undefined as never);

    render(<SettingsPage />);

    const revokeBtn = await screen.findByText('Revoke');
    await user.click(revokeBtn);

    expect(mockedRevokeApiKey).toHaveBeenCalledWith(
      'uss_test.secret',
      'abc123',
    );
  });

  /* ---- 4. Create API key shows generated wire key ---- */

  it('create API key shows the generated wire key', async () => {
    const user = userEvent.setup();

    mockedGenerateApiKeyMaterial.mockResolvedValue({
      rootKey: new Uint8Array(32),
      authToken: new Uint8Array(32),
      authTokenB64: 'dGVzdC1hdXRoLXRva2Vu',
    });
    mockedRegisterApiKey.mockResolvedValue({
      prefix: 'abcdef',
      scopes: 'full',
    });
    mockedFormatWireApiKey.mockReturnValue('ak2_abcdef.dGVzdC1hdXRoLXRva2Vu');

    render(<SettingsPage />);

    // Wait for initial load to finish
    await waitFor(() => {
      expect(mockedListApiKeys).toHaveBeenCalled();
    });

    const createBtn = screen.getByText('Create Key');
    await user.click(createBtn);

    // Wait for the wire key to appear
    expect(
      await screen.findByText('ak2_abcdef.dGVzdC1hdXRoLXRva2Vu'),
    ).toBeTruthy();

    // Verify the crypto functions were called correctly
    expect(mockedGenerateApiKeyMaterial).toHaveBeenCalled();
    expect(mockedRegisterApiKey).toHaveBeenCalledWith(
      'uss_test.secret',
      'dGVzdC1hdXRoLXRva2Vu',
    );
    expect(mockedFormatWireApiKey).toHaveBeenCalledWith(
      'abcdef',
      new Uint8Array(32),
    );
  });

  /* ---- 5. Delete account requires typing DELETE ---- */

  it('delete account confirm button is disabled until DELETE is typed', async () => {
    const user = userEvent.setup();

    render(<SettingsPage />);

    // Wait for initial load
    await waitFor(() => {
      expect(mockedListApiKeys).toHaveBeenCalled();
    });

    // Click "Delete Account" to reveal confirmation UI
    const deleteBtn = screen.getByText('Delete Account');
    await user.click(deleteBtn);

    // Confirm button should be disabled
    const confirmBtn = screen.getByRole('button', { name: 'Delete' });
    expect(confirmBtn).toBeDisabled();

    // Type something other than DELETE
    const input = screen.getByPlaceholderText('Type DELETE');
    await user.type(input, 'DELE');
    expect(confirmBtn).toBeDisabled();

    // Type the final characters to spell DELETE
    await user.type(input, 'TE');
    expect(confirmBtn).not.toBeDisabled();
  });

  /* ---- 6. Delete account calls API, logs out, and redirects ---- */

  it('delete account calls API, logs out, and redirects to /', async () => {
    const user = userEvent.setup();

    mockedDeleteAccount.mockResolvedValue({
      ok: true,
      secrets_burned: 3,
      keys_revoked: 1,
    });

    render(<SettingsPage />);

    // Wait for initial load
    await waitFor(() => {
      expect(mockedListApiKeys).toHaveBeenCalled();
    });

    // Click "Delete Account" to reveal confirmation UI
    const deleteBtn = screen.getByText('Delete Account');
    await user.click(deleteBtn);

    // Type DELETE and confirm
    const input = screen.getByPlaceholderText('Type DELETE');
    await user.type(input, 'DELETE');

    const confirmBtn = screen.getByRole('button', { name: 'Delete' });
    await user.click(confirmBtn);

    // Verify the full flow
    await waitFor(() => {
      expect(mockedDeleteAccount).toHaveBeenCalledWith('uss_test.secret');
    });
    await waitFor(() => {
      expect(mockAuth.logout).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/');
    });
  });
});
