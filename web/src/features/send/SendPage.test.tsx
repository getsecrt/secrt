import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';
import { SendPage } from './SendPage';

// ── Mocks ──

vi.mock('../../crypto/envelope', () => ({
  seal: vi.fn(),
  preloadPassphraseKdf: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../crypto/encoding', async (importActual) => {
  const actual = await importActual<typeof import('../../crypto/encoding')>();
  return {
    ...actual,
    utf8Encode: vi.fn((s: string) => new TextEncoder().encode(s)),
  };
});

vi.mock('../../crypto/frame', () => ({
  buildFrame: vi.fn((_meta: unknown, body: Uint8Array) => {
    // Return a fake frame: 16-byte header + body
    const frame = new Uint8Array(16 + body.length);
    frame[5] = 0; // CODEC_NONE by default
    frame.set(body, 16);
    return frame;
  }),
}));

vi.mock('../../crypto/compress', () => ({
  ensureCompressor: vi.fn().mockResolvedValue(undefined),
  compress: vi.fn((data: Uint8Array) => data),
}));

vi.mock('../../crypto/constants', async (importActual) => {
  const actual = await importActual<typeof import('../../crypto/constants')>();
  return { ...actual, CODEC_ZSTD: 1 };
});

vi.mock('../../lib/api', () => ({
  createSecret: vi.fn(),
  fetchInfo: vi.fn(),
  updateSecretMeta: vi.fn(),
}));

vi.mock('../../crypto/amk', () => ({
  encryptNote: vi.fn(),
  generateAmk: vi.fn(),
}));

vi.mock('../../lib/amk-store', () => ({
  loadAmk: vi.fn(),
  storeAmk: vi.fn(),
}));

vi.mock('../../lib/envelope-size', () => ({
  checkEnvelopeSize: vi.fn(),
  estimateEnvelopeSize: vi.fn(
    (frameBytes: number) => Math.ceil(((frameBytes + 16) * 4) / 3) + 400,
  ),
  frameSizeError: vi.fn((est: number, max: number, compressed?: boolean) => {
    const qualifier = compressed ? 'encrypted & compressed' : 'encrypted';
    return `File is too large (${est} B ${qualifier}).\nMaximum is ${max} B.`;
  }),
}));

vi.mock('../../lib/url', async (importActual) => {
  const actual = await importActual<typeof import('../../lib/url')>();
  return {
    ...actual,
    formatShareLink: vi.fn(),
  };
});

const mockIsTauri = vi.fn(() => false);
const mockGetCanonicalHost = vi.fn(() => 'secrt.ca');
vi.mock('../../lib/config', async (importActual) => {
  const actual = await importActual<typeof import('../../lib/config')>();
  return {
    ...actual,
    isTauri: () => mockIsTauri(),
    getCanonicalHost: () => mockGetCanonicalHost(),
  };
});

const mockTauriShellOpen = vi.fn().mockResolvedValue(undefined);
vi.mock('@tauri-apps/plugin-shell', () => ({
  open: (url: string) => mockTauriShellOpen(url),
}));

vi.mock('../../lib/clipboard', () => ({
  copyToClipboard: vi.fn().mockResolvedValue(true),
  copySensitive: vi.fn().mockResolvedValue(true),
}));

vi.mock('./password-generator', () => ({
  DEFAULT_PASSWORD_LENGTH: 20,
  MIN_PASSWORD_LENGTH: 4,
  generatePassword: vi.fn(),
}));

const mockAuth = {
  loading: false,
  authenticated: false,
  displayName: null as string | null,
  userId: null as string | null,
  sessionToken: null as string | null,
  login: vi.fn(),
  logout: vi.fn(),
};
vi.mock('../../lib/auth-context', () => ({
  useAuth: () => mockAuth,
}));

import { seal, preloadPassphraseKdf } from '../../crypto/envelope';
import { createSecret, fetchInfo, updateSecretMeta } from '../../lib/api';
import { encryptNote, generateAmk } from '../../crypto/amk';
import { loadAmk, storeAmk } from '../../lib/amk-store';
import { checkEnvelopeSize } from '../../lib/envelope-size';
import { formatShareLink } from '../../lib/url';
import { buildFrame } from '../../crypto/frame';
import { ensureCompressor } from '../../crypto/compress';
import { copySensitive } from '../../lib/clipboard';
import {
  DEFAULT_PASSWORD_LENGTH,
  generatePassword,
} from './password-generator';

const mockSeal = vi.mocked(seal);
const mockPreloadPassphraseKdf = vi.mocked(preloadPassphraseKdf);
const mockCreate = vi.mocked(createSecret);
const mockFetchInfo = vi.mocked(fetchInfo);
const mockCheckSize = vi.mocked(checkEnvelopeSize);
const mockFormatLink = vi.mocked(formatShareLink);
const mockBuildFrame = vi.mocked(buildFrame);
const mockEnsureCompressor = vi.mocked(ensureCompressor);
const mockCopySensitive = vi.mocked(copySensitive);
const mockGeneratePassword = vi.mocked(generatePassword);
const mockUpdateSecretMeta = vi.mocked(updateSecretMeta);
const mockEncryptNote = vi.mocked(encryptNote);
const mockGenerateAmk = vi.mocked(generateAmk);
const mockLoadAmk = vi.mocked(loadAmk);
const mockStoreAmk = vi.mocked(storeAmk);

const fakeEnvelope = {
  v: 1 as const,
  suite: 'v1-argon2id-hkdf-aes256gcm-sealed-payload' as const,
  enc: { alg: 'A256GCM' as const, nonce: 'n', ciphertext: 'c' },
  kdf: { name: 'none' as const },
  hkdf: {
    hash: 'SHA-256' as const,
    salt: 's',
    enc_info: 'e',
    claim_info: 'cl',
    length: 32 as const,
  },
};

describe('SendPage', () => {
  beforeEach(() => {
    localStorage.clear();
    // Reset auth to unauthenticated default
    mockAuth.loading = false;
    mockAuth.authenticated = false;
    mockAuth.displayName = null;
    mockAuth.userId = null;
    mockAuth.sessionToken = null;
    mockFetchInfo.mockResolvedValue({
      authenticated: false,
      ttl: { default_seconds: 86400, max_seconds: 2592000 },
      limits: {
        public: {
          max_envelope_bytes: 262144,
          max_secrets: 100,
          max_total_bytes: 10485760,
          rate: { requests_per_second: 2, burst: 5 },
        },
        authed: {
          max_envelope_bytes: 1048576,
          max_secrets: 1000,
          max_total_bytes: 104857600,
          rate: { requests_per_second: 10, burst: 20 },
        },
      },
      claim_rate: { requests_per_second: 5, burst: 10 },
      features: { encrypted_notes: false },
    });
    mockSeal.mockResolvedValue({
      envelope: fakeEnvelope,
      urlKey: new Uint8Array(32),
      claimHash: 'hash123',
    });
    mockCreate.mockResolvedValue({
      id: 'sec_abc',
      expires_at: '2026-03-01T00:00:00Z',
    });
    mockCheckSize.mockReturnValue(null);
    mockFormatLink.mockReturnValue('https://secrt.ca/s/sec_abc#key');
    mockCopySensitive.mockResolvedValue(true);
    mockGeneratePassword.mockReturnValue('Aa1!Aa1!Aa1!Aa1!Aa1!');
    mockPreloadPassphraseKdf.mockResolvedValue(undefined);
    mockIsTauri.mockReturnValue(false);
    mockGetCanonicalHost.mockReturnValue('secrt.ca');
    mockTauriShellOpen.mockClear();
    mockTauriShellOpen.mockResolvedValue(undefined);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('renders form with textarea, passphrase, TTL, and enabled submit', () => {
    render(<SendPage />);
    expect(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/Passphrase/)).toBeInTheDocument();
    expect(screen.getByText('Expires After')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create secret' })).toBeEnabled();
  });

  it('preloads Argon2id when passphrase input is used', async () => {
    const user = userEvent.setup();
    render(<SendPage />);

    await user.type(screen.getByLabelText(/Passphrase/), 'mypass');

    expect(mockPreloadPassphraseKdf).toHaveBeenCalled();
  });

  it('generates a default password and copies it', async () => {
    const user = userEvent.setup();
    render(<SendPage />);

    await user.click(
      screen.getByRole('button', { name: /Generate.*Password/i }),
    );

    await waitFor(() => {
      expect(mockGeneratePassword).toHaveBeenCalledWith({
        length: DEFAULT_PASSWORD_LENGTH,
        grouped: false,
      });
    });
    expect(mockCopySensitive).toHaveBeenCalledWith('Aa1!Aa1!Aa1!Aa1!Aa1!');
    expect(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
    ).toHaveValue('Aa1!Aa1!Aa1!Aa1!Aa1!');
    expect(screen.getByRole('button', { name: /copied/i })).toBeInTheDocument();
  });

  it('uses saved generator settings from localStorage on homepage generate', async () => {
    localStorage.setItem('send_password_length', '26');
    localStorage.setItem('send_password_grouped', 'true');

    const user = userEvent.setup();
    render(<SendPage />);

    await user.click(
      screen.getByRole('button', { name: /Generate.*Password/i }),
    );

    await waitFor(() => {
      expect(mockGeneratePassword).toHaveBeenCalledWith({
        length: 26,
        grouped: true,
      });
    });
  });

  it('falls back to defaults when saved length is invalid on homepage generate', async () => {
    localStorage.setItem('send_password_length', '2');
    localStorage.setItem('send_password_grouped', 'true');

    const user = userEvent.setup();
    render(<SendPage />);

    await user.click(
      screen.getByRole('button', { name: /Generate.*Password/i }),
    );

    await waitFor(() => {
      expect(mockGeneratePassword).toHaveBeenCalledWith({
        length: DEFAULT_PASSWORD_LENGTH,
        grouped: true,
      });
    });
  });

  it('uses modal settings and keeps modal open after generation', async () => {
    const user = userEvent.setup();
    mockGeneratePassword
      .mockReturnValueOnce('Bb2@Bb2@Bb2@Bb2@')
      .mockReturnValueOnce('Cc3#Cc3#Cc3#Cc3#');
    render(<SendPage />);

    await user.click(
      screen.getByRole('button', { name: 'Password generator settings' }),
    );
    expect(
      screen.getByRole('heading', { name: /Generate Password/i }),
    ).toBeInTheDocument();

    const lengthInput = screen.getByLabelText('Length');
    await user.clear(lengthInput);
    await user.type(lengthInput, '32');
    await user.click(
      screen.getByLabelText('Group characters for easier entry'),
    );
    await user.click(screen.getByRole('button', { name: /Generate & copy/i }));

    await waitFor(() => {
      expect(mockGeneratePassword).toHaveBeenLastCalledWith({
        length: 32,
        grouped: true,
      });
    });
    expect(mockCopySensitive).toHaveBeenCalledWith('Bb2@Bb2@Bb2@Bb2@');
    expect(
      screen.getByRole('heading', { name: /Generate Password/i }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText('Password Preview')).toHaveValue(
      'Bb2@Bb2@Bb2@Bb2@',
    );
    expect(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
    ).toHaveValue('Bb2@Bb2@Bb2@Bb2@');

    await user.click(screen.getByRole('button', { name: /Generate & copy/i }));
    await waitFor(() => {
      expect(mockGeneratePassword).toHaveBeenLastCalledWith({
        length: 32,
        grouped: true,
      });
    });
    expect(mockCopySensitive).toHaveBeenCalledWith('Cc3#Cc3#Cc3#Cc3#');
    expect(screen.getByLabelText('Password Preview')).toHaveValue(
      'Cc3#Cc3#Cc3#Cc3#',
    );
    expect(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
    ).toHaveValue('Cc3#Cc3#Cc3#Cc3#');
  });

  it('keeps preview and secret message in sync when editing in modal', async () => {
    const user = userEvent.setup();
    render(<SendPage />);

    await user.type(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
      'initial value',
    );
    await user.click(
      screen.getByRole('button', { name: 'Password generator settings' }),
    );

    const preview = screen.getByLabelText('Password Preview');
    await user.clear(preview);
    await user.type(preview, 'edited-password-value');

    expect(screen.getByLabelText('Password Preview')).toHaveValue(
      'edited-password-value',
    );
    expect(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
    ).toHaveValue('edited-password-value');
  });

  it('closes the password modal from the X button', async () => {
    const user = userEvent.setup();
    render(<SendPage />);

    await user.click(
      screen.getByRole('button', { name: 'Password generator settings' }),
    );
    await user.click(
      screen.getByRole('button', { name: 'Close password generator' }),
    );

    expect(
      screen.queryByRole('heading', { name: /Generate Password/i }),
    ).not.toBeInTheDocument();
  });

  it('closes the password modal when clicking outside', async () => {
    const user = userEvent.setup();
    render(<SendPage />);

    await user.click(
      screen.getByRole('button', { name: 'Password generator settings' }),
    );
    await user.click(screen.getByTestId('password-generator-backdrop'));

    expect(
      screen.queryByRole('heading', { name: /Generate Password/i }),
    ).not.toBeInTheDocument();
  });

  it('loads saved password generator settings from localStorage', async () => {
    const user = userEvent.setup();
    localStorage.setItem('send_password_length', '28');
    localStorage.setItem('send_password_grouped', 'true');
    render(<SendPage />);

    await user.click(
      screen.getByRole('button', { name: 'Password generator settings' }),
    );

    expect(screen.getByLabelText('Length')).toHaveValue(28);
    expect(
      screen.getByLabelText('Group characters for easier entry'),
    ).toBeChecked();
  });

  it('persists password generator settings to localStorage', async () => {
    const user = userEvent.setup();
    render(<SendPage />);
    await user.click(
      screen.getByRole('button', { name: 'Password generator settings' }),
    );

    const lengthInput = screen.getByLabelText('Length');
    await user.clear(lengthInput);
    await user.type(lengthInput, '26');
    await user.click(
      screen.getByLabelText('Group characters for easier entry'),
    );

    await waitFor(() => {
      expect(localStorage.getItem('send_password_length')).toBe('26');
      expect(localStorage.getItem('send_password_grouped')).toBe('true');
    });
  });

  it('homepage generate uses settings updated in modal without reload', async () => {
    const user = userEvent.setup();
    render(<SendPage />);

    await user.click(
      screen.getByRole('button', { name: 'Password generator settings' }),
    );

    const lengthInput = screen.getByLabelText('Length');
    await user.clear(lengthInput);
    await user.type(lengthInput, '31');
    await user.click(
      screen.getByLabelText('Group characters for easier entry'),
    );
    await user.click(
      screen.getByRole('button', { name: 'Close password generator' }),
    );

    mockGeneratePassword.mockClear();
    await user.click(
      screen.getByRole('button', { name: /Generate.*Password/i }),
    );

    await waitFor(() => {
      expect(mockGeneratePassword).toHaveBeenCalledWith({
        length: 31,
        grouped: true,
      });
    });
  });

  it('closes the password modal from the footer close link without generating', async () => {
    const user = userEvent.setup();
    render(<SendPage />);

    await user.click(
      screen.getByRole('button', { name: 'Password generator settings' }),
    );
    // Clear any calls that happened during modal open
    mockGeneratePassword.mockClear();

    await user.click(
      screen.getByRole('button', { name: 'Close password generator' }),
    );

    expect(
      screen.queryByRole('heading', { name: /Generate Password/i }),
    ).not.toBeInTheDocument();
    expect(mockGeneratePassword).not.toHaveBeenCalled();
  });

  it('closes the password modal on escape', async () => {
    const user = userEvent.setup();
    render(<SendPage />);

    await user.click(
      screen.getByRole('button', { name: 'Password generator settings' }),
    );
    const dialog = document.querySelector('dialog');
    dialog?.dispatchEvent(new Event('cancel'));

    await waitFor(() => {
      expect(
        screen.queryByRole('heading', { name: /Generate Password/i }),
      ).not.toBeInTheDocument();
    });
  });

  it('shows validation error when submitting empty text', async () => {
    const user = userEvent.setup();
    render(<SendPage />);
    await user.click(screen.getByRole('button', { name: 'Create secret' }));
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
    expect(screen.getByText(/Enter a secret message/)).toBeInTheDocument();
  });

  it('passphrase visibility toggle works', async () => {
    const user = userEvent.setup();
    render(<SendPage />);
    const input = screen.getByLabelText(/Passphrase/);
    expect(input).toHaveAttribute('type', 'password');
    await user.click(screen.getByLabelText('Show passphrase'));
    expect(input).toHaveAttribute('type', 'text');
    await user.click(screen.getByLabelText('Hide passphrase'));
    expect(input).toHaveAttribute('type', 'password');
  });

  it('successful text submission shows ShareResult', async () => {
    const user = userEvent.setup();
    render(<SendPage />);
    await user.type(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
      'my secret',
    );
    await user.click(screen.getByRole('button', { name: 'Create secret' }));

    await waitFor(() => {
      expect(screen.getByText('Secret Created')).toBeInTheDocument();
    });
    expect(mockSeal).toHaveBeenCalled();
    expect(mockCreate).toHaveBeenCalled();
  });

  it('passes passphrase and compress to seal when provided', async () => {
    const user = userEvent.setup();
    render(<SendPage />);
    await user.type(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
      'text',
    );
    await user.type(screen.getByLabelText(/Passphrase/), 'mypass');
    await user.click(screen.getByRole('button', { name: 'Create secret' }));

    await waitFor(() => {
      expect(mockSeal).toHaveBeenCalledWith(
        expect.any(Uint8Array),
        { type: 'text' },
        expect.objectContaining({
          passphrase: 'mypass',
          compress: expect.any(Function),
        }),
      );
    });
  });

  it('passes compress function to seal for text mode', async () => {
    const user = userEvent.setup();
    render(<SendPage />);
    await user.type(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
      'text',
    );
    await user.click(screen.getByRole('button', { name: 'Create secret' }));

    await waitFor(() => {
      expect(mockSeal).toHaveBeenCalledWith(
        expect.any(Uint8Array),
        { type: 'text' },
        expect.objectContaining({ compress: expect.any(Function) }),
      );
    });
  });

  it('calls ensureCompressor before seal on submit', async () => {
    const user = userEvent.setup();
    render(<SendPage />);
    await user.type(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
      'text',
    );
    await user.click(screen.getByRole('button', { name: 'Create secret' }));

    await waitFor(() => {
      expect(mockEnsureCompressor).toHaveBeenCalled();
    });
  });

  it('shows error when seal rejects', async () => {
    mockSeal.mockRejectedValue(new Error('crypto fail'));
    const user = userEvent.setup();
    render(<SendPage />);
    await user.type(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
      'text',
    );
    await user.click(screen.getByRole('button', { name: 'Create secret' }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
  });

  it('shows error when createSecret fails', async () => {
    mockCreate.mockRejectedValue(new Error('500 Internal Server Error'));
    const user = userEvent.setup();
    render(<SendPage />);
    await user.type(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
      'text',
    );
    await user.click(screen.getByRole('button', { name: 'Create secret' }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
    expect(screen.getByText(/Server error/)).toBeInTheDocument();
  });

  it('shows error when envelope too large', async () => {
    mockCheckSize.mockReturnValue(
      'Secret is too large (300.0 KB encrypted).\nMaximum is 256.0 KB.',
    );
    const user = userEvent.setup();
    render(<SendPage />);
    await user.type(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
      'text',
    );
    await user.click(screen.getByRole('button', { name: 'Create secret' }));

    await waitFor(() => {
      expect(screen.getByText(/too large/)).toBeInTheDocument();
    });
  });

  it('"Create another" resets to input state', async () => {
    const user = userEvent.setup();
    render(<SendPage />);
    await user.type(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
      'text',
    );
    await user.click(screen.getByRole('button', { name: 'Create secret' }));

    await waitFor(() => {
      expect(screen.getByText('Secret Created')).toBeInTheDocument();
    });

    await user.click(
      screen.getByRole('button', { name: 'Send Another Secret' }),
    );
    expect(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
    ).toBeInTheDocument();
  });

  it('shows button text transitions during submission', async () => {
    // Make seal slow enough to observe status
    let resolveSeal: (v: any) => void;
    mockSeal.mockImplementation(
      () =>
        new Promise((r) => {
          resolveSeal = r;
        }),
    );

    const user = userEvent.setup();
    render(<SendPage />);
    await user.type(
      screen.getByPlaceholderText('Enter your secret or drag a file here...'),
      'text',
    );
    await user.click(screen.getByRole('button', { name: 'Create secret' }));

    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /Encrypting/ }),
      ).toBeInTheDocument();
    });

    resolveSeal!({
      envelope: fakeEnvelope,
      urlKey: new Uint8Array(32),
      claimHash: 'h',
    });

    await waitFor(() => {
      expect(screen.getByText('Secret Created')).toBeInTheDocument();
    });
  });

  it('calls fetchInfo on mount', () => {
    render(<SendPage />);
    expect(mockFetchInfo).toHaveBeenCalled();
  });

  it('calls buildFrame during file select for pre-check', async () => {
    render(<SendPage />);

    // Wait for fetchInfo to resolve so serverInfo is populated
    await waitFor(() => {
      expect(mockFetchInfo).toHaveBeenCalled();
    });

    // Simulate file select by finding the hidden file input and triggering change
    const fileInput = document.querySelector(
      'input[type="file"]',
    ) as HTMLInputElement;
    const smallFile = new File(['hello'], 'test.txt', { type: 'text/plain' });
    Object.defineProperty(fileInput, 'files', { value: [smallFile] });
    fileInput.dispatchEvent(new Event('change', { bubbles: true }));

    await waitFor(() => {
      expect(mockBuildFrame).toHaveBeenCalled();
    });
  });

  describe('note field', () => {
    beforeEach(() => {
      sessionStorage.clear();
      // Authenticated user with encrypted_notes enabled
      mockAuth.authenticated = true;
      mockAuth.userId = 'user-abc';
      mockAuth.sessionToken = 'uss_test.tok';
      mockFetchInfo.mockResolvedValue({
        authenticated: true,
        ttl: { default_seconds: 86400, max_seconds: 2592000 },
        limits: {
          public: {
            max_envelope_bytes: 262144,
            max_secrets: 100,
            max_total_bytes: 10485760,
            rate: { requests_per_second: 2, burst: 5 },
          },
          authed: {
            max_envelope_bytes: 1048576,
            max_secrets: 1000,
            max_total_bytes: 104857600,
            rate: { requests_per_second: 10, burst: 20 },
          },
        },
        claim_rate: { requests_per_second: 5, burst: 10 },
        features: { encrypted_notes: true },
      });
      mockLoadAmk.mockResolvedValue(new Uint8Array(32).fill(0xaa));
      mockEncryptNote.mockResolvedValue({
        ct: 'ct-b64',
        nonce: 'nonce-b64',
        salt: 'salt-b64',
      });
      mockUpdateSecretMeta.mockResolvedValue({ ok: true });
      mockStoreAmk.mockResolvedValue(undefined);
      mockGenerateAmk.mockReturnValue(new Uint8Array(32).fill(0xbb));
    });

    it('shows note input when authenticated and encrypted_notes is enabled', async () => {
      render(<SendPage />);
      await waitFor(() => {
        expect(screen.getByLabelText(/Private Note/)).toBeInTheDocument();
      });
    });

    it('hides note input when encrypted_notes is disabled', async () => {
      mockFetchInfo.mockResolvedValue({
        authenticated: true,
        ttl: { default_seconds: 86400, max_seconds: 2592000 },
        limits: {
          public: {
            max_envelope_bytes: 262144,
            max_secrets: 100,
            max_total_bytes: 10485760,
            rate: { requests_per_second: 2, burst: 5 },
          },
          authed: {
            max_envelope_bytes: 1048576,
            max_secrets: 1000,
            max_total_bytes: 104857600,
            rate: { requests_per_second: 10, burst: 20 },
          },
        },
        claim_rate: { requests_per_second: 5, burst: 10 },
        features: { encrypted_notes: false },
      });
      render(<SendPage />);
      await waitFor(() => {
        expect(mockFetchInfo).toHaveBeenCalled();
      });
      expect(screen.queryByLabelText(/Private Note/)).not.toBeInTheDocument();
    });

    it('hides note input when not authenticated', async () => {
      mockAuth.authenticated = false;
      mockAuth.sessionToken = null;
      render(<SendPage />);
      await waitFor(() => {
        expect(mockFetchInfo).toHaveBeenCalled();
      });
      expect(screen.queryByLabelText(/Private Note/)).not.toBeInTheDocument();
    });

    it('attaches note on successful submission', async () => {
      const user = userEvent.setup();
      render(<SendPage />);

      // Wait for note field to appear
      await waitFor(() => {
        expect(screen.getByLabelText(/Private Note/)).toBeInTheDocument();
      });

      await user.type(
        screen.getByPlaceholderText('Enter your secret or drag a file here...'),
        'my secret',
      );
      await user.type(screen.getByLabelText(/Private Note/), 'test note');
      await user.click(screen.getByRole('button', { name: 'Create secret' }));

      await waitFor(() => {
        expect(screen.getByText('Secret Created')).toBeInTheDocument();
      });
      expect(mockEncryptNote).toHaveBeenCalledWith(
        expect.any(Uint8Array),
        'sec_abc',
        expect.any(Uint8Array),
      );
      expect(mockUpdateSecretMeta).toHaveBeenCalledWith(
        'uss_test.tok',
        'sec_abc',
        expect.objectContaining({
          v: 1,
          note: expect.objectContaining({
            ct: 'ct-b64',
            nonce: 'nonce-b64',
            salt: 'salt-b64',
          }),
        }),
        1,
        expect.any(AbortSignal),
      );
    });
  });

  describe('GetSecretForm cross-instance handling', () => {
    /**
     * Build a real share-link URL with a controllable host. We use a
     * real key + base64url so parseShareUrl (un-mocked) accepts it.
     */
    function buildShareLink(host: string, id = 'abcdef0123456789') {
      const key = new Uint8Array(32);
      for (let i = 0; i < 32; i++) key[i] = i + 1;
      // base64url encode without padding
      let b64 = btoa(String.fromCharCode(...key))
        .replaceAll('+', '-')
        .replaceAll('/', '_')
        .replace(/=+$/, '');
      return `https://${host}/s/${id}#${b64}`;
    }

    /**
     * Switch to the GetSecretForm tab. The form is one of two tabs in
     * SendPage; the get tab is keyed by 'Get Secret' or similar — find
     * by the input placeholder we render.
     */
    async function openGetTab(user: ReturnType<typeof userEvent.setup>) {
      // Find the tab toggle that exposes the get-url input
      const getTab = screen.queryByRole('tab', { name: /get/i });
      if (getTab) {
        await user.click(getTab);
      }
    }

    let hrefSetter: ((value: string) => void) & { mock: { calls: any[][] } };
    let originalHrefDescriptor: PropertyDescriptor | undefined;

    beforeEach(() => {
      hrefSetter = vi.fn() as typeof hrefSetter;
      // Find the descriptor for `href` — typically on Location.prototype,
      // not the instance. We override only the setter and delegate to the
      // original getter, so pushState/document.URL keep working normally.
      let proto: object | null = window.location;
      while (proto && !originalHrefDescriptor) {
        originalHrefDescriptor = Object.getOwnPropertyDescriptor(proto, 'href');
        proto = Object.getPrototypeOf(proto);
      }
      const originalGetter = originalHrefDescriptor?.get?.bind(window.location);
      Object.defineProperty(window.location, 'href', {
        configurable: true,
        get: () => originalGetter?.() ?? 'http://localhost/',
        set: (value: string) => hrefSetter(value),
      });
    });

    afterEach(() => {
      // Drop the instance-level override; href falls back to the prototype.
      // @ts-expect-error -- happy-dom/jsdom allow this delete
      delete window.location.href;
      originalHrefDescriptor = undefined;
    });

    it('same-apex paste uses pushState and does not navigate cross-origin', async () => {
      mockGetCanonicalHost.mockReturnValue('secrt.ca');
      const pushStateSpy = vi.spyOn(window.history, 'pushState');

      const user = userEvent.setup();
      render(<SendPage />);
      await openGetTab(user);

      const input = screen.getByLabelText(/Secret Link/);
      const link = buildShareLink('secrt.ca');
      // userEvent.type interprets {} as keyboard chord syntax — use paste
      // to deliver a literal URL (the # in the fragment would otherwise be
      // interpreted oddly).
      await user.click(input);
      await user.paste(link);
      await user.click(screen.getByRole('button', { name: /View Secret/i }));

      expect(pushStateSpy).toHaveBeenCalled();
      expect(hrefSetter).not.toHaveBeenCalled();
      expect(
        screen.queryByRole('button', { name: /Continue to|Open in Browser/i }),
      ).not.toBeInTheDocument();
    });

    it('wildcard subdomain on same apex is treated as same-instance', async () => {
      mockGetCanonicalHost.mockReturnValue('secrt.is');
      const pushStateSpy = vi.spyOn(window.history, 'pushState');

      const user = userEvent.setup();
      render(<SendPage />);
      await openGetTab(user);

      await user.type(
        screen.getByLabelText(/Secret Link/),
        buildShareLink('team.secrt.is'),
      );
      await user.click(screen.getByRole('button', { name: /View Secret/i }));

      expect(pushStateSpy).toHaveBeenCalled();
      expect(hrefSetter).not.toHaveBeenCalled();
    });

    it('web + known foreign apex shows modal and redirects to sanitized URL preserving subdomain', async () => {
      mockGetCanonicalHost.mockReturnValue('secrt.ca');
      mockIsTauri.mockReturnValue(false);

      const user = userEvent.setup();
      render(<SendPage />);
      await openGetTab(user);

      await user.type(
        screen.getByLabelText(/Secret Link/),
        buildShareLink('team.secrt.is'),
      );
      await user.click(screen.getByRole('button', { name: /View Secret/i }));

      // Modal appears
      const continueBtn = await screen.findByRole('button', {
        name: /Continue to team\.secrt\.is/i,
      });
      expect(continueBtn).toBeInTheDocument();

      await user.click(continueBtn);

      expect(hrefSetter).toHaveBeenCalledTimes(1);
      const target = hrefSetter.mock.calls[0][0] as string;
      expect(target).toMatch(
        /^https:\/\/team\.secrt\.is\/s\/abcdef0123456789#/,
      );
      expect(target).not.toContain('@'); // no userinfo
      expect(mockTauriShellOpen).not.toHaveBeenCalled();
    });

    it('Tauri + known foreign apex calls plugin-shell.open with sanitized URL', async () => {
      mockGetCanonicalHost.mockReturnValue('secrt.ca');
      mockIsTauri.mockReturnValue(true);

      const user = userEvent.setup();
      render(<SendPage />);
      await openGetTab(user);

      await user.type(
        screen.getByLabelText(/Secret Link/),
        buildShareLink('secrt.is'),
      );
      await user.click(screen.getByRole('button', { name: /View Secret/i }));

      const openInBrowserBtn = await screen.findByRole('button', {
        name: /Open in Browser/i,
      });
      await user.click(openInBrowserBtn);

      await waitFor(() => {
        expect(mockTauriShellOpen).toHaveBeenCalledTimes(1);
      });
      const target = mockTauriShellOpen.mock.calls[0][0] as string;
      expect(target).toMatch(/^https:\/\/secrt\.is\/s\/abcdef0123456789#/);
      expect(hrefSetter).not.toHaveBeenCalled();
    });

    it('Cancel button closes modal and does not navigate', async () => {
      mockGetCanonicalHost.mockReturnValue('secrt.ca');

      const user = userEvent.setup();
      render(<SendPage />);
      await openGetTab(user);

      await user.type(
        screen.getByLabelText(/Secret Link/),
        buildShareLink('secrt.is'),
      );
      await user.click(screen.getByRole('button', { name: /View Secret/i }));

      const cancelBtn = await screen.findByRole('button', { name: /^Cancel$/ });
      await user.click(cancelBtn);

      await waitFor(() => {
        expect(
          screen.queryByRole('button', { name: /Continue to/i }),
        ).not.toBeInTheDocument();
      });
      expect(hrefSetter).not.toHaveBeenCalled();
      expect(mockTauriShellOpen).not.toHaveBeenCalled();
    });

    it.each([true, false])(
      'unknown host shows inline error, no modal, no shell-open (isTauri=%s)',
      async (tauri) => {
        mockGetCanonicalHost.mockReturnValue('secrt.ca');
        mockIsTauri.mockReturnValue(tauri);

        const user = userEvent.setup();
        render(<SendPage />);
        await openGetTab(user);

        await user.type(
          screen.getByLabelText(/Secret Link/),
          buildShareLink('evil.tld'),
        );
        await user.click(screen.getByRole('button', { name: /View Secret/i }));

        expect(
          screen.getByText(/unknown secrt instance \(evil\.tld\)/i),
        ).toBeInTheDocument();
        expect(
          screen.queryByRole('button', {
            name: /Continue to|Open in Browser/i,
          }),
        ).not.toBeInTheDocument();
        expect(hrefSetter).not.toHaveBeenCalled();
        expect(mockTauriShellOpen).not.toHaveBeenCalled();
      },
    );

    it('strips userinfo when rebuilding the redirect URL', async () => {
      mockGetCanonicalHost.mockReturnValue('secrt.ca');
      mockIsTauri.mockReturnValue(false);

      const user = userEvent.setup();
      render(<SendPage />);
      await openGetTab(user);

      // Userinfo in pasted URL must be dropped on redirect
      const link = buildShareLink('secrt.is').replace(
        'https://',
        'https://attacker@',
      );
      await user.type(screen.getByLabelText(/Secret Link/), link);
      await user.click(screen.getByRole('button', { name: /View Secret/i }));

      const continueBtn = await screen.findByRole('button', {
        name: /Continue to secrt\.is/i,
      });
      await user.click(continueBtn);

      const target = hrefSetter.mock.calls[0][0] as string;
      expect(target).not.toContain('attacker');
      expect(target).not.toContain('@');
      expect(target).toMatch(/^https:\/\/secrt\.is\/s\//);
    });
  });
});
