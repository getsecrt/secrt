import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';
import { SendPage } from './SendPage';

// ── Mocks ──

vi.mock('../../crypto/envelope', () => ({
  seal: vi.fn(),
}));

vi.mock('../../crypto/encoding', () => ({
  utf8Encode: vi.fn((s: string) => new TextEncoder().encode(s)),
}));

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

vi.mock('../../crypto/constants', () => ({
  CODEC_ZSTD: 1,
}));

vi.mock('../../lib/api', () => ({
  createSecret: vi.fn(),
  fetchInfo: vi.fn(),
}));

vi.mock('../../lib/envelope-size', () => ({
  checkEnvelopeSize: vi.fn(),
  estimateEnvelopeSize: vi.fn((frameBytes: number) => Math.ceil((frameBytes + 16) * 4 / 3) + 400),
  frameSizeError: vi.fn((est: number, max: number, compressed?: boolean) => {
    const qualifier = compressed ? 'encrypted & compressed' : 'encrypted';
    return `File is too large (${est} B ${qualifier}).\nMaximum is ${max} B.`;
  }),
}));

vi.mock('../../lib/url', () => ({
  formatShareLink: vi.fn(),
}));

vi.mock('../../lib/clipboard', () => ({
  copyToClipboard: vi.fn().mockResolvedValue(true),
}));

vi.mock('../../lib/auth-context', () => ({
  useAuth: () => ({
    loading: false,
    authenticated: false,
    userId: null,
    handle: null,
    sessionToken: null,
    login: vi.fn(),
    logout: vi.fn(),
  }),
}));

import { seal } from '../../crypto/envelope';
import { createSecret, fetchInfo } from '../../lib/api';
import { checkEnvelopeSize } from '../../lib/envelope-size';
import { formatShareLink } from '../../lib/url';
import { buildFrame } from '../../crypto/frame';
import { ensureCompressor } from '../../crypto/compress';

const mockSeal = vi.mocked(seal);
const mockCreate = vi.mocked(createSecret);
const mockFetchInfo = vi.mocked(fetchInfo);
const mockCheckSize = vi.mocked(checkEnvelopeSize);
const mockFormatLink = vi.mocked(formatShareLink);
const mockBuildFrame = vi.mocked(buildFrame);
const mockEnsureCompressor = vi.mocked(ensureCompressor);

const fakeEnvelope = {
  v: 1 as const,
  suite: 'v1-pbkdf2-hkdf-aes256gcm-sealed-payload' as const,
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
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('renders form with textarea, passphrase, TTL, and enabled submit', () => {
    render(<SendPage />);
    expect(
      screen.getByPlaceholderText('Enter your secret...'),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/Passphrase/)).toBeInTheDocument();
    expect(screen.getByText('Expires After')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Create secret' }),
    ).toBeEnabled();
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
      screen.getByPlaceholderText('Enter your secret...'),
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
      screen.getByPlaceholderText('Enter your secret...'),
      'text',
    );
    await user.type(screen.getByLabelText(/Passphrase/), 'mypass');
    await user.click(screen.getByRole('button', { name: 'Create secret' }));

    await waitFor(() => {
      expect(mockSeal).toHaveBeenCalledWith(
        expect.any(Uint8Array),
        { type: 'text' },
        expect.objectContaining({ passphrase: 'mypass', compress: expect.any(Function) }),
      );
    });
  });

  it('passes compress function to seal for text mode', async () => {
    const user = userEvent.setup();
    render(<SendPage />);
    await user.type(
      screen.getByPlaceholderText('Enter your secret...'),
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
      screen.getByPlaceholderText('Enter your secret...'),
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
      screen.getByPlaceholderText('Enter your secret...'),
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
      screen.getByPlaceholderText('Enter your secret...'),
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
      screen.getByPlaceholderText('Enter your secret...'),
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
      screen.getByPlaceholderText('Enter your secret...'),
      'text',
    );
    await user.click(screen.getByRole('button', { name: 'Create secret' }));

    await waitFor(() => {
      expect(screen.getByText('Secret Created')).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: 'Send Another Secret' }));
    expect(
      screen.getByPlaceholderText('Enter your secret...'),
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
      screen.getByPlaceholderText('Enter your secret...'),
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
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    const smallFile = new File(['hello'], 'test.txt', { type: 'text/plain' });
    Object.defineProperty(fileInput, 'files', { value: [smallFile] });
    fileInput.dispatchEvent(new Event('change', { bubbles: true }));

    await waitFor(() => {
      expect(mockBuildFrame).toHaveBeenCalled();
    });
  });
});
