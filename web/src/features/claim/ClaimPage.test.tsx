import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';
import { ClaimPage } from './ClaimPage';
import { URL_KEY_LEN } from '../../crypto/constants';
import { base64urlEncode } from '../../crypto/encoding';

// ── Mocks ──

vi.mock('../../crypto/envelope', () => ({
  open: vi.fn(),
  deriveClaimToken: vi.fn(),
  preloadPassphraseKdf: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../lib/api', () => ({
  claimSecret: vi.fn(),
}));

vi.mock('../../lib/clipboard', () => ({
  copyToClipboard: vi.fn().mockResolvedValue(true),
}));

vi.mock('../../router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../router')>();
  return { ...actual, navigate: vi.fn() };
});

import {
  open,
  deriveClaimToken,
  preloadPassphraseKdf,
} from '../../crypto/envelope';
import { claimSecret } from '../../lib/api';
import { navigate } from '../../router';

const mockOpen = vi.mocked(open);
const mockDeriveClaimToken = vi.mocked(deriveClaimToken);
const mockPreloadPassphraseKdf = vi.mocked(preloadPassphraseKdf);
const mockClaim = vi.mocked(claimSecret);
const mockNavigate = vi.mocked(navigate);

const fakeUrlKey = new Uint8Array(URL_KEY_LEN).fill(0xab);
const fakeFragment = base64urlEncode(fakeUrlKey);

const noPassEnvelope = {
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

const passEnvelope = {
  ...noPassEnvelope,
  kdf: {
    name: 'argon2id' as const,
    version: 19 as const,
    salt: 'ks',
    m_cost: 19456,
    t_cost: 2,
    p_cost: 1,
    length: 32 as const,
  },
};

function setHash(hash: string) {
  Object.defineProperty(window, 'location', {
    value: { ...window.location, hash: `#${hash}`, pathname: '/s/test123' },
    writable: true,
  });
}

/** Wait for the confirm screen, then click "View Secret" to proceed. */
async function clickViewSecret() {
  const user = userEvent.setup();
  await waitFor(() => {
    expect(
      screen.getByRole('button', { name: /View Secret/i }),
    ).toBeInTheDocument();
  });
  await user.click(screen.getByRole('button', { name: /View Secret/i }));
  return user;
}

describe('ClaimPage', () => {
  beforeEach(() => {
    mockDeriveClaimToken.mockResolvedValue(new Uint8Array(32));
    mockPreloadPassphraseKdf.mockResolvedValue(undefined);
    mockClaim.mockResolvedValue({ envelope: noPassEnvelope });
    mockOpen.mockResolvedValue({
      content: new TextEncoder().encode('hello secret'),
      meta: { type: 'text' },
    });
    mockNavigate.mockReset();
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    // Reset location hash
    Object.defineProperty(window, 'location', {
      value: { ...window.location, hash: '', pathname: '/' },
      writable: true,
    });
  });

  // ── Error states (fragment validation — no confirm screen) ──

  it('no fragment shows "incomplete" error', async () => {
    Object.defineProperty(window, 'location', {
      value: { ...window.location, hash: '', pathname: '/s/test123' },
      writable: true,
    });
    render(<ClaimPage id="test123" />);
    await waitFor(() => {
      expect(screen.getByText(/incomplete/i)).toBeInTheDocument();
    });
  });

  it('invalid fragment (wrong length) shows "malformed" error', async () => {
    setHash(base64urlEncode(new Uint8Array(5)));
    render(<ClaimPage id="test123" />);
    await waitFor(() => {
      expect(screen.getByText(/malformed/i)).toBeInTheDocument();
    });
  });

  it('fragment decode throws shows "malformed" error', async () => {
    setHash('!!!invalid!!!');
    render(<ClaimPage id="test123" />);
    await waitFor(() => {
      expect(screen.getByText(/malformed|incomplete/i)).toBeInTheDocument();
    });
  });

  // ── Confirm screen ──

  it('shows confirm screen with "View Secret" button', async () => {
    setHash(fakeFragment);
    render(<ClaimPage id="test123" />);
    await waitFor(() => {
      expect(
        screen.getByText(/Someone sent you a secret/i),
      ).toBeInTheDocument();
    });
    expect(
      screen.getByRole('button', { name: /View Secret/i }),
    ).toBeInTheDocument();
    // Secret is NOT claimed yet
    expect(mockClaim).not.toHaveBeenCalled();
  });

  // ── Error states (claim errors — after clicking View Secret) ──

  it('claimSecret 404 shows "no longer available"', async () => {
    setHash(fakeFragment);
    mockClaim.mockRejectedValue(new Error('404 Not Found'));
    render(<ClaimPage id="test123" />);
    await clickViewSecret();
    await waitFor(() => {
      expect(screen.getByText(/no longer available/i)).toBeInTheDocument();
    });
  });

  it('claimSecret fetch error shows "could not reach"', async () => {
    setHash(fakeFragment);
    mockClaim.mockRejectedValue(new Error('Failed to fetch'));
    render(<ClaimPage id="test123" />);
    await clickViewSecret();
    await waitFor(() => {
      expect(screen.getByText(/could not reach/i)).toBeInTheDocument();
    });
  });

  // ── No-passphrase flow ──

  it('shows "Secret Decrypted" after claim+decrypt', async () => {
    setHash(fakeFragment);
    render(<ClaimPage id="test123" />);
    await clickViewSecret();
    await waitFor(() => {
      expect(screen.getByText('Secret Decrypted')).toBeInTheDocument();
    });
  });

  it('secret text visible immediately in a readonly textarea', async () => {
    setHash(fakeFragment);
    render(<ClaimPage id="test123" />);
    await clickViewSecret();
    await waitFor(() => {
      expect(screen.getByText('Secret Decrypted')).toBeInTheDocument();
    });

    const textarea = screen.getByDisplayValue('hello secret');
    expect(textarea).toBeInTheDocument();
    expect(textarea).toHaveAttribute('readonly');
  });

  it('copy button present with "Copy secret" label', async () => {
    setHash(fakeFragment);
    render(<ClaimPage id="test123" />);
    await clickViewSecret();
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /Copy secret/ }),
      ).toBeInTheDocument();
    });
  });

  it('"permanently deleted" message shown', async () => {
    setHash(fakeFragment);
    render(<ClaimPage id="test123" />);
    await clickViewSecret();
    await waitFor(() => {
      expect(screen.getByText(/permanently deleted/)).toBeInTheDocument();
    });
  });

  it('"Create a new secret" calls navigate("/")', async () => {
    setHash(fakeFragment);
    render(<ClaimPage id="test123" />);
    const user = await clickViewSecret();
    await waitFor(() => {
      expect(screen.getByText('Secret Decrypted')).toBeInTheDocument();
    });
    await user.click(screen.getByText('Create a New Secret'));
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  // ── File flow ──

  it('shows filename, size, "Download file" button for file secrets', async () => {
    setHash(fakeFragment);
    mockOpen.mockResolvedValue({
      content: new Uint8Array(4096),
      meta: { type: 'file', filename: 'report.pdf', mime: 'application/pdf' },
    });
    render(<ClaimPage id="test123" />);
    await clickViewSecret();
    await waitFor(() => {
      expect(screen.getByText('report.pdf')).toBeInTheDocument();
    });
    expect(screen.getByText(/4\.0 KB/)).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /Download file/ }),
    ).toBeInTheDocument();
  });

  // ── Passphrase flow ──

  it('shows "Passphrase Required" modal', async () => {
    setHash(fakeFragment);
    mockClaim.mockResolvedValue({ envelope: passEnvelope });
    render(<ClaimPage id="test123" />);
    await clickViewSecret();
    await waitFor(() => {
      expect(screen.getByText('Passphrase Required')).toBeInTheDocument();
    });
    expect(mockPreloadPassphraseKdf).toHaveBeenCalled();
  });

  it('decrypt button disabled when passphrase empty', async () => {
    setHash(fakeFragment);
    mockClaim.mockResolvedValue({ envelope: passEnvelope });
    render(<ClaimPage id="test123" />);
    await clickViewSecret();
    await waitFor(() => {
      expect(screen.getByText('Passphrase Required')).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: 'Decrypt' })).toBeDisabled();
  });

  it('decrypts successfully with passphrase', async () => {
    setHash(fakeFragment);
    mockClaim.mockResolvedValue({ envelope: passEnvelope });
    mockOpen.mockResolvedValue({
      content: new TextEncoder().encode('decrypted text'),
      meta: { type: 'text' },
    });

    render(<ClaimPage id="test123" />);
    const user = await clickViewSecret();
    await waitFor(() => {
      expect(screen.getByText('Passphrase Required')).toBeInTheDocument();
    });

    await user.type(screen.getByLabelText(/Passphrase/, { selector: 'input' }), 'correct-pass');
    await user.click(screen.getByRole('button', { name: 'Decrypt' }));

    await waitFor(() => {
      expect(screen.getByText('Secret Decrypted')).toBeInTheDocument();
    });
    expect(mockOpen).toHaveBeenCalledWith(
      passEnvelope,
      expect.any(Uint8Array),
      'correct-pass',
    );
  });

  it('shows "Wrong passphrase" on failure, allows retry', async () => {
    setHash(fakeFragment);
    mockClaim.mockResolvedValue({ envelope: passEnvelope });
    mockOpen.mockRejectedValueOnce(new Error('decrypt failed'));

    render(<ClaimPage id="test123" />);
    const user = await clickViewSecret();
    await waitFor(() => {
      expect(screen.getByText('Passphrase Required')).toBeInTheDocument();
    });

    await user.type(screen.getByLabelText(/Passphrase/, { selector: 'input' }), 'wrong-pass');
    await user.click(screen.getByRole('button', { name: 'Decrypt' }));

    await waitFor(() => {
      expect(screen.getByText(/Wrong passphrase/)).toBeInTheDocument();
    });

    // The form should still be visible for retry
    expect(screen.getByLabelText(/Passphrase/, { selector: 'input' })).toBeInTheDocument();
  });

  it('shows Argon2 load error and does not silently retry', async () => {
    setHash(fakeFragment);
    mockClaim.mockResolvedValue({ envelope: passEnvelope });
    mockOpen.mockRejectedValueOnce(
      new Error('Argon2id module failed to load. Refresh and try again.'),
    );

    render(<ClaimPage id="test123" />);
    const user = await clickViewSecret();
    await waitFor(() => {
      expect(screen.getByText('Passphrase Required')).toBeInTheDocument();
    });

    await user.type(screen.getByLabelText(/Passphrase/, { selector: 'input' }), 'correct-pass');
    await user.click(screen.getByRole('button', { name: 'Decrypt' }));

    await waitFor(() => {
      expect(
        screen.getByText(/Argon2id module failed to load/i),
      ).toBeInTheDocument();
    });
  });

  it('passphrase visibility toggle works', async () => {
    setHash(fakeFragment);
    mockClaim.mockResolvedValue({ envelope: passEnvelope });
    render(<ClaimPage id="test123" />);
    const user = await clickViewSecret();
    await waitFor(() => {
      expect(screen.getByText('Passphrase Required')).toBeInTheDocument();
    });

    const input = screen.getByLabelText(/Passphrase/, { selector: 'input' });
    expect(input).toHaveAttribute('type', 'password');
    await user.click(screen.getByLabelText('Show passphrase'));
    expect(input).toHaveAttribute('type', 'text');
  });
});
