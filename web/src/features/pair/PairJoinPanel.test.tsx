import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  render,
  screen,
  cleanup,
  waitFor,
  fireEvent,
} from '@testing-library/preact';

const mockAuth = {
  loading: false,
  authenticated: true,
  userId: 'u1',
  sessionToken: 'tok',
  displayName: null,
};
vi.mock('../../lib/auth-context', () => ({
  useAuth: () => mockAuth,
}));

const mockNavigate = vi.fn();
vi.mock('../../router', () => ({
  navigate: (...args: unknown[]) => mockNavigate(...args),
}));

const mockPairChallenge = vi.fn();
const mockPairApprove = vi.fn();
vi.mock('../../lib/api', () => ({
  pairChallenge: (...args: unknown[]) => mockPairChallenge(...args),
  pairApprove: (...args: unknown[]) => mockPairApprove(...args),
}));

const mockLoadAmk = vi.fn();
vi.mock('../../lib/amk-store', () => ({
  loadAmk: (userId: string) => mockLoadAmk(userId),
}));

const mockEncryptAmkForPeer = vi.fn();
vi.mock('./pair-crypto', () => ({
  encryptAmkForPeer: (...args: unknown[]) => mockEncryptAmkForPeer(...args),
}));

// QrScannerView starts a real camera if it ever renders — fail loudly if
// the modal-eager-mount regression comes back.
const scannerMountCount = { n: 0 };
vi.mock('./QrScanner', () => ({
  QrScannerView: () => {
    scannerMountCount.n += 1;
    return <div data-testid="scanner-rendered" />;
  },
}));

import { PairJoinPanel } from './PairJoinPanel';

describe('PairJoinPanel (Page B)', () => {
  beforeEach(() => {
    mockNavigate.mockClear();
    mockPairChallenge.mockReset();
    mockPairApprove.mockReset();
    mockLoadAmk.mockReset();
    mockEncryptAmkForPeer.mockReset();
    scannerMountCount.n = 0;
  });
  afterEach(() => cleanup());

  it('does NOT mount QrScannerView on initial render (camera-prompt-on-mount regression guard)', () => {
    render(<PairJoinPanel prefilledCode={null} />);
    expect(scannerMountCount.n).toBe(0);
    expect(screen.queryByTestId('scanner-rendered')).toBeNull();
  });

  it('runs /challenge then /approve in one shot when user submits a code', async () => {
    mockPairChallenge.mockResolvedValue({
      kind: 'ok',
      displayer_ecdh_public_key: 'pk',
    });
    mockLoadAmk.mockResolvedValue(new Uint8Array(32));
    mockEncryptAmkForPeer.mockResolvedValue({
      amkTransfer: { ct: 'ct', nonce: 'n', ecdh_public_key: 'epk' },
      browserPkBytes: new Uint8Array(65),
    });
    mockPairApprove.mockResolvedValue({ ok: true });

    render(<PairJoinPanel prefilledCode={null} />);
    const input = screen.getByPlaceholderText('XXXX-XXXX') as HTMLInputElement;
    fireEvent.input(input, { target: { value: 'K7MQ-3F2A' } });
    fireEvent.click(screen.getByRole('button', { name: /Send Account Key/i }));

    await waitFor(() =>
      expect(screen.getByText(/Account Key Sent/i)).toBeInTheDocument(),
    );
    expect(mockPairApprove).toHaveBeenCalledWith('tok', {
      user_code: 'K7MQ-3F2A',
      amk_transfer: { ct: 'ct', nonce: 'n', ecdh_public_key: 'epk' },
    });
  });

  it('renders distinct copy for each terminal /challenge state', async () => {
    mockPairChallenge.mockResolvedValue({
      kind: 'terminal',
      state: 'cancelled',
    });
    render(<PairJoinPanel prefilledCode={'AAAA-BBBB'} />);
    await waitFor(() =>
      expect(screen.getByText(/cancelled/i)).toBeInTheDocument(),
    );
    cleanup();

    mockPairChallenge.mockResolvedValue({
      kind: 'terminal',
      state: 'approved',
    });
    render(<PairJoinPanel prefilledCode={'CCCC-DDDD'} />);
    await waitFor(() =>
      expect(screen.getByText(/already approved/i)).toBeInTheDocument(),
    );
  });

  it('auto-inserts a hyphen after 4 typed characters', () => {
    render(<PairJoinPanel prefilledCode={null} />);
    const input = screen.getByPlaceholderText('XXXX-XXXX') as HTMLInputElement;
    fireEvent.input(input, { target: { value: 'K7MQ' } });
    expect(input.value).toBe('K7MQ');
    fireEvent.input(input, { target: { value: 'K7MQ3' } });
    expect(input.value).toBe('K7MQ-3');
    fireEvent.input(input, { target: { value: 'K7MQ-3F2A' } });
    expect(input.value).toBe('K7MQ-3F2A');
  });

  it('preserves a typed hyphen at the 4/5 boundary', () => {
    render(<PairJoinPanel prefilledCode={null} />);
    const input = screen.getByPlaceholderText('XXXX-XXXX') as HTMLInputElement;
    fireEvent.input(input, { target: { value: 'K7MQ' } });
    expect(input.value).toBe('K7MQ');
    fireEvent.input(input, { target: { value: 'K7MQ-' } });
    expect(input.value).toBe('K7MQ-');
    fireEvent.input(input, { target: { value: 'K7MQ-3' } });
    expect(input.value).toBe('K7MQ-3');
  });

  it('does not sticky-re-add the hyphen when backspacing through it', () => {
    render(<PairJoinPanel prefilledCode={null} />);
    const input = screen.getByPlaceholderText('XXXX-XXXX') as HTMLInputElement;
    fireEvent.input(input, { target: { value: 'K7MQ-3' } });
    expect(input.value).toBe('K7MQ-3');
    // Browser drops the trailing "3".
    fireEvent.input(input, { target: { value: 'K7MQ-' } });
    expect(input.value).toBe('K7MQ-');
    // Browser drops the hyphen.
    fireEvent.input(input, { target: { value: 'K7MQ' } });
    expect(input.value).toBe('K7MQ');
  });

  it('strips non-alphanumeric characters and uppercases input', () => {
    render(<PairJoinPanel prefilledCode={null} />);
    const input = screen.getByPlaceholderText('XXXX-XXXX') as HTMLInputElement;
    fireEvent.input(input, { target: { value: 'k7mq 3f2a!' } });
    expect(input.value).toBe('K7MQ-3F2A');
  });

  it('extracts code from a pasted full /pair URL', () => {
    render(<PairJoinPanel prefilledCode={null} />);
    const input = screen.getByPlaceholderText('XXXX-XXXX') as HTMLInputElement;
    fireEvent.input(input, {
      target: { value: 'https://secrt.is/pair?code=K7MQ-3F2A' },
    });
    expect(input.value).toBe('K7MQ-3F2A');
  });

  it('accepts a bare 8-character code without a hyphen', async () => {
    mockPairChallenge.mockResolvedValue({
      kind: 'ok',
      displayer_ecdh_public_key: 'pk',
    });
    render(<PairJoinPanel prefilledCode={null} />);
    const input = screen.getByPlaceholderText('XXXX-XXXX') as HTMLInputElement;
    fireEvent.input(input, { target: { value: 'K7MQ3F2A' } });
    expect(input.value).toBe('K7MQ-3F2A');
    fireEvent.click(screen.getByRole('button', { name: /Send Account Key/i }));
    await waitFor(() =>
      expect(mockPairChallenge).toHaveBeenCalledWith('tok', 'K7MQ-3F2A'),
    );
  });

  it('auto-sends on the deep-link / QR-scan path (no interstitial)', async () => {
    mockPairChallenge.mockResolvedValue({
      kind: 'ok',
      displayer_ecdh_public_key: 'pk',
    });
    mockLoadAmk.mockResolvedValue(new Uint8Array(32));
    mockEncryptAmkForPeer.mockResolvedValue({
      amkTransfer: { ct: 'ct', nonce: 'n', ecdh_public_key: 'epk' },
      browserPkBytes: new Uint8Array(65),
    });
    mockPairApprove.mockResolvedValue({ ok: true });
    render(<PairJoinPanel prefilledCode={'K7MQ-3F2A'} />);
    await waitFor(() =>
      expect(mockPairChallenge).toHaveBeenCalledWith('tok', 'K7MQ-3F2A'),
    );
    await waitFor(() =>
      expect(screen.getByText(/Account Key Sent/i)).toBeInTheDocument(),
    );
    expect(mockPairApprove).toHaveBeenCalledOnce();
  });
});
