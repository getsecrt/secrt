import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';
import { CopyButton } from './CopyButton';

vi.mock('../lib/clipboard', () => ({
  copyToClipboard: vi.fn(),
}));

import { copyToClipboard } from '../lib/clipboard';
const mockCopy = vi.mocked(copyToClipboard);

describe('CopyButton', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockCopy.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
    cleanup();
  });

  it('renders with default "Copy" label', () => {
    render(<CopyButton text="hello" />);
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
  });

  it('renders with provided label', () => {
    render(<CopyButton text="hello" label="Copy link" />);
    expect(
      screen.getByRole('button', { name: 'Copy link' }),
    ).toBeInTheDocument();
  });

  it('calls copyToClipboard(text) on click', async () => {
    mockCopy.mockResolvedValue(true);
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(<CopyButton text="secret-text" />);
    await user.click(screen.getByRole('button'));
    expect(mockCopy).toHaveBeenCalledWith('secret-text');
  });

  it('shows "Copied!" after success, reverts after 2s', async () => {
    mockCopy.mockResolvedValue(true);
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(<CopyButton text="hello" label="Copy" />);
    await user.click(screen.getByRole('button'));
    expect(screen.getByRole('button').textContent).toContain('Copied!');
    vi.advanceTimersByTime(2100);
    await vi.waitFor(() => {
      expect(screen.getByRole('button').textContent).not.toContain('Copied!');
    });
  });

  it('does not show "Copied!" when copy fails', async () => {
    mockCopy.mockResolvedValue(false);
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(<CopyButton text="hello" />);
    await user.click(screen.getByRole('button'));
    expect(screen.getByRole('button').textContent).toContain('Copy');
  });

  it('renders icon when provided', () => {
    render(
      <CopyButton text="hello" icon={<span data-testid="icon">IC</span>} />,
    );
    expect(screen.getByTestId('icon')).toBeInTheDocument();
  });
});
