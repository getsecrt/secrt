import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';
import { ShareResult } from './ShareResult';

vi.mock('../../lib/clipboard', () => ({
  copyToClipboard: vi.fn().mockResolvedValue(true),
}));

describe('ShareResult', () => {
  const props = {
    shareUrl: 'https://secrt.ca/s/abc123#key',
    expiresAt: '2026-03-01T12:00:00Z',
    onReset: vi.fn(),
  };

  afterEach(() => {
    cleanup();
    props.onReset.mockClear();
  });

  it('shows share URL in textbox', () => {
    render(<ShareResult {...props} />);
    const textbox = screen.getByRole('textbox', { name: 'Share URL' });
    expect(textbox.textContent).toBe(props.shareUrl);
  });

  it('shows "Secret Created" heading', () => {
    render(<ShareResult {...props} />);
    expect(
      screen.getByRole('heading', { name: 'Secret Created' }),
    ).toBeInTheDocument();
  });

  it('shows expiry text', () => {
    render(<ShareResult {...props} />);
    expect(
      screen.getByText(/This link works exactly once/),
    ).toBeInTheDocument();
  });

  it('shows "Copy Link" button', () => {
    render(<ShareResult {...props} />);
    expect(
      screen.getByRole('button', { name: 'Copy Link' }),
    ).toBeInTheDocument();
  });

  it('calls onReset when "Send Another Secret" is clicked', async () => {
    const user = userEvent.setup();
    render(<ShareResult {...props} />);
    await user.click(screen.getByRole('button', { name: 'Send Another Secret' }));
    expect(props.onReset).toHaveBeenCalledOnce();
  });
});
