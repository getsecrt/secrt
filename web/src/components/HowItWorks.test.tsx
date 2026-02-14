import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';
import { HowItWorks } from './HowItWorks';

const mockNavigate = vi.fn();
vi.mock('../router', () => ({
  navigate: (...args: unknown[]) => mockNavigate(...args),
}));

describe('HowItWorks', () => {
  afterEach(() => {
    cleanup();
    mockNavigate.mockClear();
  });

  it('renders collapsed summary', () => {
    render(<HowItWorks />);
    expect(
      screen.getByText('How does secrt keep my data safe?'),
    ).toBeInTheDocument();
  });

  it('expands to show description on click', async () => {
    const user = userEvent.setup();
    render(<HowItWorks />);
    await user.click(screen.getByText('How does secrt keep my data safe?'));
    expect(
      screen.getByText(/encrypted in your browser/),
    ).toBeInTheDocument();
  });

  it('contains link to full technical details page', async () => {
    const user = userEvent.setup();
    render(<HowItWorks />);
    await user.click(screen.getByText('How does secrt keep my data safe?'));
    const link = screen.getByText(/Full technical details/);
    expect(link).toHaveAttribute('href', '/how-it-works');
  });

  it('navigates to /how-it-works on link click', async () => {
    const user = userEvent.setup();
    render(<HowItWorks />);
    await user.click(screen.getByText('How does secrt keep my data safe?'));
    await user.click(screen.getByText(/Full technical details/));
    expect(mockNavigate).toHaveBeenCalledWith('/how-it-works');
  });
});
