import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';

const mockNavigate = vi.fn();
vi.mock('../../router', () => ({
  navigate: (...args: unknown[]) => mockNavigate(...args),
}));

import { PrivacyPage } from './PrivacyPage';

describe('PrivacyPage', () => {
  afterEach(() => {
    cleanup();
    mockNavigate.mockClear();
  });

  it('renders privacy policy heading', () => {
    render(<PrivacyPage />);
    expect(screen.getByText('Privacy Policy')).toBeInTheDocument();
  });

  it('renders all major sections', () => {
    render(<PrivacyPage />);
    expect(
      screen.getByText('Zero-knowledge architecture'),
    ).toBeInTheDocument();
    expect(screen.getByText('What we store')).toBeInTheDocument();
    expect(screen.getByText("What we don't store")).toBeInTheDocument();
    expect(screen.getByText('IP address privacy')).toBeInTheDocument();
    expect(screen.getByText('No tracking')).toBeInTheDocument();
    expect(screen.getByText('Infrastructure')).toBeInTheDocument();
    expect(screen.getByText('Open source')).toBeInTheDocument();
    expect(screen.getByText('Contact')).toBeInTheDocument();
  });

  it('contains contact email link', () => {
    render(<PrivacyPage />);
    const emailLink = screen.getByText('security@secrt.ca');
    expect(emailLink).toHaveAttribute('href', 'mailto:security@secrt.ca');
  });

  it('navigates home via back link', async () => {
    const user = userEvent.setup();
    render(<PrivacyPage />);
    const backLink = screen.getByText((_, element) => {
      return element?.tagName === 'A' && element?.getAttribute('href') === '/';
    });
    await user.click(backLink);
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('navigates to how-it-works via inline link', async () => {
    const user = userEvent.setup();
    render(<PrivacyPage />);
    const link = screen.getByText((_, element) => {
      return (
        element?.tagName === 'A' &&
        element?.getAttribute('href') === '/how-it-works'
      );
    });
    await user.click(link);
    expect(mockNavigate).toHaveBeenCalledWith('/how-it-works');
  });
});
