import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';
import { HowItWorksPage } from './HowItWorksPage';

const mockNavigate = vi.fn();
vi.mock('../../router', () => ({
  navigate: (...args: unknown[]) => mockNavigate(...args),
}));

describe('HowItWorksPage', () => {
  afterEach(() => {
    cleanup();
    mockNavigate.mockClear();
  });

  it('renders the page title', () => {
    render(<HowItWorksPage />);
    expect(screen.getByText('How secrt Works')).toBeInTheDocument();
  });

  it('renders all section headings', () => {
    render(<HowItWorksPage />);
    expect(screen.getByText('Overview')).toBeInTheDocument();
    expect(screen.getByText('Encryption')).toBeInTheDocument();
    expect(screen.getByText('Passphrase Protection')).toBeInTheDocument();
    expect(screen.getByText('One-Time Retrieval')).toBeInTheDocument();
    expect(screen.getByText('What the Server Sees')).toBeInTheDocument();
    expect(screen.getByText('Open Source')).toBeInTheDocument();
  });

  it('mentions key crypto primitives', () => {
    render(<HowItWorksPage />);
    expect(screen.getByText(/AES-256-GCM/)).toBeInTheDocument();
    expect(screen.getByText(/HKDF-SHA-256/)).toBeInTheDocument();
    expect(screen.getByText(/PBKDF2-SHA-256/)).toBeInTheDocument();
  });

  it('renders CTA button that navigates home', async () => {
    const user = userEvent.setup();
    render(<HowItWorksPage />);
    const cta = screen.getByRole('link', { name: /Create a Secret/i });
    expect(cta).toHaveAttribute('href', '/');
    await user.click(cta);
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('renders GitHub link', () => {
    render(<HowItWorksPage />);
    const ghLink = screen.getByText(/View source on GitHub/);
    expect(ghLink).toHaveAttribute(
      'href',
      'https://github.com/getsecrt/secrt',
    );
  });
});
