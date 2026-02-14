import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';

vi.mock('./Logo', () => ({
  Logo: () => <div data-testid="logo">Logo</div>,
}));
vi.mock('./ThemeToggle', () => ({
  ThemeToggle: () => <div data-testid="theme-toggle">ThemeToggle</div>,
}));

const mockNavigate = vi.fn();
vi.mock('../router', () => ({
  navigate: (...args: unknown[]) => mockNavigate(...args),
}));

import { Layout } from './Layout';

describe('Layout', () => {
  afterEach(() => {
    cleanup();
    mockNavigate.mockClear();
  });

  it('renders children', () => {
    render(
      <Layout>
        <div data-testid="child">Hello</div>
      </Layout>,
    );
    expect(screen.getByTestId('child')).toBeInTheDocument();
  });

  it('renders Logo component', () => {
    render(<Layout>content</Layout>);
    expect(screen.getByTestId('logo')).toBeInTheDocument();
  });

  it('renders ThemeToggle component', () => {
    render(<Layout>content</Layout>);
    expect(screen.getByTestId('theme-toggle')).toBeInTheDocument();
  });

  it('renders tagline', () => {
    render(<Layout>content</Layout>);
    expect(
      screen.getByText('Private, Zero-Knowledge, One-Time Secret Sharing'),
    ).toBeInTheDocument();
  });

  it('navigates to "/" when logo link is clicked', async () => {
    const user = userEvent.setup();
    render(<Layout>content</Layout>);
    const logoLink = screen.getByTestId('logo').closest('a')!;
    await user.click(logoLink);
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('renders GitHub link', () => {
    render(<Layout>content</Layout>);
    const links = screen.getAllByRole('link');
    const ghLink = links.find(
      (l) => l.getAttribute('href') === 'https://github.com/getsecrt/secrt',
    );
    expect(ghLink).toBeTruthy();
  });

  it('renders CLI & App Downloads link', () => {
    render(<Layout>content</Layout>);
    expect(screen.getByText('CLI & App Downloads')).toBeInTheDocument();
  });

  it('renders How it Works footer link', () => {
    render(<Layout>content</Layout>);
    const link = screen.getByText('How it Works');
    expect(link).toHaveAttribute('href', '/how-it-works');
  });

  it('navigates to /how-it-works when footer link is clicked', async () => {
    const user = userEvent.setup();
    render(<Layout>content</Layout>);
    await user.click(screen.getByText('How it Works'));
    expect(mockNavigate).toHaveBeenCalledWith('/how-it-works');
  });

  it('renders footer with correct structure', () => {
    render(<Layout>content</Layout>);
    expect(screen.getByText('GitHub')).toBeInTheDocument();
  });
});
