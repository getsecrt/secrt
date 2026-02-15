import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';

vi.mock('./Nav', () => ({
  Nav: () => <div data-testid="nav">Nav</div>,
}));
vi.mock('./Logo', () => ({
  Logo: () => <div data-testid="logo">Logo</div>,
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

  it('renders Nav component', () => {
    render(<Layout>content</Layout>);
    expect(screen.getByTestId('nav')).toBeInTheDocument();
  });

  it('renders Logo component', () => {
    render(<Layout>content</Layout>);
    expect(screen.getByTestId('logo')).toBeInTheDocument();
  });

  it('navigates to "/" when logo is clicked', async () => {
    const user = userEvent.setup();
    render(<Layout>content</Layout>);
    const logoLink = screen.getByTestId('logo').closest('a')!;
    await user.click(logoLink);
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('renders copyright footer', () => {
    render(<Layout>content</Layout>);
    const year = new Date().getFullYear().toString();
    expect(screen.getByText(new RegExp(`${year}\\s+JD Lien`))).toBeInTheDocument();
  });

  it('wraps children in main element', () => {
    render(
      <Layout>
        <div data-testid="child">Hello</div>
      </Layout>,
    );
    const child = screen.getByTestId('child');
    expect(child.closest('main')).toBeTruthy();
  });
});
