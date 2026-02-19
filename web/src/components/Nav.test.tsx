import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';
import type { AuthState } from '../lib/auth-context';

// Mock dependencies
vi.mock('./ThemeToggle', () => ({
  ThemeToggle: () => <div data-testid="theme-toggle">ThemeToggle</div>,
}));

const mockNavigate = vi.fn();
const mockUseRoute = vi.fn();
const mockLogin = vi.fn<(token: string, displayName: string) => void>();
const mockLogout = vi.fn<() => Promise<void>>().mockResolvedValue(undefined);
vi.mock('../router', () => ({
  navigate: (...args: unknown[]) => mockNavigate(...args),
  useRoute: () => mockUseRoute(),
}));

const mockAuth: AuthState = {
  loading: false,
  authenticated: false,
  userId: null,
  displayName: null,
  sessionToken: null,
  login: mockLogin,
  logout: mockLogout,
};
vi.mock('../lib/auth-context', () => ({
  useAuth: () => mockAuth,
}));

import { Nav } from './Nav';

describe('Nav', () => {
  beforeEach(() => {
    mockUseRoute.mockReturnValue({ page: 'send' });
    mockAuth.loading = false;
    mockAuth.authenticated = false;
    mockAuth.displayName = null;
    mockLogout.mockResolvedValue(undefined);
  });

  afterEach(() => {
    cleanup();
    mockNavigate.mockClear();
  });

  it('renders nav links', () => {
    render(<Nav />);
    expect(screen.getAllByText('Create').length).toBeGreaterThan(0);
    expect(screen.getAllByText('More Information').length).toBeGreaterThan(0);
    expect(screen.getAllByText(/CLI Downloads/).length).toBeGreaterThan(0);
  });

  it('renders ThemeToggle', () => {
    render(<Nav />);
    expect(screen.getAllByTestId('theme-toggle').length).toBeGreaterThan(0);
  });

  it('shows Log In link when not authenticated', () => {
    render(<Nav />);
    expect(screen.getAllByText('Log In').length).toBeGreaterThan(0);
  });

  it('shows displayName and Log out when authenticated', async () => {
    const user = userEvent.setup();
    mockAuth.authenticated = true;
    mockAuth.displayName = 'alice';
    render(<Nav />);
    expect(screen.getAllByText('alice').length).toBeGreaterThan(0);
    await user.click(screen.getByRole('button', { name: 'alice' }));
    expect(screen.getAllByText('Log out').length).toBeGreaterThan(0);
  });

  it('hides auth section while loading', () => {
    mockAuth.loading = true;
    render(<Nav />);
    expect(screen.queryByText('Log in')).toBeNull();
    expect(screen.queryByText('Log out')).toBeNull();
  });

  it('calls logout and navigates to "/" on Log out click', async () => {
    const user = userEvent.setup();
    mockAuth.authenticated = true;
    mockAuth.displayName = 'bob';
    render(<Nav />);
    await user.click(screen.getByRole('button', { name: 'bob' }));
    const logoutBtns = screen.getAllByText('Log out');
    await user.click(logoutBtns[0]);
    expect(mockLogout).toHaveBeenCalled();
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('navigates to dashboard from the user menu', async () => {
    const user = userEvent.setup();
    mockAuth.authenticated = true;
    mockAuth.displayName = 'alice';
    render(<Nav />);
    await user.click(screen.getByRole('button', { name: 'alice' }));
    await user.click(screen.getByText('Dashboard'));
    expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
  });

  it('navigates to settings from the user menu', async () => {
    const user = userEvent.setup();
    mockAuth.authenticated = true;
    mockAuth.displayName = 'alice';
    render(<Nav />);
    await user.click(screen.getByRole('button', { name: 'alice' }));
    await user.click(screen.getByText('Settings'));
    expect(mockNavigate).toHaveBeenCalledWith('/settings');
  });

  it('closes user popover when it is hidden', async () => {
    const user = userEvent.setup();
    mockAuth.authenticated = true;
    mockAuth.displayName = 'alice';
    render(<Nav />);
    await user.click(screen.getByRole('button', { name: 'alice' }));
    const menu = document.getElementById('user-menu') as HTMLDivElement;
    expect(menu).toBeTruthy();
    menu.hidePopover();
    await waitFor(() => {
      expect(document.getElementById('user-menu')).toBeNull();
    });
  });

  it('navigates when Create link is clicked', async () => {
    const user = userEvent.setup();
    mockUseRoute.mockReturnValue({ page: 'how-it-works' });
    render(<Nav />);
    const createLinks = screen.getAllByText('Create');
    await user.click(createLinks[0]);
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('toggles hamburger menu', async () => {
    const user = userEvent.setup();
    render(<Nav />);
    const hamburger = screen.getByLabelText('Open menu');
    await user.click(hamburger);
    expect(screen.getByLabelText('Close menu')).toBeInTheDocument();
  });

  it('closes mobile menu when backdrop is clicked', async () => {
    const user = userEvent.setup();
    const { container } = render(<Nav />);
    await user.click(screen.getByLabelText('Open menu'));
    const backdrop = container.querySelector(
      'div.fixed.inset-0',
    ) as HTMLElement;
    expect(backdrop).toBeTruthy();
    await user.click(backdrop);
    expect(screen.getByLabelText('Open menu')).toBeInTheDocument();
  });
});
