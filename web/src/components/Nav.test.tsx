import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/preact';
import userEvent from '@testing-library/user-event';

// Mock dependencies
vi.mock('./ThemeToggle', () => ({
  ThemeToggle: () => <div data-testid="theme-toggle">ThemeToggle</div>,
}));

const mockNavigate = vi.fn();
const mockUseRoute = vi.fn();
vi.mock('../router', () => ({
  navigate: (...args: unknown[]) => mockNavigate(...args),
  useRoute: () => mockUseRoute(),
}));

const mockAuth = {
  loading: false,
  authenticated: false,
  userId: null,
  handle: null,
  sessionToken: null,
  login: vi.fn(),
  logout: vi.fn().mockResolvedValue(undefined),
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
    mockAuth.userId = null;
    mockAuth.handle = null;
    mockAuth.logout.mockResolvedValue(undefined);
  });

  afterEach(() => {
    cleanup();
    mockNavigate.mockClear();
  });

  it('renders nav links', () => {
    render(<Nav />);
    expect(screen.getAllByText('Create').length).toBeGreaterThan(0);
    expect(screen.getAllByText('How it Works').length).toBeGreaterThan(0);
    expect(screen.getAllByText('GitHub').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Downloads').length).toBeGreaterThan(0);
  });

  it('renders ThemeToggle', () => {
    render(<Nav />);
    expect(screen.getAllByTestId('theme-toggle').length).toBeGreaterThan(0);
  });

  it('shows Log in link when not authenticated', () => {
    render(<Nav />);
    expect(screen.getAllByText('Log in').length).toBeGreaterThan(0);
  });

  it('shows handle and Log out when authenticated', () => {
    mockAuth.authenticated = true;
    mockAuth.handle = 'alice';
    render(<Nav />);
    expect(screen.getAllByText('alice').length).toBeGreaterThan(0);
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
    mockAuth.handle = 'bob';
    render(<Nav />);
    const logoutBtns = screen.getAllByText('Log out');
    await user.click(logoutBtns[0]);
    expect(mockAuth.logout).toHaveBeenCalled();
    expect(mockNavigate).toHaveBeenCalledWith('/');
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
});
