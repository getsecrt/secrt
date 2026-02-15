import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/preact';

// Mock child page components
vi.mock('./features/send/SendPage', () => ({
  SendPage: () => <div data-testid="send-page">SendPage</div>,
}));
vi.mock('./features/auth/LoginPage', () => ({
  LoginPage: () => <div data-testid="login-page">LoginPage</div>,
}));
vi.mock('./features/auth/RegisterPage', () => ({
  RegisterPage: () => <div data-testid="register-page">RegisterPage</div>,
}));
vi.mock('./features/dashboard/DashboardPage', () => ({
  DashboardPage: () => <div data-testid="dashboard-page">DashboardPage</div>,
}));
vi.mock('./features/settings/SettingsPage', () => ({
  SettingsPage: () => <div data-testid="settings-page">SettingsPage</div>,
}));
vi.mock('./features/test/ThemePage', () => ({
  ThemePage: () => <div data-testid="theme-page">ThemePage</div>,
}));
vi.mock('./features/test/TestClaimPage', () => ({
  TestClaimPage: () => <div data-testid="test-claim-page">TestClaimPage</div>,
}));
vi.mock('./components/Layout', () => ({
  Layout: ({ children }: { children: preact.ComponentChildren }) => (
    <div data-testid="layout">{children}</div>
  ),
}));
vi.mock('./lib/auth-context', () => ({
  AuthProvider: ({ children }: { children: preact.ComponentChildren }) => (
    <div data-testid="auth-provider">{children}</div>
  ),
}));

// Mock useRoute — must be after vi.mock calls
const mockUseRoute = vi.fn();
vi.mock('./router', () => ({
  useRoute: () => mockUseRoute(),
}));

import { App } from './app';

describe('App', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('renders ThemePage in DEV mode for "theme" route', () => {
    mockUseRoute.mockReturnValue({ page: 'theme' });
    render(<App />);
    // In test env, import.meta.env.DEV is true
    expect(screen.getByTestId('theme-page')).toBeInTheDocument();
  });

  it('renders LoginPage for "login" route', () => {
    mockUseRoute.mockReturnValue({ page: 'login' });
    render(<App />);
    expect(screen.getByTestId('login-page')).toBeInTheDocument();
  });

  it('renders RegisterPage for "register" route', () => {
    mockUseRoute.mockReturnValue({ page: 'register' });
    render(<App />);
    expect(screen.getByTestId('register-page')).toBeInTheDocument();
  });

  it('renders DashboardPage for "dashboard" route', () => {
    mockUseRoute.mockReturnValue({ page: 'dashboard' });
    render(<App />);
    expect(screen.getByTestId('dashboard-page')).toBeInTheDocument();
  });

  it('renders SettingsPage for "settings" route', () => {
    mockUseRoute.mockReturnValue({ page: 'settings' });
    render(<App />);
    expect(screen.getByTestId('settings-page')).toBeInTheDocument();
  });

  it('renders TestClaimPage in DEV mode for "test-claim" route', () => {
    mockUseRoute.mockReturnValue({ page: 'test-claim' });
    render(<App />);
    expect(screen.getByTestId('test-claim-page')).toBeInTheDocument();
  });

  it('wraps content in AuthProvider and Layout', () => {
    mockUseRoute.mockReturnValue({ page: 'send' });
    render(<App />);
    const authProvider = screen.getByTestId('auth-provider');
    const layout = screen.getByTestId('layout');
    expect(authProvider).toContainElement(layout);
    expect(layout).toContainElement(screen.getByTestId('send-page'));
  });
});
