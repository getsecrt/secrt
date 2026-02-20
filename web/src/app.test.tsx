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
vi.mock('./features/auth/DevicePage', () => ({
  DevicePage: () => <div data-testid="device-page">DevicePage</div>,
}));
vi.mock('./features/trust/PrivacyPage', () => ({
  PrivacyPage: () => <div data-testid="privacy-page">PrivacyPage</div>,
}));
vi.mock('./features/trust/HowItWorksPage', () => ({
  HowItWorksPage: () => (
    <div data-testid="how-it-works-page">HowItWorksPage</div>
  ),
}));
vi.mock('./features/claim/ClaimPage', () => ({
  ClaimPage: () => <div data-testid="claim-page">ClaimPage</div>,
}));
vi.mock('./features/sync/SyncPage', () => ({
  SyncPage: () => <div data-testid="sync-page">SyncPage</div>,
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

  it('renders DevicePage for "device" route', () => {
    mockUseRoute.mockReturnValue({ page: 'device' });
    render(<App />);
    expect(screen.getByTestId('device-page')).toBeInTheDocument();
  });

  it('renders PrivacyPage for "privacy" route', () => {
    mockUseRoute.mockReturnValue({ page: 'privacy' });
    render(<App />);
    expect(screen.getByTestId('privacy-page')).toBeInTheDocument();
  });

  it('renders not-found page for unknown routes', () => {
    mockUseRoute.mockReturnValue({ page: 'not-found' });
    render(<App />);
    expect(screen.getByText('Not found')).toBeInTheDocument();
  });

  it('wraps content in AuthProvider and Layout', () => {
    mockUseRoute.mockReturnValue({ page: 'send' });
    render(<App />);
    const authProvider = screen.getByTestId('auth-provider');
    const layout = screen.getByTestId('layout');
    expect(authProvider).toContainElement(layout);
    expect(layout).toContainElement(screen.getByTestId('send-page'));
  });

  describe('document title', () => {
    const cases: [string, string][] = [
      ['send', 'secrt'],
      ['claim', 'Claim Secret — secrt'],
      ['sync', 'Sync Key — secrt'],
      ['how-it-works', 'How It Works — secrt'],
      ['privacy', 'Privacy — secrt'],
      ['login', 'Log In — secrt'],
      ['register', 'Register — secrt'],
      ['dashboard', 'Dashboard — secrt'],
      ['settings', 'Settings — secrt'],
      ['device', 'Approve Device — secrt'],
      ['not-found', 'Not Found — secrt'],
    ];

    it.each(cases)('sets title for "%s" route to "%s"', (page, expected) => {
      mockUseRoute.mockReturnValue({ page, id: 'test-id' });
      render(<App />);
      expect(document.title).toBe(expected);
    });
  });
});
