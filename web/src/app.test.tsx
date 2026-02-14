import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/preact';

// Mock child page components
vi.mock('./features/send/SendPage', () => ({
  SendPage: () => <div data-testid="send-page">SendPage</div>,
}));
vi.mock('./features/claim/ClaimPage', () => ({
  ClaimPage: ({ id }: { id: string }) => (
    <div data-testid="claim-page">ClaimPage:{id}</div>
  ),
}));
vi.mock('./features/auth/LoginPage', () => ({
  LoginPage: () => <div data-testid="login-page">LoginPage</div>,
}));
vi.mock('./features/auth/RegisterPage', () => ({
  RegisterPage: () => <div data-testid="register-page">RegisterPage</div>,
}));
vi.mock('./features/test/ThemePage', () => ({
  ThemePage: () => <div data-testid="theme-page">ThemePage</div>,
}));
vi.mock('./features/test/TestClaimPage', () => ({
  TestClaimPage: () => <div data-testid="test-claim-page">TestClaimPage</div>,
}));
vi.mock('./features/trust/HowItWorksPage', () => ({
  HowItWorksPage: () => (
    <div data-testid="how-it-works-page">HowItWorksPage</div>
  ),
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

  it('renders SendPage for "send" route', () => {
    mockUseRoute.mockReturnValue({ page: 'send' });
    render(<App />);
    expect(screen.getByTestId('layout')).toBeInTheDocument();
    expect(screen.getByTestId('send-page')).toBeInTheDocument();
  });

  it('renders ClaimPage for "claim" route with id', () => {
    mockUseRoute.mockReturnValue({ page: 'claim', id: 'abc123' });
    render(<App />);
    expect(screen.getByText('ClaimPage:abc123')).toBeInTheDocument();
  });

  it('renders not-found card for "not-found" route', () => {
    mockUseRoute.mockReturnValue({ page: 'not-found' });
    render(<App />);
    expect(screen.getByText('Not found')).toBeInTheDocument();
    expect(screen.getByText("This page doesn't exist.")).toBeInTheDocument();
  });

  it('renders ThemePage in DEV mode for "theme" route', () => {
    mockUseRoute.mockReturnValue({ page: 'theme' });
    render(<App />);
    // In test env, import.meta.env.DEV is true
    expect(screen.getByTestId('theme-page')).toBeInTheDocument();
  });

  it('renders HowItWorksPage for "how-it-works" route', () => {
    mockUseRoute.mockReturnValue({ page: 'how-it-works' });
    render(<App />);
    expect(screen.getByTestId('how-it-works-page')).toBeInTheDocument();
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
