import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/preact';
import { h } from 'preact';
import { matchRoute, navigate, useRoute } from './router';

function RouteConsumer() {
  const route = useRoute();
  return h(
    'span',
    { 'data-testid': 'route' },
    route.page === 'claim' ? `claim:${route.id}` : route.page,
  );
}

describe('matchRoute', () => {
  it('"/" -> send page', () => {
    expect(matchRoute('/')).toEqual({ page: 'send' });
  });

  it('"" -> send page', () => {
    expect(matchRoute('')).toEqual({ page: 'send' });
  });

  it('"/s/abc123" -> claim page with id', () => {
    expect(matchRoute('/s/abc123')).toEqual({ page: 'claim', id: 'abc123' });
  });

  it('"/s/abc-def_123" -> claim with URL-safe chars', () => {
    expect(matchRoute('/s/abc-def_123')).toEqual({
      page: 'claim',
      id: 'abc-def_123',
    });
  });

  it('"/s/abc123/" -> claim with trailing slash', () => {
    expect(matchRoute('/s/abc123/')).toEqual({ page: 'claim', id: 'abc123' });
  });

  it('"/how-it-works" -> how-it-works page', () => {
    expect(matchRoute('/how-it-works')).toEqual({ page: 'how-it-works' });
  });

  it('"/login" -> login page', () => {
    expect(matchRoute('/login')).toEqual({ page: 'login' });
  });

  it('"/register" -> register page', () => {
    expect(matchRoute('/register')).toEqual({ page: 'register' });
  });

  it('"/dashboard" -> dashboard page', () => {
    expect(matchRoute('/dashboard')).toEqual({ page: 'dashboard' });
  });

  it('"/settings" -> settings page', () => {
    expect(matchRoute('/settings')).toEqual({ page: 'settings' });
  });

  it('"/test/theme" -> not-found (removed)', () => {
    expect(matchRoute('/test/theme')).toEqual({ page: 'not-found' });
  });

  it('"/test/claim" -> not-found (removed)', () => {
    expect(matchRoute('/test/claim')).toEqual({ page: 'not-found' });
  });

  it('"/unknown" -> not-found', () => {
    expect(matchRoute('/unknown')).toEqual({ page: 'not-found' });
  });

  it('"/s/" -> not-found (no ID)', () => {
    expect(matchRoute('/s/')).toEqual({ page: 'not-found' });
  });

  it('"/s/abc/extra" -> not-found (extra segments)', () => {
    expect(matchRoute('/s/abc/extra')).toEqual({ page: 'not-found' });
  });

  it('"/S/abc" -> not-found (case sensitive)', () => {
    expect(matchRoute('/S/abc')).toEqual({ page: 'not-found' });
  });
});

describe('navigate', () => {
  beforeEach(() => {
    vi.spyOn(window.history, 'pushState');
    vi.spyOn(window, 'dispatchEvent');
  });

  it('calls pushState with correct path', () => {
    navigate('/s/abc');
    expect(window.history.pushState).toHaveBeenCalledWith(null, '', '/s/abc');
  });

  it('dispatches PopStateEvent', () => {
    navigate('/');
    expect(window.dispatchEvent).toHaveBeenCalledWith(expect.any(PopStateEvent));
  });
});

describe('useRoute', () => {
  beforeEach(() => {
    window.history.pushState(null, '', '/');
  });

  afterEach(() => {
    cleanup();
  });

  it('tracks route changes from popstate events', async () => {
    render(h(RouteConsumer, {}));
    expect(screen.getByTestId('route')).toHaveTextContent('send');

    window.history.pushState(null, '', '/s/abc123');
    window.dispatchEvent(new PopStateEvent('popstate'));

    await waitFor(() => {
      expect(screen.getByTestId('route')).toHaveTextContent('claim:abc123');
    });
  });
});
