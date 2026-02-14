import { describe, it, expect, vi, beforeEach } from 'vitest';
import { matchRoute, navigate } from './router';

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

  it('"/test/theme" -> theme page', () => {
    expect(matchRoute('/test/theme')).toEqual({ page: 'theme' });
  });

  it('"/test/claim" -> test-claim page', () => {
    expect(matchRoute('/test/claim')).toEqual({ page: 'test-claim' });
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
