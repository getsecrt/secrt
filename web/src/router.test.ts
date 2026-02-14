import { describe, it, expect } from 'vitest';
import { matchRoute } from './router';

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
