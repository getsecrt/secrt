import { describe, it, expect, afterEach } from 'vitest';
import { getRedirectParam } from './redirect';

function setSearch(search: string) {
  Object.defineProperty(window, 'location', {
    value: { ...window.location, search },
    writable: true,
    configurable: true,
  });
}

describe('getRedirectParam', () => {
  afterEach(() => {
    setSearch('');
  });

  it('returns / when no redirect param', () => {
    setSearch('');
    expect(getRedirectParam()).toBe('/');
  });

  it('returns the redirect path', () => {
    setSearch('?redirect=%2Fdevice%3Fcode%3DAB-CD');
    expect(getRedirectParam()).toBe('/device?code=AB-CD');
  });

  it('returns / for protocol-relative URLs', () => {
    setSearch('?redirect=%2F%2Fevil.com');
    expect(getRedirectParam()).toBe('/');
  });

  it('returns / for absolute URLs', () => {
    setSearch('?redirect=https%3A%2F%2Fevil.com');
    expect(getRedirectParam()).toBe('/');
  });

  it('returns / for non-path values', () => {
    setSearch('?redirect=javascript%3Aalert(1)');
    expect(getRedirectParam()).toBe('/');
  });

  it('preserves query params in redirect path', () => {
    setSearch('?redirect=%2Fdashboard%3Ftab%3Dsecrets');
    expect(getRedirectParam()).toBe('/dashboard?tab=secrets');
  });
});
