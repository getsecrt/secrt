import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  normalizeHost,
  isKnownInstance,
  classifyOrigin,
  normalizeOrigin,
  getInfrastructure,
  KNOWN_INSTANCES,
} from './config';
import spec from '../../../spec/v1/instances.json';

describe('normalizeHost', () => {
  it.each([
    ['secrt.ca', 'secrt.ca'],
    ['secrt.is', 'secrt.is'],
    ['www.secrt.ca', 'secrt.ca'],
    ['my.secrt.is', 'secrt.is'],
    ['foo.bar.secrt.is', 'secrt.is'],
    ['SECRT.CA', 'secrt.ca'],
    ['Secrt.Is', 'secrt.is'],
    ['secrt.ca.', 'secrt.ca'],
    ['evil.tld', 'evil.tld'],
    ['localhost', 'localhost'],
    ['', ''],
  ])('normalizes %s -> %s', (input, expected) => {
    expect(normalizeHost(input)).toBe(expected);
  });

  it('does not collapse lookalike hosts (label-boundary suffix match)', () => {
    expect(normalizeHost('foosecrt.is')).toBe('foosecrt.is');
    expect(normalizeHost('secrt.is.evil.tld')).toBe('secrt.is.evil.tld');
    expect(normalizeHost('notsecrt.ca')).toBe('notsecrt.ca');
  });
});

describe('isKnownInstance', () => {
  it.each([
    'secrt.ca',
    'secrt.is',
    'www.secrt.ca',
    'my.secrt.is',
    'team.secrt.is',
  ])('%s is a known instance', (host) => {
    expect(isKnownInstance(host)).toBe(true);
  });

  it.each([
    'secrt.evil.tld',
    'localhost',
    '',
    'foosecrt.is',
    'secrt.is.evil.tld',
    'notsecrt.ca',
  ])('%s is NOT a known instance', (host) => {
    expect(isKnownInstance(host)).toBe(false);
  });
});

describe('spec drift', () => {
  it('KNOWN_INSTANCES matches the spec apex list', () => {
    const specApexes = spec.official_instances.map((e) => e.apex);
    expect([...KNOWN_INSTANCES]).toEqual(specApexes);
  });
});

describe('classifyOrigin', () => {
  it('classifies each official origin as Official with the right apex', () => {
    for (const entry of spec.official_instances) {
      const verdict = classifyOrigin(entry.origin);
      expect(verdict.kind).toBe('official');
      if (verdict.kind === 'official') {
        expect(verdict.apex).toBe(entry.apex);
      }
    }
  });

  it.each([
    'https://my.secrt.ca',
    'https://team.secrt.is',
    'https://foo.bar.secrt.ca/',
  ])('wildcard subdomain %s collapses to Official', (url) => {
    expect(classifyOrigin(url).kind).toBe('official');
  });

  it.each([
    'https://evil.tld',
    'https://foosecrt.is',
    'https://secrt.is.evil.tld',
    'https://notsecrt.ca',
    'https://secrt.evil.tld',
  ])('untrusted host %s classifies as untrusted', (url) => {
    expect(classifyOrigin(url).kind).toBe('untrusted');
  });

  it.each([
    'http://localhost',
    'http://localhost:8080',
    'https://localhost',
    'http://127.0.0.1:8080',
    'http://127.0.0.5',
    'http://[::1]:8080',
    'https://[::1]',
    'http://my-machine.local',
    'http://foo.local:3000',
  ])('dev-local host %s classifies as devLocal', (url) => {
    expect(classifyOrigin(url).kind).toBe('devLocal');
  });

  it('non-default port on official apex is NOT Official', () => {
    expect(classifyOrigin('https://secrt.ca:8443').kind).toBe('untrusted');
  });

  it('http on official apex is NOT Official', () => {
    expect(classifyOrigin('http://secrt.ca').kind).toBe('untrusted');
  });

  it('trusted_custom silences unknown host (case-insensitive)', () => {
    expect(classifyOrigin('https://evil.tld', ['evil.tld']).kind).toBe('trustedCustom');
    expect(classifyOrigin('https://EVIL.TLD', ['evil.tld']).kind).toBe('trustedCustom');
  });

  it.each(['', 'not a url', 'ftp://secrt.ca'])(
    'unparseable / non-http URL %s is untrusted',
    (url) => {
      expect(classifyOrigin(url).kind).toBe('untrusted');
    },
  );
});

describe('normalizeOrigin', () => {
  it.each([
    ['https://secrt.ca/some/path?x=1', 'https://secrt.ca'],
    ['https://secrt.ca:8443/path', 'https://secrt.ca:8443'],
    ['HTTPS://Secrt.Ca/Foo', 'https://secrt.ca'],
    ['http://[::1]:8080/x', 'http://[::1]:8080'],
  ])('%s -> %s', (input, expected) => {
    expect(normalizeOrigin(input)).toBe(expected);
  });

  it.each(['', 'not a url'])('returns null for unparseable %s', (input) => {
    expect(normalizeOrigin(input)).toBeNull();
  });
});

describe('getInfrastructure', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it.each(spec.official_instances.map((e) => [e.apex, e.hosting] as const))(
    'returns spec hosting block for %s',
    (apex, hosting) => {
      vi.stubGlobal('window', {
        location: { hostname: apex },
        // Tauri marker absent so isTauri() returns false.
      });
      expect(getInfrastructure()).toEqual({
        provider: hosting.provider,
        country: hosting.country,
      });
    },
  );
});
