import { describe, it, expect } from 'vitest';
import {
  formatShareLink,
  parseShareUrl,
  formatPairUrl,
  parsePairUrl,
} from './url';
import { base64urlEncode, base64urlDecode } from '../crypto/encoding';

/** Generate a 32-byte url_key for testing. */
function makeUrlKey(seed = 0): Uint8Array {
  const key = new Uint8Array(32);
  for (let i = 0; i < 32; i++) key[i] = (seed + i) & 0xff;
  return key;
}

describe('formatShareLink', () => {
  it('uses window.location.origin by default', () => {
    const key = makeUrlKey();
    const link = formatShareLink('abc123', key);
    expect(link).toMatch(
      new RegExp(
        `^${window.location.origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/s/abc123#`,
      ),
    );
  });

  it('uses custom base URL when provided', () => {
    const key = makeUrlKey();
    const link = formatShareLink('abc123', key, 'https://example.com');
    expect(link).toMatch(/^https:\/\/example\.com\/s\/abc123#/);
  });

  it('encodes url_key as base64url in fragment', () => {
    const key = makeUrlKey(1);
    const link = formatShareLink('test-id', key);
    const fragment = link.split('#')[1];
    expect(fragment).toBe(base64urlEncode(key));
    expect(base64urlDecode(fragment)).toEqual(key);
  });
});

describe('parseShareUrl', () => {
  it('parses a valid URL', () => {
    const key = makeUrlKey(42);
    const link = formatShareLink('abcdef0123456789', key);
    const result = parseShareUrl(link);
    expect(result).not.toBeNull();
    expect(result!.id).toBe('abcdef0123456789');
    expect(result!.urlKey).toEqual(key);
    expect(result!.host).toBe(window.location.hostname);
  });

  it('round-trips formatShareLink -> parseShareUrl', () => {
    const key = makeUrlKey(99);
    const id = 'rnd_abc-DEF_12345';
    const link = formatShareLink(id, key);
    const result = parseShareUrl(link);
    expect(result).not.toBeNull();
    expect(result!.id).toBe(id);
    expect(result!.urlKey).toEqual(key);
    expect(result!.host).toBe(window.location.hostname);
  });

  it('preserves subdomain in host (wildcard sibling instance)', () => {
    const key = makeUrlKey(11);
    const fragment = base64urlEncode(key);
    const result = parseShareUrl(
      `https://team.secrt.is/s/abcdef0123456789#${fragment}`,
    );
    expect(result).not.toBeNull();
    expect(result!.host).toBe('team.secrt.is');
  });

  it('lowercases host', () => {
    const key = makeUrlKey(12);
    const fragment = base64urlEncode(key);
    const result = parseShareUrl(
      `https://SECRT.CA/s/abcdef0123456789#${fragment}`,
    );
    expect(result).not.toBeNull();
    expect(result!.host).toBe('secrt.ca');
  });

  it('strips port from host', () => {
    const key = makeUrlKey(13);
    const fragment = base64urlEncode(key);
    const result = parseShareUrl(
      `https://secrt.ca:8443/s/abcdef0123456789#${fragment}`,
    );
    expect(result).not.toBeNull();
    expect(result!.host).toBe('secrt.ca');
  });

  it('rejects non-HTTPS URLs (production scheme guard)', () => {
    const key = makeUrlKey(14);
    const fragment = base64urlEncode(key);
    // http://secrt.is/... — explicit non-https scheme that's not localhost.
    // Dev mode permits localhost; this case uses a non-localhost hostname,
    // which must always be rejected.
    expect(
      parseShareUrl(`http://secrt.is/s/abcdef0123456789#${fragment}`),
    ).toBeNull();
  });

  it('coerces bare-host paste to https', () => {
    const key = makeUrlKey(15);
    const fragment = base64urlEncode(key);
    const result = parseShareUrl(`secrt.is/s/abcdef0123456789#${fragment}`);
    expect(result).not.toBeNull();
    expect(result!.host).toBe('secrt.is');
  });

  it('returns null for missing fragment', () => {
    expect(parseShareUrl('https://secrt.ca/s/abc123')).toBeNull();
  });

  it('returns null for empty fragment', () => {
    expect(parseShareUrl('https://secrt.ca/s/abc123#')).toBeNull();
  });

  it('returns null for missing /s/ prefix', () => {
    const key = makeUrlKey();
    const fragment = base64urlEncode(key);
    expect(parseShareUrl(`https://secrt.ca/x/abc123#${fragment}`)).toBeNull();
  });

  it('returns null for wrong key length (!= 32 bytes)', () => {
    // Use a 16-byte key (too short)
    const shortKey = new Uint8Array(16).fill(0xaa);
    const fragment = base64urlEncode(shortKey);
    expect(parseShareUrl(`https://secrt.ca/s/abc123#${fragment}`)).toBeNull();
  });

  it('returns null for invalid URL string', () => {
    expect(parseShareUrl('not a url at all')).toBeNull();
  });

  it('handles trailing slash on path', () => {
    const key = makeUrlKey(10);
    const fragment = base64urlEncode(key);
    const result = parseShareUrl(
      `https://secrt.ca/s/abcdef0123456789/#${fragment}`,
    );
    expect(result).not.toBeNull();
    expect(result!.id).toBe('abcdef0123456789');
  });

  it('returns null for extra path segments', () => {
    const key = makeUrlKey();
    const fragment = base64urlEncode(key);
    expect(
      parseShareUrl(`https://secrt.ca/s/abc/extra#${fragment}`),
    ).toBeNull();
  });

  it('returns null for empty ID (/s/)', () => {
    const key = makeUrlKey();
    const fragment = base64urlEncode(key);
    expect(parseShareUrl(`https://secrt.ca/s/#${fragment}`)).toBeNull();
  });

  it('handles URL-safe ID characters (alphanumeric, -, _)', () => {
    const key = makeUrlKey(5);
    const fragment = base64urlEncode(key);
    const result = parseShareUrl(
      `https://secrt.ca/s/aB3-z_9012345678#${fragment}`,
    );
    expect(result).not.toBeNull();
    expect(result!.id).toBe('aB3-z_9012345678');
  });

  it('handles URL with query params', () => {
    const key = makeUrlKey(7);
    const fragment = base64urlEncode(key);
    const result = parseShareUrl(
      `https://secrt.ca/s/abcdef0123456789?foo=bar#${fragment}`,
    );
    expect(result).not.toBeNull();
    expect(result!.id).toBe('abcdef0123456789');
  });

  it('cross-checks spec vector url_key round-trip', () => {
    // From spec vector 1
    const urlKeyB64 = 'AQIDBAUGBwgJEBESExQVFhcYGSAhIiMkJSYnKCkwMTI';
    const urlKey = base64urlDecode(urlKeyB64);
    const link = formatShareLink('spec-test-vector1', urlKey);
    const result = parseShareUrl(link);
    expect(result).not.toBeNull();
    expect(result!.urlKey).toEqual(urlKey);
    expect(base64urlEncode(result!.urlKey)).toBe(urlKeyB64);
  });
});

describe('formatPairUrl', () => {
  it('encodes a code into a /pair?code= URL on the current origin', () => {
    expect(formatPairUrl('K7MQ-3F2A')).toBe(
      `${window.location.origin}/pair?code=K7MQ-3F2A`,
    );
  });

  it('respects an explicit base URL', () => {
    expect(formatPairUrl('AAAA-BBBB', 'https://example.com')).toBe(
      'https://example.com/pair?code=AAAA-BBBB',
    );
  });
});

describe('parsePairUrl', () => {
  it('accepts a bare XXXX-XXXX code', () => {
    expect(parsePairUrl('K7MQ-3F2A')).toEqual({ code: 'K7MQ-3F2A' });
  });

  it('uppercases lower-case typed input', () => {
    expect(parsePairUrl('k7mq-3f2a')).toEqual({ code: 'K7MQ-3F2A' });
  });

  it('strips whitespace', () => {
    expect(parsePairUrl('  K7MQ-3F2A  ')).toEqual({ code: 'K7MQ-3F2A' });
  });

  it('parses a fully qualified /pair URL', () => {
    expect(parsePairUrl('https://secrt.ca/pair?code=K7MQ-3F2A')).toEqual({
      code: 'K7MQ-3F2A',
    });
  });

  it('parses a bare-host pasted /pair URL (coerces to https)', () => {
    expect(parsePairUrl('secrt.ca/pair?code=AAAA-BBBB')).toEqual({
      code: 'AAAA-BBBB',
    });
  });

  it('round-trips formatPairUrl', () => {
    const url = formatPairUrl('Z9X8-Y7W6', 'https://secrt.is');
    expect(parsePairUrl(url)).toEqual({ code: 'Z9X8-Y7W6' });
  });

  it('rejects an invalid code shape', () => {
    expect(parsePairUrl('K7MQ3F2A')).toBeNull();
    expect(parsePairUrl('K7MQ-3F2')).toBeNull();
    expect(parsePairUrl('K7MQ-3F2AA')).toBeNull();
    expect(parsePairUrl('')).toBeNull();
  });

  it('rejects a URL whose path is not /pair', () => {
    expect(parsePairUrl('https://secrt.ca/login?code=K7MQ-3F2A')).toBeNull();
  });

  it('rejects a /pair URL without a code param', () => {
    expect(parsePairUrl('https://secrt.ca/pair')).toBeNull();
  });

  it('rejects a /pair URL with a malformed code', () => {
    expect(parsePairUrl('https://secrt.ca/pair?code=NOPE')).toBeNull();
  });
});
