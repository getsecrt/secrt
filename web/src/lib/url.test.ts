import { describe, it, expect } from 'vitest';
import { formatShareLink, parseShareUrl } from './url';
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
      new RegExp(`^${window.location.origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/s/abc123#`),
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
    const link = formatShareLink('my-secret-id', key);
    const result = parseShareUrl(link);
    expect(result).not.toBeNull();
    expect(result!.id).toBe('my-secret-id');
    expect(result!.urlKey).toEqual(key);
  });

  it('round-trips formatShareLink -> parseShareUrl', () => {
    const key = makeUrlKey(99);
    const id = 'rnd_abc-DEF_123';
    const link = formatShareLink(id, key);
    const result = parseShareUrl(link);
    expect(result).not.toBeNull();
    expect(result!.id).toBe(id);
    expect(result!.urlKey).toEqual(key);
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
    const result = parseShareUrl(`https://secrt.ca/s/abc123/#${fragment}`);
    expect(result).not.toBeNull();
    expect(result!.id).toBe('abc123');
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
      `https://secrt.ca/s/aB3-z_9#${fragment}`,
    );
    expect(result).not.toBeNull();
    expect(result!.id).toBe('aB3-z_9');
  });

  it('handles URL with query params', () => {
    const key = makeUrlKey(7);
    const fragment = base64urlEncode(key);
    const result = parseShareUrl(
      `https://secrt.ca/s/abc123?foo=bar#${fragment}`,
    );
    expect(result).not.toBeNull();
    expect(result!.id).toBe('abc123');
  });

  it('cross-checks spec vector url_key round-trip', () => {
    // From spec vector 1
    const urlKeyB64 = 'AQIDBAUGBwgJEBESExQVFhcYGSAhIiMkJSYnKCkwMTI';
    const urlKey = base64urlDecode(urlKeyB64);
    const link = formatShareLink('spec-test', urlKey);
    const result = parseShareUrl(link);
    expect(result).not.toBeNull();
    expect(result!.urlKey).toEqual(urlKey);
    expect(base64urlEncode(result!.urlKey)).toBe(urlKeyB64);
  });
});
