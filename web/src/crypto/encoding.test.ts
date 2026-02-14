import { describe, it, expect } from 'vitest';
import {
  base64urlEncode,
  base64urlDecode,
  bytesToHex,
  utf8Encode,
  utf8Decode,
  concatBytes,
} from './encoding';

describe('base64urlEncode / base64urlDecode', () => {
  it('round-trips empty array', () => {
    const input = new Uint8Array([]);
    expect(base64urlDecode(base64urlEncode(input))).toEqual(input);
  });

  it('round-trips single byte', () => {
    const input = new Uint8Array([0x42]);
    expect(base64urlDecode(base64urlEncode(input))).toEqual(input);
  });

  it('round-trips 32 bytes (url_key length)', () => {
    const input = new Uint8Array(32);
    for (let i = 0; i < 32; i++) input[i] = i + 1;
    expect(base64urlDecode(base64urlEncode(input))).toEqual(input);
  });

  it('handles padding edge case: length 1 (2 padding chars)', () => {
    const input = new Uint8Array([0xff]);
    const encoded = base64urlEncode(input);
    expect(encoded).not.toContain('=');
    expect(base64urlDecode(encoded)).toEqual(input);
  });

  it('handles padding edge case: length 2 (1 padding char)', () => {
    const input = new Uint8Array([0xff, 0xfe]);
    const encoded = base64urlEncode(input);
    expect(encoded).not.toContain('=');
    expect(base64urlDecode(encoded)).toEqual(input);
  });

  it('handles padding edge case: length 3 (0 padding chars)', () => {
    const input = new Uint8Array([0xff, 0xfe, 0xfd]);
    const encoded = base64urlEncode(input);
    expect(encoded).not.toContain('=');
    expect(base64urlDecode(encoded)).toEqual(input);
  });

  it('produces URL-safe characters only (no +, /, or =)', () => {
    // Use bytes that would produce + and / in standard base64
    const input = new Uint8Array([0xfb, 0xef, 0xbe, 0xfb, 0xef, 0xbe]);
    const encoded = base64urlEncode(input);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');
  });

  it('cross-checks spec vector url_key', () => {
    // Vector 1: url_key = "AQIDBAUGBwgJEBESExQVFhcYGSAhIiMkJSYnKCkwMTI"
    const decoded = base64urlDecode('AQIDBAUGBwgJEBESExQVFhcYGSAhIiMkJSYnKCkwMTI');
    expect(decoded.length).toBe(32);
    expect(decoded[0]).toBe(0x01);
    expect(decoded[1]).toBe(0x02);
    expect(base64urlEncode(decoded)).toBe('AQIDBAUGBwgJEBESExQVFhcYGSAhIiMkJSYnKCkwMTI');
  });

  it('round-trips random-ish 64 bytes', () => {
    const input = new Uint8Array(64);
    for (let i = 0; i < 64; i++) input[i] = (i * 7 + 13) & 0xff;
    expect(base64urlDecode(base64urlEncode(input))).toEqual(input);
  });
});

describe('bytesToHex', () => {
  it('returns empty string for empty input', () => {
    expect(bytesToHex(new Uint8Array([]))).toBe('');
  });

  it('converts known value', () => {
    expect(bytesToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe(
      'deadbeef',
    );
  });

  it('preserves leading zeros', () => {
    expect(bytesToHex(new Uint8Array([0x00, 0x0a]))).toBe('000a');
  });

  it('handles single max byte', () => {
    expect(bytesToHex(new Uint8Array([0xff]))).toBe('ff');
  });

  it('handles single zero byte', () => {
    expect(bytesToHex(new Uint8Array([0x00]))).toBe('00');
  });
});

describe('utf8Encode / utf8Decode', () => {
  it('round-trips ASCII', () => {
    const str = 'hello world';
    expect(utf8Decode(utf8Encode(str))).toBe(str);
  });

  it('round-trips multi-byte UTF-8 (emoji)', () => {
    const str = 'hello \u{1F512}'; // lock emoji
    expect(utf8Decode(utf8Encode(str))).toBe(str);
  });

  it('round-trips CJK characters', () => {
    const str = '\u4F60\u597D\u4E16\u754C';
    expect(utf8Decode(utf8Encode(str))).toBe(str);
  });

  it('round-trips empty string', () => {
    expect(utf8Decode(utf8Encode(''))).toBe('');
  });
});

describe('concatBytes', () => {
  it('returns empty for zero arrays', () => {
    expect(concatBytes()).toEqual(new Uint8Array([]));
  });

  it('returns copy for single array', () => {
    const a = new Uint8Array([1, 2, 3]);
    const result = concatBytes(a);
    expect(result).toEqual(a);
    // Must be a copy, not the same reference
    expect(result).not.toBe(a);
  });

  it('concatenates multiple arrays in order', () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4, 5]);
    const c = new Uint8Array([6]);
    expect(concatBytes(a, b, c)).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
  });

  it('handles empty arrays in mix', () => {
    const a = new Uint8Array([]);
    const b = new Uint8Array([1, 2]);
    const c = new Uint8Array([]);
    expect(concatBytes(a, b, c)).toEqual(new Uint8Array([1, 2]));
  });

  it('has correct total length', () => {
    const a = new Uint8Array(10);
    const b = new Uint8Array(20);
    expect(concatBytes(a, b).length).toBe(30);
  });
});
