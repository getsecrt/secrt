import { describe, it, expect } from 'vitest';
import { checkEnvelopeSize, estimateEnvelopeSize, frameSizeError } from './envelope-size';
import type { ApiInfo, EnvelopeJson } from '../types';

function makeInfo(maxPublic: number, maxAuthed: number, authenticated: boolean): ApiInfo {
  const rate = { requests_per_second: 1, burst: 10 };
  return {
    authenticated,
    ttl: { default_seconds: 86400, max_seconds: 31536000 },
    limits: {
      public: {
        max_envelope_bytes: maxPublic,
        max_secrets: 10,
        max_total_bytes: 2097152,
        rate,
      },
      authed: {
        max_envelope_bytes: maxAuthed,
        max_secrets: 1000,
        max_total_bytes: 20971520,
        rate,
      },
    },
    claim_rate: rate,
  };
}

function makeEnvelope(ciphertextLength: number): EnvelopeJson {
  return {
    v: 1,
    suite: 'v1-pbkdf2-hkdf-aes256gcm-sealed-payload',
    enc: {
      alg: 'A256GCM',
      nonce: 'AAAAAAAAAAAAAAAA',
      ciphertext: 'x'.repeat(ciphertextLength),
    },
    kdf: { name: 'none' },
    hkdf: {
      hash: 'SHA-256',
      salt: 'AAAAAAAAAAAAAAAA',
      enc_info: 'secrt.ca/envelope/v1-enc-key',
      claim_info: 'secrt.ca/envelope/v1-claim-token',
      length: 32,
    },
  };
}

describe('checkEnvelopeSize', () => {
  it('returns null when info is not available', () => {
    const envelope = makeEnvelope(1000);
    expect(checkEnvelopeSize(envelope, null)).toBeNull();
  });

  it('returns null when envelope is within public limit', () => {
    const envelope = makeEnvelope(100);
    const info = makeInfo(262144, 1048576, false);
    expect(checkEnvelopeSize(envelope, info)).toBeNull();
  });

  it('returns error when envelope exceeds public limit', () => {
    const info = makeInfo(500, 1048576, false);
    const envelope = makeEnvelope(500);
    const result = checkEnvelopeSize(envelope, info);
    expect(result).not.toBeNull();
    expect(result).toContain('too large');
  });

  it('uses authed tier when authenticated', () => {
    const info = makeInfo(100, 1048576, true);
    const envelope = makeEnvelope(200);
    expect(checkEnvelopeSize(envelope, info)).toBeNull();
  });

  it('returns error when envelope exceeds authed limit', () => {
    const info = makeInfo(100, 500, true);
    const envelope = makeEnvelope(500);
    const result = checkEnvelopeSize(envelope, info);
    expect(result).not.toBeNull();
    expect(result).toContain('too large');
  });

  it('includes formatted sizes in error message', () => {
    const info = makeInfo(262144, 1048576, false);
    const envelope = makeEnvelope(300000);
    const result = checkEnvelopeSize(envelope, info);
    expect(result).toContain('encrypted');
    expect(result).toContain('\nMaximum is 256.0 KB');
  });

  it('respects explicit authenticated flag over info.authenticated', () => {
    // info says unauthenticated, but we pass authenticated=true
    const info = makeInfo(100, 1048576, false);
    const envelope = makeEnvelope(200);
    // With public tier (100 bytes), this would fail; with authed tier it should pass
    expect(checkEnvelopeSize(envelope, info, true)).toBeNull();
  });
});

describe('estimateEnvelopeSize', () => {
  it('returns a reasonable estimate for small frames', () => {
    // 100 byte frame: (100 + 16) * 4/3 + 400 ≈ 555
    const est = estimateEnvelopeSize(100);
    expect(est).toBeGreaterThan(500);
    expect(est).toBeLessThan(600);
  });

  it('returns a reasonable estimate for large frames', () => {
    // 200000 byte frame: (200016) * 4/3 + 400 ≈ 267088
    const est = estimateEnvelopeSize(200000);
    expect(est).toBeGreaterThan(260000);
    expect(est).toBeLessThan(270000);
  });

  it('accounts for GCM auth tag overhead', () => {
    // Difference between 0-byte frame and 16 extra bytes should be ~21 (16 * 4/3)
    const base = estimateEnvelopeSize(0);
    const withExtra = estimateEnvelopeSize(16);
    expect(withExtra - base).toBeGreaterThanOrEqual(21);
  });
});

describe('frameSizeError', () => {
  it('says "encrypted" when not compressed', () => {
    const msg = frameSizeError(500000, 262144);
    expect(msg).toContain('too large');
    expect(msg).toContain('encrypted');
    expect(msg).not.toContain('compressed');
  });

  it('says "encrypted & compressed" when compressed', () => {
    const msg = frameSizeError(300000, 262144, true);
    expect(msg).toContain('encrypted & compressed');
  });

  it('does not include ~ prefix', () => {
    const msg = frameSizeError(500000, 262144);
    expect(msg).not.toContain('~');
  });

  it('includes line break before Maximum', () => {
    const msg = frameSizeError(500000, 262144);
    expect(msg).toContain('\nMaximum is');
  });
});
