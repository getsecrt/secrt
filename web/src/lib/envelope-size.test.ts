import { describe, it, expect } from 'vitest';
import { checkEnvelopeSize } from './envelope-size';
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
    // Create an envelope whose JSON serialization exceeds 500 bytes
    const envelope = makeEnvelope(500);
    const result = checkEnvelopeSize(envelope, info);
    expect(result).not.toBeNull();
    expect(result).toContain('too large');
  });

  it('uses authed tier when authenticated', () => {
    const info = makeInfo(100, 1048576, true);
    // Envelope exceeds 100 (public) but not 1048576 (authed)
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

  it('includes the max size in KB in the error message', () => {
    const info = makeInfo(262144, 1048576, false);
    const envelope = makeEnvelope(300000);
    const result = checkEnvelopeSize(envelope, info);
    expect(result).toContain('256 KB');
  });
});
