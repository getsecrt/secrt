import { describe, it, expect } from 'vitest';
import { seal, open, deriveClaimHash, deriveClaimToken } from './envelope';
import { base64urlEncode, base64urlDecode } from './encoding';
import type { PayloadMeta, EnvelopeJson } from '../types';
import vectorsJson from '../../../spec/v1/envelope.vectors.json';

// Type for the raw vector JSON
interface VectorFile {
  aad: string;
  hkdf_info_enc: string;
  hkdf_info_claim: string;
  claim_salt_label: string;
  vectors: Vector[];
}

interface Vector {
  description: string;
  url_key: string;
  plaintext: string;
  plaintext_utf8: string;
  passphrase: string | null;
  metadata: PayloadMeta;
  codec: 'none' | 'zstd';
  ikm: string;
  enc_key: string;
  claim_token: string;
  claim_hash: string;
  envelope: EnvelopeJson;
}

const vectors = vectorsJson as unknown as VectorFile;

/**
 * Build a deterministic RNG from concatenated random bytes used during seal().
 * The seal() function calls rng in this order:
 *   1. url_key (32 bytes)
 *   2. kdf_salt (16 bytes) — only if passphrase
 *   3. hkdf_salt (32 bytes)
 *   4. nonce (12 bytes)
 */
function buildDeterministicRng(
  chunks: Uint8Array[],
): (buf: Uint8Array) => void {
  const all = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.length;
  }

  let cursor = 0;
  return (buf: Uint8Array) => {
    if (cursor + buf.length > all.length) {
      throw new Error(
        `deterministic RNG exhausted: requested ${buf.length} at offset ${cursor}, total ${all.length}`,
      );
    }
    buf.set(all.subarray(cursor, cursor + buf.length));
    cursor += buf.length;
  };
}

/**
 * Minimal zstd compressor using fzstd for decompression verification.
 * For seal tests we need a compressor that produces the exact same output
 * as the spec vectors. Since we can't easily match zstd level 3 output
 * byte-for-byte across implementations, we verify open() (decryption)
 * against the vector envelopes directly, and for seal() we only verify
 * codec=none vectors produce matching envelopes.
 */

describe('envelope spec vectors', () => {
  // Test open() (decryption) for ALL vectors — this is the critical path
  for (const [i, vec] of vectors.vectors.entries()) {
    it(`vector ${i}: open() decrypts "${vec.description}"`, async () => {
      const urlKey = base64urlDecode(vec.url_key);
      const result = await open(
        vec.envelope,
        urlKey,
        vec.passphrase ?? undefined,
      );

      // Verify decrypted content matches expected plaintext
      const expectedContent = base64urlDecode(vec.plaintext);
      expect(base64urlEncode(result.content)).toBe(vec.plaintext);
      expect(result.content.length).toBe(expectedContent.length);

      // Verify metadata
      expect(result.meta.type).toBe(vec.metadata.type);
      if (vec.metadata.filename) {
        expect(result.meta.filename).toBe(vec.metadata.filename);
      }
      if (vec.metadata.mime) {
        expect(result.meta.mime).toBe(vec.metadata.mime);
      }
    });
  }

  // Test claim_hash derivation for ALL vectors
  for (const [i, vec] of vectors.vectors.entries()) {
    it(`vector ${i}: deriveClaimHash() matches "${vec.description}"`, async () => {
      const urlKey = base64urlDecode(vec.url_key);
      const claimHash = await deriveClaimHash(urlKey);
      expect(claimHash).toBe(vec.claim_hash);
    });
  }

  // Test claim_token derivation for ALL vectors
  for (const [i, vec] of vectors.vectors.entries()) {
    it(`vector ${i}: deriveClaimToken() matches "${vec.description}"`, async () => {
      const urlKey = base64urlDecode(vec.url_key);
      const token = await deriveClaimToken(urlKey);
      expect(base64urlEncode(token)).toBe(vec.claim_token);
    });
  }

  // Test seal() round-trip for codec=none vectors (byte-exact envelope match)
  for (const [i, vec] of vectors.vectors.entries()) {
    if (vec.codec !== 'none') continue;

    it(`vector ${i}: seal() produces matching envelope for "${vec.description}"`, async () => {
      const urlKey = base64urlDecode(vec.url_key);
      const content = base64urlDecode(vec.plaintext);
      const hkdfSalt = base64urlDecode(vec.envelope.hkdf.salt);
      const nonce = base64urlDecode(vec.envelope.enc.nonce);

      // Build RNG chunks in the order seal() requests them
      const rngChunks: Uint8Array[] = [urlKey, hkdfSalt, nonce];
      if (vec.passphrase) {
        // kdf_salt goes between url_key and hkdf_salt
        const kdfSalt = base64urlDecode(
          (vec.envelope.kdf as { salt: string }).salt,
        );
        rngChunks.splice(1, 0, kdfSalt);
      }

      const rng = buildDeterministicRng(rngChunks);

      const result = await seal(content, vec.metadata, {
        passphrase: vec.passphrase ?? undefined,
        rng,
      });

      // Verify envelope matches vector exactly
      expect(result.envelope.v).toBe(vec.envelope.v);
      expect(result.envelope.suite).toBe(vec.envelope.suite);
      expect(result.envelope.enc.alg).toBe(vec.envelope.enc.alg);
      expect(result.envelope.enc.nonce).toBe(vec.envelope.enc.nonce);
      expect(result.envelope.enc.ciphertext).toBe(vec.envelope.enc.ciphertext);
      expect(result.envelope.kdf).toEqual(vec.envelope.kdf);
      expect(result.envelope.hkdf).toEqual(vec.envelope.hkdf);

      // Verify url_key and claim_hash
      expect(base64urlEncode(result.urlKey)).toBe(vec.url_key);
      expect(result.claimHash).toBe(vec.claim_hash);
    });
  }

  // Test seal() + open() round-trip for all vectors (including zstd)
  for (const [i, vec] of vectors.vectors.entries()) {
    it(`vector ${i}: seal+open round-trips "${vec.description}"`, async () => {
      const content = base64urlDecode(vec.plaintext);

      // Seal with random keys (no deterministic RNG needed for round-trip)
      const sealResult = await seal(content, vec.metadata, {
        passphrase: vec.passphrase ?? undefined,
      });

      // Open what we just sealed
      const openResult = await open(
        sealResult.envelope,
        sealResult.urlKey,
        vec.passphrase ?? undefined,
      );

      expect(base64urlEncode(openResult.content)).toBe(vec.plaintext);
      expect(openResult.meta.type).toBe(vec.metadata.type);
    });
  }
});
