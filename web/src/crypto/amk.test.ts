import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import {
  computeAmkCommit,
  deriveAmkWrapKey,
  buildWrapAad,
  wrapAmk,
  unwrapAmk,
  encryptNote,
  decryptNote,
  deriveTransferKey,
  computeSas,
  generateAmk,
  AMK_LEN,
  WRAP_KEY_LEN,
  GCM_NONCE_LEN,
  NOTE_SALT_LEN,
} from './amk';
import { base64urlEncode, base64urlDecode } from './encoding';

// Load the shared test vectors
const vectorsPath = resolve(__dirname, '../../../spec/v1/amk.vectors.json');
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf-8'));

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('AMK cross-implementation vectors', () => {
  describe('amk_commit', () => {
    const v = vectors.vectors.amk_commit;

    it('matches Rust commitment hash', async () => {
      const amk = hexToBytes(v.amk_hex);
      const commit = await computeAmkCommit(amk);
      expect(bytesToHex(commit)).toBe(v.commit_hex);
    });
  });

  describe('wrap_unwrap', () => {
    const v = vectors.vectors.wrap_unwrap;

    it('derives the same wrap key as Rust', async () => {
      const rootKey = hexToBytes(v.root_key_hex);
      const wrapKey = await deriveAmkWrapKey(rootKey);
      expect(bytesToHex(wrapKey)).toBe(v.wrap_key_hex);
    });

    it('builds the same AAD as Rust', () => {
      const aad = buildWrapAad(v.user_id, v.key_prefix, v.version);
      expect(bytesToHex(aad)).toBe(v.aad_hex);
    });

    it('can decrypt Rust-encrypted wrapped AMK', async () => {
      const rootKey = hexToBytes(v.root_key_hex);
      const wrapKey = await deriveAmkWrapKey(rootKey);
      const aad = buildWrapAad(v.user_id, v.key_prefix, v.version);

      const wrapped = {
        ct: v.ct_b64url,
        nonce: v.nonce_b64url,
        version: v.version,
      };

      const amk = await unwrapAmk(wrapped, wrapKey, aad);
      expect(bytesToHex(amk)).toBe(v.amk_hex);
    });
  });

  describe('note_encrypt_decrypt', () => {
    const v = vectors.vectors.note_encrypt_decrypt;

    it('can decrypt Rust-encrypted note', async () => {
      const amk = hexToBytes(v.amk_hex);
      const encrypted = {
        ct: v.ct_b64url,
        nonce: v.nonce_b64url,
        salt: v.salt_b64url,
      };

      const plaintext = await decryptNote(amk, v.secret_id, encrypted);
      const text = new TextDecoder().decode(plaintext);
      expect(text).toBe(v.plaintext_utf8);
    });
  });

  describe('transfer_key', () => {
    const v = vectors.vectors.transfer_key;

    it('derives the same transfer key as Rust', async () => {
      const sharedSecret = hexToBytes(v.shared_secret_hex);
      const transferKey = await deriveTransferKey(sharedSecret);
      expect(bytesToHex(transferKey)).toBe(v.transfer_key_hex);
    });
  });

  describe('sas', () => {
    const v = vectors.vectors.sas;

    it('computes the same SAS code as Rust', async () => {
      const sharedSecret = hexToBytes(v.shared_secret_hex);
      const pkA = hexToBytes(v.pk_a_hex);
      const pkB = hexToBytes(v.pk_b_hex);

      const code = await computeSas(sharedSecret, pkA, pkB);
      expect(code).toBe(v.sas_code);
    });

    it('SAS is commutative (pk order does not matter)', async () => {
      const sharedSecret = hexToBytes(v.shared_secret_hex);
      const pkA = hexToBytes(v.pk_a_hex);
      const pkB = hexToBytes(v.pk_b_hex);

      const code1 = await computeSas(sharedSecret, pkA, pkB);
      const code2 = await computeSas(sharedSecret, pkB, pkA);
      expect(code1).toBe(code2);
    });
  });
});

describe('AMK unit tests', () => {
  it('generateAmk returns 32 bytes', () => {
    const amk = generateAmk();
    expect(amk).toBeInstanceOf(Uint8Array);
    expect(amk.length).toBe(AMK_LEN);
  });

  it('wrapAmk + unwrapAmk round-trips', async () => {
    const amk = new Uint8Array(AMK_LEN);
    amk.fill(0xaa);
    const wrapKey = new Uint8Array(WRAP_KEY_LEN);
    wrapKey.fill(0xbb);
    const aad = buildWrapAad('user-1', 'prefix1', 1);

    const wrapped = await wrapAmk(amk, wrapKey, aad);
    expect(wrapped.version).toBe(1);

    const unwrapped = await unwrapAmk(wrapped, wrapKey, aad);
    expect(bytesToHex(unwrapped)).toBe(bytesToHex(amk));
  });

  it('unwrapAmk with wrong key fails', async () => {
    const amk = new Uint8Array(AMK_LEN);
    amk.fill(0xaa);
    const wrapKey = new Uint8Array(WRAP_KEY_LEN);
    wrapKey.fill(0xbb);
    const badKey = new Uint8Array(WRAP_KEY_LEN);
    badKey.fill(0xcc);
    const aad = buildWrapAad('user-1', 'prefix1', 1);

    const wrapped = await wrapAmk(amk, wrapKey, aad);
    await expect(unwrapAmk(wrapped, badKey, aad)).rejects.toThrow();
  });

  it('encryptNote + decryptNote round-trips', async () => {
    const amk = new Uint8Array(AMK_LEN);
    amk.fill(0xee);
    const plaintext = new TextEncoder().encode('test note content');

    const encrypted = await encryptNote(amk, 'secret-id', plaintext);
    const decrypted = await decryptNote(amk, 'secret-id', encrypted);
    expect(new TextDecoder().decode(decrypted)).toBe('test note content');
  });

  it('decryptNote with wrong secret_id fails', async () => {
    const amk = new Uint8Array(AMK_LEN);
    amk.fill(0xee);
    const plaintext = new TextEncoder().encode('test');

    const encrypted = await encryptNote(amk, 'secret-1', plaintext);
    await expect(decryptNote(amk, 'secret-2', encrypted)).rejects.toThrow();
  });

  it('decryptNote with wrong AMK fails', async () => {
    const amk = new Uint8Array(AMK_LEN);
    amk.fill(0xee);
    const badAmk = new Uint8Array(AMK_LEN);
    badAmk.fill(0xff);

    const encrypted = await encryptNote(amk, 'sid', new TextEncoder().encode('x'));
    await expect(decryptNote(badAmk, 'sid', encrypted)).rejects.toThrow();
  });
});
