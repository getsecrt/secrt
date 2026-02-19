/**
 * Account Master Key (AMK) crypto operations — WebCrypto mirror of Rust amk.rs.
 *
 * - AMK wrap/unwrap: per-API-key encryption of the AMK
 * - Note encrypt/decrypt: per-secret note encryption bound to secret_id
 * - AMK commitment: blinded hash for race prevention
 * - ECDH helpers: transfer key derivation and SAS computation
 */

import {
  base64urlEncode,
  base64urlDecode,
  utf8Encode,
  concatBytes,
} from './encoding';

// ── Constants ────────────────────────────────────────────────────────

export const AMK_LEN = 32;
export const WRAP_KEY_LEN = 32;
export const NOTE_KEY_LEN = 32;
export const GCM_NONCE_LEN = 12;
export const GCM_TAG_LEN = 16;
export const NOTE_SALT_LEN = 32;
export const SAS_LEN = 3;

const HKDF_INFO_AMK_WRAP = 'secrt-amk-wrap-v1';
const HKDF_INFO_NOTE = 'secrt-note-v1';
const HKDF_INFO_AMK_TRANSFER = 'secrt-amk-transfer-v1';
const HKDF_INFO_SAS = 'secrt-amk-sas-v1';
const AMK_COMMIT_DOMAIN_TAG = 'secrt-amk-commit-v1';
const ROOT_SALT_LABEL = 'secrt-apikey-v2-root-salt';

// ── Types ────────────────────────────────────────────────────────────

export interface WrappedAmk {
  ct: string; // base64url
  nonce: string; // base64url
  version: number;
}

export interface EncryptedNote {
  ct: string; // base64url
  nonce: string; // base64url
  salt: string; // base64url
}

export interface AmkTransfer {
  ct: string; // base64url
  nonce: string; // base64url
  ecdh_public_key: string; // base64url (browser's public key)
}

// ── Helpers ──────────────────────────────────────────────────────────

/** Copy Uint8Array to a fresh ArrayBuffer for strict TS BufferSource typing. */
const buf = (a: Uint8Array): ArrayBuffer => {
  const b = new ArrayBuffer(a.byteLength);
  new Uint8Array(b).set(a);
  return b;
};

/** HKDF-SHA256 derivation. */
async function hkdfDerive(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  length: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', buf(ikm), 'HKDF', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: buf(salt),
      info: buf(utf8Encode(info)),
    },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** Compute the root salt: SHA-256(ROOT_SALT_LABEL). */
async function rootSalt(): Promise<Uint8Array> {
  const d = await crypto.subtle.digest(
    'SHA-256',
    buf(utf8Encode(ROOT_SALT_LABEL)),
  );
  return new Uint8Array(d);
}

/** AES-256-GCM encrypt. */
async function aes256gcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    buf(key),
    'AES-GCM',
    false,
    ['encrypt'],
  );
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: buf(nonce), additionalData: buf(aad) },
    cryptoKey,
    buf(plaintext),
  );
  return new Uint8Array(ct);
}

/** AES-256-GCM decrypt. */
async function aes256gcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    buf(key),
    'AES-GCM',
    false,
    ['decrypt'],
  );
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: buf(nonce), additionalData: buf(aad) },
    cryptoKey,
    buf(ciphertext),
  );
  return new Uint8Array(pt);
}

// ── AMK Commitment ──────────────────────────────────────────────────

/** SHA-256("secrt-amk-commit-v1" || amk) — blinded commitment hash. */
export async function computeAmkCommit(amk: Uint8Array): Promise<Uint8Array> {
  const input = concatBytes(utf8Encode(AMK_COMMIT_DOMAIN_TAG), amk);
  const d = await crypto.subtle.digest('SHA-256', buf(input));
  return new Uint8Array(d);
}

// ── Key Derivation ──────────────────────────────────────────────────

/** Derive AMK wrap key from root_key. Same HKDF pattern as deriveAuthToken. */
export async function deriveAmkWrapKey(
  rootKey: Uint8Array,
): Promise<Uint8Array> {
  if (rootKey.length !== 32) throw new Error('root key must be 32 bytes');
  const salt = await rootSalt();
  return hkdfDerive(rootKey, salt, HKDF_INFO_AMK_WRAP, WRAP_KEY_LEN);
}

/**
 * Build domain-tagged AAD for AMK wrapping.
 * AAD = "secrt-amk-wrap-v1" || user_id || key_prefix || version (BE u16)
 */
export function buildWrapAad(
  userId: string,
  keyPrefix: string,
  version: number,
): Uint8Array {
  const versionBytes = new Uint8Array(2);
  versionBytes[0] = (version >> 8) & 0xff;
  versionBytes[1] = version & 0xff;
  return concatBytes(
    utf8Encode(HKDF_INFO_AMK_WRAP),
    utf8Encode(userId),
    utf8Encode(keyPrefix),
    versionBytes,
  );
}

// ── AMK Wrap / Unwrap ───────────────────────────────────────────────

/** Wrap (encrypt) an AMK with the derived wrap key. */
export async function wrapAmk(
  amk: Uint8Array,
  wrapKey: Uint8Array,
  aad: Uint8Array,
): Promise<WrappedAmk> {
  if (amk.length !== AMK_LEN) throw new Error('AMK must be 32 bytes');
  const nonce = new Uint8Array(GCM_NONCE_LEN);
  crypto.getRandomValues(nonce);
  const ct = await aes256gcmEncrypt(wrapKey, nonce, aad, amk);
  return {
    ct: base64urlEncode(ct),
    nonce: base64urlEncode(nonce),
    version: 1,
  };
}

/** Unwrap (decrypt) a wrapped AMK blob. */
export async function unwrapAmk(
  wrapped: WrappedAmk,
  wrapKey: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const ct = base64urlDecode(wrapped.ct);
  const nonce = base64urlDecode(wrapped.nonce);
  const amk = await aes256gcmDecrypt(wrapKey, nonce, aad, ct);
  if (amk.length !== AMK_LEN) throw new Error('unwrapped AMK is not 32 bytes');
  return amk;
}

// ── Note Encrypt / Decrypt ──────────────────────────────────────────

/** Build AAD for note encryption: "secrt-note-v1" || secret_id. */
function buildNoteAad(secretId: string): Uint8Array {
  return concatBytes(utf8Encode(HKDF_INFO_NOTE), utf8Encode(secretId));
}

/** Derive per-note key: HKDF(AMK, salt, "secrt-note-v1", 32). */
async function deriveNoteKey(
  amk: Uint8Array,
  salt: Uint8Array,
): Promise<Uint8Array> {
  return hkdfDerive(amk, salt, HKDF_INFO_NOTE, NOTE_KEY_LEN);
}

/** Encrypt a note for a specific secret. */
export async function encryptNote(
  amk: Uint8Array,
  secretId: string,
  plaintext: Uint8Array,
): Promise<EncryptedNote> {
  if (amk.length !== AMK_LEN) throw new Error('AMK must be 32 bytes');
  const salt = new Uint8Array(NOTE_SALT_LEN);
  crypto.getRandomValues(salt);
  const nonce = new Uint8Array(GCM_NONCE_LEN);
  crypto.getRandomValues(nonce);
  const noteKey = await deriveNoteKey(amk, salt);
  const aad = buildNoteAad(secretId);
  const ct = await aes256gcmEncrypt(noteKey, nonce, aad, plaintext);
  return {
    ct: base64urlEncode(ct),
    nonce: base64urlEncode(nonce),
    salt: base64urlEncode(salt),
  };
}

/** Decrypt a note for a specific secret. Verifies AAD binding. */
export async function decryptNote(
  amk: Uint8Array,
  secretId: string,
  encrypted: EncryptedNote,
): Promise<Uint8Array> {
  if (amk.length !== AMK_LEN) throw new Error('AMK must be 32 bytes');
  const ct = base64urlDecode(encrypted.ct);
  const nonce = base64urlDecode(encrypted.nonce);
  const salt = base64urlDecode(encrypted.salt);
  const noteKey = await deriveNoteKey(amk, salt);
  const aad = buildNoteAad(secretId);
  return aes256gcmDecrypt(noteKey, nonce, aad, ct);
}

// ── ECDH ────────────────────────────────────────────────────────────

/** Generate an ephemeral P-256 ECDH key pair. */
export async function generateEcdhKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  ) as Promise<CryptoKeyPair>;
}

/** Export public key bytes (uncompressed point). */
export async function exportPublicKey(
  key: CryptoKey,
): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return new Uint8Array(raw);
}

/** Perform ECDH: derive shared bits from our private key and peer's public key bytes. */
export async function performEcdh(
  privateKey: CryptoKey,
  peerPublicKeyBytes: Uint8Array,
): Promise<Uint8Array> {
  const peerKey = await crypto.subtle.importKey(
    'raw',
    buf(peerPublicKeyBytes),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerKey },
    privateKey,
    256,
  );
  return new Uint8Array(bits);
}

/** Derive transfer key from ECDH shared secret. */
export async function deriveTransferKey(
  sharedSecret: Uint8Array,
): Promise<Uint8Array> {
  return hkdfDerive(sharedSecret, new Uint8Array(0), HKDF_INFO_AMK_TRANSFER, 32);
}

/**
 * Compute 6-digit SAS code from shared secret and both public keys.
 * Keys are sorted deterministically so both sides compute the same code.
 */
export async function computeSas(
  sharedSecret: Uint8Array,
  pkA: Uint8Array,
  pkB: Uint8Array,
): Promise<number> {
  const cmp = compareBytes(pkA, pkB);
  const [minPk, maxPk] = cmp <= 0 ? [pkA, pkB] : [pkB, pkA];
  const saltBytes = concatBytes(minPk, maxPk);
  const sasBytes = await hkdfDerive(sharedSecret, saltBytes, HKDF_INFO_SAS, SAS_LEN);
  const code =
    ((sasBytes[0] << 16) | (sasBytes[1] << 8) | sasBytes[2]) % 1_000_000;
  return code;
}

/** Generate a random 32-byte AMK. */
export function generateAmk(): Uint8Array {
  const amk = new Uint8Array(AMK_LEN);
  crypto.getRandomValues(amk);
  return amk;
}

// ── Internal ────────────────────────────────────────────────────────

/** Lexicographic byte comparison. Returns <0, 0, or >0. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
