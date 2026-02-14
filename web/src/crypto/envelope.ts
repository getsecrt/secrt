import type {
  PayloadMeta,
  EnvelopeJson,
  SealResult,
  OpenResult,
  KdfPbkdf2,
} from '../types';
import {
  AAD,
  HKDF_INFO_ENC,
  HKDF_INFO_CLAIM,
  CLAIM_SALT_LABEL,
  SUITE,
  URL_KEY_LEN,
  HKDF_LEN,
  GCM_NONCE_LEN,
  HKDF_SALT_LEN,
  KDF_SALT_LEN,
  PBKDF2_ITERATIONS,
} from './constants';
import {
  base64urlEncode,
  base64urlDecode,
  utf8Encode,
  concatBytes,
} from './encoding';
import { buildFrame, parseFrame } from './frame';

// TS 5.8 makes Uint8Array generic; Web Crypto expects BufferSource.
// This helper avoids casting at every call site.
const buf = (a: Uint8Array): ArrayBuffer => {
  const b = new ArrayBuffer(a.byteLength);
  new Uint8Array(b).set(a);
  return b;
};

interface SealOptions {
  passphrase?: string;
  iterations?: number;
  rng?: (buf: Uint8Array) => void;
  compress?: (data: Uint8Array) => Uint8Array;
}

/**
 * Seal plaintext content into an encrypted envelope.
 * Returns the envelope JSON, url_key, and claim_hash.
 */
export async function seal(
  content: Uint8Array,
  meta: PayloadMeta,
  options?: SealOptions,
): Promise<SealResult> {
  const rng = options?.rng ?? cryptoRng;
  const iterations = options?.iterations ?? PBKDF2_ITERATIONS;

  // 1. Generate url_key
  const urlKey = new Uint8Array(URL_KEY_LEN);
  rng(urlKey);

  // 2. Build KDF + compute IKM
  let ikm: Uint8Array;
  let kdf: EnvelopeJson['kdf'];

  if (options?.passphrase) {
    const kdfSalt = new Uint8Array(KDF_SALT_LEN);
    rng(kdfSalt);
    const passKey = await pbkdf2Derive(options.passphrase, kdfSalt, iterations);
    ikm = new Uint8Array(
      await crypto.subtle.digest('SHA-256', buf(concatBytes(urlKey, passKey))),
    );
    kdf = {
      name: 'PBKDF2-SHA256',
      salt: base64urlEncode(kdfSalt),
      iterations,
      length: 32,
    };
  } else {
    ikm = urlKey;
    kdf = { name: 'none' };
  }

  // 3. Generate HKDF salt
  const hkdfSalt = new Uint8Array(HKDF_SALT_LEN);
  rng(hkdfSalt);

  // 4. Derive enc_key
  const encKey = await hkdfDerive(ikm, hkdfSalt, HKDF_INFO_ENC, HKDF_LEN);

  // 5. Derive claim_token + claim_hash
  const claimHash = await deriveClaimHash(urlKey);

  // 6. Build framed payload
  const frameBytes = buildFrame(meta, content, options?.compress);

  // 7. Generate nonce
  const nonce = new Uint8Array(GCM_NONCE_LEN);
  rng(nonce);

  // 8. Encrypt
  const aadBytes = utf8Encode(AAD);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    buf(encKey),
    'AES-GCM',
    false,
    ['encrypt'],
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: buf(nonce), additionalData: buf(aadBytes) },
      cryptoKey,
      buf(frameBytes),
    ),
  );

  // 9. Build envelope
  const envelope: EnvelopeJson = {
    v: 1,
    suite: SUITE,
    enc: {
      alg: 'A256GCM',
      nonce: base64urlEncode(nonce),
      ciphertext: base64urlEncode(ciphertext),
    },
    kdf,
    hkdf: {
      hash: 'SHA-256',
      salt: base64urlEncode(hkdfSalt),
      enc_info: HKDF_INFO_ENC,
      claim_info: HKDF_INFO_CLAIM,
      length: 32,
    },
  };

  return { envelope, urlKey, claimHash };
}

/**
 * Open (decrypt) an envelope using the url_key and optional passphrase.
 */
export async function open(
  envelope: EnvelopeJson,
  urlKey: Uint8Array,
  passphrase?: string,
): Promise<OpenResult> {
  // Validate envelope structure
  if (envelope.v !== 1)
    throw new Error(`unsupported envelope version: ${envelope.v}`);
  if (envelope.suite !== SUITE)
    throw new Error(`unsupported suite: ${envelope.suite}`);
  if (envelope.enc.alg !== 'A256GCM')
    throw new Error(`unsupported alg: ${envelope.enc.alg}`);

  const nonce = base64urlDecode(envelope.enc.nonce);
  if (nonce.length !== GCM_NONCE_LEN) throw new Error('invalid nonce length');

  const ciphertext = base64urlDecode(envelope.enc.ciphertext);
  if (ciphertext.length < 16) throw new Error('ciphertext too short');

  const hkdfSalt = base64urlDecode(envelope.hkdf.salt);
  if (hkdfSalt.length !== HKDF_SALT_LEN)
    throw new Error('invalid hkdf salt length');

  // Recompute IKM
  let ikm: Uint8Array;
  const kdfName = envelope.kdf.name;
  if (kdfName === 'PBKDF2-SHA256') {
    if (!passphrase) throw new Error('passphrase required');
    const kdfBlock = envelope.kdf as KdfPbkdf2;
    const kdfSalt = base64urlDecode(kdfBlock.salt);
    const passKey = await pbkdf2Derive(
      passphrase,
      kdfSalt,
      kdfBlock.iterations,
    );
    ikm = new Uint8Array(
      await crypto.subtle.digest('SHA-256', buf(concatBytes(urlKey, passKey))),
    );
  } else if (kdfName === 'none') {
    ikm = urlKey;
  } else {
    throw new Error(`unsupported kdf: ${kdfName}`);
  }

  // Derive enc_key
  const encKey = await hkdfDerive(ikm, hkdfSalt, HKDF_INFO_ENC, HKDF_LEN);

  // Decrypt
  const aadBytes = utf8Encode(AAD);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    buf(encKey),
    'AES-GCM',
    false,
    ['decrypt'],
  );
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: buf(nonce), additionalData: buf(aadBytes) },
      cryptoKey,
      buf(ciphertext),
    ),
  );

  // Parse frame
  const { meta, body } = parseFrame(plaintext);

  return { content: body, meta };
}

/**
 * Derive the claim_hash from a url_key.
 * claim_hash = base64url(SHA-256(claim_token))
 */
export async function deriveClaimHash(urlKey: Uint8Array): Promise<string> {
  const token = await deriveClaimToken(urlKey);
  const hash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', buf(token)),
  );
  return base64urlEncode(hash);
}

/**
 * Derive the claim_token from a url_key.
 * claim_token = HKDF-SHA-256(url_key, CLAIM_SALT, HKDF_INFO_CLAIM, 32)
 */
export async function deriveClaimToken(
  urlKey: Uint8Array,
): Promise<Uint8Array> {
  const claimSalt = new Uint8Array(
    await crypto.subtle.digest('SHA-256', buf(utf8Encode(CLAIM_SALT_LABEL))),
  );
  return hkdfDerive(urlKey, claimSalt, HKDF_INFO_CLAIM, HKDF_LEN);
}

// ── Internal helpers ────────────────────────────────────────

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

async function pbkdf2Derive(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    buf(utf8Encode(passphrase)),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: buf(salt),
      iterations,
    },
    key,
    256,
  );
  return new Uint8Array(bits);
}

function cryptoRng(b: Uint8Array): void {
  crypto.getRandomValues(b);
}
