import type {
  PayloadMeta,
  EnvelopeJson,
  SealResult,
  OpenResult,
  KdfArgon2id,
} from '../types';
import { isTauri } from '../lib/config';
import { nativeSeal, nativeOpen, nativeDeriveClaimToken } from './native';
import {
  AAD,
  HKDF_INFO_ENC,
  HKDF_INFO_CLAIM,
  CLAIM_SALT_LABEL,
  SUITE,
  URL_KEY_LEN,
  PASS_KEY_LEN,
  HKDF_LEN,
  GCM_NONCE_LEN,
  HKDF_SALT_LEN,
  KDF_SALT_LEN,
  ARGON2_VERSION,
  ARGON2_M_COST_DEFAULT,
  ARGON2_T_COST_DEFAULT,
  ARGON2_P_COST_DEFAULT,
  ARGON2_M_COST_MIN,
  ARGON2_M_COST_MAX,
  ARGON2_T_COST_MIN,
  ARGON2_T_COST_MAX,
  ARGON2_P_COST_MIN,
  ARGON2_P_COST_MAX,
  ARGON2_M_COST_T_COST_PRODUCT_MAX,
} from './constants';
import {
  base64urlEncode,
  base64urlDecode,
  utf8Encode,
  concatBytes,
} from './encoding';
import { buildFrame, parseFrame } from './frame';
import { deriveArgon2id, preloadArgon2id } from './argon2id';

// TS 5.8 makes Uint8Array generic; Web Crypto expects BufferSource.
// This helper avoids casting at every call site.
const buf = (a: Uint8Array): ArrayBuffer => {
  const b = new ArrayBuffer(a.byteLength);
  new Uint8Array(b).set(a);
  return b;
};

interface SealOptions {
  passphrase?: string;
  rng?: (buf: Uint8Array) => void;
  compress?: (data: Uint8Array) => Uint8Array;
  /** Pre-built frame bytes (already compressed). Skips buildFrame() when provided. */
  prebuiltFrame?: Uint8Array;
}

/**
 * Proactively load Argon2id WASM for passphrase flows.
 * Safe to call multiple times.
 */
export async function preloadPassphraseKdf(): Promise<void> {
  if (isTauri()) return; // Native argon2id needs no WASM preloading
  await preloadArgon2id();
}

/**
 * Seal plaintext content into an encrypted envelope.
 * Returns the envelope JSON, url_key, and claim_hash.
 */
async function webSeal(
  content: Uint8Array,
  meta: PayloadMeta,
  options?: SealOptions,
): Promise<SealResult> {
  const rng = options?.rng ?? cryptoRng;

  // 1. Generate url_key
  const urlKey = new Uint8Array(URL_KEY_LEN);
  rng(urlKey);

  // 2. Build KDF + compute IKM
  let ikm: Uint8Array;
  let kdf: EnvelopeJson['kdf'];

  if (options?.passphrase) {
    const kdfSalt = new Uint8Array(KDF_SALT_LEN);
    rng(kdfSalt);

    const passKey = await deriveArgon2id(
      options.passphrase,
      kdfSalt,
      ARGON2_M_COST_DEFAULT,
      ARGON2_T_COST_DEFAULT,
      ARGON2_P_COST_DEFAULT,
      PASS_KEY_LEN,
    );

    ikm = new Uint8Array(
      await crypto.subtle.digest('SHA-256', buf(concatBytes(urlKey, passKey))),
    );

    kdf = {
      name: 'argon2id',
      version: ARGON2_VERSION,
      salt: base64urlEncode(kdfSalt),
      m_cost: ARGON2_M_COST_DEFAULT,
      t_cost: ARGON2_T_COST_DEFAULT,
      p_cost: ARGON2_P_COST_DEFAULT,
      length: PASS_KEY_LEN,
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

  // 6. Build framed payload (reuse pre-built frame if provided)
  const frameBytes =
    options?.prebuiltFrame ?? buildFrame(meta, content, options?.compress);

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
async function webOpen(
  envelope: EnvelopeJson,
  urlKey: Uint8Array,
  passphrase?: string,
): Promise<OpenResult> {
  // Validate envelope structure
  if (urlKey.length !== URL_KEY_LEN)
    throw new Error(`invalid url_key length: expected ${URL_KEY_LEN} bytes`);
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

  if (envelope.hkdf.hash !== 'SHA-256')
    throw new Error(`unsupported hkdf.hash: ${envelope.hkdf.hash}`);
  if (envelope.hkdf.enc_info !== HKDF_INFO_ENC)
    throw new Error('invalid hkdf enc_info');
  if (envelope.hkdf.claim_info !== HKDF_INFO_CLAIM)
    throw new Error('invalid hkdf claim_info');
  if (envelope.hkdf.length !== HKDF_LEN)
    throw new Error(`invalid hkdf length: ${envelope.hkdf.length}`);

  const hkdfSalt = base64urlDecode(envelope.hkdf.salt);
  if (hkdfSalt.length !== HKDF_SALT_LEN)
    throw new Error('invalid hkdf salt length');

  // Recompute IKM
  let ikm: Uint8Array;
  const kdfName = envelope.kdf.name;
  if (kdfName === 'argon2id') {
    if (!passphrase) throw new Error('passphrase required');

    const kdfBlock = envelope.kdf as KdfArgon2id;
    const kdfSalt = parseAndValidateArgon2idKdf(kdfBlock);
    const passKey = await deriveArgon2id(
      passphrase,
      kdfSalt,
      kdfBlock.m_cost,
      kdfBlock.t_cost,
      kdfBlock.p_cost,
      kdfBlock.length,
    );

    ikm = new Uint8Array(
      await crypto.subtle.digest('SHA-256', buf(concatBytes(urlKey, passKey))),
    );
  } else if (kdfName === 'none') {
    assertKdfNoneHasNoExtraFields(envelope.kdf);
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
  const { meta, body } = await parseFrame(plaintext);

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
async function webDeriveClaimToken(
  urlKey: Uint8Array,
): Promise<Uint8Array> {
  const claimSalt = new Uint8Array(
    await crypto.subtle.digest('SHA-256', buf(utf8Encode(CLAIM_SALT_LABEL))),
  );
  return hkdfDerive(urlKey, claimSalt, HKDF_INFO_CLAIM, HKDF_LEN);
}

// ── Internal helpers ────────────────────────────────────────

function assertKdfNoneHasNoExtraFields(kdf: EnvelopeJson['kdf']): void {
  const raw = kdf as unknown as Record<string, unknown>;
  for (const field of [
    'version',
    'salt',
    'm_cost',
    't_cost',
    'p_cost',
    'length',
    'iterations',
  ]) {
    if (field in raw) {
      throw new Error(`kdf.name=none must not include ${field}`);
    }
  }
}

function parseAndValidateArgon2idKdf(kdf: KdfArgon2id): Uint8Array {
  if (kdf.version !== ARGON2_VERSION)
    throw new Error(`kdf.version must be ${ARGON2_VERSION}`);

  if (!Number.isInteger(kdf.m_cost))
    throw new Error('kdf.m_cost must be an integer');
  if (!Number.isInteger(kdf.t_cost))
    throw new Error('kdf.t_cost must be an integer');
  if (!Number.isInteger(kdf.p_cost))
    throw new Error('kdf.p_cost must be an integer');

  if (kdf.m_cost < ARGON2_M_COST_MIN || kdf.m_cost > ARGON2_M_COST_MAX) {
    throw new Error(
      `kdf.m_cost must be in range ${ARGON2_M_COST_MIN}..${ARGON2_M_COST_MAX}`,
    );
  }
  if (kdf.t_cost < ARGON2_T_COST_MIN || kdf.t_cost > ARGON2_T_COST_MAX) {
    throw new Error(
      `kdf.t_cost must be in range ${ARGON2_T_COST_MIN}..${ARGON2_T_COST_MAX}`,
    );
  }
  if (kdf.p_cost < ARGON2_P_COST_MIN || kdf.p_cost > ARGON2_P_COST_MAX) {
    throw new Error(
      `kdf.p_cost must be in range ${ARGON2_P_COST_MIN}..${ARGON2_P_COST_MAX}`,
    );
  }

  if (kdf.m_cost * kdf.t_cost > ARGON2_M_COST_T_COST_PRODUCT_MAX) {
    throw new Error(
      `kdf.m_cost * kdf.t_cost must be <= ${ARGON2_M_COST_T_COST_PRODUCT_MAX}`,
    );
  }

  if (kdf.length !== PASS_KEY_LEN)
    throw new Error(`kdf.length must be ${PASS_KEY_LEN}`);

  const salt = base64urlDecode(kdf.salt);
  if (salt.length < KDF_SALT_LEN) {
    throw new Error(`kdf.salt must be at least ${KDF_SALT_LEN} bytes`);
  }

  return salt;
}

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

function cryptoRng(b: Uint8Array): void {
  crypto.getRandomValues(b);
}

// ── Bridge exports: dispatch to native (Tauri) or web crypto ──

export async function seal(
  content: Uint8Array,
  meta: PayloadMeta,
  options?: SealOptions,
): Promise<SealResult> {
  if (isTauri()) return nativeSeal(content, meta, options?.passphrase);
  return webSeal(content, meta, options);
}

export async function open(
  envelope: EnvelopeJson,
  urlKey: Uint8Array,
  passphrase?: string,
): Promise<OpenResult> {
  if (isTauri()) return nativeOpen(envelope, urlKey, passphrase);
  return webOpen(envelope, urlKey, passphrase);
}

export async function deriveClaimToken(
  urlKey: Uint8Array,
): Promise<Uint8Array> {
  if (isTauri()) return nativeDeriveClaimToken(urlKey);
  return webDeriveClaimToken(urlKey);
}
