import { base64urlEncode, utf8Encode } from './encoding';

const ROOT_SALT_LABEL = 'secrt-apikey-v2-root-salt';
const HKDF_INFO_AUTH = 'secrt-auth';
const ROOT_KEY_LEN = 32;
const AUTH_TOKEN_LEN = 32;

/** Copy Uint8Array to a fresh ArrayBuffer to satisfy strict TS BufferSource typing. */
const buf = (a: Uint8Array): ArrayBuffer => {
  const b = new ArrayBuffer(a.byteLength);
  new Uint8Array(b).set(a);
  return b;
};

/** Compute the salt: SHA-256(ROOT_SALT_LABEL). */
async function rootSalt(): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', buf(utf8Encode(ROOT_SALT_LABEL)));
}

/** Derive the auth token from a 32-byte root key using HKDF-SHA256. */
export async function deriveAuthToken(rootKey: Uint8Array): Promise<Uint8Array> {
  if (rootKey.length !== ROOT_KEY_LEN) {
    throw new Error(`root key must be ${ROOT_KEY_LEN} bytes`);
  }

  const salt = await rootSalt();
  const ikm = await crypto.subtle.importKey('raw', buf(rootKey), 'HKDF', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: buf(utf8Encode(HKDF_INFO_AUTH)),
    },
    ikm,
    AUTH_TOKEN_LEN * 8,
  );
  return new Uint8Array(bits);
}

/** Generate a fresh API key root and derive its auth token. */
export async function generateApiKeyMaterial(): Promise<{
  rootKey: Uint8Array;
  authToken: Uint8Array;
  authTokenB64: string;
}> {
  const rootKey = new Uint8Array(ROOT_KEY_LEN);
  crypto.getRandomValues(rootKey);
  const authToken = await deriveAuthToken(rootKey);
  return {
    rootKey,
    authToken,
    authTokenB64: base64urlEncode(authToken),
  };
}

/** Format the wire API key string: ak2_<prefix>.<b64(authToken)> */
export function formatWireApiKey(prefix: string, authToken: Uint8Array): string {
  return `ak2_${prefix}.${base64urlEncode(authToken)}`;
}
