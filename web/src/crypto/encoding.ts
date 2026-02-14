/** Encode bytes to base64url (no padding). */
export function base64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

/** Decode base64url string to bytes. */
export function base64urlDecode(value: string): Uint8Array {
  const padded = value + '='.repeat((4 - (value.length % 4)) % 4);
  const b64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

/** Encode bytes to lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Encode UTF-8 string to bytes. */
export function utf8Encode(str: string): Uint8Array {
  return encoder.encode(str);
}

/** Decode bytes to UTF-8 string. */
export function utf8Decode(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Concatenate multiple Uint8Arrays. */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let totalLen = 0;
  for (const arr of arrays) totalLen += arr.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
