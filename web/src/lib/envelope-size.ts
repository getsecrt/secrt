import type { ApiInfo, EnvelopeJson } from '../types';
import { formatSize } from './format';

/**
 * Estimate the serialized envelope size from frame byte length.
 * Accounts for AES-GCM auth tag (16 bytes), base64url encoding (4/3 expansion),
 * and JSON structure overhead (~400 bytes for keys, nonces, salts, suite string).
 */
export function estimateEnvelopeSize(frameBytes: number): number {
  return Math.ceil((frameBytes + 16) * 4 / 3) + 400;
}

/**
 * Check whether a serialized envelope exceeds the server's size limit.
 * Returns an error message if too large, or null if within limits.
 */
export function checkEnvelopeSize(
  envelope: EnvelopeJson,
  info: ApiInfo | null,
  authenticated?: boolean,
): string | null {
  if (!info) return null; // no info available, let the server enforce

  const isAuthed = authenticated ?? info.authenticated;
  const tier = isAuthed ? info.limits.authed : info.limits.public;
  const envelopeSize = JSON.stringify(envelope).length;

  if (envelopeSize > tier.max_envelope_bytes) {
    return `Secret is too large (${formatSize(envelopeSize)} encrypted).\nMaximum is ${formatSize(tier.max_envelope_bytes)}.`;
  }

  return null;
}

/**
 * Build a pre-check error message when a file's frame is too large.
 * When compressed is true, notes that compression was already applied.
 */
export function frameSizeError(
  estimatedSize: number,
  maxBytes: number,
  compressed?: boolean,
): string {
  const estStr = formatSize(estimatedSize);
  const maxStr = formatSize(maxBytes);
  const qualifier = compressed ? 'encrypted & compressed' : 'encrypted';
  return `File is too large (${estStr} ${qualifier}).\nMaximum is ${maxStr}.`;
}
