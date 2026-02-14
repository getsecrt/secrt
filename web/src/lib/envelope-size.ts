import type { ApiInfo, EnvelopeJson } from '../types';

/**
 * Check whether a serialized envelope exceeds the server's size limit.
 * Returns an error message if too large, or null if within limits.
 */
export function checkEnvelopeSize(
  envelope: EnvelopeJson,
  info: ApiInfo | null,
): string | null {
  if (!info) return null; // no info available, let the server enforce

  const tier = info.authenticated ? info.limits.authed : info.limits.public;
  const envelopeSize = JSON.stringify(envelope).length;

  if (envelopeSize > tier.max_envelope_bytes) {
    const maxKB = Math.floor(tier.max_envelope_bytes / 1024);
    return `Secret is too large. Maximum size is ${maxKB} KB.`;
  }

  return null;
}
