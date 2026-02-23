import { base64urlEncode, base64urlDecode } from '../crypto/encoding';
import { URL_KEY_LEN } from '../crypto/constants';
import { isTauri } from './config';

/**
 * Format a share link from secret ID and url_key.
 * Fragment carries the base64url-encoded url_key.
 * Defaults to the current origin so links work in both dev and production.
 */
export function formatShareLink(
  id: string,
  urlKey: Uint8Array,
  baseUrl?: string,
): string {
  const origin = baseUrl ?? (isTauri() ? 'https://secrt.ca' : window.location.origin);
  return `${origin}/s/${id}#${base64urlEncode(urlKey)}`;
}

/**
 * Format a sync link for AMK transfer between browsers.
 * Uses /sync/ prefix instead of /s/ to trigger the auto-import flow.
 */
export function formatSyncLink(
  id: string,
  urlKey: Uint8Array,
  baseUrl?: string,
): string {
  const origin = baseUrl ?? (isTauri() ? 'https://secrt.ca' : window.location.origin);
  return `${origin}/sync/${id}#${base64urlEncode(urlKey)}`;
}

/** Minimum secret ID length (real IDs are 22 chars / 16 bytes base64url). */
const MIN_ID_LEN = 16;

/**
 * Parse a share URL, extracting the secret ID and url_key.
 * Tolerates missing protocol (prepends https://).
 * Returns null if the URL doesn't match the expected format.
 */
export function parseShareUrl(
  url: string,
): { id: string; urlKey: Uint8Array } | null {
  try {
    // Allow pasting without protocol — prepend https:// if missing
    let normalized = url;
    if (!/^https?:\/\//i.test(normalized)) {
      normalized = `https://${normalized}`;
    }

    const parsed = new URL(normalized);
    const match = parsed.pathname.match(/^\/s\/([a-zA-Z0-9_-]+)\/?$/);
    if (!match || match[1].length < MIN_ID_LEN) return null;

    const fragment = parsed.hash.slice(1); // strip leading #
    if (!fragment) return null;

    const urlKey = base64urlDecode(fragment);
    if (urlKey.length !== URL_KEY_LEN) return null;

    return { id: match[1], urlKey };
  } catch {
    return null;
  }
}
