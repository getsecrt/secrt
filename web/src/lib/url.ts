import { base64urlEncode, base64urlDecode } from '../crypto/encoding';
import { URL_KEY_LEN } from '../crypto/constants';

const DEFAULT_HOST = 'secrt.ca';

/**
 * Format a share link from secret ID and url_key.
 * Fragment carries the base64url-encoded url_key.
 */
export function formatShareLink(
  id: string,
  urlKey: Uint8Array,
  host?: string,
): string {
  return `https://${host ?? DEFAULT_HOST}/s/${id}#${base64urlEncode(urlKey)}`;
}

/**
 * Parse a share URL, extracting the secret ID and url_key.
 * Returns null if the URL doesn't match the expected format.
 */
export function parseShareUrl(
  url: string,
): { id: string; urlKey: Uint8Array } | null {
  try {
    const parsed = new URL(url);
    const match = parsed.pathname.match(/^\/s\/([a-zA-Z0-9_-]+)\/?$/);
    if (!match) return null;

    const fragment = parsed.hash.slice(1); // strip leading #
    if (!fragment) return null;

    const urlKey = base64urlDecode(fragment);
    if (urlKey.length !== URL_KEY_LEN) return null;

    return { id: match[1], urlKey };
  } catch {
    return null;
  }
}
