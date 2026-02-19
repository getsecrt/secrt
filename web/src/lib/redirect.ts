/**
 * Read and validate the `redirect` query parameter from the current URL.
 * Returns a safe relative path, falling back to '/' if missing or invalid.
 */
export function getRedirectParam(): string {
  const params = new URLSearchParams(window.location.search);
  const raw = params.get('redirect');
  if (!raw) return '/';

  // Only allow relative paths starting with '/' to prevent open redirects.
  // Block protocol-relative URLs (//evil.com) and non-path values.
  if (raw.startsWith('/') && !raw.startsWith('//')) {
    return raw;
  }

  return '/';
}
