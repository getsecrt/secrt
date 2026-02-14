/** Map a caught error into a user-friendly message. */
export function mapError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  const lower = msg.toLowerCase();
  if (lower.includes('too large') || lower.includes('payload'))
    return 'Secret is too large (max 256 KB).';
  if (lower.includes('quota')) return 'Storage quota exceeded.';
  if (lower.includes('429') || lower.includes('rate'))
    return 'Too many requests, wait a moment.';
  if (lower.includes('failed to fetch') || lower.includes('networkerror'))
    return 'Could not reach the server.';
  if (lower.includes('500') || lower.includes('server'))
    return 'Server error, please try again.';
  return msg || 'Something went wrong.';
}
