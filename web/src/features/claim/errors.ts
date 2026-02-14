export interface ClaimError {
  step: 'error';
  code:
    | 'no-fragment'
    | 'invalid-fragment'
    | 'unavailable'
    | 'decrypt'
    | 'network'
    | 'unknown';
  message: string;
}

export function mapClaimError(err: unknown): ClaimError {
  const msg = err instanceof Error ? err.message : String(err);
  const lower = msg.toLowerCase();

  if (lower.includes('404') || lower.includes('not found'))
    return {
      step: 'error',
      code: 'unavailable',
      message:
        'This secret is no longer available.\nIt may have already been viewed or expired.',
    };
  if (lower.includes('429') || lower.includes('rate'))
    return {
      step: 'error',
      code: 'network',
      message: 'Too many requests. Please wait a moment and try again.',
    };
  if (lower.includes('failed to fetch') || lower.includes('networkerror'))
    return {
      step: 'error',
      code: 'network',
      message:
        'Could not reach the server. Check your connection and try again.',
    };
  if (lower.includes('500') || lower.includes('server'))
    return {
      step: 'error',
      code: 'network',
      message: 'Server error. Please try again later.',
    };
  return {
    step: 'error',
    code: 'unknown',
    message: msg || 'Something went wrong.',
  };
}
