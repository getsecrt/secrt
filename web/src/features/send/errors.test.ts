import { describe, it, expect } from 'vitest';
import { mapError } from './errors';

describe('mapError', () => {
  it('maps "too large" to size message', () => {
    expect(mapError(new Error('Request too large'))).toBe(
      'Secret is too large (max 256 KB).',
    );
  });

  it('maps "payload" to size message', () => {
    expect(mapError(new Error('413 Payload Too Large'))).toBe(
      'Secret is too large (max 256 KB).',
    );
  });

  it('maps "quota" to quota message', () => {
    expect(mapError(new Error('Storage quota exceeded'))).toBe(
      'Storage quota exceeded.',
    );
  });

  it('maps "429" to rate limit message', () => {
    expect(mapError(new Error('429 Too Many Requests'))).toBe(
      'Too many requests, wait a moment.',
    );
  });

  it('maps "rate" to rate limit message', () => {
    expect(mapError(new Error('Rate limit exceeded'))).toBe(
      'Too many requests, wait a moment.',
    );
  });

  it('maps "failed to fetch" to network message', () => {
    expect(mapError(new TypeError('Failed to fetch'))).toBe(
      'Could not reach the server.',
    );
  });

  it('maps "networkerror" to network message', () => {
    expect(mapError(new Error('NetworkError when attempting to fetch'))).toBe(
      'Could not reach the server.',
    );
  });

  it('maps "500" to server message', () => {
    expect(mapError(new Error('500 Internal Server Error'))).toBe(
      'Server error, please try again.',
    );
  });

  it('maps "server" to server message', () => {
    expect(mapError(new Error('Server error occurred'))).toBe(
      'Server error, please try again.',
    );
  });

  it('returns original message for unknown errors', () => {
    expect(mapError(new Error('Something unexpected'))).toBe(
      'Something unexpected',
    );
  });

  it('handles non-Error thrown values', () => {
    expect(mapError('a string error')).toBe('a string error');
  });

  it('returns fallback for empty message', () => {
    expect(mapError(new Error(''))).toBe('Something went wrong.');
  });

  it('handles number thrown', () => {
    expect(mapError(42)).toBe('42');
  });
});
