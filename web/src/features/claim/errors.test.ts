import { describe, it, expect } from 'vitest';
import { mapClaimError } from './errors';

describe('mapClaimError', () => {
  it('all results have step: "error"', () => {
    const result = mapClaimError(new Error('anything'));
    expect(result.step).toBe('error');
  });

  // ── 404 / not found → unavailable ──
  it('maps "404" to unavailable', () => {
    const result = mapClaimError(new Error('HTTP 404'));
    expect(result.code).toBe('unavailable');
  });

  it('maps "not found" to unavailable', () => {
    const result = mapClaimError(new Error('Secret not found'));
    expect(result.code).toBe('unavailable');
  });

  // ── 429 / rate → network ──
  it('maps "429" to network', () => {
    const result = mapClaimError(new Error('HTTP 429'));
    expect(result.code).toBe('network');
    expect(result.message).toMatch(/too many requests/i);
  });

  it('maps "rate" to network', () => {
    const result = mapClaimError(new Error('Rate limited'));
    expect(result.code).toBe('network');
  });

  // ── fetch / networkerror → network ──
  it('maps "failed to fetch" to network', () => {
    const result = mapClaimError(new Error('Failed to fetch'));
    expect(result.code).toBe('network');
    expect(result.message).toMatch(/could not reach/i);
  });

  it('maps "networkerror" to network', () => {
    const result = mapClaimError(new Error('NetworkError when attempting'));
    expect(result.code).toBe('network');
  });

  // ── 500 / server → network ──
  it('maps "500" to network', () => {
    const result = mapClaimError(new Error('HTTP 500'));
    expect(result.code).toBe('network');
    expect(result.message).toMatch(/server error/i);
  });

  it('maps "server" to network', () => {
    const result = mapClaimError(new Error('Internal server error'));
    expect(result.code).toBe('network');
  });

  // ── case insensitive ──
  it('matches case-insensitively', () => {
    expect(mapClaimError(new Error('NOT FOUND')).code).toBe('unavailable');
    expect(mapClaimError(new Error('FAILED TO FETCH')).code).toBe('network');
  });

  // ── unknown fallback ──
  it('maps unrecognized error to unknown, preserves message', () => {
    const result = mapClaimError(new Error('Something weird happened'));
    expect(result.code).toBe('unknown');
    expect(result.message).toBe('Something weird happened');
  });

  it('handles non-Error thrown values (string)', () => {
    const result = mapClaimError('string error');
    expect(result.code).toBe('unknown');
    expect(result.message).toBe('string error');
  });

  it('handles non-Error thrown values (number)', () => {
    const result = mapClaimError(42);
    expect(result.code).toBe('unknown');
    expect(result.message).toBe('42');
  });

  it('uses fallback message for empty string', () => {
    const result = mapClaimError(new Error(''));
    expect(result.code).toBe('unknown');
    expect(result.message).toBe('Something went wrong.');
  });
});
