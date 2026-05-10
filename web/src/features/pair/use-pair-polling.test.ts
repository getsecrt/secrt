import { describe, it, expect } from 'vitest';
import { nextPollDelayMs } from './use-pair-polling';

describe('nextPollDelayMs', () => {
  it('returns 1s during the first 10 s', () => {
    expect(nextPollDelayMs(0)).toBe(1_000);
    expect(nextPollDelayMs(5_000)).toBe(1_000);
    expect(nextPollDelayMs(9_999)).toBe(1_000);
  });

  it('returns 2s in the 10-60 s window', () => {
    expect(nextPollDelayMs(10_000)).toBe(2_000);
    expect(nextPollDelayMs(30_000)).toBe(2_000);
    expect(nextPollDelayMs(59_999)).toBe(2_000);
  });

  it('returns 5s after 60 s', () => {
    expect(nextPollDelayMs(60_000)).toBe(5_000);
    expect(nextPollDelayMs(600_000)).toBe(5_000);
  });
});
