import { describe, it, expect } from 'vitest';
import {
  TTL_PRESETS,
  TTL_MIN,
  TTL_MAX,
  TTL_DEFAULT,
  isValidTtl,
  formatExpiryDate,
} from './ttl';

describe('TTL constants', () => {
  it('has expected default', () => {
    expect(TTL_DEFAULT).toBe(86_400);
  });

  it('default is one of the presets', () => {
    expect(TTL_PRESETS.some((p) => p.seconds === TTL_DEFAULT)).toBe(true);
  });

  it('presets are in ascending order', () => {
    for (let i = 1; i < TTL_PRESETS.length; i++) {
      expect(TTL_PRESETS[i].seconds).toBeGreaterThan(TTL_PRESETS[i - 1].seconds);
    }
  });
});

describe('isValidTtl', () => {
  it('accepts TTL_MIN', () => {
    expect(isValidTtl(TTL_MIN)).toBe(true);
  });

  it('accepts TTL_MAX', () => {
    expect(isValidTtl(TTL_MAX)).toBe(true);
  });

  it('accepts a mid-range value', () => {
    expect(isValidTtl(3600)).toBe(true);
  });

  it('rejects zero', () => {
    expect(isValidTtl(0)).toBe(false);
  });

  it('rejects negative', () => {
    expect(isValidTtl(-1)).toBe(false);
  });

  it('rejects above max', () => {
    expect(isValidTtl(TTL_MAX + 1)).toBe(false);
  });

  it('rejects NaN', () => {
    expect(isValidTtl(NaN)).toBe(false);
  });

  it('rejects Infinity', () => {
    expect(isValidTtl(Infinity)).toBe(false);
  });
});

describe('formatExpiryDate', () => {
  it('formats a valid ISO string', () => {
    const result = formatExpiryDate('2026-03-15T10:30:00Z');
    // Locale-dependent, but should contain the date components
    expect(result).toContain('2026');
    expect(result).toContain('15');
  });

  it('returns the input for an invalid date string', () => {
    expect(formatExpiryDate('not-a-date')).toBe('not-a-date');
  });

  it('returns the input for an empty string', () => {
    expect(formatExpiryDate('')).toBe('');
  });
});
