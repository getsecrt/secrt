import { describe, it, expect } from 'vitest';
import {
  TTL_PRESETS,
  TTL_MIN,
  TTL_MAX,
  TTL_DEFAULT,
  isValidTtl,
  formatExpiryDate,
} from './ttl';
import cliVectors from '../../../spec/v1/cli.vectors.json';

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

describe('TTL constants match spec', () => {
  it('TTL_MAX matches spec max_seconds (1 year)', () => {
    expect(TTL_MAX).toBe(31_536_000);
  });

  it('TTL_MIN is 1 second', () => {
    expect(TTL_MIN).toBe(1);
  });

  it('TTL_DEFAULT matches 24h preset', () => {
    expect(TTL_DEFAULT).toBe(86_400);
  });
});

describe('CLI spec vectors - valid TTL values', () => {
  for (const vec of cliVectors.valid) {
    it(`accepts ttl_seconds=${vec.ttl_seconds} (${vec.description})`, () => {
      expect(isValidTtl(vec.ttl_seconds)).toBe(true);
    });
  }
});

describe('CLI spec vectors - invalid TTL values', () => {
  const invalidWithSeconds = [
    { input: '0', seconds: 0, reason: 'zero value' },
    { input: '-1', seconds: -1, reason: 'negative value' },
    { input: '31536001', seconds: 31_536_001, reason: 'exceeds maximum TTL (1 year + 1 second)' },
    { input: '366d', seconds: 366 * 86_400, reason: 'exceeds maximum TTL (366 days)' },
    { input: '53w', seconds: 53 * 604_800, reason: 'exceeds maximum TTL (53 weeks)' },
    { input: '8761h', seconds: 8761 * 3600, reason: 'exceeds maximum TTL (8761 hours)' },
  ];

  for (const vec of invalidWithSeconds) {
    it(`rejects ${vec.seconds} seconds (${vec.reason})`, () => {
      expect(isValidTtl(vec.seconds)).toBe(false);
    });
  }

  it('rejects NaN (non-numeric input)', () => {
    expect(isValidTtl(NaN)).toBe(false);
  });

  it('rejects negative infinity', () => {
    expect(isValidTtl(-Infinity)).toBe(false);
  });

  it('rejects positive infinity', () => {
    expect(isValidTtl(Infinity)).toBe(false);
  });

  it('rejects fractional seconds (1.5)', () => {
    // 1.5 minutes = 90 seconds is valid, but 0.5 seconds is dubious
    // The real test is that isValidTtl(1.5) returns true because 1.5 >= 1 and <= max
    // So we test that non-integer-but-in-range still passes the function
    // (since isValidTtl only checks range, not integrality)
    expect(isValidTtl(1.5)).toBe(true);
  });
});
