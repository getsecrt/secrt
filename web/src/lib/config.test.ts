import { describe, it, expect } from 'vitest';
import { normalizeHost, isKnownInstance } from './config';

describe('normalizeHost', () => {
  it.each([
    ['secrt.ca', 'secrt.ca'],
    ['secrt.is', 'secrt.is'],
    ['www.secrt.ca', 'secrt.ca'],
    ['my.secrt.is', 'secrt.is'],
    ['foo.bar.secrt.is', 'secrt.is'],
    ['SECRT.CA', 'secrt.ca'],
    ['Secrt.Is', 'secrt.is'],
    ['secrt.ca.', 'secrt.ca'],
    ['secrt.ca:8443', 'secrt.ca'],
    ['evil.tld', 'evil.tld'],
    ['localhost', 'localhost'],
    ['', ''],
  ])('normalizes %s -> %s', (input, expected) => {
    expect(normalizeHost(input)).toBe(expected);
  });

  it('does not collapse lookalike hosts (label-boundary suffix match)', () => {
    expect(normalizeHost('foosecrt.is')).toBe('foosecrt.is');
    expect(normalizeHost('secrt.is.evil.tld')).toBe('secrt.is.evil.tld');
    expect(normalizeHost('notsecrt.ca')).toBe('notsecrt.ca');
  });
});

describe('isKnownInstance', () => {
  it.each([
    'secrt.ca',
    'secrt.is',
    'www.secrt.ca',
    'my.secrt.is',
    'team.secrt.is',
  ])('%s is a known instance', (host) => {
    expect(isKnownInstance(host)).toBe(true);
  });

  it.each([
    'secrt.evil.tld',
    'localhost',
    '',
    'foosecrt.is',
    'secrt.is.evil.tld',
    'notsecrt.ca',
  ])('%s is NOT a known instance', (host) => {
    expect(isKnownInstance(host)).toBe(false);
  });
});
