import { describe, expect, it } from 'vitest';
import {
  DEFAULT_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  generatePassword,
} from './password-generator';

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@*^_+-=?';

function makeCounterRandom() {
  let counter = 0;
  return (buffer: Uint8Array) => {
    for (let i = 0; i < buffer.length; i += 1) {
      buffer[i] = counter;
      counter = (counter + 1) & 0xff;
    }
  };
}

function classIndex(ch: string): number {
  if (LOWERCASE.includes(ch)) return 0;
  if (UPPERCASE.includes(ch)) return 1;
  if (DIGITS.includes(ch)) return 2;
  if (SYMBOLS.includes(ch)) return 3;
  throw new Error(`unexpected character: ${ch}`);
}

describe('password generator', () => {
  it('uses CLI default length and includes all character classes', () => {
    const password = generatePassword({}, makeCounterRandom());

    expect(password).toHaveLength(DEFAULT_PASSWORD_LENGTH);
    expect([...password].some((ch) => LOWERCASE.includes(ch))).toBe(true);
    expect([...password].some((ch) => UPPERCASE.includes(ch))).toBe(true);
    expect([...password].some((ch) => DIGITS.includes(ch))).toBe(true);
    expect([...password].some((ch) => SYMBOLS.includes(ch))).toBe(true);
  });

  it('enforces minimum length based on enabled classes', () => {
    expect(() =>
      generatePassword({ length: MIN_PASSWORD_LENGTH - 1 }, makeCounterRandom()),
    ).toThrow(/too short/);
  });

  it('grouped mode keeps class runs contiguous', () => {
    const password = generatePassword(
      { length: DEFAULT_PASSWORD_LENGTH, grouped: true },
      makeCounterRandom(),
    );

    const runs: number[] = [];
    let lastClass = -1;
    for (const ch of password) {
      const currentClass = classIndex(ch);
      if (currentClass !== lastClass) {
        runs.push(currentClass);
        lastClass = currentClass;
      }
    }

    expect(runs).toHaveLength(4);
    expect(new Set(runs).size).toBe(4);
  });
});
