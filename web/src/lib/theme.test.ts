import { describe, it, expect, beforeEach } from 'vitest';
import { isDark, setDarkMode } from './theme';

describe('isDark', () => {
  beforeEach(() => {
    document.documentElement.classList.remove('dark');
  });

  it('returns false when dark class is absent', () => {
    expect(isDark()).toBe(false);
  });

  it('returns true when dark class is present', () => {
    document.documentElement.classList.add('dark');
    expect(isDark()).toBe(true);
  });
});

describe('setDarkMode', () => {
  beforeEach(() => {
    document.documentElement.classList.remove('dark');
    localStorage.clear();
  });

  it('adds dark class and writes "dark" to localStorage', () => {
    setDarkMode(true);
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(localStorage.getItem('theme')).toBe('dark');
  });

  it('removes dark class and writes "light" to localStorage', () => {
    document.documentElement.classList.add('dark');
    setDarkMode(false);
    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(localStorage.getItem('theme')).toBe('light');
  });

  it('toggles from light to dark', () => {
    setDarkMode(true);
    expect(isDark()).toBe(true);
    setDarkMode(false);
    expect(isDark()).toBe(false);
  });

  it('does not throw when localStorage is unavailable', () => {
    const orig = Storage.prototype.setItem;
    Storage.prototype.setItem = () => {
      throw new Error('quota exceeded');
    };
    try {
      expect(() => setDarkMode(true)).not.toThrow();
      expect(document.documentElement.classList.contains('dark')).toBe(true);
    } finally {
      Storage.prototype.setItem = orig;
    }
  });
});
