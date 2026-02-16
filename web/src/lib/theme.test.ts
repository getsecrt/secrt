import { describe, it, expect, beforeEach } from 'vitest';
import {
  getSendPasswordGeneratorSettings,
  isDark,
  setDarkMode,
  setSendPasswordGeneratorSettings,
} from './theme';

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

describe('send password generator settings', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('returns defaults when no settings are stored', () => {
    expect(getSendPasswordGeneratorSettings(20, 4)).toEqual({
      length: 20,
      grouped: false,
    });
  });

  it('reads persisted settings from localStorage', () => {
    localStorage.setItem('send_password_length', '32');
    localStorage.setItem('send_password_grouped', 'true');

    expect(getSendPasswordGeneratorSettings(20, 4)).toEqual({
      length: 32,
      grouped: true,
    });
  });

  it('ignores invalid stored length', () => {
    localStorage.setItem('send_password_length', '2');
    localStorage.setItem('send_password_grouped', 'true');

    expect(getSendPasswordGeneratorSettings(20, 4)).toEqual({
      length: 20,
      grouped: true,
    });
  });

  it('writes settings to localStorage', () => {
    setSendPasswordGeneratorSettings(24, true);
    expect(localStorage.getItem('send_password_length')).toBe('24');
    expect(localStorage.getItem('send_password_grouped')).toBe('true');
  });

  it('does not throw when localStorage is unavailable', () => {
    const origSet = Storage.prototype.setItem;
    const origGet = Storage.prototype.getItem;

    Storage.prototype.setItem = () => {
      throw new Error('quota exceeded');
    };
    Storage.prototype.getItem = () => {
      throw new Error('unavailable');
    };

    try {
      expect(() => setSendPasswordGeneratorSettings(24, false)).not.toThrow();
      expect(() => getSendPasswordGeneratorSettings(20, 4)).not.toThrow();
    } finally {
      Storage.prototype.setItem = origSet;
      Storage.prototype.getItem = origGet;
    }
  });
});
