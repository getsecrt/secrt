import { describe, it, expect, beforeEach, vi } from 'vitest';
import { getSessionToken, setSessionToken, clearSessionToken } from './session';

describe('session', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  describe('getSessionToken', () => {
    it('returns null when no token stored', () => {
      expect(getSessionToken()).toBeNull();
    });

    it('returns stored token', () => {
      localStorage.setItem('session_token', 'uss_abc.secret');
      expect(getSessionToken()).toBe('uss_abc.secret');
    });

    it('returns null when localStorage throws', () => {
      vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
        throw new Error('blocked');
      });
      expect(getSessionToken()).toBeNull();
      vi.restoreAllMocks();
    });
  });

  describe('setSessionToken', () => {
    it('stores token in localStorage', () => {
      setSessionToken('uss_test.key');
      expect(localStorage.getItem('session_token')).toBe('uss_test.key');
    });

    it('does not throw when localStorage throws', () => {
      vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
        throw new Error('full');
      });
      expect(() => setSessionToken('token')).not.toThrow();
      vi.restoreAllMocks();
    });
  });

  describe('clearSessionToken', () => {
    it('removes token from localStorage', () => {
      localStorage.setItem('session_token', 'old');
      clearSessionToken();
      expect(localStorage.getItem('session_token')).toBeNull();
    });

    it('does not throw when localStorage throws', () => {
      vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {
        throw new Error('blocked');
      });
      expect(() => clearSessionToken()).not.toThrow();
      vi.restoreAllMocks();
    });
  });
});
