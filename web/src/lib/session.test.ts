import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  getSessionToken,
  getSessionTokenSync,
  setSessionToken,
  clearSessionToken,
} from './session';

describe('session', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  describe('getSessionToken (async)', () => {
    it('returns null when no token stored', async () => {
      expect(await getSessionToken()).toBeNull();
    });

    it('returns stored token', async () => {
      localStorage.setItem('session_token', 'uss_abc.secret');
      expect(await getSessionToken()).toBe('uss_abc.secret');
    });

    it('returns null when localStorage throws', async () => {
      vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
        throw new Error('blocked');
      });
      expect(await getSessionToken()).toBeNull();
      vi.restoreAllMocks();
    });
  });

  describe('getSessionTokenSync', () => {
    it('returns null when no token stored', () => {
      expect(getSessionTokenSync()).toBeNull();
    });

    it('returns stored token', () => {
      localStorage.setItem('session_token', 'uss_sync.secret');
      expect(getSessionTokenSync()).toBe('uss_sync.secret');
    });
  });

  describe('setSessionToken (async)', () => {
    it('stores token in localStorage', async () => {
      await setSessionToken('uss_test.key');
      expect(localStorage.getItem('session_token')).toBe('uss_test.key');
    });

    it('does not throw when localStorage throws', async () => {
      vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
        throw new Error('full');
      });
      await expect(setSessionToken('token')).resolves.toBeUndefined();
      vi.restoreAllMocks();
    });
  });

  describe('clearSessionToken (async)', () => {
    it('removes token from localStorage', async () => {
      localStorage.setItem('session_token', 'old');
      await clearSessionToken();
      expect(localStorage.getItem('session_token')).toBeNull();
    });

    it('does not throw when localStorage throws', async () => {
      vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {
        throw new Error('blocked');
      });
      await expect(clearSessionToken()).resolves.toBeUndefined();
      vi.restoreAllMocks();
    });
  });
});
