import { describe, expect, it, vi } from 'vitest';
import { registerServiceWorker } from './pwa';

describe('registerServiceWorker', () => {
  it('does not register when not in production', () => {
    const register = vi.fn().mockResolvedValue(undefined);
    const addEventListener = vi.fn();

    registerServiceWorker({
      isProduction: false,
      nav: { serviceWorker: { register } } as unknown as Pick<
        Navigator,
        'serviceWorker'
      >,
      win: { addEventListener } as unknown as Pick<Window, 'addEventListener'>,
    });

    expect(addEventListener).not.toHaveBeenCalled();
    expect(register).not.toHaveBeenCalled();
  });

  it('skips registration when serviceWorker is not supported', () => {
    const addEventListener = vi.fn();

    registerServiceWorker({
      isProduction: true,
      nav: {} as unknown as Pick<Navigator, 'serviceWorker'>,
      win: { addEventListener } as unknown as Pick<Window, 'addEventListener'>,
    });

    expect(addEventListener).not.toHaveBeenCalled();
  });

  it('registers /sw.js on window load in production', () => {
    const register = vi.fn().mockResolvedValue(undefined);
    const loadHandlers: Array<() => void> = [];
    const addEventListener = vi.fn((event: string, cb: () => void) => {
      if (event === 'load') {
        loadHandlers.push(cb);
      }
    });

    registerServiceWorker({
      isProduction: true,
      nav: { serviceWorker: { register } } as unknown as Pick<
        Navigator,
        'serviceWorker'
      >,
      win: { addEventListener } as unknown as Pick<Window, 'addEventListener'>,
    });

    expect(addEventListener).toHaveBeenCalledWith('load', expect.any(Function));
    expect(register).not.toHaveBeenCalled();

    expect(loadHandlers).toHaveLength(1);
    loadHandlers[0]?.();

    expect(register).toHaveBeenCalledWith('/sw.js', {
      scope: '/',
      updateViaCache: 'none',
    });
  });

  it('swallows registration errors silently', () => {
    const register = vi.fn().mockRejectedValue(new Error('SW failed'));
    const loadHandlers: Array<() => void> = [];
    const addEventListener = vi.fn((event: string, cb: () => void) => {
      if (event === 'load') {
        loadHandlers.push(cb);
      }
    });

    registerServiceWorker({
      isProduction: true,
      nav: { serviceWorker: { register } } as unknown as Pick<
        Navigator,
        'serviceWorker'
      >,
      win: { addEventListener } as unknown as Pick<Window, 'addEventListener'>,
    });

    loadHandlers[0]?.();

    expect(register).toHaveBeenCalled();
    // The .catch(() => undefined) should prevent unhandled rejection
  });
});
