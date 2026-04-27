import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { copyToClipboard, copySensitive } from './clipboard';

describe('copyToClipboard', () => {
  let originalClipboard: Clipboard;

  beforeEach(() => {
    originalClipboard = navigator.clipboard;
  });

  afterEach(() => {
    Object.defineProperty(navigator, 'clipboard', {
      value: originalClipboard,
      writable: true,
      configurable: true,
    });
    vi.restoreAllMocks();
  });

  it('returns true when Clipboard API succeeds', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
      writable: true,
      configurable: true,
    });

    expect(await copyToClipboard('hello')).toBe(true);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('hello');
  });

  it('returns false when Clipboard API fails', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        writeText: vi.fn().mockRejectedValue(new Error('denied')),
      },
      writable: true,
      configurable: true,
    });

    expect(await copyToClipboard('fail')).toBe(false);
  });
});

describe('copySensitive', () => {
  let originalClipboard: Clipboard;
  const originalWindow = window as unknown as Record<string, unknown>;

  beforeEach(() => {
    originalClipboard = navigator.clipboard;
  });

  afterEach(() => {
    Object.defineProperty(navigator, 'clipboard', {
      value: originalClipboard,
      writable: true,
      configurable: true,
    });
    delete originalWindow.__TAURI_INTERNALS__;
    vi.restoreAllMocks();
  });

  it('calls Tauri IPC when __TAURI_INTERNALS__ is present', async () => {
    const mockInvoke = vi.fn().mockResolvedValue(undefined);
    originalWindow.__TAURI_INTERNALS__ = {};
    vi.doMock('@tauri-apps/api/core', () => ({ invoke: mockInvoke }));

    // Re-import to pick up the mock
    const { copySensitive: cs } = await import('./clipboard');
    const result = await cs('my-secret');

    expect(result).toBe(true);
    expect(mockInvoke).toHaveBeenCalledWith('copy_sensitive', {
      text: 'my-secret',
    });

    vi.doUnmock('@tauri-apps/api/core');
  });

  it('falls back to copyToClipboard on web (no Tauri)', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
      writable: true,
      configurable: true,
    });

    const result = await copySensitive('web-secret');
    expect(result).toBe(true);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('web-secret');
  });

  it('returns false when browser clipboard fails (no Tauri)', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        writeText: vi.fn().mockRejectedValue(new Error('denied')),
      },
      writable: true,
      configurable: true,
    });

    const result = await copySensitive('fail');
    expect(result).toBe(false);
  });
});
