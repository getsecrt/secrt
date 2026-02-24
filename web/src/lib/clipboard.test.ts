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

  it('falls back to execCommand when Clipboard API fails', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        writeText: vi.fn().mockRejectedValue(new Error('denied')),
      },
      writable: true,
      configurable: true,
    });

    const execCommand = vi.fn().mockReturnValue(true);
    document.execCommand = execCommand;

    const appendSpy = vi.spyOn(document.body, 'appendChild');
    const removeSpy = vi.spyOn(document.body, 'removeChild');

    expect(await copyToClipboard('fallback text')).toBe(true);
    expect(execCommand).toHaveBeenCalledWith('copy');
    expect(appendSpy).toHaveBeenCalled();
    expect(removeSpy).toHaveBeenCalled();
  });

  it('falls back to execCommand when Clipboard API is missing', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        writeText: vi.fn().mockRejectedValue(new Error('not available')),
      },
      writable: true,
      configurable: true,
    });

    document.execCommand = vi.fn().mockReturnValue(true);

    expect(await copyToClipboard('test')).toBe(true);
  });

  it('returns false when both methods fail', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        writeText: vi.fn().mockRejectedValue(new Error('denied')),
      },
      writable: true,
      configurable: true,
    });

    document.execCommand = vi.fn().mockImplementation(() => {
      throw new Error('execCommand failed');
    });

    expect(await copyToClipboard('fail')).toBe(false);
  });

  it('creates and cleans up textarea element in fallback', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        writeText: vi.fn().mockRejectedValue(new Error('denied')),
      },
      writable: true,
      configurable: true,
    });

    document.execCommand = vi.fn().mockReturnValue(true);

    const appendSpy = vi.spyOn(document.body, 'appendChild');
    const removeSpy = vi.spyOn(document.body, 'removeChild');

    await copyToClipboard('cleanup test');

    const textarea = appendSpy.mock.calls[0][0] as HTMLTextAreaElement;
    expect(textarea.tagName).toBe('TEXTAREA');
    expect(textarea.value).toBe('cleanup test');
    expect(textarea.style.position).toBe('fixed');
    expect(textarea.style.opacity).toBe('0');
    expect(removeSpy).toHaveBeenCalledWith(textarea);
  });
});

describe('copySensitive', () => {
  let originalClipboard: Clipboard;
  const originalWindow = window as Record<string, unknown>;

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

  it('returns false when both Tauri and browser clipboard fail', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        writeText: vi.fn().mockRejectedValue(new Error('denied')),
      },
      writable: true,
      configurable: true,
    });
    document.execCommand = vi.fn().mockImplementation(() => {
      throw new Error('execCommand failed');
    });

    const result = await copySensitive('fail');
    expect(result).toBe(false);
  });
});
