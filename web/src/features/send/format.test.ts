import { describe, it, expect } from 'vitest';
import { formatSize } from './format';

describe('formatSize', () => {
  it('formats 0 bytes', () => {
    expect(formatSize(0)).toBe('0 B');
  });

  it('formats small bytes', () => {
    expect(formatSize(500)).toBe('500 B');
  });

  it('formats just under 1 KB', () => {
    expect(formatSize(1023)).toBe('1023 B');
  });

  it('formats exactly 1 KB', () => {
    expect(formatSize(1024)).toBe('1.0 KB');
  });

  it('formats 1.5 KB', () => {
    expect(formatSize(1536)).toBe('1.5 KB');
  });

  it('formats just under 1 MB', () => {
    expect(formatSize(1024 * 1024 - 1)).toBe('1024.0 KB');
  });

  it('formats exactly 1 MB', () => {
    expect(formatSize(1024 * 1024)).toBe('1.0 MB');
  });

  it('formats 1.5 MB', () => {
    expect(formatSize(1572864)).toBe('1.5 MB');
  });
});
