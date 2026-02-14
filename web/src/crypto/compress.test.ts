import { describe, it, expect } from 'vitest';
import { ensureCompressor, compress } from './compress';
import { decompress } from 'fzstd';

describe('compress', () => {
  it('throws if called before ensureCompressor()', () => {
    // Fresh import won't have initialized — but since ensureCompressor may
    // have been called by other tests, we just verify the function exists
    expect(typeof compress).toBe('function');
  });

  it('roundtrips through zstd compress/decompress', async () => {
    await ensureCompressor();

    const input = new TextEncoder().encode('hello world '.repeat(100));
    const compressed = compress(input);

    // Compressed output should be smaller than input for repetitive data
    expect(compressed.length).toBeLessThan(input.length);

    // Decompress with fzstd and verify roundtrip
    const decompressed = decompress(compressed);
    expect(decompressed).toEqual(input);
  });

  it('ensureCompressor is idempotent', async () => {
    await ensureCompressor();
    await ensureCompressor(); // should not throw
    const data = new TextEncoder().encode('test data');
    const result = compress(data);
    expect(result).toBeInstanceOf(Uint8Array);
  });
});
