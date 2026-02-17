import { describe, it, expect } from 'vitest';
import { buildFrame, parseFrame } from './frame';
import {
  FRAME_MAGIC,
  FRAME_VERSION,
  CODEC_NONE,
  CODEC_ZSTD,
  MAX_RAW_LEN,
  COMPRESS_THRESHOLD,
  COMPRESS_MIN_SAVINGS,
  COMPRESS_MIN_RATIO,
} from './constants';
import { utf8Encode, concatBytes } from './encoding';
import type { PayloadMeta } from '../types';

/** Helper: build a valid frame header manually. */
function makeHeader(
  codec: number,
  metaLen: number,
  rawLen: number,
  opts?: { magic?: Uint8Array; version?: number; reserved?: number },
): Uint8Array {
  const header = new Uint8Array(16);
  header.set(opts?.magic ?? FRAME_MAGIC, 0);
  header[4] = opts?.version ?? FRAME_VERSION;
  header[5] = codec;
  const reserved = opts?.reserved ?? 0;
  header[6] = (reserved >>> 8) & 0xff;
  header[7] = reserved & 0xff;
  // Write meta_len as big-endian u32
  header[8] = (metaLen >>> 24) & 0xff;
  header[9] = (metaLen >>> 16) & 0xff;
  header[10] = (metaLen >>> 8) & 0xff;
  header[11] = metaLen & 0xff;
  // Write raw_len as big-endian u32
  header[12] = (rawLen >>> 24) & 0xff;
  header[13] = (rawLen >>> 16) & 0xff;
  header[14] = (rawLen >>> 8) & 0xff;
  header[15] = rawLen & 0xff;
  return header;
}

describe('buildFrame', () => {
  it('builds a text frame with correct 16-byte header', () => {
    const meta: PayloadMeta = { type: 'text' };
    const body = utf8Encode('hello');
    const frame = buildFrame(meta, body);

    // Header is 16 bytes
    expect(frame.length).toBeGreaterThanOrEqual(16);

    // Magic bytes
    expect(frame.slice(0, 4)).toEqual(FRAME_MAGIC);
    // Version
    expect(frame[4]).toBe(FRAME_VERSION);
    // Codec = none (body too small for compression)
    expect(frame[5]).toBe(CODEC_NONE);
    // Reserved = 0
    expect(frame[6]).toBe(0);
    expect(frame[7]).toBe(0);
  });

  it('builds a file frame with filename and mime in metadata', async () => {
    const meta: PayloadMeta = {
      type: 'file',
      filename: 'test.txt',
      mime: 'text/plain',
    };
    const body = utf8Encode('file contents');
    const frame = buildFrame(meta, body);

    const parsed = await parseFrame(frame);
    expect(parsed.meta.type).toBe('file');
    expect(parsed.meta.filename).toBe('test.txt');
    expect(parsed.meta.mime).toBe('text/plain');
  });

  it('round-trips: buildFrame -> parseFrame returns same meta + body', async () => {
    const meta: PayloadMeta = { type: 'text' };
    const body = utf8Encode('round trip test');
    const frame = buildFrame(meta, body);
    const parsed = await parseFrame(frame);

    expect(parsed.meta).toEqual(meta);
    expect(parsed.body).toEqual(body);
  });

  it('round-trips with binary metadata', async () => {
    const meta: PayloadMeta = { type: 'binary' };
    const body = new Uint8Array([0x00, 0xff, 0x80, 0x7f]);
    const frame = buildFrame(meta, body);
    const parsed = await parseFrame(frame);

    expect(parsed.meta).toEqual(meta);
    expect(parsed.body).toEqual(body);
  });

  it('round-trips with empty body', async () => {
    const meta: PayloadMeta = { type: 'text' };
    const body = new Uint8Array([]);
    const frame = buildFrame(meta, body);
    const parsed = await parseFrame(frame);

    expect(parsed.meta).toEqual(meta);
    expect(parsed.body).toEqual(body);
  });
});

describe('buildFrame compression policy', () => {
  it('does not attempt compression when body < COMPRESS_THRESHOLD', () => {
    const meta: PayloadMeta = { type: 'text' };
    const body = new Uint8Array(COMPRESS_THRESHOLD - 1).fill(0x41);
    let called = false;
    const compress = (data: Uint8Array) => {
      called = true;
      return data;
    };
    buildFrame(meta, body, compress);
    expect(called).toBe(false);
  });

  it('does not compress pre-compressed data (PNG signature)', () => {
    const meta: PayloadMeta = { type: 'file', filename: 'img.png' };
    const body = new Uint8Array(COMPRESS_THRESHOLD + 100);
    body[0] = 0x89;
    body[1] = 0x50;
    body[2] = 0x4e;
    body[3] = 0x47;
    let called = false;
    const compress = (data: Uint8Array) => {
      called = true;
      return data;
    };
    buildFrame(meta, body, compress);
    expect(called).toBe(false);
  });

  it('does not compress pre-compressed data (JPEG signature)', () => {
    const meta: PayloadMeta = { type: 'file' };
    const body = new Uint8Array(COMPRESS_THRESHOLD + 100);
    body[0] = 0xff;
    body[1] = 0xd8;
    body[2] = 0xff;
    let called = false;
    const compress = (_data: Uint8Array) => {
      called = true;
      return _data;
    };
    buildFrame(meta, body, compress);
    expect(called).toBe(false);
  });

  it('does not compress pre-compressed data (ZIP signature)', () => {
    const meta: PayloadMeta = { type: 'file' };
    const body = new Uint8Array(COMPRESS_THRESHOLD + 100);
    body[0] = 0x50;
    body[1] = 0x4b;
    body[2] = 0x03;
    body[3] = 0x04;
    let called = false;
    const compress = (_data: Uint8Array) => {
      called = true;
      return _data;
    };
    buildFrame(meta, body, compress);
    expect(called).toBe(false);
  });

  it('does not compress pre-compressed data (gzip signature)', () => {
    const meta: PayloadMeta = { type: 'file' };
    const body = new Uint8Array(COMPRESS_THRESHOLD + 100);
    body[0] = 0x1f;
    body[1] = 0x8b;
    let called = false;
    const compress = (_data: Uint8Array) => {
      called = true;
      return _data;
    };
    buildFrame(meta, body, compress);
    expect(called).toBe(false);
  });

  it('does not compress pre-compressed data (zstd signature)', () => {
    const meta: PayloadMeta = { type: 'file' };
    const body = new Uint8Array(COMPRESS_THRESHOLD + 100);
    body[0] = 0x28;
    body[1] = 0xb5;
    body[2] = 0x2f;
    body[3] = 0xfd;
    let called = false;
    const compress = (_data: Uint8Array) => {
      called = true;
      return _data;
    };
    buildFrame(meta, body, compress);
    expect(called).toBe(false);
  });

  it('falls back to codec=none when savings < COMPRESS_MIN_SAVINGS', () => {
    const meta: PayloadMeta = { type: 'text' };
    const body = new Uint8Array(COMPRESS_THRESHOLD).fill(0x41);
    // Compress returns data that saves less than COMPRESS_MIN_SAVINGS
    const compress = (data: Uint8Array) =>
      data.slice(0, data.length - (COMPRESS_MIN_SAVINGS - 1));
    const frame = buildFrame(meta, body, compress);
    expect(frame[5]).toBe(CODEC_NONE); // codec byte
  });

  it('falls back to codec=none when ratio < COMPRESS_MIN_RATIO', () => {
    const meta: PayloadMeta = { type: 'text' };
    // Use a large body so absolute savings is met but ratio isn't
    const size = Math.ceil(COMPRESS_MIN_SAVINGS / (COMPRESS_MIN_RATIO - 0.01));
    const body = new Uint8Array(Math.max(size, COMPRESS_THRESHOLD)).fill(0x41);
    // Save exactly COMPRESS_MIN_SAVINGS bytes (but ratio won't be enough for a huge body)
    const compress = (data: Uint8Array) =>
      data.slice(0, data.length - COMPRESS_MIN_SAVINGS);
    const frame = buildFrame(meta, body, compress);
    // With small savings relative to body size, ratio < 10%
    // This depends on body size; for a body of ~641 bytes, 64/641 ≈ 10%
    // We need a body large enough that COMPRESS_MIN_SAVINGS / body.length < COMPRESS_MIN_RATIO
    // 64 / body.length < 0.1 → body.length > 640 → use 2048+
    // At 2048, 64/2048 = 3.1% < 10%, so codec should be none
    expect(frame[5]).toBe(CODEC_NONE);
  });

  it('uses zstd codec when compression is effective', () => {
    const meta: PayloadMeta = { type: 'text' };
    const body = new Uint8Array(COMPRESS_THRESHOLD).fill(0x41);
    // Compress returns much smaller data
    const compress = (_data: Uint8Array) => new Uint8Array(100);
    const frame = buildFrame(meta, body, compress);
    expect(frame[5]).toBe(CODEC_ZSTD);
  });
});

describe('parseFrame', () => {
  it('parses a valid codec=none frame', async () => {
    const meta: PayloadMeta = { type: 'text' };
    const metaJson = utf8Encode(JSON.stringify(meta));
    const body = utf8Encode('test body');
    const header = makeHeader(CODEC_NONE, metaJson.length, body.length);
    const frame = concatBytes(header, metaJson, body);

    const result = await parseFrame(frame);
    expect(result.meta).toEqual(meta);
    expect(result.body).toEqual(body);
  });

  it('throws on frame too short (<16 bytes)', async () => {
    await expect(parseFrame(new Uint8Array(15))).rejects.toThrow(
      'frame too short',
    );
  });

  it('throws on invalid magic bytes', async () => {
    const header = makeHeader(CODEC_NONE, 0, 0, {
      magic: new Uint8Array([0x00, 0x00, 0x00, 0x00]),
    });
    await expect(parseFrame(header)).rejects.toThrow('invalid frame magic');
  });

  it('throws on unsupported version', async () => {
    const header = makeHeader(CODEC_NONE, 0, 0, { version: 99 });
    await expect(parseFrame(header)).rejects.toThrow(
      'unsupported frame version: 99',
    );
  });

  it('throws on unsupported codec', async () => {
    const meta: PayloadMeta = { type: 'text' };
    const metaJson = utf8Encode(JSON.stringify(meta));
    const body = new Uint8Array(0);
    const header = makeHeader(0x02, metaJson.length, body.length);
    const frame = concatBytes(header, metaJson, body);
    await expect(parseFrame(frame)).rejects.toThrow('unsupported codec: 2');
  });

  it('throws on non-zero reserved field', async () => {
    const header = makeHeader(CODEC_NONE, 0, 0, { reserved: 1 });
    await expect(parseFrame(header)).rejects.toThrow(
      'non-zero reserved field',
    );
  });

  it('throws when meta_len exceeds frame size', async () => {
    const header = makeHeader(CODEC_NONE, 1000, 0);
    // Frame is only 16 bytes, but meta_len says 1000
    await expect(parseFrame(header)).rejects.toThrow(
      'meta_len exceeds frame size',
    );
  });

  it('throws when body length != raw_len for codec=none', async () => {
    const meta: PayloadMeta = { type: 'text' };
    const metaJson = utf8Encode(JSON.stringify(meta));
    const body = utf8Encode('short');
    // Set raw_len to something larger than actual body
    const header = makeHeader(CODEC_NONE, metaJson.length, body.length + 10);
    const frame = concatBytes(header, metaJson, body);
    await expect(parseFrame(frame)).rejects.toThrow('body length');
  });

  it('throws when raw_len exceeds MAX_RAW_LEN', async () => {
    const meta: PayloadMeta = { type: 'text' };
    const metaJson = utf8Encode(JSON.stringify(meta));
    const header = makeHeader(CODEC_NONE, metaJson.length, MAX_RAW_LEN + 1);
    const frame = concatBytes(header, metaJson, new Uint8Array(0));
    await expect(parseFrame(frame)).rejects.toThrow('exceeds 100 MiB cap');
  });
});
