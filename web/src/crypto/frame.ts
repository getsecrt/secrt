import { decompress as zstdDecompress } from 'fzstd';
import type { PayloadMeta } from '../types';
import {
  FRAME_MAGIC,
  FRAME_VERSION,
  CODEC_NONE,
  CODEC_ZSTD,
  MAX_RAW_LEN,
  COMPRESS_THRESHOLD,
  COMPRESS_MIN_SAVINGS,
  COMPRESS_MIN_RATIO,
  PRECOMPRESSED_SIGNATURES,
} from './constants';
import { utf8Encode, utf8Decode, concatBytes } from './encoding';

/** Build the payload frame from metadata and body content. */
export function buildFrame(
  meta: PayloadMeta,
  body: Uint8Array,
  compress?: (data: Uint8Array) => Uint8Array,
): Uint8Array {
  const metaJson = utf8Encode(JSON.stringify(meta));
  const rawLen = body.length;

  let codec = CODEC_NONE;
  let frameBody = body;

  if (compress && rawLen >= COMPRESS_THRESHOLD && !isPrecompressed(body)) {
    const compressed = compress(body);
    const savings = rawLen - compressed.length;
    if (
      savings >= COMPRESS_MIN_SAVINGS &&
      savings / rawLen >= COMPRESS_MIN_RATIO
    ) {
      codec = CODEC_ZSTD;
      frameBody = compressed;
    }
  }

  // Header: magic(4) + version(1) + codec(1) + reserved(2) + meta_len(4) + raw_len(4) = 16
  const header = new Uint8Array(16);
  header.set(FRAME_MAGIC, 0);
  header[4] = FRAME_VERSION;
  header[5] = codec;
  header[6] = 0; // reserved high byte
  header[7] = 0; // reserved low byte
  writeU32BE(header, 8, metaJson.length);
  writeU32BE(header, 12, rawLen);

  return concatBytes(header, metaJson, frameBody);
}

/** Parse a payload frame back into metadata and body. */
export function parseFrame(frame: Uint8Array): {
  meta: PayloadMeta;
  body: Uint8Array;
} {
  if (frame.length < 16) {
    throw new Error('frame too short');
  }

  // Validate magic
  for (let i = 0; i < 4; i++) {
    if (frame[i] !== FRAME_MAGIC[i]) {
      throw new Error('invalid frame magic');
    }
  }

  if (frame[4] !== FRAME_VERSION) {
    throw new Error(`unsupported frame version: ${frame[4]}`);
  }

  const codec = frame[5];
  if (codec !== CODEC_NONE && codec !== CODEC_ZSTD) {
    throw new Error(`unsupported codec: ${codec}`);
  }

  const reserved = (frame[6] << 8) | frame[7];
  if (reserved !== 0) {
    throw new Error('non-zero reserved field');
  }

  const metaLen = readU32BE(frame, 8);
  const rawLen = readU32BE(frame, 12);

  if (rawLen > MAX_RAW_LEN) {
    throw new Error(`raw_len ${rawLen} exceeds 100 MiB cap`);
  }

  const metaStart = 16;
  const metaEnd = metaStart + metaLen;
  if (metaEnd > frame.length) {
    throw new Error('meta_len exceeds frame size');
  }

  const metaBytes = frame.slice(metaStart, metaEnd);
  const meta = JSON.parse(utf8Decode(metaBytes)) as PayloadMeta;

  const bodyBytes = frame.slice(metaEnd);

  let body: Uint8Array;
  if (codec === CODEC_ZSTD) {
    body = zstdDecompress(bodyBytes);
    if (body.length !== rawLen) {
      throw new Error(
        `decompressed length ${body.length} != raw_len ${rawLen}`,
      );
    }
  } else {
    if (bodyBytes.length !== rawLen) {
      throw new Error(`body length ${bodyBytes.length} != raw_len ${rawLen}`);
    }
    body = bodyBytes;
  }

  return { meta, body };
}

/** Check if content starts with a known pre-compressed file signature. */
function isPrecompressed(data: Uint8Array): boolean {
  for (const sig of PRECOMPRESSED_SIGNATURES) {
    if (data.length >= sig.length) {
      let match = true;
      for (let i = 0; i < sig.length; i++) {
        if (data[i] !== sig[i]) {
          match = false;
          break;
        }
      }
      if (match) return true;
    }
  }
  return false;
}

function writeU32BE(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = (value >>> 24) & 0xff;
  buf[offset + 1] = (value >>> 16) & 0xff;
  buf[offset + 2] = (value >>> 8) & 0xff;
  buf[offset + 3] = value & 0xff;
}

function readU32BE(buf: Uint8Array, offset: number): number {
  return (
    ((buf[offset] << 24) |
      (buf[offset + 1] << 16) |
      (buf[offset + 2] << 8) |
      buf[offset + 3]) >>>
    0
  );
}
