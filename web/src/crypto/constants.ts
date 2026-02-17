/** Protocol constants from spec/v1/envelope.md */

export const URL_KEY_LEN = 32;
export const PASS_KEY_LEN = 32;
export const HKDF_LEN = 32;
export const GCM_NONCE_LEN = 12;
export const HKDF_SALT_LEN = 32;
export const KDF_SALT_LEN = 16;

export const AAD = 'secrt.ca/envelope/v1-sealed-payload';
export const HKDF_INFO_ENC = 'secrt:v1:enc:sealed-payload';
export const HKDF_INFO_CLAIM = 'secrt:v1:claim:sealed-payload';
export const CLAIM_SALT_LABEL = 'secrt-envelope-v1-claim-salt';

export const SUITE = 'v1-argon2id-hkdf-aes256gcm-sealed-payload' as const;
export const ARGON2_VERSION = 19;
export const ARGON2_M_COST_DEFAULT = 19_456;
export const ARGON2_T_COST_DEFAULT = 2;
export const ARGON2_P_COST_DEFAULT = 1;
export const ARGON2_M_COST_MIN = 19_456;
export const ARGON2_M_COST_MAX = 65_536;
export const ARGON2_T_COST_MIN = 2;
export const ARGON2_T_COST_MAX = 10;
export const ARGON2_P_COST_MIN = 1;
export const ARGON2_P_COST_MAX = 4;
export const ARGON2_M_COST_T_COST_PRODUCT_MAX = 262_144;

export const FRAME_MAGIC = new Uint8Array([0x53, 0x43, 0x52, 0x54]); // "SCRT"
export const FRAME_VERSION = 1;
export const CODEC_NONE = 0;
export const CODEC_ZSTD = 1;

export const MAX_RAW_LEN = 104_857_600; // 100 MiB

/** Minimum raw payload size before attempting compression. */
export const COMPRESS_THRESHOLD = 2048;
/** Minimum absolute savings for compression to be used (bytes). */
export const COMPRESS_MIN_SAVINGS = 64;
/** Minimum relative savings for compression to be used (0.10 = 10%). */
export const COMPRESS_MIN_RATIO = 0.1;

/** File signatures that indicate pre-compressed/media data (skip compression). */
export const PRECOMPRESSED_SIGNATURES: readonly Uint8Array[] = [
  new Uint8Array([0x89, 0x50, 0x4e, 0x47]), // PNG
  new Uint8Array([0xff, 0xd8, 0xff]), // JPEG
  new Uint8Array([0x47, 0x49, 0x46, 0x38]), // GIF
  new Uint8Array([0x52, 0x49, 0x46, 0x46]), // WEBP (RIFF container)
  new Uint8Array([0x50, 0x4b, 0x03, 0x04]), // ZIP
  new Uint8Array([0x1f, 0x8b]), // gzip
  new Uint8Array([0x42, 0x5a, 0x68]), // bzip2
  new Uint8Array([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]), // xz
  new Uint8Array([0x28, 0xb5, 0x2f, 0xfd]), // zstd
  new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]), // 7z
  new Uint8Array([0x25, 0x50, 0x44, 0x46]), // PDF
  new Uint8Array([0x00, 0x00, 0x00]), // MP4 (ftyp comes after size)
  new Uint8Array([0x49, 0x44, 0x33]), // MP3 (ID3 tag)
  new Uint8Array([0xff, 0xfb]), // MP3 (MPEG frame sync)
];
