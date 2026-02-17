use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// Crypto constants from spec/v1/envelope.md.
pub const URL_KEY_LEN: usize = 32;
pub const PASS_KEY_LEN: usize = 32;
pub const HKDF_LEN: usize = 32;
pub const GCM_NONCE_LEN: usize = 12;
pub const HKDF_SALT_LEN: usize = 32;
pub const KDF_SALT_LEN: usize = 16;
pub const AAD: &[u8] = b"secrt.ca/envelope/v1-sealed-payload";
pub const HKDF_INFO_ENC: &str = "secrt:v1:enc:sealed-payload";
pub const HKDF_INFO_CLAIM: &str = "secrt:v1:claim:sealed-payload";
pub const CLAIM_SALT_LABEL: &str = "secrt-envelope-v1-claim-salt";
pub const SUITE: &str = "v1-argon2id-hkdf-aes256gcm-sealed-payload";

pub const ARGON2_VERSION: u32 = 19;
pub const ARGON2_M_COST_DEFAULT: u32 = 19_456;
pub const ARGON2_T_COST_DEFAULT: u32 = 2;
pub const ARGON2_P_COST_DEFAULT: u32 = 1;

pub const ARGON2_M_COST_MIN: u32 = 19_456;
pub const ARGON2_M_COST_MAX: u32 = 65_536;
pub const ARGON2_T_COST_MIN: u32 = 2;
pub const ARGON2_T_COST_MAX: u32 = 10;
pub const ARGON2_P_COST_MIN: u32 = 1;
pub const ARGON2_P_COST_MAX: u32 = 4;
pub const ARGON2_M_COST_T_COST_PRODUCT_MAX: u64 = 262_144;

pub const PAYLOAD_MAGIC: &[u8; 4] = b"SCRT";
pub const PAYLOAD_FRAME_VERSION: u8 = 1;

pub const MAX_DECOMPRESSED_BYTES_DEFAULT: usize = 100 * 1024 * 1024;
pub const COMPRESSION_THRESHOLD_BYTES_DEFAULT: usize = 2048;
pub const COMPRESSION_MIN_SAVINGS_BYTES_DEFAULT: usize = 64;
pub const COMPRESSION_MIN_SAVINGS_RATIO_DEFAULT: f64 = 0.10;
pub const ZSTD_LEVEL_DEFAULT: i32 = 3;

/// Envelope is the JSON structure stored on the server.
#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u32,
    pub suite: String,
    pub enc: EncBlock,
    pub kdf: serde_json::Value,
    pub hkdf: HkdfBlock,
}

/// EncBlock holds the AES-GCM ciphertext.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncBlock {
    pub alg: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// HkdfBlock holds the HKDF parameters.
#[derive(Debug, Serialize, Deserialize)]
pub struct HkdfBlock {
    pub hash: String,
    pub salt: String,
    pub enc_info: String,
    pub claim_info: String,
    pub length: u32,
}

/// KDFNone is the KDF block when no passphrase is used.
#[derive(Debug, Serialize, Deserialize)]
pub struct KdfNone {
    pub name: String,
}

/// KDFArgon2id is the KDF block when a passphrase is used.
#[derive(Debug, Serialize, Deserialize)]
pub struct KdfArgon2id {
    pub name: String,
    pub version: u32,
    pub salt: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub length: u32,
}

/// Internal representation after parsing KDF JSON.
pub struct KdfParsed {
    pub name: String,
    pub version: u32,
    pub salt: Vec<u8>,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadType {
    Text,
    File,
    Binary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadMeta {
    #[serde(rename = "type")]
    pub payload_type: PayloadType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl PayloadMeta {
    pub fn text() -> Self {
        Self {
            payload_type: PayloadType::Text,
            filename: None,
            mime: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn binary() -> Self {
        Self {
            payload_type: PayloadType::Binary,
            filename: None,
            mime: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn file(filename: String, mime: String) -> Self {
        Self {
            payload_type: PayloadType::File,
            filename: Some(filename),
            mime: Some(mime),
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadCodec {
    None,
    Zstd,
}

#[derive(Debug, Clone, Copy)]
pub struct CompressionPolicy {
    pub threshold_bytes: usize,
    pub min_savings_bytes: usize,
    pub min_savings_ratio: f64,
    pub zstd_level: i32,
}

impl Default for CompressionPolicy {
    fn default() -> Self {
        Self {
            threshold_bytes: COMPRESSION_THRESHOLD_BYTES_DEFAULT,
            min_savings_bytes: COMPRESSION_MIN_SAVINGS_BYTES_DEFAULT,
            min_savings_ratio: COMPRESSION_MIN_SAVINGS_RATIO_DEFAULT,
            zstd_level: ZSTD_LEVEL_DEFAULT,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OpenResult {
    pub content: Vec<u8>,
    pub metadata: PayloadMeta,
    pub codec: PayloadCodec,
}

/// Parameters for creating an encrypted envelope.
pub struct SealParams<'a> {
    pub content: Vec<u8>,
    pub metadata: PayloadMeta,
    pub passphrase: String,
    pub rand_bytes: &'a dyn Fn(&mut [u8]) -> Result<(), EnvelopeError>,
    pub compression_policy: CompressionPolicy,
}

/// Outputs from creating an encrypted envelope.
pub struct SealResult {
    pub envelope: serde_json::Value,
    pub url_key: Vec<u8>,
    pub claim_token: Vec<u8>,
    pub claim_hash: String,
}

/// Parameters for decrypting an envelope.
pub struct OpenParams {
    pub envelope: serde_json::Value,
    pub url_key: Vec<u8>,
    pub passphrase: String,
}

#[derive(Debug)]
pub enum EnvelopeError {
    EmptyPlaintext,
    InvalidEnvelope(String),
    DecryptionFailed,
    InvalidFrame(String),
    UnsupportedCodec(u8),
    DecompressedTooLarge { max: usize, requested: usize },
    FrameLengthMismatch(String),
    CompressionFailed(String),
    DecompressionFailed(String),
    InvalidFragment(String),
    InvalidUrlKey,
    InvalidTtl(String),
    RngError(String),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvelopeError::EmptyPlaintext => write!(f, "plaintext must not be empty"),
            EnvelopeError::InvalidEnvelope(msg) => write!(f, "invalid envelope: {}", msg),
            EnvelopeError::DecryptionFailed => write!(f, "decryption failed"),
            EnvelopeError::InvalidFrame(msg) => write!(f, "invalid payload frame: {}", msg),
            EnvelopeError::UnsupportedCodec(v) => write!(f, "unsupported payload codec id {}", v),
            EnvelopeError::DecompressedTooLarge { max, requested } => write!(
                f,
                "decompressed payload too large: {} bytes (max {})",
                requested, max
            ),
            EnvelopeError::FrameLengthMismatch(msg) => {
                write!(f, "payload frame length mismatch: {}", msg)
            }
            EnvelopeError::CompressionFailed(msg) => write!(f, "compression failed: {}", msg),
            EnvelopeError::DecompressionFailed(msg) => write!(f, "decompression failed: {}", msg),
            EnvelopeError::InvalidFragment(msg) => write!(f, "invalid URL fragment: {}", msg),
            EnvelopeError::InvalidUrlKey => write!(f, "url_key must be 32 bytes"),
            EnvelopeError::InvalidTtl(msg) => write!(f, "invalid TTL: {}", msg),
            EnvelopeError::RngError(msg) => write!(f, "read random bytes: {}", msg),
        }
    }
}

impl std::error::Error for EnvelopeError {}
