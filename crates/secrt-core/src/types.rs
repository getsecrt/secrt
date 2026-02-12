use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// Crypto constants from spec/v1/envelope.md.
pub const URL_KEY_LEN: usize = 32;
pub const PASS_KEY_LEN: usize = 32;
pub const HKDF_LEN: usize = 32;
pub const GCM_NONCE_LEN: usize = 12;
pub const HKDF_SALT_LEN: usize = 32;
pub const KDF_SALT_LEN: usize = 16;
pub const AAD: &[u8] = b"secrt.ca/envelope/v1";
pub const HKDF_INFO_ENC: &str = "secret:v1:enc";
pub const HKDF_INFO_CLAIM: &str = "secret:v1:claim";
pub const SUITE: &str = "v1-pbkdf2-hkdf-aes256gcm";

pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 600_000;
pub const MIN_PBKDF2_ITERATIONS: u32 = 300_000;

/// Envelope is the JSON structure stored on the server.
#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u32,
    pub suite: String,
    pub enc: EncBlock,
    pub kdf: serde_json::Value,
    pub hkdf: HkdfBlock,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<HashMap<String, String>>,
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

/// KDFPBKDF2 is the KDF block when a passphrase is used.
#[derive(Debug, Serialize, Deserialize)]
pub struct KdfPbkdf2 {
    pub name: String,
    pub salt: String,
    pub iterations: u32,
    pub length: u32,
}

/// Internal representation after parsing KDF JSON.
pub struct KdfParsed {
    pub name: String,
    pub salt: Vec<u8>,
    pub iterations: u32,
}

/// Parameters for creating an encrypted envelope.
pub struct SealParams<'a> {
    pub plaintext: Vec<u8>,
    pub passphrase: String,
    pub rand_bytes: &'a dyn Fn(&mut [u8]) -> Result<(), EnvelopeError>,
    pub hint: Option<HashMap<String, String>>,
    pub iterations: u32,
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
            EnvelopeError::InvalidFragment(msg) => write!(f, "invalid URL fragment: {}", msg),
            EnvelopeError::InvalidUrlKey => write!(f, "url_key must be 32 bytes"),
            EnvelopeError::InvalidTtl(msg) => write!(f, "invalid TTL: {}", msg),
            EnvelopeError::RngError(msg) => write!(f, "read random bytes: {}", msg),
        }
    }
}

impl std::error::Error for EnvelopeError {}
