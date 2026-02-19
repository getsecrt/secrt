use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::digest::{digest, SHA256};
use ring::hkdf;
use ring::hmac;

pub const LOCAL_API_KEY_PREFIX: &str = "sk2_";
pub const WIRE_API_KEY_PREFIX: &str = "ak2_";
pub const API_KEY_PREFIX_BYTES: usize = 6;
pub const API_KEY_ROOT_LEN: usize = 32;
pub const API_KEY_AUTH_LEN: usize = 32;
pub const API_KEY_META_LEN: usize = 32;
pub const ROOT_SALT_LABEL: &[u8] = b"secrt-apikey-v2-root-salt";
pub const HKDF_INFO_AUTH: &str = "secrt-auth";
pub const HKDF_INFO_META: &str = "secrt-meta-encrypt";
pub const VERIFIER_DOMAIN_TAG: &[u8] = b"secrt-apikey-v2-verifier";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedLocalApiKey {
    pub prefix: String,
    pub root_b64: String,
    pub root_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedWireApiKey {
    pub prefix: String,
    pub auth_b64: String,
    pub auth_token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiKeyError {
    InvalidFormat,
    InvalidPrefix,
    InvalidBase64,
    InvalidLength,
    MissingPepper,
    DeriveFailed,
}

impl std::fmt::Display for ApiKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiKeyError::InvalidFormat => write!(f, "invalid api key format"),
            ApiKeyError::InvalidPrefix => write!(f, "invalid api key prefix"),
            ApiKeyError::InvalidBase64 => write!(f, "invalid base64url data"),
            ApiKeyError::InvalidLength => write!(f, "invalid key length"),
            ApiKeyError::MissingPepper => write!(f, "missing api key pepper"),
            ApiKeyError::DeriveFailed => write!(f, "failed to derive key material"),
        }
    }
}

impl std::error::Error for ApiKeyError {}

pub fn parse_local_api_key(raw: &str) -> Result<ParsedLocalApiKey, ApiKeyError> {
    parse_api_key(raw, LOCAL_API_KEY_PREFIX, API_KEY_ROOT_LEN).map(|(prefix, value_b64, value)| {
        ParsedLocalApiKey {
            prefix,
            root_b64: value_b64,
            root_key: value,
        }
    })
}

pub fn parse_wire_api_key(raw: &str) -> Result<ParsedWireApiKey, ApiKeyError> {
    parse_api_key(raw, WIRE_API_KEY_PREFIX, API_KEY_AUTH_LEN).map(|(prefix, value_b64, value)| {
        ParsedWireApiKey {
            prefix,
            auth_b64: value_b64,
            auth_token: value,
        }
    })
}

fn parse_api_key(
    raw: &str,
    expected_prefix: &str,
    expected_len: usize,
) -> Result<(String, String, Vec<u8>), ApiKeyError> {
    let key = raw.trim();
    if !key.starts_with(expected_prefix) {
        return Err(ApiKeyError::InvalidFormat);
    }

    let rest = &key[expected_prefix.len()..];
    let Some((prefix, value_b64)) = rest.split_once('.') else {
        return Err(ApiKeyError::InvalidFormat);
    };
    if !is_valid_prefix(prefix) {
        return Err(ApiKeyError::InvalidPrefix);
    }

    let value = URL_SAFE_NO_PAD
        .decode(value_b64)
        .map_err(|_| ApiKeyError::InvalidBase64)?;
    if value.len() != expected_len {
        return Err(ApiKeyError::InvalidLength);
    }

    Ok((prefix.to_string(), value_b64.to_string(), value))
}

pub fn derive_auth_token(root_key: &[u8]) -> Result<Vec<u8>, ApiKeyError> {
    derive_from_root(root_key, HKDF_INFO_AUTH, API_KEY_AUTH_LEN)
}

pub fn derive_meta_key(root_key: &[u8]) -> Result<Vec<u8>, ApiKeyError> {
    derive_from_root(root_key, HKDF_INFO_META, API_KEY_META_LEN)
}

pub(crate) fn derive_from_root(
    root_key: &[u8],
    info: &str,
    out_len: usize,
) -> Result<Vec<u8>, ApiKeyError> {
    if root_key.len() != API_KEY_ROOT_LEN {
        return Err(ApiKeyError::InvalidLength);
    }
    let salt_bytes = root_salt();
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt_bytes);
    let prk = salt.extract(root_key);
    let info_parts = [info.as_bytes()];
    let okm = prk
        .expand(&info_parts, HkdfLen(out_len))
        .map_err(|_| ApiKeyError::DeriveFailed)?;
    let mut out = vec![0u8; out_len];
    okm.fill(&mut out).map_err(|_| ApiKeyError::DeriveFailed)?;
    Ok(out)
}

struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

pub fn root_salt() -> [u8; 32] {
    let d = digest(&SHA256, ROOT_SALT_LABEL);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

pub fn format_wire_api_key(prefix: &str, auth_token: &[u8]) -> Result<String, ApiKeyError> {
    if !is_valid_prefix(prefix) {
        return Err(ApiKeyError::InvalidPrefix);
    }
    if auth_token.len() != API_KEY_AUTH_LEN {
        return Err(ApiKeyError::InvalidLength);
    }
    let auth_b64 = URL_SAFE_NO_PAD.encode(auth_token);
    Ok(format!("{WIRE_API_KEY_PREFIX}{prefix}.{auth_b64}"))
}

pub fn derive_wire_api_key(local_key: &str) -> Result<String, ApiKeyError> {
    let parsed = parse_local_api_key(local_key)?;
    let auth = derive_auth_token(&parsed.root_key)?;
    format_wire_api_key(&parsed.prefix, &auth)
}

pub fn is_valid_prefix(prefix: &str) -> bool {
    prefix.len() >= API_KEY_PREFIX_BYTES
        && prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn build_auth_verifier_message(
    prefix: &str,
    auth_token: &[u8],
) -> Result<Vec<u8>, ApiKeyError> {
    if !is_valid_prefix(prefix) {
        return Err(ApiKeyError::InvalidPrefix);
    }
    if auth_token.len() != API_KEY_AUTH_LEN {
        return Err(ApiKeyError::InvalidLength);
    }

    let mut msg =
        Vec::with_capacity(VERIFIER_DOMAIN_TAG.len() + 2 + prefix.len() + auth_token.len());
    msg.extend_from_slice(VERIFIER_DOMAIN_TAG);
    let p_len = prefix.len() as u16;
    msg.extend_from_slice(&p_len.to_be_bytes());
    msg.extend_from_slice(prefix.as_bytes());
    msg.extend_from_slice(auth_token);
    Ok(msg)
}

pub fn compute_auth_hash_hex(
    pepper: &str,
    prefix: &str,
    auth_token: &[u8],
) -> Result<String, ApiKeyError> {
    if pepper.is_empty() {
        return Err(ApiKeyError::MissingPepper);
    }
    let msg = build_auth_verifier_message(prefix, auth_token)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, pepper.as_bytes());
    Ok(hex::encode(hmac::sign(&key, &msg).as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_derive_wire_key() {
        let root = [7u8; API_KEY_ROOT_LEN];
        let local = format!("sk2_abcdef.{}", URL_SAFE_NO_PAD.encode(root));
        let wire = derive_wire_api_key(&local).expect("derive");
        assert!(wire.starts_with("ak2_abcdef."));
        let parsed_wire = parse_wire_api_key(&wire).expect("parse wire");
        assert_eq!(parsed_wire.auth_token.len(), API_KEY_AUTH_LEN);
    }

    #[test]
    fn invalid_prefix_rejected() {
        let root = [1u8; API_KEY_ROOT_LEN];
        let local = format!("sk2_bad:prefix.{}", URL_SAFE_NO_PAD.encode(root));
        assert!(matches!(
            parse_local_api_key(&local),
            Err(ApiKeyError::InvalidPrefix)
        ));
    }

    #[test]
    fn verifier_message_is_structured() {
        let auth = [9u8; API_KEY_AUTH_LEN];
        let msg = build_auth_verifier_message("abcdef", &auth).expect("msg");
        assert!(msg.starts_with(VERIFIER_DOMAIN_TAG));
        let len_off = VERIFIER_DOMAIN_TAG.len();
        let p_len = u16::from_be_bytes([msg[len_off], msg[len_off + 1]]);
        assert_eq!(p_len, 6);
        let prefix = &msg[len_off + 2..len_off + 2 + p_len as usize];
        assert_eq!(prefix, b"abcdef");
    }
}
