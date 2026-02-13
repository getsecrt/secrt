use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use secrt_core::{
    compute_auth_hash_hex, parse_wire_api_key, ParsedWireApiKey, API_KEY_PREFIX_BYTES,
    WIRE_API_KEY_PREFIX,
};

use crate::storage::{ApiKeyRecord, ApiKeysStore, StorageError};

pub const API_KEY_PREFIX: &str = WIRE_API_KEY_PREFIX;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid api key")]
    InvalidApiKey,
    #[error("missing api key pepper")]
    MissingPepper,
    #[error("storage error: {0}")]
    Storage(String),
}

#[derive(Clone, Debug)]
pub struct ParsedApiKey {
    pub prefix: String,
    pub auth_token: Vec<u8>,
}

#[derive(Clone)]
pub struct Authenticator<S>
where
    S: ApiKeysStore,
{
    pepper: String,
    store: S,
}

impl<S> Authenticator<S>
where
    S: ApiKeysStore,
{
    pub fn new(pepper: String, store: S) -> Self {
        Self { pepper, store }
    }

    pub async fn authenticate(&self, raw_key: &str) -> Result<ApiKeyRecord, AuthError> {
        let parsed = parse_api_key(raw_key)?;
        let expected = hash_api_key_auth_token(&self.pepper, &parsed.prefix, &parsed.auth_token)?;

        let key = self
            .store
            .get_by_prefix(&parsed.prefix)
            .await
            .map_err(|e| match e {
                StorageError::NotFound => AuthError::InvalidApiKey,
                other => AuthError::Storage(other.to_string()),
            })?;

        if key.revoked_at.is_some() {
            return Err(AuthError::InvalidApiKey);
        }

        if !secure_equals_hex(&key.auth_hash, &expected) {
            return Err(AuthError::InvalidApiKey);
        }

        Ok(key)
    }
}

pub fn parse_api_key(key: &str) -> Result<ParsedApiKey, AuthError> {
    let ParsedWireApiKey {
        prefix, auth_token, ..
    } = parse_wire_api_key(key).map_err(|_| AuthError::InvalidApiKey)?;
    Ok(ParsedApiKey { prefix, auth_token })
}

pub fn hash_api_key_auth_token(
    pepper: &str,
    prefix: &str,
    auth_token: &[u8],
) -> Result<String, AuthError> {
    compute_auth_hash_hex(pepper, prefix, auth_token).map_err(|e| match e {
        secrt_core::ApiKeyError::MissingPepper => AuthError::MissingPepper,
        _ => AuthError::InvalidApiKey,
    })
}

pub fn secure_equals_hex(a: &str, b: &str) -> bool {
    let Ok(ab) = hex::decode(a) else {
        return false;
    };
    let Ok(bb) = hex::decode(b) else {
        return false;
    };

    constant_time_eq(&ab, &bb)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn generate_api_key_prefix() -> Result<String, AuthError> {
    let rng = SystemRandom::new();
    let mut prefix_bytes = [0u8; API_KEY_PREFIX_BYTES];
    rng.fill(&mut prefix_bytes)
        .map_err(|_| AuthError::Storage("generate api key prefix".into()))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(prefix_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use secrt_core::{derive_auth_token, format_wire_api_key};

    #[test]
    fn parse_key_shape() {
        let auth = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let k = format!("{API_KEY_PREFIX}abcdef.{auth}");
        let p = parse_api_key(&k).unwrap();
        assert_eq!(p.prefix, "abcdef");
        assert_eq!(p.auth_token.len(), 32);
        assert!(parse_api_key("bad").is_err());
    }

    #[test]
    fn hash_and_compare() {
        let auth = [1u8; 32];
        let h1 = hash_api_key_auth_token("pepper", "prefix", &auth).unwrap();
        let h2 = hash_api_key_auth_token("pepper", "prefix", &auth).unwrap();
        assert!(secure_equals_hex(&h1, &h2));
        assert!(!secure_equals_hex(&h1, "deadbeef"));
    }

    #[test]
    fn generate_prefix() {
        let prefix = generate_api_key_prefix().unwrap();
        assert!(!prefix.is_empty());
        assert!(prefix.len() >= API_KEY_PREFIX_BYTES);
    }

    #[test]
    fn parse_key_invalid_shapes() {
        assert!(parse_api_key("ak2_short.a").is_err());
        assert!(parse_api_key("ak2_missingdot").is_err());
        assert!(parse_api_key("ak2_abcdef.").is_err());
        assert!(parse_api_key("  ").is_err());
    }

    #[test]
    fn hash_requires_pepper() {
        assert!(matches!(
            hash_api_key_auth_token("", "abcdef", &[7u8; 32]),
            Err(AuthError::MissingPepper)
        ));
    }

    #[test]
    fn local_to_wire_roundtrip_hashes() {
        let root = [3u8; 32];
        let auth = derive_auth_token(&root).expect("derive");
        let wire = format_wire_api_key("abcdef", &auth).expect("wire");
        let parsed = parse_api_key(&wire).expect("parse");
        assert_eq!(parsed.prefix, "abcdef");
        assert_eq!(parsed.auth_token, auth);
    }
}
