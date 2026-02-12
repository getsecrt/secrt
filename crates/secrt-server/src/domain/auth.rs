use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

use crate::storage::{ApiKeyRecord, ApiKeysStore, StorageError};

pub const API_KEY_PREFIX: &str = "sk_";
const API_KEY_SEPARATOR: &str = ".";
const API_KEY_PREFIX_BYTES: usize = 6;
const API_KEY_SECRET_BYTES: usize = 32;

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
    pub secret: String,
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
        let expected = hash_api_key_secret(&self.pepper, &parsed.prefix, &parsed.secret)?;

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

        if !secure_equals_hex(&key.hash, &expected) {
            return Err(AuthError::InvalidApiKey);
        }

        Ok(key)
    }
}

pub fn parse_api_key(key: &str) -> Result<ParsedApiKey, AuthError> {
    let key = key.trim();
    if !key.starts_with(API_KEY_PREFIX) {
        return Err(AuthError::InvalidApiKey);
    }

    let rest = &key[API_KEY_PREFIX.len()..];
    let Some((prefix, secret)) = rest.split_once(API_KEY_SEPARATOR) else {
        return Err(AuthError::InvalidApiKey);
    };

    if prefix.len() < API_KEY_PREFIX_BYTES || secret.is_empty() {
        return Err(AuthError::InvalidApiKey);
    }

    Ok(ParsedApiKey {
        prefix: prefix.to_string(),
        secret: secret.to_string(),
    })
}

pub fn hash_api_key_secret(pepper: &str, prefix: &str, secret: &str) -> Result<String, AuthError> {
    if pepper.is_empty() {
        return Err(AuthError::MissingPepper);
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, pepper.as_bytes());
    let mut msg = Vec::with_capacity(prefix.len() + secret.len() + 1);
    msg.extend_from_slice(prefix.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(secret.as_bytes());
    let sum = hmac::sign(&key, &msg);
    Ok(hex::encode(sum.as_ref()))
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

pub fn generate_api_key(pepper: &str) -> Result<(String, String, String), AuthError> {
    let rng = SystemRandom::new();
    let mut prefix_bytes = [0u8; API_KEY_PREFIX_BYTES];
    let mut secret_bytes = [0u8; API_KEY_SECRET_BYTES];
    rng.fill(&mut prefix_bytes)
        .map_err(|_| AuthError::Storage("generate api key prefix".into()))?;
    rng.fill(&mut secret_bytes)
        .map_err(|_| AuthError::Storage("generate api key secret".into()))?;

    let prefix = URL_SAFE_NO_PAD.encode(prefix_bytes);
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let api_key = format!("{API_KEY_PREFIX}{prefix}{API_KEY_SEPARATOR}{secret}");
    let hash = hash_api_key_secret(pepper, &prefix, &secret)?;

    Ok((api_key, prefix, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_key_shape() {
        let k = format!("{API_KEY_PREFIX}abcdef.123");
        let p = parse_api_key(&k).unwrap();
        assert_eq!(p.prefix, "abcdef");
        assert_eq!(p.secret, "123");
        assert!(parse_api_key("bad").is_err());
    }

    #[test]
    fn hash_and_compare() {
        let h1 = hash_api_key_secret("pepper", "prefix", "secret").unwrap();
        let h2 = hash_api_key_secret("pepper", "prefix", "secret").unwrap();
        assert!(secure_equals_hex(&h1, &h2));
        assert!(!secure_equals_hex(&h1, "deadbeef"));
    }

    #[test]
    fn generate_key() {
        let (api, prefix, hash) = generate_api_key("pepper").unwrap();
        assert!(api.starts_with(API_KEY_PREFIX));
        assert!(api.contains('.'));
        assert!(!prefix.is_empty());
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn parse_key_invalid_shapes() {
        assert!(parse_api_key("sk_short.a").is_err());
        assert!(parse_api_key("sk_missingdot").is_err());
        assert!(parse_api_key("sk_abcdef.").is_err());
        assert!(parse_api_key("  ").is_err());
    }

    #[test]
    fn hash_requires_pepper() {
        assert!(matches!(
            hash_api_key_secret("", "abcdef", "secret"),
            Err(AuthError::MissingPepper)
        ));
    }
}
