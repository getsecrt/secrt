use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

pub const DEFAULT_PUBLIC_MAX_ENVELOPE_BYTES: i64 = 256 * 1024;
pub const DEFAULT_AUTHED_MAX_ENVELOPE_BYTES: i64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SecretRuleError {
    #[error("invalid envelope")]
    InvalidEnvelope,
    #[error("envelope too large")]
    EnvelopeTooLarge,
    #[error("generate id")]
    GenerateId,
}

pub fn generate_id() -> Result<String, SecretRuleError> {
    let rng = SystemRandom::new();
    let mut b = [0u8; 16];
    rng.fill(&mut b).map_err(|_| SecretRuleError::GenerateId)?;
    Ok(URL_SAFE_NO_PAD.encode(b))
}

pub fn validate_envelope(envelope: &str, max_bytes: i64) -> Result<(), SecretRuleError> {
    if envelope.is_empty() {
        return Err(SecretRuleError::InvalidEnvelope);
    }

    if envelope.len() as i64 > max_bytes {
        return Err(SecretRuleError::EnvelopeTooLarge);
    }

    if !envelope.trim_start().starts_with('{') {
        return Err(SecretRuleError::InvalidEnvelope);
    }

    let parsed = serde_json::from_str::<serde_json::Value>(envelope)
        .map_err(|_| SecretRuleError::InvalidEnvelope)?;
    if !parsed.is_object() {
        return Err(SecretRuleError::InvalidEnvelope);
    }

    Ok(())
}

pub fn format_bytes(b: i64) -> String {
    if b >= 1024 * 1024 && b % (1024 * 1024) == 0 {
        format!("{} MB", b / (1024 * 1024))
    } else if b >= 1024 && b % 1024 == 0 {
        format!("{} KB", b / 1024)
    } else {
        format!("{} bytes", b)
    }
}

#[derive(Clone)]
pub struct OwnerHasher {
    key: hmac::Key,
}

impl OwnerHasher {
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key)
            .expect("owner hasher: crypto/rand failed");
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, &key),
        }
    }

    pub fn hash_ip(&self, ip: &str) -> String {
        let sum = hmac::sign(&self.key, ip.as_bytes());
        format!("ip:{}", hex::encode(sum.as_ref()))
    }
}

impl Default for OwnerHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_validation() {
        assert!(validate_envelope("{}", 8).is_ok());
        assert!(matches!(
            validate_envelope("[]", 8),
            Err(SecretRuleError::InvalidEnvelope)
        ));
        assert!(matches!(
            validate_envelope(&"{".repeat(20), 8),
            Err(SecretRuleError::EnvelopeTooLarge)
        ));
    }

    #[test]
    fn bytes_formatting() {
        assert_eq!(format_bytes(256 * 1024), "256 KB");
        assert_eq!(format_bytes(1024 * 1024), "1 MB");
        assert_eq!(format_bytes(777), "777 bytes");
    }

    #[test]
    fn id_generation() {
        let id = generate_id().unwrap();
        assert!(!id.is_empty());
    }

    #[test]
    fn owner_hash_prefix() {
        let h = OwnerHasher::new();
        let out = h.hash_ip("127.0.0.1");
        assert!(out.starts_with("ip:"));
    }
}
