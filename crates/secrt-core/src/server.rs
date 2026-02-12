use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::digest::{digest, SHA256};

use crate::ttl::MAX_TTL_SECONDS;
use crate::types::EnvelopeError;

pub const DEFAULT_TTL_SECONDS: i64 = 86_400;
pub const MIN_CLAIM_TOKEN_BYTES: usize = 16;

/// Normalize API ttl_seconds to a valid positive value, defaulting to 24h.
pub fn normalize_api_ttl(ttl_seconds: Option<i64>) -> Result<i64, EnvelopeError> {
    let ttl = ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    if ttl <= 0 {
        return Err(EnvelopeError::InvalidTtl("value must be positive".into()));
    }
    if ttl > MAX_TTL_SECONDS {
        return Err(EnvelopeError::InvalidTtl(format!(
            "exceeds maximum ({} seconds)",
            MAX_TTL_SECONDS
        )));
    }
    Ok(ttl)
}

/// Validate that claim_hash is base64url(sha256(..)) shape.
pub fn validate_claim_hash(claim_hash: &str) -> Result<(), EnvelopeError> {
    let trimmed = claim_hash.trim();
    if trimmed.is_empty() {
        return Err(EnvelopeError::InvalidEnvelope("empty claim_hash".into()));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|_| EnvelopeError::InvalidEnvelope("invalid claim_hash".into()))?;
    if decoded.len() != 32 {
        return Err(EnvelopeError::InvalidEnvelope("invalid claim_hash".into()));
    }
    Ok(())
}

/// Hash a base64url-encoded claim token as base64url(sha256(token_bytes)).
pub fn hash_claim_token(claim_token_b64: &str) -> Result<String, EnvelopeError> {
    let token = URL_SAFE_NO_PAD
        .decode(claim_token_b64.trim())
        .map_err(|_| EnvelopeError::InvalidEnvelope("invalid claim token".into()))?;
    if token.len() < MIN_CLAIM_TOKEN_BYTES {
        return Err(EnvelopeError::InvalidEnvelope("invalid claim token".into()));
    }
    let sum = digest(&SHA256, &token);
    Ok(URL_SAFE_NO_PAD.encode(sum.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_claim_token;
    use crate::types::URL_KEY_LEN;

    #[test]
    fn normalize_ttl_default_and_bounds() {
        assert_eq!(normalize_api_ttl(None).unwrap(), DEFAULT_TTL_SECONDS);
        assert!(normalize_api_ttl(Some(0)).is_err());
        assert!(normalize_api_ttl(Some(MAX_TTL_SECONDS + 1)).is_err());
    }

    #[test]
    fn claim_hash_roundtrip() {
        let key = vec![7u8; URL_KEY_LEN];
        let claim = derive_claim_token(&key).unwrap();
        let claim_b64 = URL_SAFE_NO_PAD.encode(claim);
        let hash = hash_claim_token(&claim_b64).unwrap();
        validate_claim_hash(&hash).unwrap();
    }

    #[test]
    fn claim_token_rejects_short_or_invalid() {
        assert!(hash_claim_token("%%%").is_err());
        let short = URL_SAFE_NO_PAD.encode(vec![1u8; MIN_CLAIM_TOKEN_BYTES - 1]);
        assert!(hash_claim_token(&short).is_err());
    }
}
