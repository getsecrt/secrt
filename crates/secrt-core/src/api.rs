use serde::{Deserialize, Serialize};

use crate::crypto::b64_encode;

/// API payload for creating a secret.
#[derive(Serialize)]
pub struct CreateRequest {
    pub envelope: serde_json::Value,
    pub claim_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i64>,
}

/// API response from creating a secret.
#[derive(Clone, Deserialize)]
pub struct CreateResponse {
    pub id: String,
    pub share_url: String,
    pub expires_at: String,
}

/// API payload for claiming a secret.
#[derive(Serialize)]
pub struct ClaimRequest {
    pub claim: String,
}

impl ClaimRequest {
    pub fn from_token(claim_token: &[u8]) -> Self {
        ClaimRequest {
            claim: b64_encode(claim_token),
        }
    }
}

/// API response from claiming a secret.
#[derive(Clone, Deserialize)]
pub struct ClaimResponse {
    pub envelope: serde_json::Value,
    pub expires_at: String,
}

/// Server info response from GET /api/v1/info.
#[derive(Clone, Deserialize)]
pub struct InfoResponse {
    pub authenticated: bool,
    pub ttl: InfoTTL,
    pub limits: InfoLimits,
    pub claim_rate: InfoRate,
}

#[derive(Clone, Deserialize)]
pub struct InfoTTL {
    pub default_seconds: i64,
    pub max_seconds: i64,
}

#[derive(Clone, Deserialize)]
pub struct InfoLimits {
    pub public: InfoTier,
    pub authed: InfoTier,
}

#[derive(Clone, Deserialize)]
pub struct InfoTier {
    pub max_envelope_bytes: i64,
    pub max_secrets: i64,
    pub max_total_bytes: i64,
    pub rate: InfoRate,
}

#[derive(Clone, Deserialize)]
pub struct InfoRate {
    pub requests_per_second: f64,
    pub burst: i64,
}

/// Metadata for a single secret in a list response.
#[derive(Clone, Deserialize, Serialize)]
pub struct SecretMetadataItem {
    pub id: String,
    pub share_url: String,
    pub expires_at: String,
    pub created_at: String,
    pub ciphertext_size: i64,
    pub passphrase_protected: bool,
}

/// API response from listing secrets.
#[derive(Clone, Deserialize, Serialize)]
pub struct ListSecretsResponse {
    pub secrets: Vec<SecretMetadataItem>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Trait abstracting the API for testing.
pub trait SecretApi {
    fn create(&self, req: CreateRequest) -> Result<CreateResponse, String>;
    fn claim(&self, secret_id: &str, claim_token: &[u8]) -> Result<ClaimResponse, String>;
    fn burn(&self, secret_id: &str) -> Result<(), String>;
    fn info(&self) -> Result<InfoResponse, String>;
    fn list(&self, limit: Option<i64>, offset: Option<i64>) -> Result<ListSecretsResponse, String>;
}
