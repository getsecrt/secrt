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
    #[serde(default)]
    pub user_id: Option<String>,
    pub ttl: InfoTTL,
    pub limits: InfoLimits,
    pub claim_rate: InfoRate,
    /// Newest CLI release the server has observed via its GitHub Releases
    /// poll. Absent until the first successful poll, or always absent on
    /// air-gapped servers (`GITHUB_POLL_INTERVAL_SECONDS=0`).
    #[serde(default)]
    pub latest_cli_version: Option<String>,
    /// RFC 3339 timestamp of the most recent successful poll.
    #[serde(default)]
    pub latest_cli_version_checked_at: Option<String>,
    /// Hard floor for CLI compatibility with this server. Always present;
    /// older servers that pre-date the field will deserialize as `None`.
    #[serde(default)]
    pub min_supported_cli_version: Option<String>,
    /// Server's own version (`CARGO_PKG_VERSION` at build time). Lets
    /// operators verify deploys without SSH and lets the CLI record which
    /// server version a response came from. Older servers that pre-date the
    /// field will deserialize as `None`.
    #[serde(default)]
    pub server_version: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc_meta: Option<EncMetaV1>,
}

/// Encrypted metadata v1 envelope (strict schema, deny unknown fields).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncMetaV1 {
    pub v: u16,
    pub note: EncMetaNoteV1,
}

/// Encrypted note blob within enc_meta.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncMetaNoteV1 {
    pub ct: String,    // base64url, max 8 KiB decoded
    pub nonce: String, // base64url, exactly 12 bytes decoded
    pub salt: String,  // base64url, exactly 32 bytes decoded
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

    /// Get metadata for a single secret by ID.
    fn get_secret_metadata(&self, _id: &str) -> Result<SecretMetadataItem, String> {
        Err("get_secret_metadata not implemented".into())
    }

    /// Attach or update encrypted metadata on a secret.
    fn update_secret_meta(
        &self,
        _secret_id: &str,
        _enc_meta: &EncMetaV1,
        _meta_key_version: i16,
    ) -> Result<(), String> {
        Err("update_secret_meta not implemented".into())
    }

    /// Get the AMK wrapper for the caller's API key. Returns None if no wrapper exists.
    fn get_amk_wrapper(&self) -> Result<Option<AmkWrapperResponse>, String> {
        Err("get_amk_wrapper not implemented".into())
    }

    /// Upsert an AMK wrapper (with commit verification).
    fn upsert_amk_wrapper(
        &self,
        _key_prefix: &str,
        _wrapped_amk: &str,
        _nonce: &str,
        _amk_commit: &str,
        _version: i16,
    ) -> Result<(), String> {
        Err("upsert_amk_wrapper not implemented".into())
    }
}

/// Response from GET /api/v1/amk/wrapper.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AmkWrapperResponse {
    pub user_id: String,
    pub wrapped_amk: String,
    pub nonce: String,
    pub version: i16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_response_parses_without_cli_version_fields() {
        // Older server (or future field-less response) still deserializes.
        let body = r#"{
            "authenticated": false,
            "ttl": {"default_seconds": 3600, "max_seconds": 86400},
            "limits": {
                "public": {"max_envelope_bytes": 1, "max_secrets": 1, "max_total_bytes": 1, "rate": {"requests_per_second": 1.0, "burst": 1}},
                "authed": {"max_envelope_bytes": 1, "max_secrets": 1, "max_total_bytes": 1, "rate": {"requests_per_second": 1.0, "burst": 1}}
            },
            "claim_rate": {"requests_per_second": 1.0, "burst": 1}
        }"#;
        let info: InfoResponse = serde_json::from_str(body).expect("parse");
        assert!(info.latest_cli_version.is_none());
        assert!(info.latest_cli_version_checked_at.is_none());
        assert!(info.min_supported_cli_version.is_none());
        assert!(info.server_version.is_none());
    }

    #[test]
    fn info_response_parses_all_cli_version_fields() {
        let body = r#"{
            "authenticated": false,
            "ttl": {"default_seconds": 3600, "max_seconds": 86400},
            "limits": {
                "public": {"max_envelope_bytes": 1, "max_secrets": 1, "max_total_bytes": 1, "rate": {"requests_per_second": 1.0, "burst": 1}},
                "authed": {"max_envelope_bytes": 1, "max_secrets": 1, "max_total_bytes": 1, "rate": {"requests_per_second": 1.0, "burst": 1}}
            },
            "claim_rate": {"requests_per_second": 1.0, "burst": 1},
            "latest_cli_version": "0.16.0",
            "latest_cli_version_checked_at": "2026-04-25T09:08:07Z",
            "min_supported_cli_version": "0.15.0",
            "server_version": "0.16.3"
        }"#;
        let info: InfoResponse = serde_json::from_str(body).expect("parse");
        assert_eq!(info.latest_cli_version.as_deref(), Some("0.16.0"));
        assert_eq!(
            info.latest_cli_version_checked_at.as_deref(),
            Some("2026-04-25T09:08:07Z")
        );
        assert_eq!(info.min_supported_cli_version.as_deref(), Some("0.15.0"));
        assert_eq!(info.server_version.as_deref(), Some("0.16.3"));
    }

    #[test]
    fn info_response_parses_with_only_min_supported() {
        // Server pre-poll: latest fields absent, min always present.
        let body = r#"{
            "authenticated": true,
            "user_id": "user-1",
            "ttl": {"default_seconds": 3600, "max_seconds": 86400},
            "limits": {
                "public": {"max_envelope_bytes": 1, "max_secrets": 1, "max_total_bytes": 1, "rate": {"requests_per_second": 1.0, "burst": 1}},
                "authed": {"max_envelope_bytes": 1, "max_secrets": 1, "max_total_bytes": 1, "rate": {"requests_per_second": 1.0, "burst": 1}}
            },
            "claim_rate": {"requests_per_second": 1.0, "burst": 1},
            "min_supported_cli_version": "0.15.0",
            "future_unknown_field": "ignored"
        }"#;
        let info: InfoResponse = serde_json::from_str(body).expect("parse");
        assert!(info.latest_cli_version.is_none());
        assert!(info.latest_cli_version_checked_at.is_none());
        assert_eq!(info.min_supported_cli_version.as_deref(), Some("0.15.0"));
        assert!(info.authenticated);
    }
}
