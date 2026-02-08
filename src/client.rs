use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::envelope::b64_encode;

/// API payload for creating a secret.
#[derive(Serialize)]
pub struct CreateRequest {
    pub envelope: serde_json::Value,
    pub claim_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i64>,
}

/// API response from creating a secret.
#[derive(Deserialize)]
pub struct CreateResponse {
    pub id: String,
    pub share_url: String,
    pub expires_at: String,
}

/// API payload for claiming a secret.
#[derive(Serialize)]
struct ClaimRequest {
    claim: String,
}

/// API response from claiming a secret.
#[derive(Deserialize)]
pub struct ClaimResponse {
    pub envelope: serde_json::Value,
    pub expires_at: String,
}

/// HTTP API client for secrt.
pub struct ApiClient {
    pub base_url: String,
    pub api_key: String,
}

/// API error response.
#[derive(Deserialize)]
struct ApiErrorResponse {
    error: String,
}

impl ApiClient {
    fn agent(&self) -> ureq::Agent {
        ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_global(Some(Duration::from_secs(30)))
                .build(),
        )
    }

    /// Upload an encrypted envelope and return the server response.
    pub fn create(&self, req: CreateRequest) -> Result<CreateResponse, String> {
        let endpoint = if self.api_key.is_empty() {
            format!("{}/api/v1/public/secrets", self.base_url)
        } else {
            format!("{}/api/v1/secrets", self.base_url)
        };

        let body = serde_json::to_vec(&req).map_err(|e| format!("marshal request: {}", e))?;

        let mut request = self
            .agent()
            .post(&endpoint)
            .header("Content-Type", "application/json");

        if !self.api_key.is_empty() {
            request = request.header("X-API-Key", &self.api_key);
        }

        let resp = request
            .send(&body[..])
            .map_err(|e| self.handle_ureq_error(e))?;

        if resp.status().as_u16() != 201 {
            return Err(self.read_api_error_from_response(resp));
        }

        let body_str = resp
            .into_body()
            .read_to_string()
            .map_err(|e| format!("decode response: {}", e))?;
        let result: CreateResponse =
            serde_json::from_str(&body_str).map_err(|e| format!("decode response: {}", e))?;

        Ok(result)
    }

    /// Send a claim token and return the envelope.
    pub fn claim(&self, secret_id: &str, claim_token: &[u8]) -> Result<ClaimResponse, String> {
        let req = ClaimRequest {
            claim: b64_encode(claim_token),
        };
        let body = serde_json::to_vec(&req).map_err(|e| format!("marshal request: {}", e))?;

        let endpoint = format!("{}/api/v1/secrets/{}/claim", self.base_url, secret_id);

        let resp = self
            .agent()
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .send(&body[..])
            .map_err(|e| self.handle_ureq_error(e))?;

        if resp.status().as_u16() != 200 {
            return Err(self.read_api_error_from_response(resp));
        }

        let body_str = resp
            .into_body()
            .read_to_string()
            .map_err(|e| format!("decode response: {}", e))?;
        let result: ClaimResponse =
            serde_json::from_str(&body_str).map_err(|e| format!("decode response: {}", e))?;

        Ok(result)
    }

    /// Delete a secret without claiming it.
    pub fn burn(&self, secret_id: &str) -> Result<(), String> {
        let endpoint = format!("{}/api/v1/secrets/{}/burn", self.base_url, secret_id);

        let mut request = self
            .agent()
            .post(&endpoint)
            .header("Content-Type", "application/json");

        if !self.api_key.is_empty() {
            request = request.header("X-API-Key", &self.api_key);
        }

        let resp = request
            .send(&[][..])
            .map_err(|e| self.handle_ureq_error(e))?;

        if resp.status().as_u16() != 200 {
            return Err(self.read_api_error_from_response(resp));
        }

        Ok(())
    }

    fn handle_ureq_error(&self, err: ureq::Error) -> String {
        match err {
            ureq::Error::StatusCode(status) => {
                format!("server error ({})", status)
            }
            other => format!("HTTP request failed: {}", other),
        }
    }

    fn read_api_error_from_response(&self, resp: ureq::http::Response<ureq::Body>) -> String {
        let status = resp.status().as_u16();
        if let Ok(body_str) = resp.into_body().read_to_string() {
            if let Ok(err_resp) = serde_json::from_str::<ApiErrorResponse>(&body_str) {
                if !err_resp.error.is_empty() {
                    return format!("server error ({}): {}", status, err_resp.error);
                }
            }
        }
        format!("server error ({})", status)
    }
}
