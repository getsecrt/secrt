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
#[derive(Clone, Deserialize)]
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

/// Trait abstracting the API for testing.
pub trait SecretApi {
    fn create(&self, req: CreateRequest) -> Result<CreateResponse, String>;
    fn claim(&self, secret_id: &str, claim_token: &[u8]) -> Result<ClaimResponse, String>;
    fn burn(&self, secret_id: &str) -> Result<(), String>;
    fn info(&self) -> Result<InfoResponse, String>;
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
                .http_status_as_error(false)
                .build(),
        )
    }

    fn handle_ureq_error(&self, err: ureq::Error) -> String {
        let msg = err.to_string();
        if msg.contains("tls") || msg.contains("certificate") || msg.contains("ssl") {
            format!("TLS error connecting to {}: {}", self.base_url, msg)
        } else if msg.contains("dns") || msg.contains("resolve") || msg.contains("No such host") {
            format!("cannot resolve host {}: {}", self.base_url, msg)
        } else if msg.contains("timed out") || msg.contains("timeout") {
            format!("connection to {} timed out", self.base_url)
        } else if msg.contains("Connection refused") || msg.contains("connection refused") {
            format!("connection refused by {}", self.base_url)
        } else {
            format!("HTTP request failed: {}", msg)
        }
    }

    fn read_api_error_from_response(&self, resp: ureq::http::Response<ureq::Body>) -> String {
        let status = resp.status().as_u16();
        let body = resp.into_body().read_to_string().unwrap_or_default();
        format_api_error(status, &body)
    }
}

/// Friendly fallback error message for HTTP status codes when the server
/// provides no JSON error body.
fn format_status_error(status: u16) -> String {
    let desc = match status {
        401 => "unauthorized; check your API key",
        403 => "forbidden",
        404 => "secret not found or already claimed",
        429 => "rate limit exceeded; please try again in a few seconds",
        500 | 502 | 503 => "server is temporarily unavailable; please try again later",
        _ => "",
    };
    if desc.is_empty() {
        format!("server error ({})", status)
    } else {
        format!("server error ({}): {}", status, desc)
    }
}

/// Format an API error from a JSON body and status code.
/// Returns `None` if the body doesn't contain a valid error message.
fn format_api_error(status: u16, body: &str) -> String {
    if let Ok(err_resp) = serde_json::from_str::<ApiErrorResponse>(body) {
        if !err_resp.error.is_empty() {
            return format!("server error ({}): {}", status, err_resp.error);
        }
    }
    format_status_error(status)
}

impl SecretApi for ApiClient {
    fn create(&self, req: CreateRequest) -> Result<CreateResponse, String> {
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

    fn claim(&self, secret_id: &str, claim_token: &[u8]) -> Result<ClaimResponse, String> {
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

    fn burn(&self, secret_id: &str) -> Result<(), String> {
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

    fn info(&self) -> Result<InfoResponse, String> {
        let endpoint = format!("{}/api/v1/info", self.base_url);

        let agent = ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_global(Some(Duration::from_secs(2)))
                .http_status_as_error(false)
                .build(),
        );

        let mut request = agent.get(&endpoint);

        if !self.api_key.is_empty() {
            request = request.header("X-API-Key", &self.api_key);
        }

        let resp = request.call().map_err(|e| self.handle_ureq_error(e))?;

        if resp.status().as_u16() != 200 {
            return Err(self.read_api_error_from_response(resp));
        }

        let body_str = resp
            .into_body()
            .read_to_string()
            .map_err(|e| format!("decode response: {}", e))?;
        let result: InfoResponse =
            serde_json::from_str(&body_str).map_err(|e| format!("decode response: {}", e))?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- format_status_error: friendly fallback messages ---

    #[test]
    fn status_429_rate_limit() {
        let msg = format_status_error(429);
        assert_eq!(
            msg,
            "server error (429): rate limit exceeded; please try again in a few seconds"
        );
    }

    #[test]
    fn status_401_unauthorized() {
        let msg = format_status_error(401);
        assert_eq!(msg, "server error (401): unauthorized; check your API key");
    }

    #[test]
    fn status_403_forbidden() {
        let msg = format_status_error(403);
        assert_eq!(msg, "server error (403): forbidden");
    }

    #[test]
    fn status_404_not_found() {
        let msg = format_status_error(404);
        assert_eq!(
            msg,
            "server error (404): secret not found or already claimed"
        );
    }

    #[test]
    fn status_500_unavailable() {
        let msg = format_status_error(500);
        assert_eq!(
            msg,
            "server error (500): server is temporarily unavailable; please try again later"
        );
    }

    #[test]
    fn status_502_unavailable() {
        let msg = format_status_error(502);
        assert_eq!(
            msg,
            "server error (502): server is temporarily unavailable; please try again later"
        );
    }

    #[test]
    fn status_503_unavailable() {
        let msg = format_status_error(503);
        assert_eq!(
            msg,
            "server error (503): server is temporarily unavailable; please try again later"
        );
    }

    #[test]
    fn status_unknown_code() {
        let msg = format_status_error(418);
        assert_eq!(msg, "server error (418)");
    }

    // --- format_api_error: JSON body parsing + fallback ---

    #[test]
    fn api_error_json_body() {
        let body = r#"{"error":"rate limit exceeded; please try again in a few seconds"}"#;
        let msg = format_api_error(429, body);
        assert_eq!(
            msg,
            "server error (429): rate limit exceeded; please try again in a few seconds"
        );
    }

    #[test]
    fn api_error_custom_message() {
        let body = r#"{"error":"quota exceeded for your plan"}"#;
        let msg = format_api_error(429, body);
        assert_eq!(msg, "server error (429): quota exceeded for your plan");
    }

    #[test]
    fn api_error_empty_json_error_falls_back() {
        let body = r#"{"error":""}"#;
        let msg = format_api_error(429, body);
        assert_eq!(
            msg,
            "server error (429): rate limit exceeded; please try again in a few seconds"
        );
    }

    #[test]
    fn api_error_invalid_json_falls_back() {
        let msg = format_api_error(429, "not json");
        assert_eq!(
            msg,
            "server error (429): rate limit exceeded; please try again in a few seconds"
        );
    }

    #[test]
    fn api_error_empty_body_falls_back() {
        let msg = format_api_error(429, "");
        assert_eq!(
            msg,
            "server error (429): rate limit exceeded; please try again in a few seconds"
        );
    }

    #[test]
    fn api_error_unknown_status_no_json() {
        let msg = format_api_error(418, "");
        assert_eq!(msg, "server error (418)");
    }

    #[test]
    fn api_error_server_message_overrides_fallback() {
        let body = r#"{"error":"custom server message"}"#;
        let msg = format_api_error(500, body);
        assert_eq!(msg, "server error (500): custom server message");
    }
}
