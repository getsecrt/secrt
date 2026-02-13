use serde::Deserialize;
use std::time::Duration;

pub use secrt_core::api::*;

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

    fn api_key_for_wire(&self) -> Result<Option<String>, String> {
        let key = self.api_key.trim();
        if key.is_empty() {
            return Ok(None);
        }

        if key.starts_with(secrt_core::LOCAL_API_KEY_PREFIX) {
            return secrt_core::derive_wire_api_key(key)
                .map(Some)
                .map_err(|e| format!("invalid --api-key: {}", e));
        }

        if key.starts_with(secrt_core::WIRE_API_KEY_PREFIX) {
            return secrt_core::parse_wire_api_key(key)
                .map(|_| Some(key.to_string()))
                .map_err(|e| format!("invalid --api-key: {}", e));
        }

        // Keep pass-through for non-v2 formats during alpha transition.
        Ok(Some(key.to_string()))
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
        let wire_api_key = self.api_key_for_wire()?;
        let endpoint = if wire_api_key.is_none() {
            format!("{}/api/v1/public/secrets", self.base_url)
        } else {
            format!("{}/api/v1/secrets", self.base_url)
        };

        let body = serde_json::to_vec(&req).map_err(|e| format!("marshal request: {}", e))?;

        let mut request = self
            .agent()
            .post(&endpoint)
            .header("Content-Type", "application/json");

        if let Some(key) = wire_api_key.as_ref() {
            request = request.header("X-API-Key", key);
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
        let req = ClaimRequest::from_token(claim_token);
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
        let wire_api_key = self.api_key_for_wire()?;

        let mut request = self
            .agent()
            .post(&endpoint)
            .header("Content-Type", "application/json");

        if let Some(key) = wire_api_key.as_ref() {
            request = request.header("X-API-Key", key);
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
        let wire_api_key = self.api_key_for_wire()?;

        let agent = ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_global(Some(Duration::from_secs(2)))
                .http_status_as_error(false)
                .build(),
        );

        let mut request = agent.get(&endpoint);

        if let Some(key) = wire_api_key.as_ref() {
            request = request.header("X-API-Key", key);
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
    use base64::Engine;

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

    #[test]
    fn local_sk2_derives_wire_ak2() {
        let root = [9u8; 32];
        let local = format!(
            "sk2_abcdef.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(root)
        );
        let client = ApiClient {
            base_url: "https://example.com".into(),
            api_key: local,
        };
        let wire = client.api_key_for_wire().expect("derive").expect("api key");
        assert!(wire.starts_with("ak2_abcdef."));
        assert!(secrt_core::parse_wire_api_key(&wire).is_ok());
    }

    #[test]
    fn malformed_sk2_is_rejected() {
        let client = ApiClient {
            base_url: "https://example.com".into(),
            api_key: "sk2_bad.invalid".into(),
        };
        let err = client.api_key_for_wire().expect_err("should fail");
        assert!(err.contains("invalid --api-key"));
    }

    #[test]
    fn valid_ak2_is_accepted() {
        let auth = [3u8; 32];
        let wire = secrt_core::format_wire_api_key("abcdef", &auth).expect("wire");
        let client = ApiClient {
            base_url: "https://example.com".into(),
            api_key: wire.clone(),
        };
        let got = client.api_key_for_wire().expect("ok").expect("some");
        assert_eq!(got, wire);
    }

    #[test]
    fn sk2_vectors_derive_expected_wire_keys() {
        #[derive(Deserialize)]
        struct Vectors {
            cases: Vec<VectorCase>,
        }
        #[derive(Deserialize)]
        struct VectorCase {
            local_key: String,
            wire_key: String,
        }

        let vectors: Vectors =
            serde_json::from_str(include_str!("../../../spec/v1/apikey.vectors.json"))
                .expect("valid vectors");

        for case in vectors.cases {
            let client = ApiClient {
                base_url: "https://example.com".into(),
                api_key: case.local_key,
            };
            let wire = client.api_key_for_wire().expect("derive").expect("api key");
            assert_eq!(wire, case.wire_key);
        }
    }
}
