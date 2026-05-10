use serde::Deserialize;
use std::time::{Duration, SystemTime};

pub use secrt_core::api::*;

/// `User-Agent` value sent on every CLI HTTP request. The CLI's HTTP client
/// behavior (`spec/v1/cli.md § HTTP Client Behavior`) requires every
/// outbound request to identify itself this way, so the server can correlate
/// usage by version and trigger version-specific incident remediation.
pub const USER_AGENT: &str = concat!("secrt/", env!("CARGO_PKG_VERSION"));

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
    /// Base URL with trailing slashes stripped.
    fn url(&self) -> &str {
        self.base_url.trim_end_matches('/')
    }

    fn agent(&self) -> ureq::Agent {
        ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_global(Some(Duration::from_secs(30)))
                .http_status_as_error(false)
                .user_agent(USER_AGENT)
                .build(),
        )
    }

    /// Read the three advisory CLI-version headers off any successful or
    /// failed server response and feed them into the shared update-check
    /// cache. Best-effort: never fails, never blocks the caller.
    fn observe_response<B>(resp: &ureq::http::Response<B>) {
        let h = resp.headers();
        let latest = h
            .get("x-secrt-latest-cli-version")
            .and_then(|v| v.to_str().ok());
        let checked_at = h
            .get("x-secrt-latest-cli-version-checked-at")
            .and_then(|v| v.to_str().ok());
        let min = h
            .get("x-secrt-min-cli-version")
            .and_then(|v| v.to_str().ok());
        if latest.is_none() && checked_at.is_none() && min.is_none() {
            return;
        }
        crate::update_check::ingest_advisory_headers(
            latest,
            checked_at,
            min,
            &|k| std::env::var(k).ok(),
            SystemTime::now(),
        );
    }

    /// Format a JSON-decode failure into something a user can act on.
    /// For truly Untrusted hosts (where this most commonly means "you
    /// pointed at a non-secrt server and got back HTML"), point at the
    /// likely cause instead of leaking serde's column-number diagnostics.
    /// DevLocal and Official hosts keep the verbose decode message —
    /// the assumption "may not be a secrt server" would be wrong there.
    fn decode_error<E: std::fmt::Display>(&self, e: E) -> String {
        let host = secrt_core::host_of(&self.base_url).unwrap_or_else(|| self.base_url.clone());
        if matches!(
            secrt_core::classify_origin(&self.base_url, &[]),
            secrt_core::TrustDecision::Untrusted
        ) {
            format!(
                "{host} returned a response that wasn't a valid secrt API reply — \
                 it may not be a secrt server"
            )
        } else {
            format!("decode response: {e}")
        }
    }

    fn handle_ureq_error(&self, err: ureq::Error) -> String {
        let host = secrt_core::host_of(&self.base_url).unwrap_or_else(|| self.base_url.clone());
        // Hint at the *root cause* (likely "this isn't a secrt server")
        // when the connection fails to a host we have no reason to
        // believe is one. Only fires for Untrusted: Official hosts are
        // assumed to be a secrt server (the failure is a network or
        // outage problem), and DevLocal is usually the user's own dev
        // server where the same assumption holds.
        let untrusted = matches!(
            secrt_core::classify_origin(&self.base_url, &[]),
            secrt_core::TrustDecision::Untrusted
        );
        let not_secrt_hint = if untrusted {
            format!(" — {host} may not be a secrt server")
        } else {
            String::new()
        };

        // Variant-match first (most reliable) and fall back to message
        // substrings for transports whose error variant we don't pattern
        // explicitly. Drops ureq's `docs.rs` link and rustls internals
        // from user-visible output; the raw cause is still in the logs
        // if the caller chooses to surface it elsewhere.
        match &err {
            ureq::Error::Tls(_) => {
                return format!("could not establish a secure connection to {host}{not_secrt_hint}")
            }
            ureq::Error::Io(io_err) => {
                use std::io::ErrorKind::*;
                return match io_err.kind() {
                    NotFound => {
                        format!("could not resolve {host}; check the spelling or your network")
                    }
                    TimedOut => format!("connection to {host} timed out"),
                    ConnectionRefused => {
                        format!("{host} refused the connection{not_secrt_hint}")
                    }
                    ConnectionReset | ConnectionAborted | UnexpectedEof => {
                        format!("connection to {host} was closed unexpectedly{not_secrt_hint}")
                    }
                    _ => format!("could not connect to {host}{not_secrt_hint}"),
                };
            }
            _ => {}
        }

        let msg_lc = err.to_string().to_lowercase();
        if msg_lc.contains("tls") || msg_lc.contains("certificate") || msg_lc.contains("ssl") {
            format!("could not establish a secure connection to {host}{not_secrt_hint}")
        } else if msg_lc.contains("dns")
            || msg_lc.contains("resolve")
            || msg_lc.contains("no such host")
        {
            format!("could not resolve {host}; check the spelling or your network")
        } else if msg_lc.contains("timed out") || msg_lc.contains("timeout") {
            format!("connection to {host} timed out")
        } else if msg_lc.contains("connection refused") {
            format!("{host} refused the connection{not_secrt_hint}")
        } else {
            format!("could not connect to {host}{not_secrt_hint}")
        }
    }

    fn read_api_error_from_response(&self, resp: ureq::http::Response<ureq::Body>) -> String {
        let status = resp.status().as_u16();
        Self::observe_response(&resp);
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
        404 => "not found",
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

// --- Device authorization flow types ---

#[derive(Debug, Deserialize)]
pub struct DeviceStartResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_url: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Deserialize)]
pub struct AmkTransferPayload {
    pub ct: String,
    pub nonce: String,
    pub ecdh_public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct DevicePollResponse {
    pub status: String,
    pub prefix: Option<String>,
    pub amk_transfer: Option<AmkTransferPayload>,
}

impl ApiClient {
    /// Start a device authorization flow (unauthenticated).
    /// If `ecdh_public_key_b64` is provided, it's included in the request for AMK transfer.
    pub fn device_start(
        &self,
        auth_token_b64: &str,
        ecdh_public_key_b64: Option<&str>,
    ) -> Result<DeviceStartResponse, String> {
        let endpoint = format!("{}/api/v1/auth/device/start", self.url());
        let mut body = serde_json::json!({ "auth_token": auth_token_b64 });
        if let Some(pk) = ecdh_public_key_b64 {
            body["ecdh_public_key"] = serde_json::Value::String(pk.to_string());
        }
        let body_bytes =
            serde_json::to_vec(&body).map_err(|e| format!("marshal request: {}", e))?;

        let resp = self
            .agent()
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .send(&body_bytes[..])
            .map_err(|e| self.handle_ureq_error(e))?;
        Self::observe_response(&resp);

        let status = resp.status().as_u16();
        if status != 200 {
            let inner = self.read_api_error_from_response(resp);
            return if status == 404 {
                Err(format!(
                    "device auth endpoint not found at {} (is the server up to date?)",
                    self.base_url
                ))
            } else {
                Err(inner)
            };
        }

        let body_str = resp
            .into_body()
            .read_to_string()
            .map_err(|e| self.decode_error(e))?;
        serde_json::from_str(&body_str).map_err(|e| self.decode_error(e))
    }

    /// Poll for device authorization completion (unauthenticated).
    pub fn device_poll(&self, device_code: &str) -> Result<DevicePollResponse, String> {
        let endpoint = format!("{}/api/v1/auth/device/poll", self.url());
        let body = serde_json::json!({ "device_code": device_code });
        let body_bytes =
            serde_json::to_vec(&body).map_err(|e| format!("marshal request: {}", e))?;

        let resp = self
            .agent()
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .send(&body_bytes[..])
            .map_err(|e| self.handle_ureq_error(e))?;
        Self::observe_response(&resp);

        if resp.status().as_u16() != 200 {
            return Err(self.read_api_error_from_response(resp));
        }

        let body_str = resp
            .into_body()
            .read_to_string()
            .map_err(|e| self.decode_error(e))?;
        serde_json::from_str(&body_str).map_err(|e| self.decode_error(e))
    }
}

impl SecretApi for ApiClient {
    fn create(&self, req: CreateRequest) -> Result<CreateResponse, String> {
        let wire_api_key = self.api_key_for_wire()?;
        let endpoint = if wire_api_key.is_none() {
            format!("{}/api/v1/public/secrets", self.url())
        } else {
            format!("{}/api/v1/secrets", self.url())
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
        Self::observe_response(&resp);

        if resp.status().as_u16() != 201 {
            return Err(self.read_api_error_from_response(resp));
        }

        let body_str = resp
            .into_body()
            .read_to_string()
            .map_err(|e| self.decode_error(e))?;
        let result: CreateResponse =
            serde_json::from_str(&body_str).map_err(|e| self.decode_error(e))?;

        Ok(result)
    }

    fn claim(&self, secret_id: &str, claim_token: &[u8]) -> Result<ClaimResponse, String> {
        let req = ClaimRequest::from_token(claim_token);
        let body = serde_json::to_vec(&req).map_err(|e| format!("marshal request: {}", e))?;

        let endpoint = format!("{}/api/v1/secrets/{}/claim", self.url(), secret_id);

        let resp = self
            .agent()
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .send(&body[..])
            .map_err(|e| self.handle_ureq_error(e))?;
        Self::observe_response(&resp);

        if resp.status().as_u16() != 200 {
            return Err(self.read_api_error_from_response(resp));
        }

        let body_str = resp
            .into_body()
            .read_to_string()
            .map_err(|e| self.decode_error(e))?;
        let result: ClaimResponse =
            serde_json::from_str(&body_str).map_err(|e| self.decode_error(e))?;

        Ok(result)
    }

    fn burn(&self, secret_id: &str) -> Result<(), String> {
        let endpoint = format!("{}/api/v1/secrets/{}/burn", self.url(), secret_id);
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
        Self::observe_response(&resp);

        if resp.status().as_u16() != 200 {
            return Err(self.read_api_error_from_response(resp));
        }

        Ok(())
    }

    fn list(&self, limit: Option<i64>, offset: Option<i64>) -> Result<ListSecretsResponse, String> {
        let mut endpoint = format!("{}/api/v1/secrets", self.url());
        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={}", l));
        }
        if let Some(o) = offset {
            params.push(format!("offset={}", o));
        }
        if !params.is_empty() {
            endpoint = format!("{}?{}", endpoint, params.join("&"));
        }

        let wire_api_key = self.api_key_for_wire()?;
        let mut request = self.agent().get(&endpoint);
        if let Some(key) = wire_api_key.as_ref() {
            request = request.header("X-API-Key", key);
        }

        let resp = request.call().map_err(|e| self.handle_ureq_error(e))?;
        Self::observe_response(&resp);

        if resp.status().as_u16() != 200 {
            return Err(self.read_api_error_from_response(resp));
        }

        let body_str = resp
            .into_body()
            .read_to_string()
            .map_err(|e| self.decode_error(e))?;
        serde_json::from_str(&body_str).map_err(|e| self.decode_error(e))
    }

    fn get_secret_metadata(&self, id: &str) -> Result<SecretMetadataItem, String> {
        let endpoint = format!("{}/api/v1/secrets/{}", self.url(), id);
        let wire_api_key = self.api_key_for_wire()?;

        let mut request = self.agent().get(&endpoint);
        if let Some(key) = wire_api_key.as_ref() {
            request = request.header("X-API-Key", key);
        }

        let resp = request.call().map_err(|e| self.handle_ureq_error(e))?;
        Self::observe_response(&resp);

        if resp.status().as_u16() != 200 {
            return Err(self.read_api_error_from_response(resp));
        }

        let body_str = resp
            .into_body()
            .read_to_string()
            .map_err(|e| self.decode_error(e))?;
        serde_json::from_str(&body_str).map_err(|e| self.decode_error(e))
    }

    fn update_secret_meta(
        &self,
        secret_id: &str,
        enc_meta: &EncMetaV1,
        meta_key_version: i16,
    ) -> Result<(), String> {
        let wire_api_key = self.api_key_for_wire()?;
        let endpoint = format!("{}/api/v1/secrets/{}/meta", self.url(), secret_id);

        let body = serde_json::json!({
            "enc_meta": enc_meta,
            "meta_key_version": meta_key_version,
        });
        let body_bytes =
            serde_json::to_vec(&body).map_err(|e| format!("marshal request: {}", e))?;

        let mut request = self
            .agent()
            .put(&endpoint)
            .header("Content-Type", "application/json");
        if let Some(key) = wire_api_key.as_ref() {
            request = request.header("X-API-Key", key);
        }

        let resp = request
            .send(&body_bytes[..])
            .map_err(|e| self.handle_ureq_error(e))?;
        Self::observe_response(&resp);

        if resp.status().as_u16() != 200 {
            return Err(self.read_api_error_from_response(resp));
        }
        Ok(())
    }

    fn get_amk_wrapper(&self) -> Result<Option<AmkWrapperResponse>, String> {
        let wire_api_key = self
            .api_key_for_wire()?
            .ok_or_else(|| "API key required for AMK operations".to_string())?;
        let endpoint = format!("{}/api/v1/amk/wrapper", self.url());

        let resp = self
            .agent()
            .get(&endpoint)
            .header("X-API-Key", &wire_api_key)
            .call()
            .map_err(|e| self.handle_ureq_error(e))?;
        Self::observe_response(&resp);

        let status = resp.status().as_u16();
        if status == 404 {
            return Ok(None);
        }
        if status != 200 {
            return Err(self.read_api_error_from_response(resp));
        }

        let body_str = resp
            .into_body()
            .read_to_string()
            .map_err(|e| self.decode_error(e))?;
        let wrapper: AmkWrapperResponse =
            serde_json::from_str(&body_str).map_err(|e| self.decode_error(e))?;
        Ok(Some(wrapper))
    }

    fn upsert_amk_wrapper(
        &self,
        key_prefix: &str,
        wrapped_amk: &str,
        nonce: &str,
        amk_commit: &str,
        version: i16,
    ) -> Result<(), String> {
        let wire_api_key = self
            .api_key_for_wire()?
            .ok_or_else(|| "API key required for AMK operations".to_string())?;
        let endpoint = format!("{}/api/v1/amk/wrapper", self.url());

        let body = serde_json::json!({
            "key_prefix": key_prefix,
            "wrapped_amk": wrapped_amk,
            "nonce": nonce,
            "amk_commit": amk_commit,
            "version": version,
        });
        let body_bytes =
            serde_json::to_vec(&body).map_err(|e| format!("marshal request: {}", e))?;

        let resp = self
            .agent()
            .put(&endpoint)
            .header("Content-Type", "application/json")
            .header("X-API-Key", &wire_api_key)
            .send(&body_bytes[..])
            .map_err(|e| self.handle_ureq_error(e))?;
        Self::observe_response(&resp);

        let status = resp.status().as_u16();
        if status == 409 {
            return Err(
                "AMK commit mismatch: another device committed a different notes key".to_string(),
            );
        }
        if status != 200 {
            return Err(self.read_api_error_from_response(resp));
        }
        Ok(())
    }

    fn info(&self) -> Result<InfoResponse, String> {
        let endpoint = format!("{}/api/v1/info", self.url());
        let wire_api_key = self.api_key_for_wire()?;

        let agent = ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_global(Some(Duration::from_secs(2)))
                .http_status_as_error(false)
                .user_agent(USER_AGENT)
                .build(),
        );

        let mut request = agent.get(&endpoint);

        if let Some(key) = wire_api_key.as_ref() {
            request = request.header("X-API-Key", key);
        }

        let resp = request.call().map_err(|e| self.handle_ureq_error(e))?;
        Self::observe_response(&resp);

        if resp.status().as_u16() != 200 {
            return Err(self.read_api_error_from_response(resp));
        }

        let body_str = resp
            .into_body()
            .read_to_string()
            .map_err(|e| self.decode_error(e))?;
        let result: InfoResponse =
            serde_json::from_str(&body_str).map_err(|e| self.decode_error(e))?;

        // Refresh the local update-check cache from the typed body fields,
        // covering the path where advisory headers may have been stripped
        // by an intermediary proxy.
        crate::update_check::ingest_info_response(
            &result,
            &|k| std::env::var(k).ok(),
            SystemTime::now(),
        );

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    fn read_http_request(stream: &mut std::net::TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        let mut header_end = None;
        let mut content_len = 0usize;

        loop {
            let n = stream.read(&mut tmp).expect("read request");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);

            if header_end.is_none() {
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = Some(pos + 4);
                    let headers = String::from_utf8_lossy(&buf[..pos + 4]).to_ascii_lowercase();
                    for line in headers.lines() {
                        if let Some(v) = line.strip_prefix("content-length:") {
                            content_len = v.trim().parse::<usize>().unwrap_or(0);
                        }
                    }
                }
            }

            if let Some(end) = header_end {
                if buf.len() >= end + content_len {
                    break;
                }
            }
        }

        String::from_utf8_lossy(&buf).into_owned()
    }

    fn json_response(status: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn spawn_one_shot_server<F>(handler: F) -> (String, std::thread::JoinHandle<()>)
    where
        F: FnOnce(String) -> Vec<u8> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let h = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let req = read_http_request(&mut stream);
            let resp = handler(req);
            stream.write_all(&resp).expect("write response");
            stream.flush().expect("flush response");
        });
        (format!("http://{}", addr), h)
    }

    fn sample_create_request() -> CreateRequest {
        CreateRequest {
            envelope: serde_json::json!({"ciphertext":"abc"}),
            claim_hash: "claimhash".to_string(),
            ttl_seconds: Some(60),
        }
    }

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
        assert_eq!(msg, "server error (404): not found");
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

    #[test]
    fn handle_ureq_error_tls_dns_timeout_branches() {
        let client = ApiClient {
            base_url: "https://example.com".into(),
            api_key: String::new(),
        };

        let tls = client.handle_ureq_error(ureq::Error::Tls("certificate verify failed"));
        assert!(
            tls.contains("could not establish a secure connection to example.com"),
            "got: {tls}"
        );
        assert!(
            tls.contains("may not be a secrt server"),
            "unofficial host should get the not-secrt hint; got: {tls}"
        );
        // The rustls/docs.rs noise from the ureq error must be hidden.
        assert!(
            !tls.contains("docs.rs") && !tls.contains("close_notify"),
            "should not leak rustls internals; got: {tls}"
        );

        let dns = client.handle_ureq_error(ureq::Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No such host",
        )));
        assert!(dns.contains("could not resolve example.com"), "got: {dns}");

        let timeout = client.handle_ureq_error(ureq::Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        )));
        assert!(timeout.contains("timed out"), "got: {timeout}");
    }

    #[test]
    fn handle_ureq_error_official_host_omits_not_secrt_hint() {
        // Official hosts shouldn't be told "may not be a secrt server" —
        // that would be misleading for transient network issues.
        let client = ApiClient {
            base_url: "https://secrt.ca".into(),
            api_key: String::new(),
        };
        let tls = client.handle_ureq_error(ureq::Error::Tls("handshake failed"));
        assert!(
            !tls.contains("may not be a secrt server"),
            "official host must not get the unofficial hint; got: {tls}"
        );
        assert!(
            tls.contains("could not establish a secure connection to secrt.ca"),
            "got: {tls}"
        );
    }

    #[test]
    fn create_public_success_uses_public_endpoint_without_header() {
        let (base_url, server) = spawn_one_shot_server(|req| {
            assert!(req.starts_with("POST /api/v1/public/secrets "));
            assert!(!req.to_ascii_lowercase().contains("\r\nx-api-key:"));
            json_response(
                "201 Created",
                r#"{"id":"s1","share_url":"https://example.com/s/s1","expires_at":"2026-01-01T00:00:00Z"}"#,
            )
        });

        let client = ApiClient {
            base_url,
            api_key: String::new(),
        };
        let got = client.create(sample_create_request()).expect("create");
        assert_eq!(got.id, "s1");
        server.join().expect("server join");
    }

    #[test]
    fn create_authed_non_201_returns_server_error() {
        let auth = [7u8; 32];
        let wire = secrt_core::format_wire_api_key("abcdef", &auth).expect("wire");
        let wire_check = wire.clone();
        let (base_url, server) = spawn_one_shot_server(move |req| {
            assert!(req.starts_with("POST /api/v1/secrets "));
            let req_l = req.to_ascii_lowercase();
            assert!(req_l.contains(&format!(
                "x-api-key: {}\r\n",
                wire_check.to_ascii_lowercase()
            )));
            json_response("401 Unauthorized", r#"{"error":"unauthorized"}"#)
        });

        let client = ApiClient {
            base_url,
            api_key: wire,
        };
        let err = client
            .create(sample_create_request())
            .err()
            .expect("non-201");
        assert!(err.contains("unauthorized"));
        server.join().expect("server join");
    }

    #[test]
    fn create_201_with_invalid_json_fails_decode() {
        let (base_url, server) =
            spawn_one_shot_server(|_| json_response("201 Created", "{not valid json"));
        let client = ApiClient {
            base_url,
            api_key: String::new(),
        };
        let err = client
            .create(sample_create_request())
            .err()
            .expect("decode fail");
        assert!(err.contains("decode response"));
        server.join().expect("server join");
    }

    #[test]
    fn claim_success_and_error_paths() {
        let (base_ok, server_ok) = spawn_one_shot_server(|req| {
            assert!(req.starts_with("POST /api/v1/secrets/abc/claim "));
            json_response(
                "200 OK",
                r#"{"envelope":{"ciphertext":"x"},"expires_at":"2026-01-01T00:00:00Z"}"#,
            )
        });
        let client_ok = ApiClient {
            base_url: base_ok,
            api_key: String::new(),
        };
        let ok = client_ok.claim("abc", &[1, 2, 3]).expect("claim");
        assert_eq!(ok.envelope["ciphertext"], "x");
        server_ok.join().expect("server join");

        let (base_bad, server_bad) =
            spawn_one_shot_server(|_| json_response("404 Not Found", r#"{"error":"not found"}"#));
        let client_bad = ApiClient {
            base_url: base_bad,
            api_key: String::new(),
        };
        let err = client_bad
            .claim("abc", &[1, 2, 3])
            .err()
            .expect("claim fail");
        assert!(err.contains("not found"));
        server_bad.join().expect("server join");

        let (base_decode, server_decode) =
            spawn_one_shot_server(|_| json_response("200 OK", r#"{"envelope":1}"#));
        let client_decode = ApiClient {
            base_url: base_decode,
            api_key: String::new(),
        };
        let err = client_decode
            .claim("abc", &[1, 2, 3])
            .err()
            .expect("claim decode fail");
        assert!(err.contains("decode response"));
        server_decode.join().expect("server join");
    }

    // --- trailing-slash base_url handling ---

    #[test]
    fn trailing_slash_base_url_does_not_double_slash() {
        let (base_url, server) = spawn_one_shot_server(|req| {
            // Verify no double slash in the path
            assert!(
                req.contains("POST /api/v1/auth/device/start "),
                "expected clean path, got: {}",
                req.lines().next().unwrap_or("")
            );
            json_response(
                "200 OK",
                r#"{"device_code":"dc","user_code":"AB-CD","verification_url":"http://x/device?code=AB-CD","expires_in":600,"interval":5}"#,
            )
        });
        let client = ApiClient {
            base_url: format!("{}/", base_url),
            api_key: String::new(),
        };
        client
            .device_start("dGVzdA", None)
            .expect("should succeed despite trailing slash");
        server.join().expect("server join");
    }

    // --- device_start error handling ---

    #[test]
    fn device_start_404_gives_endpoint_not_found_error() {
        let (base_url, server) = spawn_one_shot_server(|_| json_response("404 Not Found", ""));
        let client = ApiClient {
            base_url: base_url.clone(),
            api_key: String::new(),
        };
        let err = client
            .device_start("dGVzdA", None)
            .expect_err("should fail");
        assert!(
            err.contains("device auth endpoint not found"),
            "expected endpoint-not-found message, got: {}",
            err
        );
        assert!(err.contains(&base_url), "should include base_url");
        assert!(err.contains("is the server up to date?"));
        server.join().expect("server join");
    }

    #[test]
    fn device_start_429_passes_through_server_error() {
        let (base_url, server) = spawn_one_shot_server(|_| {
            json_response(
                "429 Too Many Requests",
                r#"{"error":"rate limit exceeded; please try again in a few seconds"}"#,
            )
        });
        let client = ApiClient {
            base_url,
            api_key: String::new(),
        };
        let err = client
            .device_start("dGVzdA", None)
            .expect_err("should fail");
        assert!(err.contains("429"));
        assert!(err.contains("rate limit"));
        server.join().expect("server join");
    }

    #[test]
    fn device_start_success_parses_response() {
        let (base_url, server) = spawn_one_shot_server(|req| {
            assert!(req.starts_with("POST /api/v1/auth/device/start "));
            json_response(
                "200 OK",
                r#"{"device_code":"dc123","user_code":"ABCD-1234","verification_url":"https://example.com/device?code=ABCD-1234","expires_in":600,"interval":5}"#,
            )
        });
        let client = ApiClient {
            base_url,
            api_key: String::new(),
        };
        let resp = client.device_start("dGVzdA", None).expect("should succeed");
        assert_eq!(resp.device_code, "dc123");
        assert_eq!(resp.user_code, "ABCD-1234");
        assert_eq!(resp.expires_in, 600);
        assert_eq!(resp.interval, 5);
        server.join().expect("server join");
    }

    // --- device_poll error handling ---

    #[test]
    fn device_poll_non_200_returns_server_error() {
        let (base_url, server) = spawn_one_shot_server(|_| {
            json_response("400 Bad Request", r#"{"error":"expired_token"}"#)
        });
        let client = ApiClient {
            base_url,
            api_key: String::new(),
        };
        let err = client.device_poll("dc123").expect_err("should fail");
        assert!(err.contains("expired_token"));
        server.join().expect("server join");
    }

    #[test]
    fn device_poll_pending_parses_response() {
        let (base_url, server) = spawn_one_shot_server(|req| {
            assert!(req.starts_with("POST /api/v1/auth/device/poll "));
            json_response("200 OK", r#"{"status":"authorization_pending"}"#)
        });
        let client = ApiClient {
            base_url,
            api_key: String::new(),
        };
        let resp = client.device_poll("dc123").expect("should succeed");
        assert_eq!(resp.status, "authorization_pending");
        assert!(resp.prefix.is_none());
        server.join().expect("server join");
    }

    #[test]
    fn device_poll_complete_includes_prefix() {
        let (base_url, server) = spawn_one_shot_server(|_| {
            json_response("200 OK", r#"{"status":"complete","prefix":"aBcDeF"}"#)
        });
        let client = ApiClient {
            base_url,
            api_key: String::new(),
        };
        let resp = client.device_poll("dc123").expect("should succeed");
        assert_eq!(resp.status, "complete");
        assert_eq!(resp.prefix.as_deref(), Some("aBcDeF"));
        server.join().expect("server join");
    }

    #[test]
    fn burn_success_and_error_paths() {
        let auth = [9u8; 32];
        let wire = secrt_core::format_wire_api_key("abcdef", &auth).expect("wire");
        let wire_ok = wire.clone();
        let (base_ok, server_ok) = spawn_one_shot_server(move |req| {
            assert!(req.starts_with("POST /api/v1/secrets/xyz/burn "));
            let req_l = req.to_ascii_lowercase();
            assert!(req_l.contains(&format!("x-api-key: {}\r\n", wire_ok.to_ascii_lowercase())));
            json_response("200 OK", r#"{"ok":true}"#)
        });
        let client_ok = ApiClient {
            base_url: base_ok,
            api_key: wire.clone(),
        };
        client_ok.burn("xyz").expect("burn");
        server_ok.join().expect("server join");

        let wire_bad = wire;
        let (base_bad, server_bad) = spawn_one_shot_server(move |_| {
            json_response("403 Forbidden", r#"{"error":"forbidden"}"#)
        });
        let client_bad = ApiClient {
            base_url: base_bad,
            api_key: wire_bad,
        };
        let err = client_bad.burn("xyz").expect_err("burn fail");
        assert!(err.contains("forbidden"));
        server_bad.join().expect("server join");
    }

    // ---- HTTP-client behavior tests ----
    //
    // The CLI's HTTP client behavior is specified in `spec/v1/cli.md
    // § HTTP Client Behavior`: every outbound request MUST include the
    // `User-Agent: secrt/<version>` header, and every server response
    // MUST be observed for advisory `X-Secrt-*` headers so the
    // implicit-banner cache stays warm without an extra round-trip.

    #[test]
    fn outbound_requests_include_user_agent() {
        let (base_url, server) = spawn_one_shot_server(|req| {
            let req_l = req.to_ascii_lowercase();
            assert!(
                req_l.contains(&format!(
                    "user-agent: {}\r\n",
                    USER_AGENT.to_ascii_lowercase()
                )),
                "expected User-Agent header in request, got:\n{}",
                req
            );
            json_response(
                "201 Created",
                r#"{"id":"s1","share_url":"https://example.com/s/s1","expires_at":"2026-01-01T00:00:00Z"}"#,
            )
        });
        let client = ApiClient {
            base_url,
            api_key: String::new(),
        };
        client.create(sample_create_request()).expect("create");
        server.join().expect("server join");
    }

    /// Tests that mutate process env vars (XDG_CACHE_HOME) must serialize
    /// to avoid stomping on each other or on other test threads.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Best-effort RAII guard that restores `XDG_CACHE_HOME` on drop. Used
    /// by the advisory-header observer test below — process env is global,
    /// so we restore it and serialize via `ENV_LOCK`.
    struct CacheHomeGuard {
        prev: Option<String>,
    }
    impl CacheHomeGuard {
        fn set(path: &str) -> Self {
            let prev = std::env::var("XDG_CACHE_HOME").ok();
            std::env::set_var("XDG_CACHE_HOME", path);
            Self { prev }
        }
    }
    impl Drop for CacheHomeGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
                None => std::env::remove_var("XDG_CACHE_HOME"),
            }
        }
    }

    #[test]
    fn observe_response_writes_advisory_headers_to_cache() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "secrt_observe_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp");
        let _env = CacheHomeGuard::set(dir.to_str().unwrap());

        // 201 + advisory headers — observe_response runs unconditionally
        // on the response path.
        let (base_url, server) = spawn_one_shot_server(|_req| {
            let body = r#"{"id":"s1","share_url":"https://example.com/s/s1","expires_at":"2026-01-01T00:00:00Z"}"#;
            format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Secrt-Latest-Cli-Version: 99.0.0\r\nX-Secrt-Latest-Cli-Version-Checked-At: 2026-04-25T09:00:00Z\r\nX-Secrt-Min-Cli-Version: 0.15.0\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            ).into_bytes()
        });
        let client = ApiClient {
            base_url,
            api_key: String::new(),
        };
        client.create(sample_create_request()).expect("create");
        server.join().expect("server join");

        // The cache file should now reflect the advisory headers.
        let cache_path = dir.join("secrt").join("update-check.json");
        let bytes = std::fs::read(&cache_path).expect("cache file written");
        let body = String::from_utf8(bytes).expect("utf8");
        assert!(
            body.contains("\"latest\":\"99.0.0\""),
            "cache should record latest version: {}",
            body
        );
        assert!(
            body.contains("\"min_supported\":\"0.15.0\""),
            "cache should record min_supported: {}",
            body
        );
        assert!(
            body.contains("2026-04-25T09:00:00Z"),
            "cache should preserve checked_at from header: {}",
            body
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn observe_response_silent_when_no_advisory_headers() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "secrt_observe_silent_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp");
        let _env = CacheHomeGuard::set(dir.to_str().unwrap());

        // Plain 201 response — no X-Secrt-* headers. observe_response
        // must not write a cache file (the early return when all three
        // header values are absent guards against stamping a hollow
        // entry).
        let (base_url, server) = spawn_one_shot_server(|_req| {
            json_response(
                "201 Created",
                r#"{"id":"s1","share_url":"https://example.com/s/s1","expires_at":"2026-01-01T00:00:00Z"}"#,
            )
        });
        let client = ApiClient {
            base_url,
            api_key: String::new(),
        };
        client.create(sample_create_request()).expect("create");
        server.join().expect("server join");

        let cache_path = dir.join("secrt").join("update-check.json");
        assert!(
            !cache_path.exists(),
            "cache file must not be created when no advisory headers"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
