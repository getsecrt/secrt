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

    #[test]
    fn handle_ureq_error_tls_dns_timeout_branches() {
        let client = ApiClient {
            base_url: "https://example.com".into(),
            api_key: String::new(),
        };

        let tls = client.handle_ureq_error(ureq::Error::Tls("certificate verify failed"));
        assert!(tls.contains("TLS error connecting to"));

        let dns = client.handle_ureq_error(ureq::Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No such host",
        )));
        assert!(dns.contains("cannot resolve host"));

        let timeout = client.handle_ureq_error(ureq::Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        )));
        assert!(timeout.contains("timed out"));
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
}
