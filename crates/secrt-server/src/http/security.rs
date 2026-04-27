//! Browser-enforced security headers for the SPA: CSP, COOP, CORP,
//! Permissions-Policy, and Cache-Control.

use std::sync::OnceLock;

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderName, HeaderValue};
use axum::response::Response;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ring::digest::{digest, SHA256};

// `'wasm-unsafe-eval'` is the CSP3-narrow source for WebAssembly
// compilation (Argon2 ships as WASM). Strictly narrower than
// `'unsafe-eval'`: it allows WASM but NOT JS eval/Function/setTimeout(str).
const CSP_TEMPLATE_HEAD: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'";
const CSP_TEMPLATE_TAIL: &str = "; style-src 'self'; \
     img-src 'self' data: blob:; \
     font-src 'self'; \
     connect-src 'self'; \
     manifest-src 'self'; \
     worker-src 'self'; \
     form-action 'none'; \
     base-uri 'none'; \
     frame-ancestors 'none'; \
     object-src 'none'; \
     upgrade-insecure-requests";

const COOP_NAME: HeaderName = HeaderName::from_static("cross-origin-opener-policy");
const CORP_NAME: HeaderName = HeaderName::from_static("cross-origin-resource-policy");
const PERMISSIONS_POLICY_NAME: HeaderName = HeaderName::from_static("permissions-policy");
const CSP_NAME: HeaderName = HeaderName::from_static("content-security-policy");

const COOP_VALUE: HeaderValue = HeaderValue::from_static("same-origin");
const CORP_VALUE: HeaderValue = HeaderValue::from_static("same-origin");
const PERMISSIONS_POLICY_VALUE: HeaderValue = HeaderValue::from_static(
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
     microphone=(), payment=(), usb=(), interest-cohort=()",
);
const NO_STORE_VALUE: HeaderValue = HeaderValue::from_static("no-store");

/// Returns the CSP header value, computed once from the embedded
/// `index.html`. Each inline `<script>` body in that document contributes
/// a `'sha256-…'` source to `script-src`, so the strict CSP can ship
/// without `'unsafe-inline'`.
pub fn csp_value() -> &'static str {
    static CSP: OnceLock<String> = OnceLock::new();
    CSP.get_or_init(|| {
        let html = crate::assets::spa_index_html()
            .unwrap_or_else(|| include_str!("../../templates/index.html").to_string());
        build_csp(&html)
    })
}

fn build_csp(html: &str) -> String {
    let mut out = String::with_capacity(512);
    out.push_str(CSP_TEMPLATE_HEAD);
    for body in inline_script_bodies(html) {
        let hash = digest(&SHA256, body.as_bytes());
        let b64 = BASE64_STANDARD.encode(hash.as_ref());
        out.push_str(" 'sha256-");
        out.push_str(&b64);
        out.push('\'');
    }
    out.push_str(CSP_TEMPLATE_TAIL);
    out
}

/// Extracts each inline `<script>` body from `html`. Scripts with a `src`
/// attribute are skipped — those are external and policed by `script-src`
/// host sources, not hashes. Order is preserved.
fn inline_script_bodies(html: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = html.as_bytes();
    let mut i = 0;

    while let Some(start) = find_subseq_ci(&bytes[i..], b"<script") {
        let tag_open_start = i + start;
        let Some(rel_open_end) = bytes[tag_open_start..].iter().position(|&b| b == b'>') else {
            break;
        };
        let tag_open_end = tag_open_start + rel_open_end;
        let attrs = &bytes[tag_open_start + b"<script".len()..tag_open_end];
        i = tag_open_end + 1;

        if attrs.last() == Some(&b'/') {
            continue;
        }
        if has_src_attr(attrs) {
            if let Some(close_rel) = find_subseq_ci(&bytes[i..], b"</script>") {
                i += close_rel + b"</script>".len();
            }
            continue;
        }

        let Some(close_rel) = find_subseq_ci(&bytes[i..], b"</script>") else {
            break;
        };
        let body = &html[i..i + close_rel];
        out.push(body);
        i += close_rel + b"</script>".len();
    }

    out
}

fn has_src_attr(attrs: &[u8]) -> bool {
    let needle = b"src=";
    let mut i = 0;
    while i + needle.len() <= attrs.len() {
        let prev_ok = i == 0 || attrs[i - 1].is_ascii_whitespace();
        if prev_ok && attrs[i..i + needle.len()].eq_ignore_ascii_case(needle) {
            return true;
        }
        i += 1;
    }
    false
}

fn find_subseq_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let last = haystack.len() - needle.len();
    for i in 0..=last {
        if haystack[i..i + needle.len()].eq_ignore_ascii_case(needle) {
            return Some(i);
        }
    }
    None
}

/// Apply the always-on browser hardening headers, plus CSP and Cache-Control
/// for HTML responses.
pub fn apply_security_headers(resp: &mut Response) {
    let is_html = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            ct.trim_start()
                .to_ascii_lowercase()
                .starts_with("text/html")
        });

    let headers = resp.headers_mut();
    headers.insert(COOP_NAME, COOP_VALUE);
    headers.insert(CORP_NAME, CORP_VALUE);
    headers.insert(PERMISSIONS_POLICY_NAME, PERMISSIONS_POLICY_VALUE);

    if is_html {
        if let Ok(value) = HeaderValue::from_str(csp_value()) {
            headers.insert(CSP_NAME, value);
        }
        headers.insert(CACHE_CONTROL, NO_STORE_VALUE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_single_inline_script() {
        let html = "<html><head><script>console.log('x')</script></head></html>";
        let bodies = inline_script_bodies(html);
        assert_eq!(bodies, vec!["console.log('x')"]);
    }

    #[test]
    fn skips_external_scripts() {
        let html = r#"<head>
            <script src="/main.js"></script>
            <script>console.log('inline')</script>
            <script SRC="/other.js"></script>
        </head>"#;
        let bodies = inline_script_bodies(html);
        assert_eq!(bodies, vec!["console.log('inline')"]);
    }

    #[test]
    fn handles_attributes_on_inline_script() {
        let html = r#"<script type="module">var a = 1;</script>"#;
        let bodies = inline_script_bodies(html);
        assert_eq!(bodies, vec!["var a = 1;"]);
    }

    #[test]
    fn build_csp_includes_sha256_for_each_inline_script() {
        let html = "<head><script>a</script><script>b</script></head>";
        let csp = build_csp(html);
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("script-src 'self' 'wasm-unsafe-eval' 'sha256-"));
        let count = csp.matches("'sha256-").count();
        assert_eq!(count, 2, "expected 2 hashes, got CSP: {csp}");
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("object-src 'none'"));
        assert!(csp.contains("upgrade-insecure-requests"));
        assert!(!csp.contains("'unsafe-inline'"));
        assert!(!csp.contains("'unsafe-eval'"));
    }

    #[test]
    fn embedded_index_csp_covers_every_inline_script() {
        // Drift guard: any inline <script> in the served index.html must
        // have its hash in csp_value(). If anyone adds a new inline
        // script, this fails until the CSP is regenerated (the OnceLock
        // recomputes on next start).
        let html = crate::assets::spa_index_html()
            .unwrap_or_else(|| include_str!("../../templates/index.html").to_string());
        let csp = build_csp(&html);
        for body in inline_script_bodies(&html) {
            let hash = digest(&SHA256, body.as_bytes());
            let b64 = BASE64_STANDARD.encode(hash.as_ref());
            let token = format!("'sha256-{b64}'");
            assert!(
                csp.contains(&token),
                "CSP missing hash for inline script body: {body:?}"
            );
        }
    }
}
