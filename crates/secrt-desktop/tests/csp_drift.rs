//! Drift test: `tauri.conf.json` CSP `connect-src` directive must list
//! every official secrt instance from `secrt_core::KNOWN_INSTANCES`.
//!
//! A widened CSP isn't enforced at the type system level — if someone
//! adds a new official instance to the spec without updating this file,
//! the desktop app would silently refuse to talk to it. This test
//! catches that drift at build time.

use secrt_core::KNOWN_INSTANCES;
use std::collections::HashSet;

#[test]
fn csp_connect_src_matches_known_instances() {
    let conf_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tauri.conf.json");
    let raw = std::fs::read_to_string(conf_path).expect("read tauri.conf.json");
    let json: serde_json::Value = serde_json::from_str(&raw).expect("parse tauri.conf.json");

    let csp = json
        .pointer("/app/security/csp")
        .and_then(|v| v.as_str())
        .expect("tauri.conf.json missing /app/security/csp");

    let connect_src =
        extract_directive(csp, "connect-src").expect("CSP missing connect-src directive");

    let connect_src_tokens: HashSet<&str> = connect_src.split_whitespace().collect();

    for apex in KNOWN_INSTANCES {
        let expected = format!("https://{apex}");
        assert!(
            connect_src_tokens.contains(expected.as_str()),
            "CSP connect-src missing official instance origin `{expected}`. \
             KNOWN_INSTANCES = {KNOWN_INSTANCES:?}, connect-src = `{connect_src}`. \
             Update tauri.conf.json to widen CSP for the new instance."
        );
    }
}

/// Extract the value portion of a single CSP directive (everything after
/// the directive name and before the next `;` or end of string). Returns
/// `None` if the directive is absent.
fn extract_directive<'a>(csp: &'a str, name: &str) -> Option<&'a str> {
    for chunk in csp.split(';') {
        let trimmed = chunk.trim();
        if let Some(rest) = trimmed.strip_prefix(name) {
            // Require a whitespace boundary so `connect-src` doesn't
            // match `connect-src-elem` or similar.
            if let Some(value) = rest.strip_prefix(char::is_whitespace) {
                return Some(value.trim());
            }
        }
    }
    None
}
