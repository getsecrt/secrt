//! Spec-vector tests for the instance trust module. The JSON file at
//! `spec/v1/instances.json` is the normative source; this test fails if
//! `KNOWN_INSTANCES` drifts from the spec apex list, or if the verdict
//! function ever disagrees with the table below.

use secrt_core::{classify_origin, normalize_origin, TrustDecision, KNOWN_INSTANCES};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn load_spec() -> Value {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("spec/v1/instances.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("parse instances.json")
}

#[test]
fn known_instances_matches_spec_apex_list() {
    let spec = load_spec();
    let spec_apexes: Vec<String> = spec["official_instances"]
        .as_array()
        .expect("official_instances array")
        .iter()
        .map(|e| e["apex"].as_str().expect("apex string").to_string())
        .collect();
    let core_apexes: Vec<String> = KNOWN_INSTANCES.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        spec_apexes, core_apexes,
        "spec/v1/instances.json apex list must match KNOWN_INSTANCES",
    );
}

#[test]
fn official_origins_classify_as_official() {
    let spec = load_spec();
    for entry in spec["official_instances"].as_array().unwrap() {
        let origin = entry["origin"].as_str().unwrap();
        let apex = entry["apex"].as_str().unwrap();
        match classify_origin(origin, &[]) {
            TrustDecision::Official { apex: got } => assert_eq!(
                got, apex,
                "{origin} should classify as Official for apex {apex}"
            ),
            other => panic!("{origin} classified as {other:?}, wanted Official"),
        }
    }
}

#[test]
fn wildcard_subdomains_collapse_to_apex() {
    for url in [
        "https://my.secrt.ca",
        "https://team.secrt.is",
        "https://foo.bar.secrt.ca/",
    ] {
        match classify_origin(url, &[]) {
            TrustDecision::Official { .. } => {}
            other => panic!("{url} classified as {other:?}, wanted Official"),
        }
    }
}

#[test]
fn untrusted_hosts_classify_as_untrusted() {
    for url in [
        "https://evil.tld",
        "https://foosecrt.is",
        "https://secrt.is.evil.tld",
        "https://notsecrt.ca",
        "https://secrt.evil.tld",
    ] {
        assert_eq!(
            classify_origin(url, &[]),
            TrustDecision::Untrusted,
            "{url} should be Untrusted",
        );
    }
}

#[test]
fn devlocal_hosts() {
    for url in [
        "http://localhost",
        "http://localhost:8080",
        "https://localhost",
        "http://127.0.0.1:8080",
        "http://127.0.0.5",
        "http://[::1]:8080",
        "https://[::1]",
        "http://my-machine.local",
        "http://foo.local:3000",
    ] {
        assert_eq!(
            classify_origin(url, &[]),
            TrustDecision::DevLocal,
            "{url} should be DevLocal",
        );
    }
}

#[test]
fn non_default_port_on_official_apex_is_not_official() {
    assert_eq!(
        classify_origin("https://secrt.ca:8443", &[]),
        TrustDecision::Untrusted,
        "non-default port on official apex must require trusted_servers opt-in",
    );
}

#[test]
fn http_scheme_on_official_apex_is_not_official() {
    assert_eq!(
        classify_origin("http://secrt.ca", &[]),
        TrustDecision::Untrusted,
    );
}

#[test]
fn trusted_custom_silences_unknown_host() {
    let trusted = vec!["evil.tld".to_string()];
    assert_eq!(
        classify_origin("https://evil.tld", &trusted),
        TrustDecision::TrustedCustom,
    );
    // Case-insensitive match.
    assert_eq!(
        classify_origin("https://EVIL.TLD", &trusted),
        TrustDecision::TrustedCustom,
    );
}

#[test]
fn unparseable_url_is_untrusted() {
    assert_eq!(classify_origin("", &[]), TrustDecision::Untrusted);
    assert_eq!(classify_origin("not a url", &[]), TrustDecision::Untrusted);
    assert_eq!(
        classify_origin("ftp://secrt.ca", &[]),
        TrustDecision::Untrusted,
    );
}

#[test]
fn normalize_origin_returns_scheme_host_port() {
    assert_eq!(
        normalize_origin("https://secrt.ca/some/path?x=1"),
        Some("https://secrt.ca".to_string()),
    );
    assert_eq!(
        normalize_origin("https://secrt.ca:8443/path"),
        Some("https://secrt.ca:8443".to_string()),
    );
    assert_eq!(
        normalize_origin("HTTPS://Secrt.Ca/Foo"),
        Some("https://secrt.ca".to_string()),
    );
    // IPv6 brackets preserved.
    assert_eq!(
        normalize_origin("http://[::1]:8080/x"),
        Some("http://[::1]:8080".to_string()),
    );
    assert_eq!(normalize_origin(""), None);
    assert_eq!(normalize_origin("not a url"), None);
}
