//! End-to-end tests that hit a real server.
//! Gated behind the `SECRET_E2E_BASE_URL` environment variable.
//!
//! Run with:
//!   SECRET_E2E_BASE_URL=https://secrt.ca cargo test e2e -- --ignored
//!
//! For burn/api-key tests:
//!   SECRET_E2E_BASE_URL=https://secrt.ca SECRET_E2E_API_KEY=sk_... cargo test e2e -- --ignored

mod helpers;

use helpers::{args, TestDepsBuilder};
use secrt::cli;

fn base_url() -> String {
    std::env::var("SECRET_E2E_BASE_URL").unwrap_or_default()
}

fn api_key() -> String {
    std::env::var("SECRET_E2E_API_KEY").unwrap_or_default()
}

fn should_skip() -> bool {
    base_url().is_empty()
}

fn should_skip_api_key() -> bool {
    should_skip() || api_key().is_empty()
}

#[test]
#[ignore]
fn e2e_create_claim_roundtrip() {
    if should_skip() {
        return;
    }
    let url = base_url();
    let plaintext = "e2e-roundtrip-test-data";

    // Create
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(plaintext.as_bytes())
        .env("SECRET_BASE_URL", &url)
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 0, "create failed: {}", stderr.to_string());

    let share_link = stdout.to_string().trim().to_string();
    assert!(!share_link.is_empty(), "no share link returned");

    // Claim
    let (mut deps2, stdout2, stderr2) = TestDepsBuilder::new().build();
    let code2 = cli::run(&args(&["secrt", "claim", &share_link]), &mut deps2);
    assert_eq!(code2, 0, "claim failed: {}", stderr2.to_string());

    let recovered = stdout2.to_string();
    assert_eq!(recovered, plaintext);
}

#[test]
#[ignore]
fn e2e_create_with_passphrase() {
    if should_skip() {
        return;
    }
    let url = base_url();
    let plaintext = "e2e-passphrase-test";

    // Create with passphrase via env
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(plaintext.as_bytes())
        .env("SECRET_BASE_URL", &url)
        .env("MY_E2E_PASS", "testpass123")
        .build();
    let code = cli::run(
        &args(&["secrt", "create", "--passphrase-env", "MY_E2E_PASS"]),
        &mut deps,
    );
    assert_eq!(code, 0, "create failed: {}", stderr.to_string());

    let share_link = stdout.to_string().trim().to_string();

    // Claim with same passphrase
    let (mut deps2, stdout2, stderr2) = TestDepsBuilder::new()
        .env("MY_E2E_PASS", "testpass123")
        .build();
    let code2 = cli::run(
        &args(&[
            "secrt",
            "claim",
            &share_link,
            "--passphrase-env",
            "MY_E2E_PASS",
        ]),
        &mut deps2,
    );
    assert_eq!(code2, 0, "claim failed: {}", stderr2.to_string());
    assert_eq!(stdout2.to_string(), plaintext);
}

#[test]
#[ignore]
fn e2e_create_with_ttl() {
    if should_skip() {
        return;
    }
    let url = base_url();

    // Create with TTL and JSON output
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"e2e-ttl-test")
        .env("SECRET_BASE_URL", &url)
        .build();
    let code = cli::run(
        &args(&["secrt", "create", "--ttl", "5m", "--json"]),
        &mut deps,
    );
    assert_eq!(code, 0, "create failed: {}", stderr.to_string());

    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON output");
    assert!(json.get("share_link").is_some());
    assert!(json.get("expires_at").is_some());
}

#[test]
#[ignore]
fn e2e_create_claim_json() {
    if should_skip() {
        return;
    }
    let url = base_url();

    // Create with JSON
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"e2e-json-test")
        .env("SECRET_BASE_URL", &url)
        .build();
    let code = cli::run(&args(&["secrt", "create", "--json"]), &mut deps);
    assert_eq!(code, 0, "create failed: {}", stderr.to_string());

    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON");
    let share_link = json["share_link"].as_str().unwrap().to_string();

    // Claim with JSON output
    let (mut deps2, stdout2, stderr2) = TestDepsBuilder::new().build();
    let code2 = cli::run(
        &args(&["secrt", "claim", &share_link, "--json"]),
        &mut deps2,
    );
    assert_eq!(code2, 0, "claim failed: {}", stderr2.to_string());

    let out2 = stdout2.to_string();
    let json2: serde_json::Value = serde_json::from_str(out2.trim()).expect("invalid JSON");
    assert!(json2.get("expires_at").is_some());
}

#[test]
#[ignore]
fn e2e_create_with_api_key() {
    if should_skip_api_key() {
        return;
    }
    let url = base_url();
    let key = api_key();
    let plaintext = "e2e-api-key-create-test";

    // Create with API key (uses authenticated endpoint)
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(plaintext.as_bytes())
        .env("SECRET_BASE_URL", &url)
        .build();
    let code = cli::run(
        &args(&["secrt", "create", "--api-key", &key, "--json"]),
        &mut deps,
    );
    assert_eq!(code, 0, "create failed: {}", stderr.to_string());

    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON");
    let share_link = json["share_link"].as_str().unwrap().to_string();

    // Claim it back
    let (mut deps2, stdout2, stderr2) = TestDepsBuilder::new().build();
    let code2 = cli::run(&args(&["secrt", "claim", &share_link]), &mut deps2);
    assert_eq!(code2, 0, "claim failed: {}", stderr2.to_string());
    assert_eq!(stdout2.to_string(), plaintext);
}

#[test]
#[ignore]
fn e2e_burn() {
    if should_skip_api_key() {
        return;
    }
    let url = base_url();
    let key = api_key();

    // Create a secret to burn
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"e2e-burn-test")
        .env("SECRET_BASE_URL", &url)
        .build();
    let code = cli::run(
        &args(&["secrt", "create", "--api-key", &key, "--json"]),
        &mut deps,
    );
    assert_eq!(code, 0, "create failed: {}", stderr.to_string());

    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON");
    let secret_id = json["id"].as_str().unwrap().to_string();

    // Burn it
    let (mut deps2, _stdout2, stderr2) = TestDepsBuilder::new()
        .env("SECRET_BASE_URL", &url)
        .build();
    let code2 = cli::run(
        &args(&["secrt", "burn", &secret_id, "--api-key", &key]),
        &mut deps2,
    );
    assert_eq!(code2, 0, "burn failed: {}", stderr2.to_string());
    assert!(
        stderr2.to_string().contains("Secret burned."),
        "stderr: {}",
        stderr2.to_string()
    );
}
