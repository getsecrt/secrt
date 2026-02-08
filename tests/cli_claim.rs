mod helpers;

use helpers::{args, TestDepsBuilder};
use secrt::cli;
use secrt::client::ClaimResponse;
use secrt::envelope::crypto::b64_encode;
use secrt::envelope::{self, SealParams};

/// Non-routable address to ensure API calls fail
const DEAD_URL: &str = "http://127.0.0.1:19191";

fn make_share_url(base: &str, id: &str) -> String {
    let key = vec![42u8; 32];
    let key_b64 = b64_encode(&key);
    format!("{}/s/{}#v1.{}", base, id, key_b64)
}

fn real_rand(buf: &mut [u8]) -> Result<(), secrt::envelope::EnvelopeError> {
    use ring::rand::{SecureRandom, SystemRandom};
    SystemRandom::new()
        .fill(buf)
        .map_err(|_| secrt::envelope::EnvelopeError::RngError("SystemRandom failed".into()))
}

/// Seal an envelope and return (share_link, seal_result)
fn seal_test_secret(plaintext: &[u8], passphrase: &str) -> (String, envelope::SealResult) {
    let result = envelope::seal(SealParams {
        plaintext: plaintext.to_vec(),
        passphrase: passphrase.to_string(),
        rand_bytes: &real_rand,
        hint: None,
        iterations: if passphrase.is_empty() {
            0
        } else {
            300_000
        },
    })
    .unwrap();
    let share_link = envelope::format_share_link(
        &format!("https://secrt.ca/s/{}", "mock-id"),
        &result.url_key,
    );
    (share_link, result)
}

#[test]
fn claim_unknown_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "claim", "--bogus"]), &mut deps);
    assert_eq!(code, 2);
    assert!(
        stderr.to_string().contains("unknown flag"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn claim_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "claim", "--help"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().is_empty());
}

#[test]
fn claim_no_url() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "claim"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("required"));
}

#[test]
fn claim_invalid_url() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "claim", "not-a-valid-url"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("invalid"));
}

#[test]
fn claim_api_call_fails() {
    let url = make_share_url(DEAD_URL, "test123");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "claim", &url]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn claim_base_url_flag_override() {
    let url = make_share_url("https://secrt.ca", "test123");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&["secrt", "claim", &url, "--base-url", DEAD_URL]),
        &mut deps,
    );
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn claim_json_error() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "claim", "--json", "not-valid"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(err.contains("\"error\""), "should be JSON error: {}", err);
}

// --- Mock API success tests ---

#[test]
fn claim_success_plain() {
    let plaintext = b"hello from mock claim";
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "claim", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "hello from mock claim");
}

#[test]
fn claim_success_json() {
    let plaintext = b"json claim test";
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T12:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "claim", &share_link, "--json"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON output");
    assert_eq!(
        json["expires_at"].as_str().unwrap(),
        "2026-02-09T12:00:00Z"
    );
}

#[test]
fn claim_success_with_passphrase() {
    let plaintext = b"passphrase protected";
    let (share_link, seal_result) = seal_test_secret(plaintext, "mypass");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .mock_claim(Ok(mock_resp))
        .env("MY_PASS", "mypass")
        .build();
    let code = cli::run(
        &args(&[
            "secrt",
            "claim",
            &share_link,
            "--passphrase-env",
            "MY_PASS",
        ]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "passphrase protected");
}

#[test]
fn claim_decryption_error() {
    let plaintext = b"will fail";
    let (_share_link, seal_result) = seal_test_secret(plaintext, "");
    // Use a different key in the share URL so decryption fails
    let bad_key = vec![99u8; 32];
    let bad_share_link = envelope::format_share_link(
        "https://secrt.ca/s/mock-id",
        &bad_key,
    );
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "claim", &bad_share_link]), &mut deps);
    assert_eq!(code, 1);
    assert!(
        stderr.to_string().contains("decryption failed"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn claim_api_error() {
    let url = make_share_url("https://secrt.ca", "test123");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .mock_claim(Err("server error (404): secret not found".into()))
        .build();
    let code = cli::run(&args(&["secrt", "claim", &url]), &mut deps);
    assert_eq!(code, 1);
    assert!(
        stderr.to_string().contains("claim failed"),
        "stderr: {}",
        stderr.to_string()
    );
}
