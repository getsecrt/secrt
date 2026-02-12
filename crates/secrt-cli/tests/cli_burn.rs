mod helpers;

use helpers::{args, TestDepsBuilder};
use secrt::cli;
use secrt::envelope::crypto::b64_encode;

/// Non-routable address to ensure API calls fail
const DEAD_URL: &str = "http://127.0.0.1:19191";

fn make_share_url(base: &str, id: &str) -> String {
    let key = vec![42u8; 32];
    let key_b64 = b64_encode(&key);
    format!("{}/s/{}#{}", base, id, key_b64)
}

#[test]
fn burn_unknown_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "burn", "--bogus"]), &mut deps);
    assert_eq!(code, 2);
    assert!(
        stderr.to_string().contains("unknown flag"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn burn_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "burn", "--help"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().is_empty());
}

#[test]
fn burn_no_id() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "burn"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("required"));
}

#[test]
fn burn_no_api_key() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "burn", "testid"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("api-key"));
}

#[test]
fn burn_bare_id() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(
        &args(&["secrt", "burn", "testid", "--api-key", "sk_test"]),
        &mut deps,
    );
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn burn_share_url() {
    let url = make_share_url(DEAD_URL, "abc123");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&["secrt", "burn", &url, "--api-key", "sk_test"]),
        &mut deps,
    );
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn burn_json_output() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(
        &args(&["secrt", "burn", "testid", "--api-key", "sk_test", "--json"]),
        &mut deps,
    );
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(err.contains("\"error\""), "should be JSON error: {}", err);
}

#[test]
fn burn_malformed_url() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&["secrt", "burn", "bad/url#short", "--api-key", "sk_test"]),
        &mut deps,
    );
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("invalid"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn burn_env_api_key() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", "sk_from_env")
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "burn", "testid"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

// --- Mock API success tests ---

#[test]
fn burn_success_plain() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().mock_burn(Ok(())).build();
    let code = cli::run(
        &args(&["secrt", "burn", "test-id-123", "--api-key", "sk_test"]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("Secret burned."),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn burn_success_json() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new().mock_burn(Ok(())).build();
    let code = cli::run(
        &args(&[
            "secrt",
            "burn",
            "test-id-123",
            "--api-key",
            "sk_test",
            "--json",
        ]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON output");
    assert_eq!(json["ok"].as_bool().unwrap(), true);
}

#[test]
fn burn_success_share_url() {
    let url = make_share_url("https://secrt.ca", "burn-test");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().mock_burn(Ok(())).build();
    let code = cli::run(
        &args(&["secrt", "burn", &url, "--api-key", "sk_test"]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("Secret burned."),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn burn_api_error() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .mock_burn(Err("server error (403): forbidden".into()))
        .build();
    let code = cli::run(
        &args(&["secrt", "burn", "test-id", "--api-key", "sk_bad"]),
        &mut deps,
    );
    assert_eq!(code, 1);
    assert!(
        stderr.to_string().contains("burn failed"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn burn_silent_suppresses_message() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().mock_burn(Ok(())).build();
    let code = cli::run(
        &args(&[
            "secrt",
            "burn",
            "test-id-123",
            "--api-key",
            "sk_test",
            "--silent",
        ]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(
        !stderr.to_string().contains("Secret burned"),
        "silent burn should suppress message: {}",
        stderr.to_string()
    );
}

#[test]
fn burn_success_tty_shows_checkmark() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .mock_burn(Ok(()))
        .build();
    let code = cli::run(
        &args(&["secrt", "burn", "test-id", "--api-key", "sk_test"]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(
        err.contains("\u{2713}") || err.contains("Secret burned"),
        "TTY burn should show checkmark or message: {}",
        err
    );
}
