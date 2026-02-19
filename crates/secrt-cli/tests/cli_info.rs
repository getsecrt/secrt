mod helpers;

use helpers::{args, TestDepsBuilder};
use secrt_cli::cli;
use secrt_cli::client::SecretMetadataItem;

fn sample_meta() -> SecretMetadataItem {
    SecretMetadataItem {
        id: "abc123def456".into(),
        share_url: "https://secrt.ca/s/abc123def456".into(),
        expires_at: "2099-12-31T23:59:59Z".into(),
        created_at: "2026-02-14T10:30:00Z".into(),
        ciphertext_size: 256,
        passphrase_protected: false,
        enc_meta: None,
    }
}

fn sample_api_key() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let root = [9u8; 32];
    format!("sk2_abcdef.{}", URL_SAFE_NO_PAD.encode(root))
}

#[test]
fn info_help_shows_usage() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "info", "--help"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("INFO"), "should show INFO heading");
    assert!(err.contains("info"), "should mention info command");
}

#[test]
fn help_info_shows_info_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "info"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("INFO"), "should show INFO heading");
}

#[test]
fn info_missing_id_exits_2() {
    let api_key = sample_api_key();
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .build();
    let code = cli::run(&args(&["secrt", "info"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(
        err.contains("secret ID or share URL is required"),
        "should report missing ID, got: {}",
        err
    );
}

#[test]
fn info_no_auth_exits_2() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "info", "abc123"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(
        err.contains("--api-key is required"),
        "should require auth, got: {}",
        err
    );
}

#[test]
fn info_displays_metadata() {
    let api_key = sample_api_key();
    let meta = sample_meta();
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_get_secret_metadata(Ok(meta.clone()))
        .build();
    let code = cli::run(&args(&["secrt", "info", "abc123def456"]), &mut deps);
    assert_eq!(code, 0);
    let out = stdout.to_string();
    assert!(out.contains("abc123def456"), "should show ID");
    assert!(
        out.contains("https://secrt.ca/s/abc123def456"),
        "should show share URL"
    );
    assert!(out.contains("256 B"), "should show size");
}

#[test]
fn info_json_outputs_metadata() {
    let api_key = sample_api_key();
    let meta = sample_meta();
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_get_secret_metadata(Ok(meta))
        .build();
    let code = cli::run(
        &args(&["secrt", "info", "--json", "abc123def456"]),
        &mut deps,
    );
    assert_eq!(code, 0);
    let out = stdout.to_string();
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(parsed["id"], "abc123def456");
    assert_eq!(parsed["ciphertext_size"], 256);
}

#[test]
fn info_passphrase_protected_shown() {
    let api_key = sample_api_key();
    let mut meta = sample_meta();
    meta.passphrase_protected = true;
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_get_secret_metadata(Ok(meta))
        .build();
    let code = cli::run(&args(&["secrt", "info", "abc123def456"]), &mut deps);
    assert_eq!(code, 0);
    let out = stdout.to_string();
    assert!(
        out.contains("Passphrase-protected"),
        "should indicate passphrase, got: {}",
        out
    );
}

#[test]
fn info_server_error_exits_1() {
    let api_key = sample_api_key();
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_get_secret_metadata(Err("server error (500): internal error".into()))
        .build();
    let code = cli::run(&args(&["secrt", "info", "abc123"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("info failed"),
        "should show error, got: {}",
        err
    );
}
