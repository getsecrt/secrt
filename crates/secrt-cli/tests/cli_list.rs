mod helpers;

use helpers::{args, TestDepsBuilder};
use secrt_cli::cli;
use secrt_cli::client::{ListSecretsResponse, SecretMetadataItem};

fn sample_secrets() -> Vec<SecretMetadataItem> {
    vec![
        SecretMetadataItem {
            id: "abc123def456ghij".into(),
            share_url: "https://secrt.ca/s/abc123def456ghij".into(),
            expires_at: "2099-12-31T23:59:59Z".into(),
            created_at: "2026-02-14T10:30:00Z".into(),
            ciphertext_size: 1234,
            passphrase_protected: true,
        },
        SecretMetadataItem {
            id: "xyz789ghi012klmn".into(),
            share_url: "https://secrt.ca/s/xyz789ghi012klmn".into(),
            expires_at: "2099-06-15T12:00:00Z".into(),
            created_at: "2026-02-14T09:00:00Z".into(),
            ciphertext_size: 256,
            passphrase_protected: false,
        },
    ]
}

fn sample_response() -> ListSecretsResponse {
    ListSecretsResponse {
        secrets: sample_secrets(),
        total: 2,
        limit: 50,
        offset: 0,
    }
}

#[test]
fn list_no_api_key() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "list"]), &mut deps);
    assert_eq!(code, 2);
    assert!(
        stderr.to_string().contains("api-key"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn list_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "list", "--help"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("list"), "stderr: {}", err);
    assert!(err.contains("--limit"), "stderr: {}", err);
    assert!(err.contains("--offset"), "stderr: {}", err);
}

#[test]
fn list_help_subcommand() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "list"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().is_empty());
}

#[test]
fn list_unknown_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "list", "--bogus"]), &mut deps);
    assert_eq!(code, 2);
    assert!(
        stderr.to_string().contains("unknown flag"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn list_table_output() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new()
        .mock_list(Ok(sample_response()))
        .build();
    let code = cli::run(&args(&["secrt", "list", "--api-key", "sk_test"]), &mut deps);
    assert_eq!(code, 0);
    let out = stdout.to_string();
    // Header row
    assert!(out.contains("ID"), "should have ID header: {}", out);
    assert!(
        out.contains("Created"),
        "should have Created header: {}",
        out
    );
    assert!(
        out.contains("Expires In"),
        "should have Expires In header: {}",
        out
    );
    assert!(out.contains("Size"), "should have Size header: {}", out);
    // Key glyph header
    assert!(out.contains("\u{26b7}"), "should have key glyph: {}", out);
    // Data rows
    assert!(
        out.contains("abc123def456ghij"),
        "should contain first ID: {}",
        out
    );
    assert!(
        out.contains("xyz789ghi012klmn"),
        "should contain second ID: {}",
        out
    );
    // Key glyph for passphrase-protected row
    assert!(
        out.contains("\u{26b7}"),
        "should have key glyph for passphrase: {}",
        out
    );
    // Size formatting
    assert!(out.contains("1.2 KB"), "should format size: {}", out);
    assert!(out.contains("256 B"), "should format small size: {}", out);
    // Created formatting
    assert!(
        out.contains("Feb 14, 10:30"),
        "should format created date: {}",
        out
    );
}

#[test]
fn list_json_output() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new()
        .mock_list(Ok(sample_response()))
        .build();
    let code = cli::run(
        &args(&["secrt", "list", "--api-key", "sk_test", "--json"]),
        &mut deps,
    );
    assert_eq!(code, 0);
    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON output");
    assert_eq!(json["total"], 2);
    assert_eq!(json["secrets"].as_array().unwrap().len(), 2);
    assert_eq!(json["secrets"][0]["id"], "abc123def456ghij");
    assert_eq!(json["secrets"][1]["passphrase_protected"], false);
}

#[test]
fn list_empty() {
    let resp = ListSecretsResponse {
        secrets: vec![],
        total: 0,
        limit: 50,
        offset: 0,
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new().mock_list(Ok(resp)).build();
    let code = cli::run(&args(&["secrt", "list", "--api-key", "sk_test"]), &mut deps);
    assert_eq!(code, 0);
    assert!(
        stdout.to_string().is_empty(),
        "no table output for empty list"
    );
    assert!(
        stderr.to_string().contains("No active secrets"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn list_api_error() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .mock_list(Err("server error (401): unauthorized".into()))
        .build();
    let code = cli::run(&args(&["secrt", "list", "--api-key", "sk_bad"]), &mut deps);
    assert_eq!(code, 1);
    assert!(
        stderr.to_string().contains("list failed"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn list_pagination_hint() {
    let resp = ListSecretsResponse {
        secrets: sample_secrets(),
        total: 10,
        limit: 2,
        offset: 0,
    };
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().mock_list(Ok(resp)).build();
    let code = cli::run(&args(&["secrt", "list", "--api-key", "sk_test"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("Showing 1-2 of 10"),
        "should show pagination: {}",
        err
    );
    assert!(
        err.contains("--offset 2"),
        "should hint next offset: {}",
        err
    );
}

#[test]
fn list_with_limit_and_offset_flags() {
    let resp = ListSecretsResponse {
        secrets: sample_secrets(),
        total: 50,
        limit: 5,
        offset: 10,
    };
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().mock_list(Ok(resp)).build();
    let code = cli::run(
        &args(&[
            "secrt",
            "list",
            "--api-key",
            "sk_test",
            "--limit",
            "5",
            "--offset",
            "10",
        ]),
        &mut deps,
    );
    assert_eq!(code, 0);
    assert!(!stdout.to_string().is_empty());
}

#[test]
fn list_id_truncation() {
    let mut secrets = sample_secrets();
    secrets[0].id = "abcdefghijklmnopqrstuvwxyz0123456789".into();
    let resp = ListSecretsResponse {
        secrets,
        total: 2,
        limit: 50,
        offset: 0,
    };
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().mock_list(Ok(resp)).build();
    let code = cli::run(&args(&["secrt", "list", "--api-key", "sk_test"]), &mut deps);
    assert_eq!(code, 0);
    let out = stdout.to_string();
    // Should be truncated with ellipsis
    assert!(
        out.contains("abcdefghijklmnop\u{2026}"),
        "should truncate long ID: {}",
        out
    );
}

#[test]
fn list_silent_suppresses_empty_message() {
    let resp = ListSecretsResponse {
        secrets: vec![],
        total: 0,
        limit: 50,
        offset: 0,
    };
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().mock_list(Ok(resp)).build();
    let code = cli::run(
        &args(&["secrt", "list", "--api-key", "sk_test", "--silent"]),
        &mut deps,
    );
    assert_eq!(code, 0);
    assert!(
        !stderr.to_string().contains("No active secrets"),
        "silent should suppress message: {}",
        stderr.to_string()
    );
}

#[test]
fn list_env_api_key() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", "sk_from_env")
        .mock_list(Ok(sample_response()))
        .build();
    let code = cli::run(&args(&["secrt", "list"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stdout.to_string().is_empty());
}
