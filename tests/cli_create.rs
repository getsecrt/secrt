mod helpers;

use helpers::{args, TestDepsBuilder};
use secrt::cli;
use secrt::client::CreateResponse;

/// Use a non-routable address to ensure API calls fail
const DEAD_URL: &str = "http://127.0.0.1:19191";

#[test]
fn create_unknown_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "create", "--bogus"]), &mut deps);
    assert_eq!(code, 2);
    assert!(
        stderr.to_string().contains("unknown flag"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn create_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "create", "--help"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().is_empty());
}

#[test]
fn create_stdin() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret data")
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn create_text_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "create", "--text", "hello"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn create_file_flag() {
    let dir = std::env::temp_dir();
    let path = dir.join("secrt_test_create_file.txt");
    std::fs::write(&path, "file content").unwrap();

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(
        &args(&["secrt", "create", "--file", path.to_str().unwrap()]),
        &mut deps,
    );
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn create_multiple_sources() {
    let dir = std::env::temp_dir();
    let path = dir.join("secrt_test_create_multi.txt");
    std::fs::write(&path, "data").unwrap();

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&[
            "secrt",
            "create",
            "--text",
            "hello",
            "--file",
            path.to_str().unwrap(),
        ]),
        &mut deps,
    );
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn create_empty_stdin() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().stdin(b"").build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
    assert!(stderr.to_string().contains("empty"));
}

#[test]
fn create_invalid_ttl() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().stdin(b"data").build();
    let code = cli::run(&args(&["secrt", "create", "--ttl", "abc"]), &mut deps);
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
}

#[test]
fn create_tty_prompt() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"tty data")
        .is_tty(true)
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("Enter secret"),
        "stderr should contain prompt: {}",
        stderr.to_string()
    );
}

#[test]
fn create_with_passphrase_env() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"data")
        .env("MY_PASS", "secret123")
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(
        &args(&["secrt", "create", "--passphrase-env", "MY_PASS"]),
        &mut deps,
    );
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn create_empty_file() {
    let dir = std::env::temp_dir();
    let path = dir.join("secrt_test_create_empty_file.txt");
    std::fs::write(&path, "").unwrap();

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&["secrt", "create", "--file", path.to_str().unwrap()]),
        &mut deps,
    );
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("file is empty"),
        "stderr: {}",
        stderr.to_string()
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn create_json_output() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"data")
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "create", "--json"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(err.contains("\"error\""), "stderr should be JSON: {}", err);
}

// --- Mock API success tests ---

fn mock_create_response() -> CreateResponse {
    CreateResponse {
        id: "test-id-123".into(),
        share_url: "https://secrt.ca/s/test-id-123".into(),
        expires_at: "2026-02-09T00:00:00Z".into(),
    }
}

#[test]
fn create_success_plain() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    assert!(
        out.contains("https://secrt.ca/s/test-id-123#v1."),
        "stdout should contain share link: {}",
        out
    );
}

#[test]
fn create_success_json() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create", "--json"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON output");
    assert_eq!(json["id"].as_str().unwrap(), "test-id-123");
    assert!(json["share_link"].as_str().unwrap().contains("#v1."));
    assert!(json["share_url"].as_str().is_some());
    assert!(json["expires_at"].as_str().is_some());
}

#[test]
fn create_success_with_ttl() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create", "--ttl", "5m"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    assert!(
        out.contains("#v1."),
        "stdout should contain share link: {}",
        out
    );
}

#[test]
fn create_api_error() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .mock_create(Err("server error (500): internal error".into()))
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 1);
    assert!(
        stderr.to_string().contains("server error"),
        "stderr: {}",
        stderr.to_string()
    );
}
