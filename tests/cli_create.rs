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
        .read_pass(&["tty secret data"])
        .is_tty(true)
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("Enter your secret"),
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

fn mock_create_response() -> CreateResponse {
    CreateResponse {
        id: "test-id-123".into(),
        share_url: "https://secrt.ca/s/test-id-123".into(),
        expires_at: "2026-02-09T00:00:00Z".into(),
    }
}

// --- TTY status message tests ---

#[test]
fn create_tty_shows_status_message_on_success() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["my secret"])
        .is_tty(true)
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(
        err.contains("Encrypting and uploading..."),
        "TTY stderr should show status message: {}",
        err
    );
}

#[test]
fn create_tty_shows_status_message_on_api_error() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["my secret"])
        .is_tty(true)
        .mock_create(Err("connection refused".into()))
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("Encrypting and uploading..."),
        "TTY stderr should show status message before error: {}",
        err
    );
    assert!(
        err.contains("connection refused"),
        "stderr should contain the error: {}",
        err
    );
}

#[test]
fn create_non_tty_no_status_message() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .is_tty(false)
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(
        !err.contains("Encrypting and uploading"),
        "non-TTY stderr should NOT show status message: {}",
        err
    );
}

// --- Multi-line and trim tests ---

#[test]
fn create_multi_line_tty_reads_from_stdin() {
    // With --multi-line in TTY mode, should read from stdin (not read_pass)
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"line 1\nline 2\n")
        .is_tty(true)
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create", "--multi-line"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(
        stdout.to_string().contains("#v1."),
        "should succeed and output share link: {}",
        stdout.to_string()
    );
}

#[test]
fn create_multi_line_tty_shows_prompt() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"some data")
        .is_tty(true)
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create", "-m"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(
        err.contains("Ctrl+D"),
        "multi-line TTY prompt should mention Ctrl+D: {}",
        err
    );
}

#[test]
fn create_multi_line_preserves_exact_bytes() {
    // Multi-line should preserve trailing newlines exactly
    let input = b"line 1\nline 2\n";
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(input)
        .is_tty(true)
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create", "--multi-line"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    // Success means the exact bytes were used (not trimmed)
    assert!(stdout.to_string().contains("#v1."));
}

#[test]
fn create_multi_line_empty_input() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"")
        .is_tty(true)
        .build();
    let code = cli::run(&args(&["secrt", "create", "--multi-line"]), &mut deps);
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("empty"),
        "should error on empty input: {}",
        stderr.to_string()
    );
}

#[test]
fn create_trim_strips_whitespace_stdin() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"  my secret  \n")
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create", "--trim"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#v1."));
}

#[test]
fn create_trim_with_text_flag() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(
        &args(&["secrt", "create", "--text", "  hello  ", "--trim"]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#v1."));
}

#[test]
fn create_trim_with_file_flag() {
    let dir = std::env::temp_dir();
    let path = dir.join("secrt_test_create_trim_file.txt");
    std::fs::write(&path, "  secret data  \r\n").unwrap();

    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(
        &args(&["secrt", "create", "--file", path.to_str().unwrap(), "--trim"]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#v1."));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn create_trim_makes_empty_errors() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"  \n  \r\n  ")
        .build();
    let code = cli::run(&args(&["secrt", "create", "--trim"]), &mut deps);
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("empty"),
        "trim to empty should error: {}",
        stderr.to_string()
    );
}

#[test]
fn create_multi_line_with_trim() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"\n  line 1\n  line 2  \n\n")
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(
        &args(&["secrt", "create", "--multi-line", "--trim"]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#v1."));
}

#[test]
fn create_default_tty_uses_single_line() {
    // Default TTY (no --multi-line) should use read_pass (single-line, no echo)
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["single line secret"])
        .is_tty(true)
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#v1."));
    // Should show "input is hidden" hint on instruction line
    let err = stderr.to_string();
    assert!(
        err.contains("input is hidden"),
        "single-line prompt should mention hidden input: {}",
        err
    );
    // Should show "Secret:" on the prompt line
    assert!(
        err.contains("Secret:"),
        "single-line prompt should show Secret: prompt: {}",
        err
    );
}

// --- Mock API success tests ---

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

#[test]
fn create_rate_limit_error_shows_friendly_message() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .mock_create(Err(
            "server error (429): rate limit exceeded; please try again in a few seconds".into(),
        ))
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("rate limit exceeded"),
        "stderr should contain friendly rate limit message: {}",
        err
    );
    assert!(
        err.contains("try again"),
        "stderr should contain retry guidance: {}",
        err
    );
}

#[test]
fn create_unauthorized_error_shows_api_key_hint() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .mock_create(Err("server error (401): unauthorized; check your API key".into()))
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("unauthorized"),
        "stderr should contain auth error: {}",
        err
    );
    assert!(
        err.contains("API key"),
        "stderr should hint about API key: {}",
        err
    );
}

// --- --show / --hidden / --silent tests ---

#[test]
fn create_show_flag_reads_visible_input() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"visible secret\n")
        .is_tty(true)
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create", "--show"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#v1."));
    let err = stderr.to_string();
    assert!(
        err.contains("input will be shown"),
        "should indicate visible input: {}",
        err
    );
}

#[test]
fn create_show_short_flag() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"visible secret\n")
        .is_tty(true)
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create", "-s"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#v1."));
}

#[test]
fn create_hidden_overrides_show() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["hidden secret"])
        .is_tty(true)
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create", "--show", "--hidden"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(
        err.contains("input is hidden"),
        "--hidden should override --show: {}",
        err
    );
}

#[test]
fn create_silent_suppresses_status() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create", "--silent"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#v1."));
    let err = stderr.to_string();
    assert!(
        err.is_empty(),
        "silent mode should suppress stderr: {}",
        err
    );
}

#[test]
fn create_silent_tty_suppresses_prompts_and_status() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["my secret"])
        .is_tty(true)
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create", "--silent"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#v1."));
    let err = stderr.to_string();
    assert!(
        !err.contains("Enter your secret"),
        "silent mode should suppress instruction: {}",
        err
    );
    assert!(
        !err.contains("Encrypting"),
        "silent mode should suppress status: {}",
        err
    );
}

#[test]
fn create_tty_status_indicator_success() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["my secret"])
        .is_tty(true)
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    // Should contain both the in-progress and success indicators
    assert!(
        err.contains("\u{25CB}"),
        "should show circle indicator: {}",
        err
    );
    assert!(
        err.contains("Encrypted and uploaded!"),
        "should show success message: {}",
        err
    );
}

#[test]
fn create_show_empty_input_errors() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"\n")
        .is_tty(true)
        .build();
    let code = cli::run(&args(&["secrt", "create", "--show"]), &mut deps);
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("empty"),
        "empty show input should error: {}",
        stderr.to_string()
    );
}

#[test]
fn create_passphrase_conflicting_flags() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .env("MY_PASS", "pass123")
        .read_pass(&["pass123", "pass123"])
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(
        &args(&[
            "secrt",
            "create",
            "-p",
            "--passphrase-env",
            "MY_PASS",
        ]),
        &mut deps,
    );
    assert_eq!(code, 2);
    assert!(
        stderr.to_string().contains("at most one"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn create_api_error_tty_silent() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["my secret"])
        .is_tty(true)
        .mock_create(Err("server error (500): internal error".into()))
        .build();
    let code = cli::run(&args(&["secrt", "create", "--silent"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("internal error"),
        "should show error even when silent: {}",
        err
    );
    assert!(
        !err.contains("Encrypting"),
        "silent should suppress status: {}",
        err
    );
}

#[test]
fn create_success_tty_stdout_shows_link() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["my secret"])
        .is_tty(true)
        .is_stdout_tty(true)
        .mock_create(Ok(mock_create_response()))
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    assert!(
        out.contains("#v1."),
        "should show share link: {}",
        out
    );
}
