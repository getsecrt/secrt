mod helpers;

use helpers::{args, TestDepsBuilder};
use secrt::cli;
use secrt::client::CreateResponse;

/// Use a non-routable address to ensure API calls fail
const DEAD_URL: &str = "http://127.0.0.1:19191";

#[test]
fn send_unknown_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "send", "--bogus"]), &mut deps);
    assert_eq!(code, 2);
    assert!(
        stderr.to_string().contains("unknown flag"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn send_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "send", "--help"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().is_empty());
}

#[test]
fn send_stdin() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret data")
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn send_text_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "send", "--text", "hello"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn send_file_flag() {
    let dir = std::env::temp_dir();
    let path = dir.join("secrt_test_create_file.txt");
    std::fs::write(&path, "file content").unwrap();

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(
        &args(&["secrt", "send", "--file", path.to_str().unwrap()]),
        &mut deps,
    );
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn send_multiple_sources() {
    let dir = std::env::temp_dir();
    let path = dir.join("secrt_test_create_multi.txt");
    std::fs::write(&path, "data").unwrap();

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&[
            "secrt",
            "send",
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
fn send_empty_stdin() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().stdin(b"").build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
    assert!(stderr.to_string().contains("empty"));
}

#[test]
fn send_invalid_ttl() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().stdin(b"data").build();
    let code = cli::run(&args(&["secrt", "send", "--ttl", "abc"]), &mut deps);
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
}

#[test]
fn send_tty_prompt() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["tty secret data"])
        .is_tty(true)
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("Enter your secret"),
        "stderr should contain prompt: {}",
        stderr.to_string()
    );
}

#[test]
fn send_with_passphrase_env() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"data")
        .env("MY_PASS", "secret123")
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(
        &args(&["secrt", "send", "--passphrase-env", "MY_PASS"]),
        &mut deps,
    );
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn send_empty_file() {
    let dir = std::env::temp_dir();
    let path = dir.join("secrt_test_create_empty_file.txt");
    std::fs::write(&path, "").unwrap();

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&["secrt", "send", "--file", path.to_str().unwrap()]),
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
fn send_json_output() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"data")
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "send", "--json"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(err.contains("\"error\""), "stderr should be JSON: {}", err);
}

fn mock_send_response() -> CreateResponse {
    CreateResponse {
        id: "test-id-123".into(),
        share_url: "https://secrt.ca/s/test-id-123".into(),
        expires_at: "2026-02-09T00:00:00Z".into(),
    }
}

// --- TTY status message tests ---

#[test]
fn send_tty_shows_status_message_on_success() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["my secret"])
        .is_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(
        err.contains("Encrypting and uploading..."),
        "TTY stderr should show status message: {}",
        err
    );
}

#[test]
fn send_tty_shows_status_message_on_api_error() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["my secret"])
        .is_tty(true)
        .mock_create(Err("connection refused".into()))
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
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
fn send_non_tty_no_status_message() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .is_tty(false)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
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
fn send_multi_line_tty_reads_from_stdin() {
    // With --multi-line in TTY mode, should read from stdin (not read_pass)
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"line 1\nline 2\n")
        .is_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "--multi-line"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(
        stdout.to_string().contains("#"),
        "should succeed and output share link: {}",
        stdout.to_string()
    );
}

#[test]
fn send_multi_line_tty_shows_prompt() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"some data")
        .is_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "-m"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(
        err.contains("Ctrl+D"),
        "multi-line TTY prompt should mention Ctrl+D: {}",
        err
    );
}

#[test]
fn send_multi_line_preserves_exact_bytes() {
    // Multi-line should preserve trailing newlines exactly
    let input = b"line 1\nline 2\n";
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(input)
        .is_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "--multi-line"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    // Success means the exact bytes were used (not trimmed)
    assert!(stdout.to_string().contains("#"));
}

#[test]
fn send_multi_line_empty_input() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().stdin(b"").is_tty(true).build();
    let code = cli::run(&args(&["secrt", "send", "--multi-line"]), &mut deps);
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("empty"),
        "should error on empty input: {}",
        stderr.to_string()
    );
}

#[test]
fn send_trim_strips_whitespace_stdin() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"  my secret  \n")
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "--trim"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#"));
}

#[test]
fn send_trim_with_text_flag() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(
        &args(&["secrt", "send", "--text", "  hello  ", "--trim"]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#"));
}

#[test]
fn send_trim_with_file_flag() {
    let dir = std::env::temp_dir();
    let path = dir.join("secrt_test_create_trim_file.txt");
    std::fs::write(&path, "  secret data  \r\n").unwrap();

    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(
        &args(&["secrt", "send", "--file", path.to_str().unwrap(), "--trim"]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn send_trim_makes_empty_errors() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().stdin(b"  \n  \r\n  ").build();
    let code = cli::run(&args(&["secrt", "send", "--trim"]), &mut deps);
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("empty"),
        "trim to empty should error: {}",
        stderr.to_string()
    );
}

#[test]
fn send_multi_line_with_trim() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"\n  line 1\n  line 2  \n\n")
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(
        &args(&["secrt", "send", "--multi-line", "--trim"]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#"));
}

#[test]
fn send_default_tty_uses_single_line() {
    // Default TTY (no --multi-line) should use read_pass (single-line, no echo)
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["single line secret"])
        .is_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#"));
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
fn send_success_plain() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    assert!(
        out.contains("https://secrt.ca/s/test-id-123#"),
        "stdout should contain share link: {}",
        out
    );
}

#[test]
fn send_success_json() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "--json"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON output");
    assert_eq!(json["id"].as_str().unwrap(), "test-id-123");
    assert!(json["share_link"].as_str().unwrap().contains("#"));
    assert!(json["share_url"].as_str().is_some());
    assert!(json["expires_at"].as_str().is_some());
}

#[test]
fn send_success_with_ttl() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "--ttl", "5m"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    assert!(
        out.contains("#"),
        "stdout should contain share link: {}",
        out
    );
}

#[test]
fn send_api_error() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .mock_create(Err("server error (500): internal error".into()))
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
    assert_eq!(code, 1);
    assert!(
        stderr.to_string().contains("server error"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn send_rate_limit_error_shows_friendly_message() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .mock_create(Err(
            "server error (429): rate limit exceeded; please try again in a few seconds".into(),
        ))
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
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
fn send_unauthorized_error_shows_api_key_hint() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .mock_create(Err(
            "server error (401): unauthorized; check your API key".into()
        ))
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
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
fn send_show_flag_reads_visible_input() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"visible secret\n")
        .is_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "--show"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#"));
    let err = stderr.to_string();
    assert!(
        err.contains("input will be shown"),
        "should indicate visible input: {}",
        err
    );
}

#[test]
fn send_show_short_flag() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"visible secret\n")
        .is_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "-s"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#"));
}

#[test]
fn send_hidden_overrides_show() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["hidden secret"])
        .is_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "--show", "--hidden"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(
        err.contains("input is hidden"),
        "--hidden should override --show: {}",
        err
    );
}

#[test]
fn send_silent_suppresses_status() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "--silent"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#"));
    let err = stderr.to_string();
    assert!(
        err.is_empty(),
        "silent mode should suppress stderr: {}",
        err
    );
}

#[test]
fn send_silent_tty_suppresses_prompts_and_status() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["my secret"])
        .is_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "--silent"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#"));
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
fn send_tty_status_indicator_success() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["my secret"])
        .is_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    // Should contain both the in-progress and success indicators
    assert!(
        err.contains("\u{25CB}"),
        "should show circle indicator: {}",
        err
    );
    assert!(
        err.contains("Encrypted and uploaded."),
        "should show success message: {}",
        err
    );
    assert!(err.contains("Expires"), "should show expiry info: {}", err);
}

#[test]
fn send_show_empty_input_errors() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().stdin(b"\n").is_tty(true).build();
    let code = cli::run(&args(&["secrt", "send", "--show"]), &mut deps);
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("empty"),
        "empty show input should error: {}",
        stderr.to_string()
    );
}

#[test]
fn send_passphrase_conflicting_flags() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret")
        .env("MY_PASS", "pass123")
        .read_pass(&["pass123", "pass123"])
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(
        &args(&["secrt", "send", "-p", "--passphrase-env", "MY_PASS"]),
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
fn send_api_error_tty_silent() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["my secret"])
        .is_tty(true)
        .mock_create(Err("server error (500): internal error".into()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "--silent"]), &mut deps);
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
fn send_success_tty_stdout_shows_link() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["my secret"])
        .is_tty(true)
        .is_stdout_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    assert!(out.contains("#"), "should show share link: {}", out);
}

#[test]
fn send_tty_status_shows_with_passphrase() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["my secret"])
        .is_tty(true)
        .env("MY_PASS", "testpass")
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(
        &args(&["secrt", "send", "--passphrase-env", "MY_PASS"]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(
        err.contains("Encrypted and uploaded with passphrase."),
        "should show 'with passphrase' when passphrase is used: {}",
        err
    );
}

#[test]
fn send_tty_status_no_passphrase_message_without_passphrase() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["my secret"])
        .is_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(
        err.contains("Encrypted and uploaded."),
        "should show plain message without passphrase: {}",
        err
    );
    assert!(
        !err.contains("with passphrase"),
        "should NOT mention passphrase when none used: {}",
        err
    );
}

#[test]
fn send_show_crlf_stripping() {
    // --show mode should strip trailing \r\n
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"secret with crlf\r\n")
        .is_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "--show"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#"));
}

#[test]
fn send_hidden_empty_input_error() {
    // Default hidden mode with empty password from read_pass
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().read_pass(&[""]).is_tty(true).build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
    assert_eq!(code, 2);
    assert!(
        stderr.to_string().contains("empty"),
        "should error on empty hidden input: {}",
        stderr.to_string()
    );
}

#[test]
fn send_silent_show_mode_suppresses_prompts() {
    // --silent + --show on TTY should not show prompts
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret\n")
        .is_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "--show", "--silent"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#"));
    let err = stderr.to_string();
    assert!(
        !err.contains("input will be shown"),
        "silent should suppress instruction: {}",
        err
    );
    assert!(
        !err.contains("Secret:"),
        "silent should suppress prompt: {}",
        err
    );
}

#[test]
fn send_hidden_read_error() {
    // Hidden mode when read_pass returns an I/O error
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass_error("terminal lost")
        .is_tty(true)
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
    assert_eq!(code, 2);
    assert!(
        stderr.to_string().contains("read secret"),
        "should contain read error: {}",
        stderr.to_string()
    );
}
