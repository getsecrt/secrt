mod helpers;

use std::fs;
use std::sync::Mutex;

use std::collections::HashMap;

use helpers::{args, TestDepsBuilder};
use secrt::cli;
use secrt::client::ClaimResponse;
use secrt::envelope::crypto::b64_encode;
use secrt::envelope::{self, SealParams};

/// Non-routable address to ensure API calls fail
const DEAD_URL: &str = "http://127.0.0.1:19191";

/// Mutex to serialize tests that change the current working directory.
/// CWD is process-global, so parallel tests that call set_current_dir race.
static CWD_LOCK: Mutex<()> = Mutex::new(());

fn make_share_url(base: &str, id: &str) -> String {
    let key = vec![42u8; 32];
    let key_b64 = b64_encode(&key);
    format!("{}/s/{}#{}", base, id, key_b64)
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
        iterations: if passphrase.is_empty() { 0 } else { 300_000 },
    })
    .unwrap();
    let share_link = envelope::format_share_link(
        &format!("https://secrt.ca/s/{}", "mock-id"),
        &result.url_key,
    );
    (share_link, result)
}

#[test]
fn get_unknown_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "get", "--bogus"]), &mut deps);
    assert_eq!(code, 2);
    assert!(
        stderr.to_string().contains("unknown flag"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn get_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "get", "--help"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().is_empty());
}

#[test]
fn get_no_url() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "get"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("required"));
}

#[test]
fn get_invalid_url() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "get", "not-a-valid-url"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("invalid"));
}

#[test]
fn get_api_call_fails() {
    let url = make_share_url(DEAD_URL, "test123");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "get", &url]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn get_base_url_flag_override() {
    let url = make_share_url("https://secrt.ca", "test123");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&["secrt", "get", &url, "--base-url", DEAD_URL]),
        &mut deps,
    );
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn get_json_error() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "get", "--json", "not-valid"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(err.contains("\"error\""), "should be JSON error: {}", err);
}

// --- Mock API success tests ---

#[test]
fn get_success_plain() {
    let plaintext = b"hello from mock claim";
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new().mock_claim(Ok(mock_resp)).build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "hello from mock claim");
}

#[test]
fn get_success_tty_shows_label() {
    let plaintext = b"my secret value";
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_stdout_tty(true)
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "my secret value\n");
    assert!(
        stderr.to_string().contains("Secret:"),
        "TTY claim should show label on stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn get_success_non_tty_no_label() {
    let plaintext = b"my secret value";
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_stdout_tty(false)
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    // Non-TTY: exact bytes, no label, no trailing newline
    assert_eq!(stdout.to_string(), "my secret value");
    assert!(
        !stderr.to_string().contains("Secret:"),
        "non-TTY claim should NOT show label: {}",
        stderr.to_string()
    );
}

#[test]
fn get_success_json() {
    let plaintext = b"json claim test";
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T12:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new().mock_claim(Ok(mock_resp)).build();
    let code = cli::run(&args(&["secrt", "get", &share_link, "--json"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON output");
    assert_eq!(json["plaintext"].as_str().unwrap(), "json claim test");
    assert_eq!(json["expires_at"].as_str().unwrap(), "2026-02-09T12:00:00Z");
}

#[test]
fn get_success_json_with_unicode() {
    // Test that unicode/emoji survives the JSON round-trip
    let plaintext = "🔐 Secret with émoji and 日本語!".as_bytes();
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T12:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new().mock_claim(Ok(mock_resp)).build();
    let code = cli::run(&args(&["secrt", "get", &share_link, "--json"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON output");
    assert_eq!(
        json["plaintext"].as_str().unwrap(),
        "🔐 Secret with émoji and 日本語!"
    );
}

#[test]
fn get_success_json_with_binary() {
    // Test that binary data (non-UTF-8) uses base64 encoding in JSON output
    let plaintext: &[u8] = &[0x80, 0x81, 0x82, 0xFF, 0xFE]; // Invalid UTF-8 bytes
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T12:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new().mock_claim(Ok(mock_resp)).build();
    let code = cli::run(&args(&["secrt", "get", &share_link, "--json"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON output");
    // Binary data should be base64-encoded
    let b64 = json["plaintext_base64"].as_str().unwrap();
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    assert_eq!(STANDARD.decode(b64).unwrap(), plaintext);
}

#[test]
fn get_success_with_passphrase() {
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
        &args(&["secrt", "get", &share_link, "--passphrase-env", "MY_PASS"]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "passphrase protected");
}

#[test]
fn get_decryption_error() {
    let plaintext = b"will fail";
    let (_share_link, seal_result) = seal_test_secret(plaintext, "");
    // Use a different key in the share URL so decryption fails
    let bad_key = vec![99u8; 32];
    let bad_share_link = envelope::format_share_link("https://secrt.ca/s/mock-id", &bad_key);
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", "/tmp/secrt_test_no_config")
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "get", &bad_share_link]), &mut deps);
    assert_eq!(code, 1);
    assert!(
        stderr.to_string().contains("decryption failed"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn get_api_error() {
    let url = make_share_url("https://secrt.ca", "test123");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .mock_claim(Err("server error (404): secret not found".into()))
        .build();
    let code = cli::run(&args(&["secrt", "get", &url]), &mut deps);
    assert_eq!(code, 1);
    assert!(
        stderr.to_string().contains("get failed"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn get_silent_suppresses_label() {
    let plaintext = b"silent claim test";
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_stdout_tty(true)
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link, "--silent"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "silent claim test\n");
    assert!(
        !stderr.to_string().contains("Secret:"),
        "silent claim should NOT show label: {}",
        stderr.to_string()
    );
}

// --- Passphrase auto-prompt tests ---

#[test]
fn get_passphrase_auto_prompt_on_tty() {
    let plaintext = b"auto prompt secret";
    let (share_link, seal_result) = seal_test_secret(plaintext, "mypass");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    // TTY + no passphrase flags → should auto-prompt
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", "/tmp/secrt_test_no_config")
        .is_tty(true)
        .mock_claim(Ok(mock_resp))
        .read_pass(&["mypass"])
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "auto prompt secret");
    let err = stderr.to_string();
    assert!(
        err.contains("passphrase-protected"),
        "should show passphrase notice: {}",
        err
    );
}

#[test]
fn get_passphrase_auto_prompt_shows_key_symbol() {
    let plaintext = b"key symbol test";
    let (share_link, seal_result) = seal_test_secret(plaintext, "pass123");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .mock_claim(Ok(mock_resp))
        .read_pass(&["pass123"])
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(err.contains("\u{26b7}"), "should show key symbol: {}", err);
}

#[test]
fn get_passphrase_auto_prompt_silent_hides_notice() {
    let plaintext = b"silent passphrase";
    let (share_link, seal_result) = seal_test_secret(plaintext, "mypass");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .mock_claim(Ok(mock_resp))
        .read_pass(&["mypass"])
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link, "--silent"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "silent passphrase");
    assert!(
        !stderr.to_string().contains("passphrase-protected"),
        "silent should hide notice: {}",
        stderr.to_string()
    );
}

#[test]
fn get_passphrase_non_tty_errors_with_hint() {
    let plaintext = b"non-tty secret";
    let (share_link, seal_result) = seal_test_secret(plaintext, "mypass");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    // Non-TTY + no passphrase flags → should error with helpful message
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(false)
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("passphrase-protected"),
        "should mention passphrase-protected: {}",
        err
    );
    assert!(err.contains("-p"), "should hint at -p flag: {}", err);
}

#[test]
fn get_passphrase_retry_on_wrong_passphrase() {
    let plaintext = b"retry secret";
    let (share_link, seal_result) = seal_test_secret(plaintext, "correct");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    // First attempt wrong, second attempt correct
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .mock_claim(Ok(mock_resp))
        .read_pass(&["wrong", "correct"])
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "retry secret");
    let err = stderr.to_string();
    assert!(
        err.contains("Wrong passphrase"),
        "should show retry message: {}",
        err
    );
}

#[test]
fn get_passphrase_retry_many_then_succeed() {
    let plaintext = b"many retries";
    let (share_link, seal_result) = seal_test_secret(plaintext, "correct");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    // 4 wrong attempts then correct — no limit on retries
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .mock_claim(Ok(mock_resp))
        .read_pass(&["wrong1", "wrong2", "wrong3", "wrong4", "correct"])
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "many retries");
    let err = stderr.to_string();
    // Should have shown "Wrong passphrase" 4 times
    assert_eq!(
        err.matches("Wrong passphrase").count(),
        4,
        "should show 4 retry messages: {}",
        err
    );
}

#[test]
fn get_passphrase_no_retry_with_env_flag() {
    let plaintext = b"env flag no retry";
    let (share_link, seal_result) = seal_test_secret(plaintext, "correct");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    // Wrong passphrase via --passphrase-env → no retry even on TTY
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .mock_claim(Ok(mock_resp))
        .env("BAD_PASS", "wrong")
        .build();
    let code = cli::run(
        &args(&["secrt", "get", &share_link, "--passphrase-env", "BAD_PASS"]),
        &mut deps,
    );
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("decryption failed"),
        "should fail without retry: {}",
        err
    );
    assert!(
        !err.contains("Wrong passphrase"),
        "should NOT show retry message: {}",
        err
    );
}

#[test]
fn get_passphrase_prompt_flag_allows_retry() {
    let plaintext = b"prompt flag retry";
    let (share_link, seal_result) = seal_test_secret(plaintext, "correct");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    // Wrong first via -p, then correct on retry
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .mock_claim(Ok(mock_resp))
        .read_pass(&["wrong", "correct"])
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link, "-p"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "prompt flag retry");
}

#[test]
fn get_passphrase_auto_prompt_empty_input() {
    let plaintext = b"empty input test";
    let (share_link, seal_result) = seal_test_secret(plaintext, "mypass");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .mock_claim(Ok(mock_resp))
        .read_pass(&[""])
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 1);
    assert!(
        stderr.to_string().contains("must not be empty"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn get_passphrase_auto_prompt_read_error() {
    let plaintext = b"read error test";
    let (share_link, seal_result) = seal_test_secret(plaintext, "mypass");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .mock_claim(Ok(mock_resp))
        .read_pass_error("terminal lost")
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 1);
    assert!(
        stderr.to_string().contains("read passphrase"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn get_passphrase_retry_empty_input() {
    let plaintext = b"retry empty test";
    let (share_link, seal_result) = seal_test_secret(plaintext, "correct");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    // First attempt wrong, retry gives empty string
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .mock_claim(Ok(mock_resp))
        .read_pass(&["wrong", ""])
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(err.contains("Wrong passphrase"), "stderr: {}", err);
    assert!(err.contains("must not be empty"), "stderr: {}", err);
}

#[test]
fn get_passphrase_conflicting_flags() {
    let plaintext = b"conflict test";
    let (share_link, seal_result) = seal_test_secret(plaintext, "mypass");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .mock_claim(Ok(mock_resp))
        .env("MY_PASS", "mypass")
        .read_pass(&["mypass"])
        .build();
    let code = cli::run(
        &args(&[
            "secrt",
            "get",
            &share_link,
            "-p",
            "--passphrase-env",
            "MY_PASS",
        ]),
        &mut deps,
    );
    assert_eq!(code, 1);
    assert!(
        stderr.to_string().contains("at most one"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn get_passphrase_json_non_tty_error() {
    let plaintext = b"json non-tty";
    let (share_link, seal_result) = seal_test_secret(plaintext, "mypass");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(false)
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link, "--json"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(err.contains("\"error\""), "should be JSON error: {}", err);
    assert!(
        err.contains("passphrase-protected"),
        "should mention passphrase: {}",
        err
    );
}

// --- Decryption passphrase list tests ---

/// Helper to create a temp config dir with a config.toml containing the given TOML content.
/// Returns the path to use as XDG_CONFIG_HOME.
fn setup_config(toml_content: &str) -> std::path::PathBuf {
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("secrt_test_cfg_{}", id));
    let secrt_dir = dir.join("secrt");
    let _ = fs::create_dir_all(&secrt_dir);
    let config_path = secrt_dir.join("config.toml");
    fs::write(&config_path, toml_content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600));
    }
    dir
}

#[test]
fn get_passphrase_list_first_matches() {
    let plaintext = b"list first match";
    let (share_link, seal_result) = seal_test_secret(plaintext, "correct");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let cfg_dir = setup_config("decryption_passphrases = [\"correct\", \"other\"]\n");
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_tty(false)
        .mock_claim(Ok(mock_resp))
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "list first match");
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn get_passphrase_list_second_matches() {
    let plaintext = b"list second match";
    let (share_link, seal_result) = seal_test_secret(plaintext, "correct");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let cfg_dir = setup_config("decryption_passphrases = [\"wrong\", \"correct\"]\n");
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_tty(false)
        .mock_claim(Ok(mock_resp))
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "list second match");
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn get_passphrase_default_tried_before_list() {
    let plaintext = b"default first";
    let (share_link, seal_result) = seal_test_secret(plaintext, "default-pass");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    // passphrase (default) = "default-pass", list has different entries
    let cfg_dir = setup_config(
        "passphrase = \"default-pass\"\ndecryption_passphrases = [\"other1\", \"other2\"]\n",
    );
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_tty(false)
        .mock_claim(Ok(mock_resp))
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "default first");
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn get_passphrase_list_no_match_non_tty_error() {
    let plaintext = b"no match";
    let (share_link, seal_result) = seal_test_secret(plaintext, "actual-pass");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let cfg_dir = setup_config("decryption_passphrases = [\"wrong1\", \"wrong2\"]\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(false)
        .mock_claim(Ok(mock_resp))
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("tried 2 configured passphrase"),
        "should mention tried count: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn get_passphrase_list_no_match_tty_falls_through_to_prompt() {
    let plaintext = b"tty prompt fallback";
    let (share_link, seal_result) = seal_test_secret(plaintext, "correct");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let cfg_dir = setup_config("decryption_passphrases = [\"wrong1\"]\n");
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .mock_claim(Ok(mock_resp))
        .read_pass(&["correct"])
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "tty prompt fallback");
    let err = stderr.to_string();
    assert!(
        err.contains("didn't match"),
        "should mention list didn't match: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn get_passphrase_explicit_flag_bypasses_list() {
    let plaintext = b"explicit bypasses list";
    let (share_link, seal_result) = seal_test_secret(plaintext, "correct");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    // Config has the correct passphrase in list, but explicit --passphrase-env with wrong value
    let cfg_dir = setup_config("decryption_passphrases = [\"correct\"]\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(false)
        .mock_claim(Ok(mock_resp))
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .env("BAD_PASS", "wrong")
        .build();
    let code = cli::run(
        &args(&["secrt", "get", &share_link, "--passphrase-env", "BAD_PASS"]),
        &mut deps,
    );
    assert_eq!(code, 1, "explicit flag should bypass list");
    let err = stderr.to_string();
    assert!(
        err.contains("decryption failed"),
        "should fail with decryption error: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn get_passphrase_list_deduplication() {
    // If default passphrase and list contain the same value, it should only be tried once
    let plaintext = b"dedup test";
    let (share_link, seal_result) = seal_test_secret(plaintext, "same-pass");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let cfg_dir = setup_config(
        "passphrase = \"same-pass\"\ndecryption_passphrases = [\"same-pass\", \"other\"]\n",
    );
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_tty(false)
        .mock_claim(Ok(mock_resp))
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "dedup test");
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn get_implicit_from_share_url() {
    let plaintext = b"implicit claim works";
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new().mock_claim(Ok(mock_resp)).build();
    // No "get" subcommand — just secrt <url>
    let code = cli::run(&args(&["secrt", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "implicit claim works");
}

#[test]
fn get_implicit_with_flags() {
    let plaintext = b"implicit with json";
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new().mock_claim(Ok(mock_resp)).build();
    // Implicit get with --json flag
    let code = cli::run(&args(&["secrt", &share_link, "--json"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(
        stdout.to_string().contains("\"plaintext\""),
        "stdout: {}",
        stdout.to_string()
    );
}

// --- File hint tests ---

/// Seal an envelope with a file hint and return (share_link, seal_result)
fn seal_test_file(plaintext: &[u8], filename: &str, mime: &str) -> (String, envelope::SealResult) {
    let mut hint = HashMap::new();
    hint.insert("type".into(), "file".into());
    hint.insert("filename".into(), filename.into());
    hint.insert("mime".into(), mime.into());
    let result = envelope::seal(SealParams {
        plaintext: plaintext.to_vec(),
        passphrase: String::new(),
        rand_bytes: &real_rand,
        hint: Some(hint),
        iterations: 0,
    })
    .unwrap();
    let share_link = envelope::format_share_link(
        &format!("https://secrt.ca/s/{}", "mock-id"),
        &result.url_key,
    );
    (share_link, result)
}

#[test]
fn get_file_auto_save_on_tty() {
    let _guard = CWD_LOCK.lock().unwrap();
    let plaintext = b"\x89PNG\r\n\x1a\nfake png data";
    let (share_link, seal_result) = seal_test_file(plaintext, "photo.png", "image/png");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    // Use a temp dir to avoid polluting CWD
    let dir = std::env::temp_dir().join(format!(
        "secrt_test_auto_save_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::create_dir_all(&dir);
    let orig_dir = std::env::current_dir().unwrap();
    let _ = std::env::set_current_dir(&dir);

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .is_stdout_tty(true)
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);

    let _ = std::env::set_current_dir(&orig_dir);

    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(
        err.contains("Saved to") && err.contains("photo.png"),
        "should show save message: {}",
        err
    );

    // Verify file was written
    let saved = fs::read(dir.join("photo.png")).expect("file should exist");
    assert_eq!(saved, plaintext);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_file_output_flag() {
    let plaintext = b"explicit output path";
    let (share_link, seal_result) =
        seal_test_file(plaintext, "data.bin", "application/octet-stream");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let dir = std::env::temp_dir();
    let out_path = dir.join(format!(
        "secrt_test_output_{}.bin",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().mock_claim(Ok(mock_resp)).build();
    let code = cli::run(
        &args(&[
            "secrt",
            "get",
            &share_link,
            "--output",
            out_path.to_str().unwrap(),
        ]),
        &mut deps,
    );

    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(
        err.contains("Saved to"),
        "should show save message: {}",
        err
    );

    let saved = fs::read(&out_path).expect("output file should exist");
    assert_eq!(saved, plaintext);

    let _ = fs::remove_file(&out_path);
}

#[test]
fn get_file_output_dash_stdout() {
    let plaintext = b"raw stdout output";
    let (share_link, seal_result) = seal_test_file(plaintext, "test.txt", "text/plain");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new().mock_claim(Ok(mock_resp)).build();
    let code = cli::run(
        &args(&["secrt", "get", &share_link, "--output", "-"]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    // Raw bytes to stdout, no label, no newline
    assert_eq!(stdout.0.lock().unwrap().as_slice(), plaintext);
}

#[test]
fn get_file_piped_stdout_raw_bytes() {
    let plaintext = b"\x00\x01\x02binary\xff\xfe";
    let (share_link, seal_result) =
        seal_test_file(plaintext, "data.bin", "application/octet-stream");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_stdout_tty(false) // piped
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    // Piped: raw bytes, no label
    assert_eq!(stdout.0.lock().unwrap().as_slice(), plaintext);
}

#[test]
fn get_file_json_with_hint_utf8() {
    let plaintext = b"file text content";
    let (share_link, seal_result) = seal_test_file(plaintext, "notes.txt", "text/plain");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T12:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new().mock_claim(Ok(mock_resp)).build();
    let code = cli::run(&args(&["secrt", "get", &share_link, "--json"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());

    let json: serde_json::Value =
        serde_json::from_str(stdout.to_string().trim()).expect("valid JSON");
    assert_eq!(json["plaintext"].as_str().unwrap(), "file text content");
    assert_eq!(json["filename"].as_str().unwrap(), "notes.txt");
    assert_eq!(json["mime"].as_str().unwrap(), "text/plain");
    assert_eq!(json["type"].as_str().unwrap(), "text/plain");
    assert!(json.get("plaintext_base64").is_none());
}

#[test]
fn get_file_json_with_hint_binary() {
    let plaintext: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0xFF, 0xFE];
    let (share_link, seal_result) = seal_test_file(plaintext, "photo.png", "image/png");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T12:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new().mock_claim(Ok(mock_resp)).build();
    let code = cli::run(&args(&["secrt", "get", &share_link, "--json"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());

    let json: serde_json::Value =
        serde_json::from_str(stdout.to_string().trim()).expect("valid JSON");
    // Binary + file hint → base64
    assert!(
        json.get("plaintext").is_none(),
        "should not have plaintext key for binary"
    );
    let b64 = json["plaintext_base64"].as_str().unwrap();
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let decoded = STANDARD.decode(b64).unwrap();
    assert_eq!(decoded, plaintext);
    assert_eq!(json["filename"].as_str().unwrap(), "photo.png");
    assert_eq!(json["mime"].as_str().unwrap(), "image/png");
}

#[test]
fn get_text_no_hint_unchanged_behavior() {
    // Verify that text secrets without file hints still work exactly as before
    let plaintext = b"just a text secret";
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_stdout_tty(true)
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "just a text secret\n");
    assert!(
        stderr.to_string().contains("Secret:"),
        "should show Secret: label for text on TTY"
    );
    assert!(
        !stderr.to_string().contains("Saved to"),
        "should NOT save text secrets to file"
    );
}

#[test]
fn get_binary_no_hint_tty_auto_saves() {
    // Binary data without a file hint on a TTY should auto-save to secret.bin
    // (file writing verified via --output in claim_file_output_flag; here we just
    // confirm the right code path is taken without cwd manipulation that races)
    let plaintext: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]; // PNG header
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };

    // Use --output with an explicit temp path to avoid cwd races in parallel tests
    let tmp = std::env::temp_dir().join(format!(
        "secrt_test_binary_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_stdout_tty(true)
        .mock_claim(Ok(mock_resp))
        .build();
    let tmp_str = tmp.to_string_lossy().to_string();
    let code = cli::run(
        &args(&["secrt", "get", &share_link, "--output", &tmp_str]),
        &mut deps,
    );

    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("Saved to"),
        "should show save confirmation: {}",
        stderr.to_string()
    );
    assert!(
        stdout.to_string().is_empty(),
        "should NOT dump binary to stdout"
    );

    // Verify file contents
    let saved = std::fs::read(&tmp).expect("file should exist");
    assert_eq!(saved, plaintext);

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn get_binary_no_hint_piped_passes_through() {
    // Binary data without a hint on piped stdout should pass through raw
    let plaintext: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new()
        .is_stdout_tty(false)
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "piped binary should succeed");
    assert_eq!(
        &*stdout.0.lock().unwrap(),
        plaintext,
        "should pass raw bytes through"
    );
}

#[test]
fn get_output_flag_missing_value() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "get", "--output"]), &mut deps);
    assert_eq!(code, 2);
    assert!(
        stderr.to_string().contains("--output requires a value"),
        "stderr: {}",
        stderr.to_string()
    );
}

#[test]
fn get_output_short_flag() {
    let plaintext = b"short flag test";
    let (share_link, seal_result) = seal_test_file(plaintext, "test.txt", "text/plain");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().mock_claim(Ok(mock_resp)).build();
    let code = cli::run(&args(&["secrt", "get", &share_link, "-o", "-"]), &mut deps);
    assert_eq!(code, 0);
    assert_eq!(stdout.0.lock().unwrap().as_slice(), plaintext);
}

#[test]
fn get_file_output_flag_text_no_hint() {
    // --output works for text secrets too (no file hint needed)
    let plaintext = b"save this text";
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let dir = std::env::temp_dir();
    let out_path = dir.join(format!(
        "secrt_test_text_output_{}.txt",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().mock_claim(Ok(mock_resp)).build();
    let code = cli::run(
        &args(&[
            "secrt",
            "get",
            &share_link,
            "--output",
            out_path.to_str().unwrap(),
        ]),
        &mut deps,
    );
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let saved = fs::read(&out_path).expect("output file should exist");
    assert_eq!(saved, plaintext);
    let _ = fs::remove_file(&out_path);
}

#[test]
fn get_passphrase_non_tty_no_candidates_error() {
    // Non-TTY, passphrase-protected, no configured passphrases (tried==0)
    let plaintext = b"no candidates";
    let (share_link, seal_result) = seal_test_secret(plaintext, "mypass");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(false)
        .mock_claim(Ok(mock_resp))
        .env("XDG_CONFIG_HOME", "/tmp/secrt_test_no_config_nonexistent")
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("passphrase-protected"),
        "should mention passphrase-protected: {}",
        err
    );
    assert!(
        !err.contains("tried"),
        "should NOT mention tried count when 0 candidates: {}",
        err
    );
}

#[test]
fn get_passphrase_prompt_retry_read_error() {
    // Phase A: -p flag, first attempt wrong, retry read fails
    let plaintext = b"retry error test";
    let (share_link, seal_result) = seal_test_secret(plaintext, "correct");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    // Only one response: "wrong". Second read_pass call returns error.
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .mock_claim(Ok(mock_resp))
        .read_pass(&["wrong"])
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link, "-p"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("Wrong passphrase"),
        "should show retry message: {}",
        err
    );
    assert!(
        err.contains("read passphrase"),
        "should show read error: {}",
        err
    );
}

#[test]
fn get_passphrase_prompt_retry_empty() {
    // Phase A: -p flag, first attempt wrong, retry returns empty
    let plaintext = b"retry empty phase a";
    let (share_link, seal_result) = seal_test_secret(plaintext, "correct");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .mock_claim(Ok(mock_resp))
        .read_pass(&["wrong", ""])
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link, "-p"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(err.contains("Wrong passphrase"), "stderr: {}", err);
    assert!(err.contains("must not be empty"), "stderr: {}", err);
}

#[test]
fn get_file_auto_save_collision() {
    let _guard = CWD_LOCK.lock().unwrap();
    let plaintext = b"collision test data";
    let (share_link, seal_result) = seal_test_file(plaintext, "data.txt", "text/plain");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };

    let dir = std::env::temp_dir().join(format!(
        "secrt_test_collision_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::create_dir_all(&dir);
    let orig_dir = std::env::current_dir().unwrap();

    // Create existing file to cause collision
    fs::write(dir.join("data.txt"), "existing").unwrap();

    let _ = std::env::set_current_dir(&dir);

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .is_stdout_tty(true)
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);

    let _ = std::env::set_current_dir(&orig_dir);

    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(err.contains("Saved to"), "should save: {}", err);
    assert!(
        err.contains("data (1).txt"),
        "should use collision-avoidance name: {}",
        err
    );

    let saved = fs::read(dir.join("data (1).txt")).expect("collision file should exist");
    assert_eq!(saved, plaintext);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_binary_no_hint_tty_auto_saves_secret_bin() {
    let _guard = CWD_LOCK.lock().unwrap();
    // Binary data without a file hint on a TTY should auto-save to secret.bin
    let plaintext: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let (share_link, seal_result) = seal_test_secret(plaintext, "");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };

    let dir = std::env::temp_dir().join(format!(
        "secrt_test_binautosave_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::create_dir_all(&dir);
    let orig_dir = std::env::current_dir().unwrap();
    let _ = std::env::set_current_dir(&dir);

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .is_stdout_tty(true)
        .mock_claim(Ok(mock_resp))
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);

    let _ = std::env::set_current_dir(&orig_dir);

    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(err.contains("Saved to"), "should auto-save: {}", err);
    assert!(
        err.contains("secret.bin"),
        "should save as secret.bin: {}",
        err
    );

    let saved = fs::read(dir.join("secret.bin")).expect("secret.bin should exist");
    assert_eq!(saved, plaintext);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_tty_no_candidates_shows_notice() {
    // TTY, passphrase-protected, no configured passphrases (tried==0)
    // Should show "This secret is passphrase-protected" notice
    let plaintext = b"tty no candidates";
    let (share_link, seal_result) = seal_test_secret(plaintext, "correct");
    let mock_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2026-02-09T00:00:00Z".into(),
    };
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .mock_claim(Ok(mock_resp))
        .read_pass(&["correct"])
        .env("XDG_CONFIG_HOME", "/tmp/secrt_test_no_config_nonexistent")
        .build();
    let code = cli::run(&args(&["secrt", "get", &share_link]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert_eq!(stdout.to_string(), "tty no candidates");
    let err = stderr.to_string();
    assert!(
        err.contains("passphrase-protected"),
        "should show notice: {}",
        err
    );
    assert!(
        !err.contains("didn't match"),
        "should NOT show 'didn't match' when 0 candidates: {}",
        err
    );
}
