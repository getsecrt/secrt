mod helpers;

use helpers::{args, TestDepsBuilder};
use secrt::cli;
use secrt::client::CreateResponse;

#[test]
fn gen_default() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen"]), &mut deps);
    assert_eq!(code, 0);
    let out = stdout.to_string();
    let pw = out.trim();
    assert_eq!(pw.len(), 20, "default password should be 20 chars: {}", pw);
}

#[test]
fn gen_custom_length() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "--length", "32"]), &mut deps);
    assert_eq!(code, 0);
    let pw = stdout.to_string().trim().to_string();
    assert_eq!(pw.len(), 32);
}

#[test]
fn gen_short_length_flag() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "-L", "16"]), &mut deps);
    assert_eq!(code, 0);
    let pw = stdout.to_string().trim().to_string();
    assert_eq!(pw.len(), 16);
}

#[test]
fn gen_no_symbols() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "-S"]), &mut deps);
    assert_eq!(code, 0);
    let pw = stdout.to_string().trim().to_string();
    let symbols = b"!@*^_+-=?";
    assert!(
        !pw.bytes().any(|b| symbols.contains(&b)),
        "should not contain symbols: {}",
        pw
    );
}

#[test]
fn gen_no_numbers() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "-N"]), &mut deps);
    assert_eq!(code, 0);
    let pw = stdout.to_string().trim().to_string();
    assert!(
        !pw.chars().any(|c| c.is_ascii_digit()),
        "should not contain digits: {}",
        pw
    );
}

#[test]
fn gen_no_caps() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "-C"]), &mut deps);
    assert_eq!(code, 0);
    let pw = stdout.to_string().trim().to_string();
    assert!(
        !pw.chars().any(|c| c.is_ascii_uppercase()),
        "should not contain uppercase: {}",
        pw
    );
}

#[test]
fn gen_all_exclusions() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "-S", "-N", "-C"]), &mut deps);
    assert_eq!(code, 0);
    let pw = stdout.to_string().trim().to_string();
    assert!(
        pw.chars().all(|c| c.is_ascii_lowercase()),
        "should be all lowercase: {}",
        pw
    );
}

#[test]
fn gen_grouped() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "-G"]), &mut deps);
    assert_eq!(code, 0);
    let pw = stdout.to_string().trim().to_string();
    assert_eq!(pw.len(), 20, "grouped should still be 20 chars: {}", pw);
}

#[test]
fn gen_json_single() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "--json"]), &mut deps);
    assert_eq!(code, 0);
    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
    assert!(json["password"].is_string());
}

#[test]
fn gen_json_multiple() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&["secrt", "gen", "--json", "--count", "3"]),
        &mut deps,
    );
    assert_eq!(code, 0);
    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
    let passwords = json["passwords"].as_array().expect("passwords array");
    assert_eq!(passwords.len(), 3);
}

#[test]
fn gen_count_multiple() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "--count", "5"]), &mut deps);
    assert_eq!(code, 0);
    let out = stdout.to_string();
    let lines: Vec<&str> = out.trim().lines().collect();
    assert_eq!(lines.len(), 5, "should output 5 passwords: {}", out);
}

#[test]
fn gen_length_too_short() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "-L", "2"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(
        err.contains("too short"),
        "should error on too-short length: {}",
        err
    );
}

#[test]
fn gen_invalid_length() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "-L", "abc"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(
        err.contains("--length requires a positive integer"),
        "should error on invalid length: {}",
        err
    );
}

#[test]
fn gen_count_zero() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "--count", "0"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(
        err.contains("--count requires a positive integer"),
        "should error on count 0: {}",
        err
    );
}

#[test]
fn gen_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "-h"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("gen") || err.contains("Generate"));
}

#[test]
fn gen_help_long() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "--help"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("gen") || err.contains("Generate"));
}

#[test]
fn gen_generate_alias() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "generate"]), &mut deps);
    assert_eq!(code, 0);
    let pw = stdout.to_string().trim().to_string();
    assert_eq!(pw.len(), 20);
}

fn mock_send_response() -> CreateResponse {
    CreateResponse {
        id: "test-id-gen".into(),
        share_url: "https://secrt.ca/s/test-id-gen".into(),
        expires_at: "2026-02-09T00:00:00Z".into(),
    }
}

#[test]
fn gen_send_combined() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "gen", "send"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    assert!(out.contains("#"), "should output share link: {}", out);
}

#[test]
fn send_gen_combined() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "send", "gen"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    assert!(out.contains("#"), "should output share link: {}", out);
}

#[test]
fn gen_send_with_ttl() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "gen", "send", "--ttl", "1h"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    assert!(out.contains("#"), "should output share link: {}", out);
}

#[test]
fn gen_send_with_length() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "gen", "send", "-L", "32"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("#"));
}

#[test]
fn gen_send_json() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "gen", "send", "--json"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
    assert!(json["share_link"].as_str().unwrap().contains("#"));
    assert!(
        json["password"].is_string(),
        "should include password in JSON"
    );
}

#[test]
fn gen_send_count_error() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "gen", "send", "--count", "3"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(
        err.contains("--count cannot be used with send"),
        "should reject --count with send: {}",
        err
    );
}

#[test]
fn gen_send_tty_shows_generated_password() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .is_tty(true)
        .is_stdout_tty(true)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "gen", "send"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(
        err.contains("Generated:"),
        "TTY should show 'Generated:' label: {}",
        err
    );
    assert!(stdout.to_string().contains("#"));
}

#[test]
fn gen_send_non_tty_shows_password_on_stderr() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .is_tty(false)
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "gen", "send"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    // Non-TTY should output generated password on stderr (plain, no label)
    assert!(
        !err.is_empty(),
        "should output generated password on stderr"
    );
    assert!(
        !err.contains("Generated:"),
        "non-TTY should not have label: {}",
        err
    );
}

#[test]
fn gen_send_silent_suppresses_generated_password() {
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .mock_create(Ok(mock_send_response()))
        .build();
    let code = cli::run(&args(&["secrt", "gen", "send", "--silent"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    let err = stderr.to_string();
    assert!(
        !err.contains("Generated"),
        "silent should suppress generated password: {}",
        err
    );
    assert!(stdout.to_string().contains("#"));
}
