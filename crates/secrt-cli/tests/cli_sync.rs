mod helpers;

use helpers::{args, TestDepsBuilder};
use secrt_cli::cli;

#[test]
fn sync_help_shows_usage() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "sync", "--help"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("SYNC"), "should show SYNC heading");
    assert!(err.contains("sync"), "should mention sync command");
}

#[test]
fn sync_missing_url_exits_2() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "sync"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(
        err.contains("sync URL is required"),
        "should report missing URL, got: {}",
        err
    );
}

#[test]
fn sync_invalid_url_exits_2() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "sync", "not-a-url"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(
        err.contains("invalid sync URL"),
        "should report invalid URL, got: {}",
        err
    );
}

#[test]
fn sync_no_auth_exits_1() {
    // Valid URL format but no API key configured
    let key_b64 = secrt_core::b64_encode(&[42u8; 32]);
    let url = format!("https://secrt.ca/sync/abc123#{}", key_b64);

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "sync", &url]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("authentication"),
        "should require auth, got: {}",
        err
    );
}

#[test]
fn help_sync_shows_sync_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "sync"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("SYNC"), "should show SYNC heading");
}
