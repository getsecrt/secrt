//! End-to-end tests that hit a real server.
//! Gated behind the `SECRET_E2E_BASE_URL` environment variable.
//!
//! Run with:
//!   SECRET_E2E_BASE_URL=https://secrt.ca cargo test e2e -- --ignored
//!
//! For burn/api-key tests:
//!   SECRET_E2E_BASE_URL=https://secrt.ca SECRET_E2E_API_KEY=sk2_... cargo test e2e -- --ignored

mod helpers;

use helpers::{args, TestDepsBuilder};
use secrt_cli::cli;

fn base_url() -> String {
    std::env::var("SECRET_E2E_BASE_URL").unwrap_or_default()
}

fn api_key() -> String {
    std::env::var("SECRET_E2E_API_KEY").unwrap_or_default()
}

fn should_skip() -> bool {
    base_url().is_empty()
}

fn should_skip_api_key() -> bool {
    should_skip() || api_key().is_empty()
}

#[test]
#[ignore]
fn e2e_send_get_roundtrip() {
    if should_skip() {
        return;
    }
    let url = base_url();
    let plaintext = "e2e-roundtrip-test-data";

    // Send
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(plaintext.as_bytes())
        .env("SECRET_BASE_URL", &url)
        .build();
    let code = cli::run(&args(&["secrt", "send"]), &mut deps);
    assert_eq!(code, 0, "send failed: {}", stderr);

    let share_link = stdout.to_string().trim().to_string();
    assert!(!share_link.is_empty(), "no share link returned");

    // Get
    let (mut deps2, stdout2, stderr2) = TestDepsBuilder::new().build();
    let code2 = cli::run(&args(&["secrt", "get", &share_link]), &mut deps2);
    assert_eq!(code2, 0, "get failed: {}", stderr2);

    let recovered = stdout2.to_string();
    assert_eq!(recovered, plaintext);
}

#[test]
#[ignore]
fn e2e_send_with_passphrase() {
    if should_skip() {
        return;
    }
    let url = base_url();
    let plaintext = "e2e-passphrase-test";

    // Send with passphrase via env
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(plaintext.as_bytes())
        .env("SECRET_BASE_URL", &url)
        .env("MY_E2E_PASS", "testpass123")
        .build();
    let code = cli::run(
        &args(&["secrt", "send", "--passphrase-env", "MY_E2E_PASS"]),
        &mut deps,
    );
    assert_eq!(code, 0, "send failed: {}", stderr);

    let share_link = stdout.to_string().trim().to_string();

    // Get with same passphrase
    let (mut deps2, stdout2, stderr2) = TestDepsBuilder::new()
        .env("MY_E2E_PASS", "testpass123")
        .build();
    let code2 = cli::run(
        &args(&[
            "secrt",
            "get",
            &share_link,
            "--passphrase-env",
            "MY_E2E_PASS",
        ]),
        &mut deps2,
    );
    assert_eq!(code2, 0, "get failed: {}", stderr2);
    assert_eq!(stdout2.to_string(), plaintext);
}

#[test]
#[ignore]
fn e2e_send_with_ttl() {
    if should_skip() {
        return;
    }
    let url = base_url();

    // Send with TTL and JSON output
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"e2e-ttl-test")
        .env("SECRET_BASE_URL", &url)
        .build();
    let code = cli::run(
        &args(&["secrt", "send", "--ttl", "5m", "--json"]),
        &mut deps,
    );
    assert_eq!(code, 0, "send failed: {}", stderr);

    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON output");
    assert!(json.get("share_link").is_some());
    assert!(json.get("expires_at").is_some());
}

#[test]
#[ignore]
fn e2e_send_get_json() {
    if should_skip() {
        return;
    }
    let url = base_url();

    // Send with JSON
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"e2e-json-test")
        .env("SECRET_BASE_URL", &url)
        .build();
    let code = cli::run(&args(&["secrt", "send", "--json"]), &mut deps);
    assert_eq!(code, 0, "send failed: {}", stderr);

    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON");
    let share_link = json["share_link"].as_str().unwrap().to_string();

    // Get with JSON output
    let (mut deps2, stdout2, stderr2) = TestDepsBuilder::new().build();
    let code2 = cli::run(&args(&["secrt", "get", &share_link, "--json"]), &mut deps2);
    assert_eq!(code2, 0, "get failed: {}", stderr2);

    let out2 = stdout2.to_string();
    let json2: serde_json::Value = serde_json::from_str(out2.trim()).expect("invalid JSON");
    assert!(json2.get("expires_at").is_some());
}

#[test]
#[ignore]
fn e2e_send_with_api_key() {
    if should_skip_api_key() {
        return;
    }
    let url = base_url();
    let key = api_key();
    let plaintext = "e2e-api-key-send-test";

    // Send with API key (uses authenticated endpoint)
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(plaintext.as_bytes())
        .env("SECRET_BASE_URL", &url)
        .build();
    let code = cli::run(
        &args(&["secrt", "send", "--api-key", &key, "--json"]),
        &mut deps,
    );
    assert_eq!(code, 0, "send failed: {}", stderr);

    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON");
    let share_link = json["share_link"].as_str().unwrap().to_string();

    // Get it back
    let (mut deps2, stdout2, stderr2) = TestDepsBuilder::new().build();
    let code2 = cli::run(&args(&["secrt", "get", &share_link]), &mut deps2);
    assert_eq!(code2, 0, "get failed: {}", stderr2);
    assert_eq!(stdout2.to_string(), plaintext);
}

#[test]
#[ignore]
fn e2e_burn() {
    if should_skip_api_key() {
        return;
    }
    let url = base_url();
    let key = api_key();

    // Send a secret to burn
    let (mut deps, stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"e2e-burn-test")
        .env("SECRET_BASE_URL", &url)
        .build();
    let code = cli::run(
        &args(&["secrt", "send", "--api-key", &key, "--json"]),
        &mut deps,
    );
    assert_eq!(code, 0, "send failed: {}", stderr);

    let out = stdout.to_string();
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("invalid JSON");
    let secret_id = json["id"].as_str().unwrap().to_string();

    // Burn it
    let (mut deps2, _stdout2, stderr2) =
        TestDepsBuilder::new().env("SECRET_BASE_URL", &url).build();
    let code2 = cli::run(
        &args(&["secrt", "burn", &secret_id, "--api-key", &key]),
        &mut deps2,
    );
    assert_eq!(code2, 0, "burn failed: {}", stderr2);
    assert!(
        stderr2.to_string().contains("Secret burned."),
        "stderr: {}",
        stderr2
    );
}

#[test]
#[ignore]
fn e2e_server_info_unauthenticated() {
    if should_skip() {
        return;
    }
    let url = base_url();

    // Use the API client directly to test info endpoint
    let client = secrt_cli::client::ApiClient {
        base_url: url,
        api_key: String::new(),
    };

    use secrt_cli::client::SecretApi;
    let info = client.info().expect("info() should succeed");
    assert!(
        !info.authenticated,
        "should not be authenticated without key"
    );
    assert_eq!(info.ttl.default_seconds, 86400);
    assert_eq!(info.ttl.max_seconds, 31536000);
    assert!(info.limits.public.max_envelope_bytes > 0);
    assert!(info.limits.authed.max_envelope_bytes > 0);
    assert!(info.limits.authed.max_envelope_bytes > info.limits.public.max_envelope_bytes);
    assert!(info.claim_rate.requests_per_second > 0.0);
}

#[test]
#[ignore]
fn e2e_server_info_authenticated() {
    if should_skip_api_key() {
        return;
    }
    let url = base_url();
    let key = api_key();

    let client = secrt_cli::client::ApiClient {
        base_url: url,
        api_key: key,
    };

    use secrt_cli::client::SecretApi;
    let info = client.info().expect("info() should succeed");
    assert!(info.authenticated, "should be authenticated with valid key");
}

#[test]
#[ignore]
fn e2e_config_show_with_server_info() {
    if should_skip() {
        return;
    }
    let url = base_url();

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().env("SECRET_BASE_URL", &url).build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0, "config failed: {}", stderr);

    let err = stderr.to_string();
    assert!(
        err.contains("SERVER LIMITS"),
        "should show SERVER LIMITS: {}",
        err
    );
    assert!(
        err.contains("default_ttl"),
        "should show default_ttl: {}",
        err
    );
    assert!(err.contains("max_ttl"), "should show max_ttl: {}", err);
    assert!(
        err.contains("max_envelope"),
        "should show max_envelope: {}",
        err
    );
    assert!(
        err.contains("claim_rate"),
        "should show claim_rate: {}",
        err
    );
    // default_ttl in EFFECTIVE SETTINGS should show actual value from server
    assert!(
        err.contains("1d"),
        "should show 1d for default_ttl: {}",
        err
    );
    assert!(
        err.contains("server default"),
        "should indicate server default: {}",
        err
    );
}

// ---------------------------------------------------------------------------
// `secrt update` E2E against a local HTTP mock.
//
// This is `#[ignore]`-gated like the rest of e2e.rs (no live server
// required, but it spawns a TCP listener thread). It exercises the full
// download + checksum + atomic-install path against canned bytes served
// from 127.0.0.1, mirroring the `--release-base-url` workflow documented
// in `docs/update-flow-testing.md § 1`.
//
// Run with:
//   cargo test -p secrt-cli e2e_update -- --ignored
// ---------------------------------------------------------------------------

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use secrt_cli::update::{
    exit as update_exit, raw_asset_name, run_update_with, sha256_hex, UreqUpdateHttp,
    CHECKSUM_FILENAME_PUB,
};

#[test]
#[ignore]
fn e2e_update_local_mock_full_install() {
    // Per-host asset.
    let asset = raw_asset_name(std::env::consts::OS, std::env::consts::ARCH)
        .expect("unsupported (os, arch) for self-update");

    // Canned binary contents + checksum.
    let bin: Vec<u8> = b"\x7fELF e2e canned binary".to_vec();
    let hex = sha256_hex(&bin);
    let version = "9.9.9";

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let bin_clone = bin.clone();
    let asset_path = format!("/cli/v{}/{}", version, asset);
    let checksum_path = format!("/cli/v{}/{}", version, CHECKSUM_FILENAME_PUB);
    let checksum_body = format!("{}  {}\n", hex, asset);

    // Tiny single-pass HTTP/1.1 server. Serves the next request whose
    // path matches one of the two known endpoints; ignores everything
    // else. Loops until shutdown is signaled by the channel below.
    let stop = Arc::new(Mutex::new(false));
    let stop_clone = stop.clone();
    let server_handle = thread::spawn(move || {
        listener.set_nonblocking(true).ok();
        loop {
            if *stop_clone.lock().unwrap() {
                break;
            }
            match listener.accept() {
                Ok((mut sock, _)) => {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line = req.lines().next().unwrap_or("");
                    let path = first_line.split_whitespace().nth(1).unwrap_or("");
                    if path == checksum_path {
                        let body = checksum_body.as_bytes();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = sock.write_all(resp.as_bytes());
                        let _ = sock.write_all(body);
                    } else if path == asset_path {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            bin_clone.len()
                        );
                        let _ = sock.write_all(resp.as_bytes());
                        let _ = sock.write_all(&bin_clone);
                    } else {
                        let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = sock.write_all(resp);
                    }
                    let _ = sock.flush();
                }
                Err(_) => {
                    thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        }
    });

    let dir = std::env::temp_dir().join(format!(
        "secrt_e2e_update_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let target = dir.join(if cfg!(windows) { "secrt.exe" } else { "secrt" });
    fs::write(&target, b"old e2e payload").unwrap();

    let base = format!("http://127.0.0.1:{}", port);
    let (mut deps, stdout, stderr) = TestDepsBuilder::new().build();
    let code = run_update_with(
        &args(&[
            "--version",
            version,
            "--install-dir",
            &dir.to_string_lossy(),
            "--release-base-url",
            &base,
            "--force",
        ])[..],
        &mut deps,
        &UreqUpdateHttp,
    );

    *stop.lock().unwrap() = true;
    // Best-effort: nudge the listener to wake from `accept` so the thread
    // can observe shutdown. A bound TCP listener with a no-op connect is
    // the simplest portable nudge.
    let _ = std::net::TcpStream::connect(format!("127.0.0.1:{}", port));
    let _ = server_handle.join();

    assert_eq!(
        code,
        update_exit::OK,
        "stdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    let installed: PathBuf = dir.join(if cfg!(windows) { "secrt.exe" } else { "secrt" });
    assert_eq!(fs::read(&installed).unwrap(), bin);
}
