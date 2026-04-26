//! Integration tests for `secrt update`. The pure-logic helpers (flag
//! parsing, OS+arch mapping, managed-install detection, checksum parsing)
//! live in `update::tests`. This file exercises the orchestration:
//! download + verify + install + lock contention + error messages.
//!
//! The real download path is driven against a `MockHttp` impl that records
//! every URL it served, so we can assert on URL shape and User-Agent
//! parity without spinning a TCP listener for each test. A separate
//! `User-Agent` test uses a real `std::net::TcpListener` to verify the
//! ureq-backed `UreqUpdateHttp` sets the header on the wire.

mod helpers;

use std::collections::HashMap;
use std::fs;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use helpers::{args, TestDepsBuilder};
use secrt_cli::update::{
    exit, run_update_with, sha256_hex, UpdateHttp, UreqUpdateHttp, CHECKSUM_FILENAME_PUB,
    INSTALL_LOCK_FILENAME_PUB,
};

/// Per-test temp dir.
fn tempdir(label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "secrt_cli_update_{}_{}_{:?}_{}",
        label,
        std::process::id(),
        std::thread::current().id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&p).unwrap();
    p
}

/// Asset filename for the host this test is running on.
fn host_asset() -> &'static str {
    secrt_cli::update::raw_asset_name(std::env::consts::OS, std::env::consts::ARCH)
        .expect("running on an unsupported (os, arch) — add it to the table")
}

/// Mock `UpdateHttp` with canned responses. URL → bytes (or text).
#[derive(Clone, Default)]
struct MockHttp {
    text: HashMap<String, String>,
    bytes: HashMap<String, Vec<u8>>,
    /// Every URL passed to fetch_text or fetch_bytes, in order.
    seen: Arc<Mutex<Vec<String>>>,
    /// If a URL is in this set, return an error. URL → error message.
    errors: HashMap<String, String>,
}

impl MockHttp {
    fn with_text(mut self, url: &str, body: &str) -> Self {
        self.text.insert(url.to_string(), body.to_string());
        self
    }
    fn with_bytes(mut self, url: &str, body: Vec<u8>) -> Self {
        self.bytes.insert(url.to_string(), body);
        self
    }
    #[allow(dead_code)]
    fn with_error(mut self, url: &str, msg: &str) -> Self {
        self.errors.insert(url.to_string(), msg.to_string());
        self
    }
}

impl UpdateHttp for MockHttp {
    fn fetch_text(&self, url: &str) -> Result<String, String> {
        self.seen.lock().unwrap().push(url.to_string());
        if let Some(e) = self.errors.get(url) {
            return Err(e.clone());
        }
        self.text
            .get(url)
            .cloned()
            .ok_or_else(|| format!("MockHttp: no canned text for {}", url))
    }
    fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, String> {
        self.seen.lock().unwrap().push(url.to_string());
        if let Some(e) = self.errors.get(url) {
            return Err(e.clone());
        }
        self.bytes
            .get(url)
            .cloned()
            .ok_or_else(|| format!("MockHttp: no canned bytes for {}", url))
    }
}

/// Build a release base URL pointing at an in-memory mock.
fn mock_base_url() -> &'static str {
    "http://release.test/getsecrt/secrt/releases/download"
}

/// Build canned checksums file for one asset.
fn checksums_file(asset: &str, hex: &str) -> String {
    format!("{}  {}\n", hex, asset)
}

#[test]
fn check_only_reports_up_to_date_when_target_equals_current() {
    let version = secrt_cli::update_check::CURRENT_VERSION;
    let base = mock_base_url();
    let release_url = format!("{}/cli/v{}", base, version);
    let asset = host_asset();
    let bin = b"placeholder".to_vec();
    let hex = sha256_hex(&bin);
    let checksums = checksums_file(asset, &hex);

    let http = MockHttp::default()
        .with_text(
            &format!("{}/{}", release_url, CHECKSUM_FILENAME_PUB),
            &checksums,
        )
        .with_bytes(&format!("{}/{}", release_url, asset), bin);

    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = run_update_with(
        &args(&["--check", "--version", version, "--release-base-url", base])[..],
        &mut deps,
        &http,
    );
    assert_eq!(code, exit::OK);
    let s = stdout.to_string();
    assert!(s.contains("up to date"), "stdout: {}", s);
}

#[test]
fn check_only_reports_upgrade_when_target_is_newer() {
    let base = mock_base_url();

    // Pretend a far-future release exists. The current CLI version is
    // strictly less than 99.0.0, so --check should announce the upgrade.
    let http = MockHttp::default();

    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = run_update_with(
        &args(&["--check", "--version", "99.0.0", "--release-base-url", base])[..],
        &mut deps,
        &http,
    );
    assert_eq!(code, exit::OK);
    let s = stdout.to_string();
    // New shape: two-line header + indented command, matching the
    // implicit banner so users see the same copy-pasteable instruction.
    assert!(s.contains("99.0.0 available"), "stdout: {}", s);
    assert!(s.contains("current: "), "stdout: {}", s);
    assert!(s.contains("\n  secrt update"), "stdout: {}", s);
}

#[test]
fn version_strictness_rejected_at_parse() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let http = MockHttp::default();
    let code = run_update_with(&args(&["--version", "0.16.0-rc.1"])[..], &mut deps, &http);
    assert_eq!(code, exit::USAGE);
    assert!(stderr.to_string().contains("strict semver"));
}

#[test]
fn channel_prerelease_is_reserved() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let http = MockHttp::default();
    let code = run_update_with(&args(&["--channel", "prerelease"])[..], &mut deps, &http);
    assert_eq!(code, exit::USAGE);
    assert!(stderr
        .to_string()
        .contains("prerelease channel is reserved"));
}

#[test]
fn checksum_mismatch_halts_with_exit_2() {
    // Stage a writable install dir + a "running binary" inside it. The
    // canonicalize → managed-install check defaults to Plain because the
    // canonical path != ~/.cargo/bin/secrt etc.
    let dir = tempdir("checksum_mismatch");
    let target = dir.join("secrt");
    fs::write(&target, b"old").unwrap();

    let bin = b"new contents".to_vec();
    // Wrong hash — flip a byte's worth of nibbles.
    let bad_hex = "0".repeat(64);
    let asset = host_asset();
    let base = mock_base_url();
    let release_url = format!("{}/cli/v9.9.9", base);
    let http = MockHttp::default()
        .with_text(
            &format!("{}/{}", release_url, CHECKSUM_FILENAME_PUB),
            &checksums_file(asset, &bad_hex),
        )
        .with_bytes(&format!("{}/{}", release_url, asset), bin);

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = run_update_with(
        &args(&[
            "--version",
            "9.9.9",
            "--install-dir",
            &dir.to_string_lossy(),
            "--release-base-url",
            base,
            "--force",
        ])[..],
        &mut deps,
        &http,
    );
    assert_eq!(code, exit::CHECKSUM_MISMATCH);
    let err = stderr.to_string();
    assert!(err.contains("SHA-256 mismatch"), "stderr: {}", err);
    assert!(err.contains("expected:"), "stderr: {}", err);
    assert!(err.contains("actual:"), "stderr: {}", err);
    // No binary written.
    assert_eq!(fs::read(&target).unwrap(), b"old");
}

#[test]
fn checksum_file_missing_asset_entry_exits_2() {
    let dir = tempdir("missing_entry");
    let _target = dir.join("secrt");
    let base = mock_base_url();
    let release_url = format!("{}/cli/v9.9.9", base);
    let http = MockHttp::default().with_text(
        &format!("{}/{}", release_url, CHECKSUM_FILENAME_PUB),
        // Empty checksum file — no rows for our asset.
        "",
    );

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = run_update_with(
        &args(&[
            "--version",
            "9.9.9",
            "--install-dir",
            &dir.to_string_lossy(),
            "--release-base-url",
            base,
            "--force",
        ])[..],
        &mut deps,
        &http,
    );
    assert_eq!(code, exit::CHECKSUM_MISMATCH);
    assert!(stderr.to_string().contains("no entry for"));
}

#[cfg(unix)]
#[test]
fn happy_path_installs_atomically() {
    let dir = tempdir("happy");
    // With `--install-dir`, the install target is always `<dir>/secrt` —
    // the canonical product name, regardless of the running binary's
    // filename. Pre-stage so we can assert atomic replacement.
    let target = dir.join("secrt");
    fs::write(&target, b"old version").unwrap();

    let asset = host_asset();
    let bin = b"\x7fELF brand-new binary contents".to_vec();
    let hex = sha256_hex(&bin);
    let base = mock_base_url();
    let release_url = format!("{}/cli/v9.9.9", base);
    let http = MockHttp::default()
        .with_text(
            &format!("{}/{}", release_url, CHECKSUM_FILENAME_PUB),
            &checksums_file(asset, &hex),
        )
        .with_bytes(&format!("{}/{}", release_url, asset), bin.clone());

    let (mut deps, stdout, stderr) = TestDepsBuilder::new().build();
    let code = run_update_with(
        &args(&[
            "--version",
            "9.9.9",
            "--install-dir",
            &dir.to_string_lossy(),
            "--release-base-url",
            base,
            "--force",
        ])[..],
        &mut deps,
        &http,
    );
    assert_eq!(code, exit::OK, "stderr: {}", stderr.to_string());
    assert!(stdout.to_string().contains("9.9.9 installed"));
    assert_eq!(fs::read(&target).unwrap(), bin);
    let mode = fs::metadata(&target).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(mode.mode() & 0o777, 0o755);
    // No `.new` artifact left over.
    assert!(!dir.join("secrt.new").exists());
}

#[cfg(unix)]
#[test]
fn lock_contention_returns_exit_5() {
    use secrt_cli::update::InstallLock;

    let dir = tempdir("lock_contention");
    let target = dir.join("secrt");
    fs::write(&target, b"placeholder").unwrap();

    // Hold the lock from this thread.
    let _held = InstallLock::try_acquire(&dir)
        .expect("acquire")
        .expect("got lock");

    // Spawn a child process to attempt the second acquire — flock(2) is
    // per-fd, not per-process, so a sibling fd in the same process would
    // still succeed. We use a child via `cargo run` would be heavy, so
    // instead exercise the lock path with a stdlib `Command::new("sh")`
    // that calls flock(1).
    //
    // Easiest cross-platform approach: use a child thread that opens a
    // *separate* fd to the same lockfile and calls flock LOCK_EX|LOCK_NB.
    // That triggers contention because flock(2) on Linux/macOS rejects a
    // second LOCK_EX on the same file from a different fd in the same
    // process.
    let dir2 = dir.clone();
    let h = thread::spawn(move || InstallLock::try_acquire(&dir2));
    let result = h.join().unwrap().expect("acquire returned Err");
    assert!(
        result.is_none(),
        "expected contention, got {:?}",
        result.is_some()
    );
    drop(_held);
}

#[cfg(unix)]
#[test]
fn lock_contention_exit_5_via_run_update() {
    // Drive the real exit-5 path: pre-acquire the lock, then run_update
    // hits contention before any download happens.
    use secrt_cli::update::InstallLock;

    let dir = tempdir("lock_contention_e2e");
    let target = dir.join("secrt");
    fs::write(&target, b"placeholder").unwrap();

    let _held = InstallLock::try_acquire(&dir)
        .expect("acquire")
        .expect("got lock");

    // Run `secrt update` from another thread (so the in-process locks
    // are held by distinct fds — required for flock contention).
    let dir2 = dir.clone();
    let h = thread::spawn(move || {
        let asset = host_asset();
        let bin = b"new".to_vec();
        let hex = sha256_hex(&bin);
        let base = mock_base_url();
        let release_url = format!("{}/cli/v9.9.9", base);
        let http = MockHttp::default()
            .with_text(
                &format!("{}/{}", release_url, CHECKSUM_FILENAME_PUB),
                &checksums_file(asset, &hex),
            )
            .with_bytes(&format!("{}/{}", release_url, asset), bin);

        let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
        let code = run_update_with(
            &args(&[
                "--version",
                "9.9.9",
                "--install-dir",
                &dir2.to_string_lossy(),
                "--release-base-url",
                base,
                "--force",
            ])[..],
            &mut deps,
            &http,
        );
        (code, stderr.to_string())
    });
    let (code, err) = h.join().unwrap();
    assert_eq!(code, exit::LOCK_CONTENTION, "stderr: {}", err);
    assert!(err.contains("another secrt update is in progress"));
    drop(_held);
}

#[cfg(unix)]
#[test]
fn permission_denied_install_dir_exits_4_with_install_dir_hint() {
    // Make a read-only directory and try to install into it.
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir("permdenied");
    let mut perms = fs::metadata(&dir).unwrap().permissions();
    perms.set_mode(0o555); // r-x r-x r-x — no writes
    fs::set_permissions(&dir, perms).unwrap();

    let asset = host_asset();
    let bin = b"new contents".to_vec();
    let hex = sha256_hex(&bin);
    let base = mock_base_url();
    let release_url = format!("{}/cli/v9.9.9", base);
    let http = MockHttp::default()
        .with_text(
            &format!("{}/{}", release_url, CHECKSUM_FILENAME_PUB),
            &checksums_file(asset, &hex),
        )
        .with_bytes(&format!("{}/{}", release_url, asset), bin);

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = run_update_with(
        &args(&[
            "--version",
            "9.9.9",
            "--install-dir",
            &dir.to_string_lossy(),
            "--release-base-url",
            base,
            "--force",
        ])[..],
        &mut deps,
        &http,
    );

    // Restore perms so cleanup works regardless of test outcome.
    let mut perms2 = fs::metadata(&dir).unwrap().permissions();
    perms2.set_mode(0o755);
    let _ = fs::set_permissions(&dir, perms2);

    // Running as root would defeat this test (root ignores 0o555).
    if nix_running_as_root() {
        eprintln!("skipping permission test: running as root");
        return;
    }

    assert_eq!(
        code,
        exit::PERMISSION_DENIED,
        "stderr: {}",
        stderr.to_string()
    );
    let err = stderr.to_string();
    assert!(
        err.contains("--install-dir"),
        "must hint --install-dir, not sudo: {}",
        err
    );
    assert!(!err.contains("sudo"), "must not recommend sudo: {}", err);
}

#[cfg(unix)]
fn nix_running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn user_agent_header_present_on_real_request() {
    // Stand up a tiny single-shot HTTP server in a thread, hit it with
    // `UreqUpdateHttp`, and assert the recorded request includes
    // `User-Agent: secrt/<version>`.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured2 = captured.clone();
    let handle = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        // Read one HTTP request.
        let mut buf = vec![0u8; 4096];
        let n = sock.read(&mut buf).unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        *captured2.lock().unwrap() = Some(req);
        // Reply with the smallest valid HTTP/1.1 response.
        let body = b"hi";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = sock.write_all(resp.as_bytes());
        let _ = sock.write_all(body);
        let _ = sock.flush();
    });

    let url = format!("http://127.0.0.1:{}/anything", port);
    let body = UreqUpdateHttp.fetch_text(&url).expect("fetch");
    assert_eq!(body, "hi");
    handle.join().unwrap();

    let req = captured.lock().unwrap().clone().expect("captured");
    // ureq lowercases header names on the wire, so compare case-insensitively.
    let lower = req.to_ascii_lowercase();
    let expected = format!("user-agent: secrt/{}", env!("CARGO_PKG_VERSION"));
    assert!(
        lower.contains(&expected),
        "expected `{}` in request (case-insensitive), got:\n{}",
        expected,
        req
    );
}

#[test]
fn lockfile_constant_is_exposed() {
    // Sanity-check the public constant we export for tests/external
    // tooling, so a rename of the internal LOCK_FILENAME doesn't silently
    // change observable behavior.
    assert_eq!(INSTALL_LOCK_FILENAME_PUB, ".secrt-update.lock");
    let _: &str = CHECKSUM_FILENAME_PUB;
}

// --- Helpers used only by this binary -------------------------------------

#[cfg(unix)]
extern crate libc;

#[allow(dead_code)]
fn write_tmp(path: &Path, body: &[u8]) {
    fs::write(path, body).unwrap();
}

// Suppress unused-imports/linter complaints on Windows where the cfg-gated
// blocks are inactive but the symbols are still referenced.
#[allow(dead_code)]
fn _silence_unused() {
    let _ = Duration::from_secs;
}
