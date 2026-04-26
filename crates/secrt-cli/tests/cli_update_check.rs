//! End-to-end tests for the implicit update-check banner. Drives `cli::run`
//! with a pre-populated cache file and a controlled environment, then
//! asserts whether the banner appears on stderr.
//!
//! The banner-emit gate is a process-global `OnceLock`, so this file runs
//! at most one banner-emitting case per test binary (Cargo runs each
//! integration test file as a separate process). Suppression cases never
//! touch the gate and can run concurrently.

mod helpers;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use helpers::{args, SharedBuf, TestDepsBuilder};
use secrt_cli::cli;
use secrt_cli::update_check::CURRENT_VERSION;

/// Per-test temp dir used as `XDG_CACHE_HOME`. Random suffix so concurrent
/// tests in this binary don't collide.
fn fresh_cache_dir(label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "secrt_cli_update_check_{}_{:?}_{}_{}",
        label,
        std::thread::current().id(),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&p).unwrap();
    p
}

fn write_cache(dir: &Path, latest: &str, checked_at_iso: &str, min_supported: Option<&str>) {
    let secrt_dir = dir.join("secrt");
    fs::create_dir_all(&secrt_dir).unwrap();
    let body = match min_supported {
        Some(m) => format!(
            r#"{{"checked_at":"{checked_at_iso}","latest":"{latest}","current":"{cur}","min_supported":"{m}"}}"#,
            cur = CURRENT_VERSION
        ),
        None => format!(
            r#"{{"checked_at":"{checked_at_iso}","latest":"{latest}","current":"{cur}"}}"#,
            cur = CURRENT_VERSION
        ),
    };
    fs::write(secrt_dir.join("update-check.json"), body).unwrap();
}

fn now_minus_seconds(secs: u64) -> SystemTime {
    SystemTime::now() - Duration::from_secs(secs)
}

/// `SystemTime` formatted as RFC 3339, matching what `update_check`
/// expects. We use a fixed epoch so cache contents are deterministic.
fn rfc3339_at(secs_ago: u64) -> (String, SystemTime) {
    let now = SystemTime::now();
    let stamp = now - Duration::from_secs(secs_ago);
    let secs = stamp.duration_since(UNIX_EPOCH).unwrap().as_secs();
    // Reuse the inverse of `secrt_cli::send::parse_iso_to_epoch` via a
    // local copy: this test only needs second-precision, UTC, no-frac.
    let (year, month, day) = epoch_to_civil(secs / 86400);
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    let iso = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, h, m, s
    );
    (iso, now)
}

fn epoch_to_civil(days: u64) -> (i64, u32, u32) {
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

fn build(label: &str, args_extra: &[&str]) -> (cli::Deps, SharedBuf, PathBuf) {
    let dir = fresh_cache_dir(label);
    let (deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CACHE_HOME", dir.to_str().unwrap())
        .env("HOME", dir.to_str().unwrap()) // keep ~/.cache fallback inside our sandbox
        .stderr_tty(true)
        .build();
    let _ = args_extra; // only here so callers can document intent at the call site
    (deps, stderr, dir)
}

/// We only allow the banner-emit gate to be tripped by a single test in
/// this file. All other tests assert *suppression* and so never reach the
/// gate.
static BANNER_TEST_GATE: OnceLock<()> = OnceLock::new();

fn claim_banner_emit_slot() -> bool {
    BANNER_TEST_GATE.set(()).is_ok()
}

#[test]
fn banner_emitted_when_cache_fresh_and_stderr_is_tty() {
    if !claim_banner_emit_slot() {
        // Another test in this file already exercised the gate. Skip
        // gracefully — concurrent runs of this binary should not both
        // assert banner emission.
        return;
    }
    let (mut deps, stderr, dir) = build("emit", &[]);
    let (iso, _now) = rfc3339_at(60); // 1 minute ago
    write_cache(&dir, "99.0.0", &iso, None);

    let code = cli::run(&args(&["secrt", "--version"]), &mut deps);
    assert_eq!(code, 0, "version flag should exit 0");

    let err = stderr.to_string();
    // New two-line banner: header carries `<latest> available`, followed
    // by an indented `secrt update` line in bold cyan.
    assert!(
        err.contains("99.0.0 available"),
        "expected banner header, got stderr: {:?}",
        err
    );
    assert!(
        err.contains("secrt update"),
        "expected indented `secrt update` line, got stderr: {:?}",
        err
    );
    assert!(
        err.contains(CURRENT_VERSION),
        "banner should reference the current version"
    );
}

#[test]
fn banner_suppressed_when_stderr_not_tty() {
    let dir = fresh_cache_dir("suppress_no_tty");
    let (iso, _) = rfc3339_at(60);
    write_cache(&dir, "99.0.0", &iso, None);
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CACHE_HOME", dir.to_str().unwrap())
        .env("HOME", dir.to_str().unwrap())
        .stderr_tty(false) // critical: stderr-not-TTY is the suppression rule
        .build();

    let code = cli::run(&args(&["secrt", "--version"]), &mut deps);
    assert_eq!(code, 0);
    assert!(
        !stderr.to_string().contains("99.0.0 available"),
        "banner must be suppressed when stderr is not a TTY"
    );
}

#[test]
fn banner_suppressed_with_no_update_check_flag() {
    let dir = fresh_cache_dir("suppress_flag");
    let (iso, _) = rfc3339_at(60);
    write_cache(&dir, "99.0.0", &iso, None);
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CACHE_HOME", dir.to_str().unwrap())
        .env("HOME", dir.to_str().unwrap())
        .stderr_tty(true)
        .build();

    let code = cli::run(
        &args(&["secrt", "--version", "--no-update-check"]),
        &mut deps,
    );
    assert_eq!(code, 0);
    assert!(
        !stderr.to_string().contains("99.0.0 available"),
        "banner must be suppressed by --no-update-check"
    );
}

#[test]
fn banner_suppressed_with_silent_flag() {
    let dir = fresh_cache_dir("suppress_silent");
    let (iso, _) = rfc3339_at(60);
    write_cache(&dir, "99.0.0", &iso, None);
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CACHE_HOME", dir.to_str().unwrap())
        .env("HOME", dir.to_str().unwrap())
        .stderr_tty(true)
        .build();

    let code = cli::run(&args(&["secrt", "--version", "--silent"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().contains("99.0.0 available"));
}

#[test]
fn banner_suppressed_with_json_flag() {
    let dir = fresh_cache_dir("suppress_json");
    let (iso, _) = rfc3339_at(60);
    write_cache(&dir, "99.0.0", &iso, None);
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CACHE_HOME", dir.to_str().unwrap())
        .env("HOME", dir.to_str().unwrap())
        .stderr_tty(true)
        .build();

    let code = cli::run(&args(&["secrt", "--version", "--json"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().contains("99.0.0 available"));
}

#[test]
fn banner_suppressed_with_env_var() {
    let dir = fresh_cache_dir("suppress_env");
    let (iso, _) = rfc3339_at(60);
    write_cache(&dir, "99.0.0", &iso, None);
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CACHE_HOME", dir.to_str().unwrap())
        .env("HOME", dir.to_str().unwrap())
        .env("SECRET_NO_UPDATE_CHECK", "1")
        .stderr_tty(true)
        .build();

    let code = cli::run(&args(&["secrt", "--version"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().contains("99.0.0 available"));
}

#[test]
fn banner_suppressed_when_config_disables_update_check() {
    let dir = fresh_cache_dir("suppress_config");
    let (iso, _) = rfc3339_at(60);
    write_cache(&dir, "99.0.0", &iso, None);

    // Config file lives under XDG_CONFIG_HOME, not XDG_CACHE_HOME — they're
    // separate paths in our setup but the same parent dir is fine.
    let cfg_dir = dir.join("config");
    let secrt_cfg = cfg_dir.join("secrt");
    fs::create_dir_all(&secrt_cfg).unwrap();
    fs::write(secrt_cfg.join("config.toml"), "update_check = false\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(
            secrt_cfg.join("config.toml"),
            fs::Permissions::from_mode(0o600),
        );
    }

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CACHE_HOME", dir.to_str().unwrap())
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .env("HOME", dir.to_str().unwrap())
        .stderr_tty(true)
        .build();

    let code = cli::run(&args(&["secrt", "--version"]), &mut deps);
    assert_eq!(code, 0);
    assert!(
        !stderr.to_string().contains("99.0.0 available"),
        "config update_check=false must suppress banner"
    );
}

#[test]
fn banner_suppressed_for_secrt_update_command() {
    // `secrt update` itself never carries the banner — it IS the upgrade
    // path. (PR4 hasn't landed the subcommand yet, so this hits the
    // unknown-command branch; what matters is that the banner check sees
    // args[1] == "update" and bails before any cache lookup.)
    let dir = fresh_cache_dir("suppress_self");
    let (iso, _) = rfc3339_at(60);
    write_cache(&dir, "99.0.0", &iso, None);
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CACHE_HOME", dir.to_str().unwrap())
        .env("HOME", dir.to_str().unwrap())
        .stderr_tty(true)
        .build();

    let _code = cli::run(&args(&["secrt", "update", "--check"]), &mut deps);
    assert!(
        !stderr.to_string().contains("99.0.0 available"),
        "banner must be suppressed when running `secrt update`"
    );
}

#[test]
fn banner_silent_when_cache_missing() {
    let (mut deps, stderr, _dir) = build("missing", &[]);
    // No write_cache — file doesn't exist.
    let code = cli::run(&args(&["secrt", "--version"]), &mut deps);
    assert_eq!(code, 0);
    assert!(
        !stderr.to_string().contains("99.0.0 available"),
        "missing cache must produce no banner"
    );
}

#[test]
fn banner_silent_when_cache_corrupted() {
    let dir = fresh_cache_dir("corrupted");
    let secrt_dir = dir.join("secrt");
    fs::create_dir_all(&secrt_dir).unwrap();
    fs::write(secrt_dir.join("update-check.json"), "{not valid json").unwrap();
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CACHE_HOME", dir.to_str().unwrap())
        .env("HOME", dir.to_str().unwrap())
        .stderr_tty(true)
        .build();

    let code = cli::run(&args(&["secrt", "--version"]), &mut deps);
    assert_eq!(code, 0);
    assert!(
        !stderr.to_string().contains("99.0.0 available"),
        "corrupted cache must collapse to silent (no panic, no banner)"
    );
}

#[test]
fn banner_silent_when_cache_stale() {
    let dir = fresh_cache_dir("stale");
    // 25 hours ago — past the 24h TTL.
    let (iso, _) = rfc3339_at(25 * 3600);
    write_cache(&dir, "99.0.0", &iso, None);
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CACHE_HOME", dir.to_str().unwrap())
        .env("HOME", dir.to_str().unwrap())
        .stderr_tty(true)
        .build();

    let code = cli::run(&args(&["secrt", "--version"]), &mut deps);
    assert_eq!(code, 0);
    assert!(
        !stderr.to_string().contains("99.0.0 available"),
        "stale cache must produce no banner"
    );
    let _ = now_minus_seconds(0); // silence dead-code lint
}
