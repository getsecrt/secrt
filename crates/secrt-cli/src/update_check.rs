//! Update-check infrastructure: cache management, semver comparison, banner
//! formatting, and opportunistic refresh paths from server responses.
//!
//! The implicit banner is **cache-only** — none of the read paths in this
//! module make a network call. The cache is opportunistically refreshed by:
//!
//! 1. Commands that already call `/api/v1/info` → [`ingest_info_response`].
//! 2. Advisory `X-Secrt-*` response headers from any other server response
//!    → [`ingest_advisory_headers`].
//! 3. Explicit `secrt update --check` / `secrt update` (PR4, not in this
//!    revision) — those bypass the local cache for the *read* and write back.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::send::parse_iso_to_epoch;

/// Current CLI version, baked in at compile time.
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Cache freshness window. Entries older than this are treated as stale and
/// trigger a re-fetch on the next command path that already hits the server.
pub const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// On-disk cache shape per `spec/v1/cli.md § Local Cache`. Extra fields are
/// tolerated for forward compatibility.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpdateCheckCache {
    /// RFC 3339 timestamp of when the cache was last refreshed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
    /// Newest version observed at refresh time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    /// CLI version that wrote the cache. Used to invalidate the cache when
    /// the user upgrades the CLI itself (so a stale "you are out of date"
    /// banner doesn't follow them past the upgrade).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    /// Server's hard-floor minimum supported version, if known. Optional in
    /// the cache (older versions of the cache won't have it). Drives the
    /// stronger "may not be compatible" banner when the running CLI is below
    /// this floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_supported: Option<String>,
}

/// Result of a successful banner-eligibility check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BannerInfo {
    pub current: String,
    pub latest: String,
    /// True when the running CLI is below the server's hard floor — the CLI
    /// SHOULD render a stronger "may not be compatible" message in that case.
    pub below_min_supported: bool,
}

/// Resolve the cache file path: `$XDG_CACHE_HOME/secrt/update-check.json` or
/// `~/.cache/secrt/update-check.json`. Returns `None` when neither env var
/// nor home dir is resolvable (e.g., very minimal CI environment).
pub fn cache_path(getenv: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let cache_dir = getenv("XDG_CACHE_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".cache")));
    cache_dir.map(|d| d.join("secrt").join("update-check.json"))
}

/// Read the cache file; tolerate missing files, corrupted JSON, and IO
/// errors. Never panics. Never returns a `Result` because every error mode
/// collapses to "cold cache".
fn read_cache(getenv: &dyn Fn(&str) -> Option<String>) -> UpdateCheckCache {
    let Some(path) = cache_path(getenv) else {
        return UpdateCheckCache::default();
    };
    let Ok(bytes) = fs::read(&path) else {
        return UpdateCheckCache::default();
    };
    serde_json::from_slice::<UpdateCheckCache>(&bytes).unwrap_or_default()
}

/// Best-effort cache write. Permission errors, missing parent dirs, and IO
/// failures are silently ignored — caching is an optimization, not a
/// correctness guarantee.
fn write_cache(getenv: &dyn Fn(&str) -> Option<String>, cache: &UpdateCheckCache) {
    let Some(path) = cache_path(getenv) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let Ok(bytes) = serde_json::to_vec(cache) else {
        return;
    };
    let _ = fs::write(&path, bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
}

/// Read the cache and decide whether the running CLI should display the
/// banner. Returns `None` when the cache is cold, stale, corrupted, in the
/// future (clock skew), the running CLI version differs from the version
/// that wrote the cache, or `latest` is not strictly greater than
/// `current_version`.
///
/// **No network call. Ever.** This is the implicit banner read path.
pub fn check_cache(getenv: &dyn Fn(&str) -> Option<String>, now: SystemTime) -> Option<BannerInfo> {
    let cache = read_cache(getenv);
    let latest = cache.latest.as_deref()?;
    let cached_current = cache.current.as_deref();
    let checked_at = cache.checked_at.as_deref()?;

    // Invalidate when the user upgraded since the last cache write.
    if let Some(prev) = cached_current {
        if prev != CURRENT_VERSION {
            return None;
        }
    } else {
        // No `current` recorded — treat as untrusted, just like a corrupt
        // cache.
        return None;
    }

    let cached_epoch = parse_iso_to_epoch(checked_at)?;
    let now_epoch = now.duration_since(UNIX_EPOCH).ok()?.as_secs();

    // Clock skew: a future timestamp is treated as stale.
    if cached_epoch > now_epoch {
        return None;
    }
    if now_epoch.saturating_sub(cached_epoch) > CACHE_TTL.as_secs() {
        return None;
    }

    let below_min_supported = cache
        .min_supported
        .as_deref()
        .map(|m| compare_semver(CURRENT_VERSION, m) == std::cmp::Ordering::Less)
        .unwrap_or(false);

    let needs_banner =
        compare_semver(CURRENT_VERSION, latest) == std::cmp::Ordering::Less || below_min_supported;
    if !needs_banner {
        return None;
    }

    Some(BannerInfo {
        current: CURRENT_VERSION.to_string(),
        latest: latest.to_string(),
        below_min_supported,
    })
}

/// Refresh the cache from advisory `X-Secrt-*` response headers. Any subset
/// of the three values may be absent; present values are merged into the
/// cache. Best-effort: errors are silently ignored.
pub fn ingest_advisory_headers(
    latest: Option<&str>,
    checked_at: Option<&str>,
    min_supported: Option<&str>,
    getenv: &dyn Fn(&str) -> Option<String>,
    now: SystemTime,
) {
    if latest.is_none() && checked_at.is_none() && min_supported.is_none() {
        return;
    }
    let mut cache = read_cache(getenv);
    if let Some(v) = latest {
        if is_valid_semver(v) {
            cache.latest = Some(v.to_string());
        }
    }
    if let Some(v) = checked_at {
        if parse_iso_to_epoch(v).is_some() {
            cache.checked_at = Some(v.to_string());
        }
    } else if latest.is_some() {
        // Caller gave us a new `latest` without a server-side `checked_at`
        // (synthetic value, e.g., pulled from a body field that omitted the
        // timestamp). Stamp our local clock so `check_cache` doesn't reject
        // the entry as stale.
        cache.checked_at = Some(format_rfc3339(now));
    }
    if let Some(v) = min_supported {
        if is_valid_semver(v) {
            cache.min_supported = Some(v.to_string());
        }
    }
    cache.current = Some(CURRENT_VERSION.to_string());
    write_cache(getenv, &cache);
}

/// Refresh the cache from a parsed `/api/v1/info` body. Mirrors
/// [`ingest_advisory_headers`] but reads the typed body fields.
pub fn ingest_info_response(
    info: &secrt_core::api::InfoResponse,
    getenv: &dyn Fn(&str) -> Option<String>,
    now: SystemTime,
) {
    ingest_advisory_headers(
        info.latest_cli_version.as_deref(),
        info.latest_cli_version_checked_at.as_deref(),
        info.min_supported_cli_version.as_deref(),
        getenv,
        now,
    );
}

/// Per-process gate so the implicit banner fires at most once per
/// invocation, even if multiple commands or library calls trigger an
/// `ingest_*` followed by a banner check.
static BANNER_EMITTED: OnceLock<()> = OnceLock::new();

/// Emit the banner to `stderr` per `spec/v1/cli.md § Implicit Banner`.
///
/// **TTY-only.** When `stderr_is_tty` is false the banner is suppressed
/// entirely — a bare `secrt update` line in a non-TTY pipe (CI logs,
/// deploy scripts) would be more confusing than helpful. Callers that
/// reach this function should already have applied the suppression
/// matrix in `cli::banner_suppressed`; the TTY check here is defense in
/// depth.
///
/// Returns whether the banner was emitted.
pub fn emit_banner(stderr: &mut dyn Write, info: &BannerInfo, stderr_is_tty: bool) -> bool {
    if !stderr_is_tty {
        return false;
    }
    if BANNER_EMITTED.set(()).is_err() {
        return false;
    }
    let _ = writeln!(stderr, "{}", format_banner_line(info, /* ansi */ true));
    true
}

/// Build the two-line update banner.
///
/// Format:
///
/// ```text
/// <header>      ← DIM (or WARN when below min_supported)
///   secrt update ← bold cyan, indented to read as "do this"
/// ```
///
/// `ansi` controls whether ANSI SGR codes are emitted. Both [`emit_banner`]
/// (implicit stderr banner) and `secrt update --check` (explicit stdout
/// reply) call this; the implicit path forces `ansi=true` because it
/// already gates on stderr being a TTY, while the explicit `--check` path
/// passes the stdout TTY state — `--check` always prints, but only colorizes
/// when stdout is interactive.
pub fn format_banner_line(info: &BannerInfo, ansi: bool) -> String {
    // Codes match the semantic tokens in `color.rs`: DIM=2, WARN=33, URL
    // (bold cyan)=1;36.
    let (header, header_sgr) = if info.below_min_supported {
        (
            format!(
                "warning: secrt {} may not be compatible with this server",
                info.current
            ),
            "33", // WARN — yellow
        )
    } else {
        (
            format!(
                "secrt {} available (current: {})",
                info.latest, info.current
            ),
            "2", // DIM
        )
    };
    if ansi {
        format!(
            "\x1b[{sgr}m{header}\x1b[0m\n  \x1b[1;36msecrt update\x1b[0m",
            sgr = header_sgr,
            header = header,
        )
    } else {
        format!("{}\n  secrt update", header)
    }
}

/// Compare two semver-ish strings (`X.Y.Z`, optionally with a `-prerelease`
/// suffix). Inputs that fail to parse compare as Equal — callers treat that
/// as "no upgrade signal" so we never falsely advertise an upgrade.
///
/// Prerelease ordering follows the bits of semver.org we actually use:
/// a stable version always sorts above any prerelease of the same triplet,
/// and two prereleases of the same triplet compare structurally on
/// `(channel_rank, index)` for `(alpha|beta|rc).N`. Tokens that don't match
/// that shape fall back to lexicographic compare so we still produce a total
/// order (the picker rejects non-conforming tokens at the tag-pattern level).
pub fn compare_semver(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let pa = parse_semver_relaxed(a);
    let pb = parse_semver_relaxed(b);
    match (pa, pb) {
        (Some((maj_a, min_a, pat_a, pre_a)), Some((maj_b, min_b, pat_b, pre_b))) => {
            match (maj_a, min_a, pat_a).cmp(&(maj_b, min_b, pat_b)) {
                Ordering::Equal => match (pre_a.as_ref(), pre_b.as_ref()) {
                    (None, None) => Ordering::Equal,
                    (None, Some(_)) => Ordering::Greater, // stable > prerelease
                    (Some(_), None) => Ordering::Less,
                    (Some(x), Some(y)) => compare_prerelease(x, y),
                },
                other => other,
            }
        }
        _ => Ordering::Equal,
    }
}

/// Order prerelease tokens of the form `(alpha|beta|rc).N` by
/// `(channel_rank, index)`. Unrecognized tokens fall back to lexicographic
/// compare so total ordering is preserved.
fn compare_prerelease(a: &str, b: &str) -> std::cmp::Ordering {
    match (parse_pre_token(a), parse_pre_token(b)) {
        (Some(pa), Some(pb)) => pa.cmp(&pb),
        _ => a.cmp(b),
    }
}

/// Parse a prerelease token of the form `(alpha|beta|rc).N` into
/// `(channel_rank, index)`. `alpha < beta < rc`.
fn parse_pre_token(s: &str) -> Option<(u8, u64)> {
    let (kind, num) = s.split_once('.')?;
    let rank = match kind {
        "alpha" => 0,
        "beta" => 1,
        "rc" => 2,
        _ => return None,
    };
    if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((rank, num.parse::<u64>().ok()?))
}

/// Strict validity check used at cache-write boundaries: rejects prereleases,
/// build metadata, and anything that isn't `\d+\.\d+\.\d+`. Per
/// `spec/v1/cli.md § Reserved Future Behavior`, prerelease tags MUST be
/// skipped by both the server poller and the CLI's GitHub-direct fallback,
/// so we refuse to cache prerelease values even if a future server emits
/// them.
fn is_valid_semver(s: &str) -> bool {
    parse_semver_strict(s).is_some()
}

/// Parse a strict `X.Y.Z` triplet. Rejects prerelease (`-rc.1`) and build
/// (`+sha`) suffixes.
fn parse_semver_strict(s: &str) -> Option<(u64, u64, u64)> {
    let mut parts = s.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if !patch.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((major, minor, patch.parse::<u64>().ok()?))
}

/// Parse a `X.Y.Z` triplet with an optional `-prerelease` suffix. Returns
/// `(major, minor, patch, prerelease)`. Build metadata (`+sha…`) is rejected.
fn parse_semver_relaxed(s: &str) -> Option<(u64, u64, u64, Option<String>)> {
    if s.contains('+') {
        return None;
    }
    let (head, prerelease) = match s.split_once('-') {
        Some((h, p)) if !p.is_empty() => (h, Some(p.to_string())),
        Some(_) => return None, // trailing '-' with empty prerelease
        None => (s, None),
    };
    let (maj, min, pat) = parse_semver_strict(head)?;
    Some((maj, min, pat, prerelease))
}

/// Format a `SystemTime` as `YYYY-MM-DDTHH:MM:SSZ` (UTC). Inverse of
/// [`parse_iso_to_epoch`].
fn format_rfc3339(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (year, month, day) = epoch_to_civil(secs / 86400);
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, h, m, s
    )
}

/// Convert days from Unix epoch to civil `(year, month, day)`. Inverse of
/// the algorithm in `crate::send::parse_iso_to_epoch`. Howard Hinnant's
/// civil_from_days algorithm.
fn epoch_to_civil(days: u64) -> (i64, u32, u32) {
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;

    /// Each test stages its own temp dir under XDG_CACHE_HOME so reads/
    /// writes don't bleed across tests or pick up the developer's real
    /// cache.
    fn isolated_dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "secrt_update_check_{}_{:?}_{}",
            std::process::id(),
            std::thread::current().id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::create_dir_all(&p);
        p
    }

    fn getenv_for(dir: &Path) -> impl Fn(&str) -> Option<String> + '_ {
        |k: &str| {
            if k == "XDG_CACHE_HOME" {
                Some(dir.to_string_lossy().to_string())
            } else {
                None
            }
        }
    }

    fn write_raw_cache(dir: &Path, contents: &str) {
        let cache_dir = dir.join("secrt");
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("update-check.json"), contents).unwrap();
    }

    fn epoch(s: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(s)
    }

    #[test]
    fn parse_semver_strict_form() {
        assert_eq!(parse_semver_strict("0.15.0"), Some((0, 15, 0)));
        assert_eq!(parse_semver_strict("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_semver_strict("0.15.0-rc.1"), None);
        assert_eq!(parse_semver_strict("0.15"), None);
        assert_eq!(parse_semver_strict("0.15.0.1"), None);
        assert_eq!(parse_semver_strict(""), None);
    }

    #[test]
    fn parse_semver_relaxed_accepts_prereleases() {
        assert_eq!(
            parse_semver_relaxed("0.15.0-rc.1"),
            Some((0, 15, 0, Some("rc.1".into())))
        );
        assert_eq!(parse_semver_relaxed("0.15.0"), Some((0, 15, 0, None)));
        // Trailing `-` with empty prerelease is invalid.
        assert_eq!(parse_semver_relaxed("0.15.0-"), None);
        // Build metadata is rejected per spec.
        assert_eq!(parse_semver_relaxed("0.15.0+abc"), None);
        assert_eq!(parse_semver_relaxed("0.15.0-rc.1+abc"), None);
    }

    #[test]
    fn compare_semver_orderings() {
        use std::cmp::Ordering::*;
        assert_eq!(compare_semver("0.15.0", "0.16.0"), Less);
        assert_eq!(compare_semver("0.16.0", "0.15.0"), Greater);
        assert_eq!(compare_semver("0.15.0", "0.15.0"), Equal);
        assert_eq!(compare_semver("0.15.10", "0.15.2"), Greater);
        // Bad inputs collapse to Equal so we never falsely claim an upgrade.
        assert_eq!(compare_semver("garbage", "0.15.0"), Equal);
    }

    #[test]
    fn compare_semver_prerelease_ordering() {
        use std::cmp::Ordering::*;
        // Stable always greater than its own prerelease.
        assert_eq!(compare_semver("0.15.0-rc.1", "0.15.0"), Less);
        assert_eq!(compare_semver("0.15.0", "0.15.0-rc.1"), Greater);
        // Two prereleases of the same triplet — numeric on the index.
        assert_eq!(compare_semver("0.15.0-rc.1", "0.15.0-rc.2"), Less);
        assert_eq!(compare_semver("0.15.0-alpha.1", "0.15.0-rc.1"), Less);
        // Triplet ordering still wins over prerelease semantics.
        assert_eq!(compare_semver("0.15.0-rc.99", "0.16.0-alpha.1"), Less);
    }

    #[test]
    fn compare_semver_prerelease_numeric_ordering() {
        use std::cmp::Ordering::*;
        // Regression: lexicographic compare put rc.10 < rc.2 because '1' < '2'.
        assert_eq!(compare_semver("0.15.0-rc.10", "0.15.0-rc.2"), Greater);
        assert_eq!(compare_semver("0.15.0-rc.2", "0.15.0-rc.10"), Less);
        assert_eq!(compare_semver("0.15.0-beta.10", "0.15.0-beta.2"), Greater);
        assert_eq!(compare_semver("0.15.0-alpha.10", "0.15.0-alpha.2"), Greater);
        // Channel rank dominates index: any rc beats any beta/alpha at the
        // same triplet.
        assert_eq!(compare_semver("0.15.0-rc.1", "0.15.0-beta.99"), Greater);
        assert_eq!(compare_semver("0.15.0-beta.1", "0.15.0-alpha.99"), Greater);
        // Triplet still wins over prerelease channel rank.
        assert_eq!(compare_semver("0.16.0-alpha.1", "0.15.10-rc.99"), Greater);
        // Equal prereleases compare Equal.
        assert_eq!(compare_semver("0.15.0-rc.5", "0.15.0-rc.5"), Equal);
    }

    #[test]
    fn is_valid_semver_rejects_prereleases() {
        // Cache-write boundary stays strict — prerelease values published
        // by a server are still skipped.
        assert!(!is_valid_semver("0.15.0-rc.1"));
        assert!(!is_valid_semver("0.15.0+sha"));
        assert!(is_valid_semver("0.15.0"));
    }

    #[test]
    fn rfc3339_round_trip() {
        let t = epoch(1_745_578_087); // 2025-04-25T08:48:07Z
        let formatted = format_rfc3339(t);
        let parsed = parse_iso_to_epoch(&formatted).unwrap();
        assert_eq!(parsed, 1_745_578_087);
    }

    #[test]
    fn rfc3339_format_known_dates() {
        assert_eq!(format_rfc3339(epoch(0)), "1970-01-01T00:00:00Z");
        // 2026-04-25T12:38:57Z -> precomputed:
        // From Unix epoch days: 2026-04-25 is day 20568 since 1970-01-01.
        let t = epoch(20568 * 86400 + 12 * 3600 + 38 * 60 + 57);
        assert_eq!(format_rfc3339(t), "2026-04-25T12:38:57Z");
    }

    #[test]
    fn check_cache_returns_none_when_missing() {
        let dir = isolated_dir();
        let getenv = getenv_for(&dir);
        assert!(check_cache(&getenv, SystemTime::now()).is_none());
    }

    #[test]
    fn check_cache_returns_none_when_corrupted() {
        let dir = isolated_dir();
        write_raw_cache(&dir, "{not valid json");
        let getenv = getenv_for(&dir);
        assert!(check_cache(&getenv, SystemTime::now()).is_none());
    }

    #[test]
    fn check_cache_returns_none_when_stale() {
        let dir = isolated_dir();
        let now_epoch = 1_745_578_000_u64;
        let stale_epoch = now_epoch - (25 * 60 * 60); // 25h ago
        let stale_iso = format_rfc3339(epoch(stale_epoch));
        write_raw_cache(
            &dir,
            &format!(
                r#"{{"checked_at":"{stale_iso}","latest":"99.0.0","current":"{cur}"}}"#,
                cur = CURRENT_VERSION
            ),
        );
        let getenv = getenv_for(&dir);
        assert!(check_cache(&getenv, epoch(now_epoch)).is_none());
    }

    #[test]
    fn check_cache_returns_none_when_clock_skew() {
        let dir = isolated_dir();
        let now_epoch = 1_745_578_000_u64;
        let future_iso = format_rfc3339(epoch(now_epoch + 60 * 60));
        write_raw_cache(
            &dir,
            &format!(
                r#"{{"checked_at":"{future_iso}","latest":"99.0.0","current":"{cur}"}}"#,
                cur = CURRENT_VERSION
            ),
        );
        let getenv = getenv_for(&dir);
        assert!(check_cache(&getenv, epoch(now_epoch)).is_none());
    }

    #[test]
    fn check_cache_returns_none_when_current_version_changed() {
        // User upgraded since last cache write — we ignore the entry so a
        // stale "you are out of date" banner doesn't follow them.
        let dir = isolated_dir();
        let now_epoch = 1_745_578_000_u64;
        let iso = format_rfc3339(epoch(now_epoch));
        write_raw_cache(
            &dir,
            &format!(r#"{{"checked_at":"{iso}","latest":"99.0.0","current":"0.0.1-different"}}"#),
        );
        let getenv = getenv_for(&dir);
        assert!(check_cache(&getenv, epoch(now_epoch)).is_none());
    }

    #[test]
    fn check_cache_returns_some_when_upgrade_available() {
        let dir = isolated_dir();
        let now_epoch = 1_745_578_000_u64;
        let iso = format_rfc3339(epoch(now_epoch));
        write_raw_cache(
            &dir,
            &format!(
                r#"{{"checked_at":"{iso}","latest":"99.0.0","current":"{cur}"}}"#,
                cur = CURRENT_VERSION
            ),
        );
        let getenv = getenv_for(&dir);
        let info = check_cache(&getenv, epoch(now_epoch)).expect("banner info");
        assert_eq!(info.latest, "99.0.0");
        assert_eq!(info.current, CURRENT_VERSION);
        assert!(!info.below_min_supported);
    }

    #[test]
    fn check_cache_flags_below_min_supported() {
        let dir = isolated_dir();
        let now_epoch = 1_745_578_000_u64;
        let iso = format_rfc3339(epoch(now_epoch));
        // latest equal to current (no version-up banner) but min_supported
        // is in the future — the stronger banner should fire.
        write_raw_cache(
            &dir,
            &format!(
                r#"{{"checked_at":"{iso}","latest":"{cur}","current":"{cur}","min_supported":"99.0.0"}}"#,
                cur = CURRENT_VERSION
            ),
        );
        let getenv = getenv_for(&dir);
        let info = check_cache(&getenv, epoch(now_epoch)).expect("banner info");
        assert!(info.below_min_supported);
    }

    #[test]
    fn ingest_advisory_headers_writes_cache() {
        let dir = isolated_dir();
        let getenv = getenv_for(&dir);
        ingest_advisory_headers(
            Some("0.16.0"),
            Some("2026-04-25T09:00:00Z"),
            Some("0.15.0"),
            &getenv,
            SystemTime::now(),
        );
        let cache = read_cache(&getenv);
        assert_eq!(cache.latest.as_deref(), Some("0.16.0"));
        assert_eq!(cache.checked_at.as_deref(), Some("2026-04-25T09:00:00Z"));
        assert_eq!(cache.min_supported.as_deref(), Some("0.15.0"));
        assert_eq!(cache.current.as_deref(), Some(CURRENT_VERSION));
    }

    #[test]
    fn ingest_advisory_headers_min_only_keeps_latest() {
        // First call: populate latest.
        let dir = isolated_dir();
        let getenv = getenv_for(&dir);
        ingest_advisory_headers(
            Some("0.16.0"),
            Some("2026-04-25T09:00:00Z"),
            None,
            &getenv,
            SystemTime::now(),
        );
        // Second call: only min_supported present (e.g., a response from a
        // server whose poll cache is cold). Latest must persist.
        ingest_advisory_headers(None, None, Some("0.15.0"), &getenv, SystemTime::now());
        let cache = read_cache(&getenv);
        assert_eq!(cache.latest.as_deref(), Some("0.16.0"));
        assert_eq!(cache.min_supported.as_deref(), Some("0.15.0"));
    }

    #[test]
    fn ingest_advisory_headers_rejects_invalid_semver() {
        let dir = isolated_dir();
        let getenv = getenv_for(&dir);
        ingest_advisory_headers(
            Some("not-a-semver"),
            Some("2026-04-25T09:00:00Z"),
            Some("0.16.0-rc.1"),
            &getenv,
            SystemTime::now(),
        );
        let cache = read_cache(&getenv);
        assert!(cache.latest.is_none());
        assert!(cache.min_supported.is_none());
        // checked_at is still updated — that's fine, we just don't believe
        // the version values.
        assert_eq!(cache.checked_at.as_deref(), Some("2026-04-25T09:00:00Z"));
    }

    #[test]
    fn ingest_advisory_headers_no_op_when_all_absent() {
        let dir = isolated_dir();
        let getenv = getenv_for(&dir);
        ingest_advisory_headers(None, None, None, &getenv, SystemTime::now());
        // No file should have been written.
        assert!(!cache_path(&getenv).unwrap().exists());
    }

    #[test]
    fn ingest_advisory_headers_synthesizes_checked_at_when_missing() {
        // E.g., a synthetic feed from a body that doesn't carry checked_at
        // but does carry latest. We stamp local time so check_cache treats
        // the entry as fresh.
        let dir = isolated_dir();
        let getenv = getenv_for(&dir);
        let now = epoch(1_745_578_000);
        ingest_advisory_headers(Some("0.16.0"), None, None, &getenv, now);
        let cache = read_cache(&getenv);
        assert_eq!(cache.latest.as_deref(), Some("0.16.0"));
        assert_eq!(
            cache.checked_at.as_deref(),
            Some(format_rfc3339(now)).as_deref()
        );
    }

    #[test]
    fn ingest_info_response_round_trip() {
        let dir = isolated_dir();
        let getenv = getenv_for(&dir);
        let info = secrt_core::api::InfoResponse {
            authenticated: false,
            user_id: None,
            ttl: secrt_core::api::InfoTTL {
                default_seconds: 0,
                max_seconds: 0,
            },
            limits: secrt_core::api::InfoLimits {
                public: secrt_core::api::InfoTier {
                    max_envelope_bytes: 0,
                    max_secrets: 0,
                    max_total_bytes: 0,
                    rate: secrt_core::api::InfoRate {
                        requests_per_second: 0.0,
                        burst: 0,
                    },
                },
                authed: secrt_core::api::InfoTier {
                    max_envelope_bytes: 0,
                    max_secrets: 0,
                    max_total_bytes: 0,
                    rate: secrt_core::api::InfoRate {
                        requests_per_second: 0.0,
                        burst: 0,
                    },
                },
            },
            claim_rate: secrt_core::api::InfoRate {
                requests_per_second: 0.0,
                burst: 0,
            },
            latest_cli_version: Some("0.16.0".into()),
            latest_cli_version_checked_at: Some("2026-04-25T09:00:00Z".into()),
            min_supported_cli_version: Some("0.15.0".into()),
            server_version: Some("0.16.2".into()),
        };
        ingest_info_response(&info, &getenv, SystemTime::now());
        let cache = read_cache(&getenv);
        assert_eq!(cache.latest.as_deref(), Some("0.16.0"));
        assert_eq!(cache.min_supported.as_deref(), Some("0.15.0"));
    }

    #[test]
    fn cache_write_in_unwritable_dir_does_not_panic() {
        // The primary contract: a write that fails for any filesystem reason
        // must not propagate as a panic.
        //
        // On Unix, `/dev/null/not-a-dir` is a stable "guaranteed unwritable"
        // recipe (you can't make a child of a character device), so we can
        // additionally verify the cache stays empty.
        //
        // On Windows there is no equally clean recipe — `/foo` resolves to
        // `C:\foo` which is happily writable on the GH Actions runner. NUL
        // device tricks like `\\?\NUL\sub` are inconsistent across Windows
        // versions and runner configurations. So we only verify the
        // no-panic contract on Windows; the cache write may succeed and
        // that's a legitimate platform difference, not a bug.
        let getenv = |k: &str| {
            if k == "XDG_CACHE_HOME" {
                #[cfg(unix)]
                {
                    Some("/dev/null/not-a-dir".to_string())
                }
                #[cfg(not(unix))]
                {
                    Some("/secrt-impossible-test-path".to_string())
                }
            } else {
                None
            }
        };
        ingest_advisory_headers(
            Some("0.16.0"),
            Some("2026-04-25T09:00:00Z"),
            Some("0.15.0"),
            &getenv,
            SystemTime::now(),
        );
        // Unix-only: an unwritable cache means read returns the default (cold).
        #[cfg(unix)]
        assert!(read_cache(&getenv).latest.is_none());
    }

    #[test]
    fn banner_line_two_lines_dim_header_bold_cyan_command() {
        let info = BannerInfo {
            current: "0.15.0".into(),
            latest: "0.16.0".into(),
            below_min_supported: false,
        };
        let line = format_banner_line(&info, /* ansi */ true);
        // Header: DIM (\x1b[2m) wrapping the "X.Y.Z available" text.
        assert!(line.starts_with("\x1b[2msecrt 0.16.0 available (current: 0.15.0)\x1b[0m"));
        // Command on its own line, indented, bold cyan.
        assert!(line.contains("\n  \x1b[1;36msecrt update\x1b[0m"));
    }

    #[test]
    fn banner_line_plain_when_ansi_off() {
        let info = BannerInfo {
            current: "0.15.0".into(),
            latest: "0.16.0".into(),
            below_min_supported: false,
        };
        let line = format_banner_line(&info, /* ansi */ false);
        assert_eq!(
            line,
            "secrt 0.16.0 available (current: 0.15.0)\n  secrt update"
        );
        assert!(!line.contains("\x1b["));
    }

    #[test]
    fn banner_line_below_min_supported_uses_warn() {
        let info = BannerInfo {
            current: "0.14.0".into(),
            latest: "0.14.0".into(),
            below_min_supported: true,
        };
        let line = format_banner_line(&info, /* ansi */ true);
        // Stronger warning swaps DIM for WARN (yellow, 33) on the header.
        assert!(line.starts_with(
            "\x1b[33mwarning: secrt 0.14.0 may not be compatible with this server\x1b[0m"
        ));
        assert!(line.contains("\n  \x1b[1;36msecrt update\x1b[0m"));
    }

    #[test]
    fn emit_banner_suppresses_when_not_tty() {
        let info = BannerInfo {
            current: "0.15.0".into(),
            latest: "0.16.0".into(),
            below_min_supported: false,
        };
        let mut buf = Vec::new();
        let emitted = emit_banner(&mut buf, &info, /* stderr_is_tty */ false);
        assert!(!emitted, "banner must be suppressed on non-TTY stderr");
        assert!(buf.is_empty(), "stderr must be untouched: {:?}", buf);
    }

    /// Serialize banner-emit tests so the once-per-process gate doesn't
    /// produce flaky cross-test interaction. The gate is intentionally
    /// process-global; tests that exercise it must run sequentially within
    /// this module.
    static EMIT_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn emit_banner_fires_once_per_process() {
        let _g = EMIT_LOCK.lock().unwrap();
        let info = BannerInfo {
            current: "0.15.0".into(),
            latest: "0.16.0".into(),
            below_min_supported: false,
        };
        let mut buf = Vec::new();
        // Pass `stderr_is_tty = true` so emit actually fires.
        let first = emit_banner(&mut buf, &info, true);
        let second = emit_banner(&mut buf, &info, true);
        // First call may or may not be the first across the entire test
        // process (other tests share the gate). What we *can* assert is
        // that the second call returned `false` after a successful first
        // *and* did not double-write — at most one banner header is in
        // the buffer.
        if first {
            assert!(!second, "second emit should be suppressed");
            let s = String::from_utf8(buf).unwrap();
            assert_eq!(s.matches("0.16.0 available").count(), 1);
        }
    }
}
