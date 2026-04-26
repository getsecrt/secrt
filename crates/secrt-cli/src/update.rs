//! `secrt update` subcommand: in-place self-upgrade against GitHub Releases.
//!
//! See `spec/v1/cli.md § secrt update Subcommand`. The hot path:
//!
//! 1. Detect managed installs (Homebrew, asdf, mise, Nix, cargo, generic
//!    symlink) and refuse with a manager-specific upgrade command.
//! 2. Resolve the latest available version (via `--version`, the GitHub
//!    Releases API, or `--release-base-url` for tests).
//! 3. Fetch the published checksum file, then the raw per-platform binary.
//!    SHA-256 verify; loud halt on mismatch (exit 2).
//! 4. Acquire an exclusive install lock (flock(2) on Unix, LockFileEx on
//!    Windows); contention exits with code 5.
//! 5. Atomic install: write `<install_dir>/secrt.new` mode 0755, fsync,
//!    `rename(2)` over the running binary. Windows: rename-self-aside
//!    (`secrt.exe` → `secrt.exe.old`) and place new at `secrt.exe`.
//!
//! Self-update fetches **raw binaries**, not archives — the CLI dep graph
//! must not include `flate2`/`tar`/`zip`. The release pipeline publishes
//! both raw binaries (for self-update) and tarballs/zips (for human
//! install via `install.sh` or brew).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use ring::digest;

use crate::cli::Deps;
use crate::client::USER_AGENT;
use crate::update_check;

/// Default hostname for GitHub raw asset downloads. Each release's assets
/// are at `<base>/getsecrt/secrt/releases/download/cli/v<version>/<asset>`.
const DEFAULT_RELEASE_DOWNLOAD_BASE: &str = "https://github.com/getsecrt/secrt/releases/download";
const DEFAULT_GITHUB_API_BASE: &str = "https://api.github.com";

/// Filename of the published checksum file (one entry per asset).
const CHECKSUM_FILENAME: &str = "secrt-checksums-sha256.txt";

/// On-disk lockfile name (sits next to the install target). Tests poke
/// this directly; end-users never see it.
const LOCK_FILENAME: &str = ".secrt-update.lock";

/// Re-exports of the file-name constants for integration tests. Not part
/// of any wire contract; kept stable enough for tests to assert on.
pub const CHECKSUM_FILENAME_PUB: &str = CHECKSUM_FILENAME;
pub const INSTALL_LOCK_FILENAME_PUB: &str = LOCK_FILENAME;

/// Suffix used when staging the new binary in the same directory as the
/// running one (Unix) or the rename-self-aside target (Windows `.old`).
#[cfg(unix)]
const STAGED_SUFFIX: &str = ".new";

#[cfg(windows)]
const WINDOWS_OLD_SUFFIX: &str = ".old";

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

/// Update channel selection per `spec/v1/cli.md § Update Channels`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Channel {
    #[default]
    Stable,
    Prerelease,
}

/// Parsed `secrt update` flags.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct UpdateArgs {
    pub check: bool,
    pub force: bool,
    pub version: Option<String>,
    pub install_dir: Option<PathBuf>,
    /// Selected channel; defaults to `Stable` when `--channel` is omitted.
    pub channel: Channel,
    /// Hidden `--release-base-url <url>` test seam. Mirrors
    /// `ReqwestFetcher::with_base_url` from the server poller. Replaces the
    /// GitHub Releases download host so tests can serve canned binaries
    /// from a local HTTP server without touching the real release stream.
    pub release_base_url: Option<String>,
    /// Hidden Windows `--cleanup` flag. Deletes `<install_dir>/secrt.exe.old`
    /// silently if present, then exits 0. Wired from `cli.rs` startup
    /// (cheap; no-op on platforms where the file isn't there).
    pub cleanup: bool,
    /// Show help.
    pub help: bool,
}

/// Parse `secrt update` arguments. Hand-rolled per project convention
/// (`secrt-cli/CLAUDE.md` — no clap).
pub fn parse_update_args(args: &[String]) -> Result<UpdateArgs, String> {
    let mut out = UpdateArgs::default();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if arg.starts_with("--") => (f, Some(v.to_string())),
            _ => (arg.as_str(), None),
        };
        let mut take_val = |name: &str| -> Result<String, String> {
            if let Some(v) = inline.clone() {
                Ok(v)
            } else {
                i += 1;
                if i >= args.len() {
                    Err(format!("{} requires a value", name))
                } else {
                    Ok(args[i].clone())
                }
            }
        };
        match flag {
            "-h" | "--help" => out.help = true,
            "--check" => out.check = true,
            "--force" => out.force = true,
            "--version" => {
                // Defer validation until after the full arg list is parsed:
                // `--version` validity depends on the selected channel
                // (`stable` requires a strict triplet; `prerelease` accepts
                // a `-(rc|beta|alpha).N` suffix).
                out.version = Some(take_val("--version")?);
            }
            "--install-dir" => out.install_dir = Some(PathBuf::from(take_val("--install-dir")?)),
            "--channel" => {
                let v = take_val("--channel")?;
                out.channel = match v.as_str() {
                    "stable" => Channel::Stable,
                    "prerelease" => Channel::Prerelease,
                    _ => {
                        return Err(format!(
                            "--channel must be 'stable' or 'prerelease', got {:?}",
                            v
                        ))
                    }
                };
            }
            "--release-base-url" => out.release_base_url = Some(take_val("--release-base-url")?),
            "--cleanup" => out.cleanup = true,
            _ => return Err(format!("unknown flag: {}", arg)),
        }
        i += 1;
    }
    if let Some(v) = out.version.as_deref() {
        if !is_valid_version_for_channel(v, out.channel) {
            return match out.channel {
                Channel::Stable => Err(format!(
                    "--version must be a strict semver \\d+.\\d+.\\d+, got {:?}. \
                     Use --channel prerelease to install a prerelease build.",
                    v
                )),
                Channel::Prerelease => Err(format!(
                    "--version must match \\d+.\\d+.\\d+(-(rc|beta|alpha).\\d+)?, got {:?}",
                    v
                )),
            };
        }
    }
    Ok(out)
}

/// Validate `--version` against the selected channel per
/// `spec/v1/update.vectors.json#channel_resolution`.
///
/// - `stable`: requires strict `\d+.\d+.\d+`.
/// - `prerelease`: accepts strict triplets and `\d+.\d+.\d+-(rc|beta|alpha).\d+`.
pub fn is_valid_version_for_channel(s: &str, channel: Channel) -> bool {
    if is_strict_triplet(s) {
        return true;
    }
    matches!(channel, Channel::Prerelease) && is_pre_release_form(s)
}

/// Validate the `\d+.\d+.\d+-(rc|beta|alpha).\d+` shape used by prerelease
/// `--version` pins. Callers gate this on `Channel::Prerelease`.
fn is_pre_release_form(s: &str) -> bool {
    let Some((triplet, suffix)) = s.split_once('-') else {
        return false;
    };
    if !is_strict_triplet(triplet) {
        return false;
    }
    let Some((kind, num)) = suffix.split_once('.') else {
        return false;
    };
    matches!(kind, "alpha" | "beta" | "rc")
        && !num.is_empty()
        && num.chars().all(|c| c.is_ascii_digit())
}

/// Strict `\d+.\d+.\d+` validator — no prerelease, no build metadata. Used
/// for `--version` per the spec, and for parsing the highest stable release
/// from the GitHub API.
pub fn is_strict_triplet(s: &str) -> bool {
    let mut parts = s.split('.');
    let a = parts.next();
    let b = parts.next();
    let c = parts.next();
    if parts.next().is_some() {
        return false;
    }
    matches!(
        (a, b, c),
        (Some(a), Some(b), Some(c)) if !a.is_empty() && !b.is_empty() && !c.is_empty()
            && a.chars().all(|ch| ch.is_ascii_digit())
            && b.chars().all(|ch| ch.is_ascii_digit())
            && c.chars().all(|ch| ch.is_ascii_digit())
    )
}

// ---------------------------------------------------------------------------
// OS + arch → asset filename
// ---------------------------------------------------------------------------

/// Map (os, arch) tuples to the raw-binary asset filename per
/// `spec/v1/cli.md § secrt update Subcommand`. Returns `None` for tuples
/// not in the table; callers translate that into a hard error.
pub fn raw_asset_name(os: &str, arch: &str) -> Option<&'static str> {
    Some(match (os, arch) {
        ("linux", "x86_64") => "secrt-linux-amd64",
        ("linux", "aarch64") => "secrt-linux-arm64",
        ("macos", "x86_64") => "secrt-darwin-amd64",
        ("macos", "aarch64") => "secrt-darwin-arm64",
        ("windows", "x86_64") => "secrt-windows-amd64.exe",
        ("windows", "aarch64") => "secrt-windows-arm64.exe",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Managed-install detection (refuse + redirect to package manager)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallKind {
    /// Plain install — the running binary is its own canonical path and
    /// not under a known package manager root. Self-update may proceed.
    Plain,
    Homebrew,
    Asdf,
    Mise,
    Nix,
    Cargo,
    /// A symlink we don't recognize. The canonical path differs from
    /// `current_exe()` but doesn't match any known manager pattern.
    GenericSymlink,
}

impl InstallKind {
    /// Refusal message printed to stderr when self-update is declined.
    /// Empty for [`InstallKind::Plain`] — the caller checks for that
    /// variant instead.
    pub fn refusal_message(&self, canonical: &Path) -> String {
        match self {
            InstallKind::Plain => String::new(),
            InstallKind::Homebrew => {
                "secrt is managed by Homebrew. Run: brew upgrade secrt".to_string()
            }
            InstallKind::Asdf => {
                "secrt is managed by asdf. Run: asdf install secrt latest && asdf global secrt latest".to_string()
            }
            InstallKind::Mise => {
                "secrt is managed by mise. Run: mise upgrade secrt".to_string()
            }
            InstallKind::Nix => {
                "secrt is managed by Nix. Run: nix profile upgrade secrt (or update your flake)".to_string()
            }
            InstallKind::Cargo => {
                "secrt was installed via cargo into ~/.cargo/bin. Update with the same cargo invocation you originally used (e.g., 'cargo install --force secrt-cli', or 'cargo install --git https://github.com/getsecrt/secrt --force secrt-cli').".to_string()
            }
            InstallKind::GenericSymlink => format!(
                "secrt appears to be installed via a symlink at {}. Update it through whichever tool installed it.",
                canonical.display()
            ),
        }
    }
}

/// Pure classifier for managed-install detection. Takes the un-canonicalized
/// `current_exe` and the canonicalized form, plus the home dir for cargo
/// detection. Decoupled from `std::env` so tests drive it with synthetic
/// paths.
///
/// Pattern match order matches `spec/v1/cli.md § secrt update Subcommand`:
/// the first match wins.
pub fn classify_install(current: &Path, canonical: &Path, home: Option<&Path>) -> InstallKind {
    let canon_str = canonical.to_string_lossy();
    let canon_norm = canon_str.replace('\\', "/");

    if canon_norm.contains("/Cellar/") {
        return InstallKind::Homebrew;
    }
    if canon_norm.contains("/.asdf/installs/") {
        return InstallKind::Asdf;
    }
    if canon_norm.contains("/.local/share/mise/installs/") {
        return InstallKind::Mise;
    }
    if canon_norm.starts_with("/nix/store/") || canon_norm.contains("/nix/store/") {
        return InstallKind::Nix;
    }
    if let Some(home) = home {
        let cargo_bin = home.join(".cargo").join("bin");
        if canonical.parent() == Some(cargo_bin.as_path()) {
            return InstallKind::Cargo;
        }
    }
    if canonical != current {
        return InstallKind::GenericSymlink;
    }
    InstallKind::Plain
}

// ---------------------------------------------------------------------------
// Checksum file parsing
// ---------------------------------------------------------------------------

/// Parse a `sha256sum`-style checksum file. Each non-blank line is
/// `<hex>  <filename>` (two spaces) or `<hex> *<filename>` (binary mode).
/// Returns `(filename, hex)` pairs. Malformed lines are silently skipped —
/// the lookup function reports a clear error if the wanted asset isn't in
/// the result set.
pub fn parse_checksum_file(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let hex = match parts.next() {
            Some(h) => h.trim(),
            None => continue,
        };
        let rest = match parts.next() {
            Some(r) => r.trim_start().trim_start_matches('*'),
            None => continue,
        };
        if hex.is_empty() || rest.is_empty() {
            continue;
        }
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) || hex.len() != 64 {
            continue;
        }
        out.push((rest.to_string(), hex.to_lowercase()));
    }
    out
}

/// Look up the SHA-256 (lowercase hex) for `asset` in a parsed checksum
/// table.
pub fn checksum_for_asset<'a>(table: &'a [(String, String)], asset: &str) -> Option<&'a str> {
    table
        .iter()
        .find_map(|(name, hex)| (name == asset).then_some(hex.as_str()))
}

/// Compute SHA-256 of `bytes` as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let d = digest::digest(&digest::SHA256, bytes);
    let mut s = String::with_capacity(64);
    for b in d.as_ref() {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

// ---------------------------------------------------------------------------
// HTTP indirection (so tests can substitute a mock without ureq).
// ---------------------------------------------------------------------------

/// HTTP surface used by `run_update`. Two operations: fetch a small text
/// payload (checksums, GitHub API JSON) and fetch a binary blob (the new
/// `secrt` itself). Both MUST set `User-Agent: secrt/<version>`. Errors
/// are returned as `String` — `run_update` formats them with operation
/// context before printing.
pub trait UpdateHttp {
    fn fetch_text(&self, url: &str) -> Result<String, String>;
    fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, String>;
}

/// `ureq`-backed implementation. Used by `main.rs` for production runs
/// and by integration tests that drive the full download path against a
/// local HTTP server.
pub struct UreqUpdateHttp;

impl UreqUpdateHttp {
    fn agent() -> ureq::Agent {
        ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_global(Some(std::time::Duration::from_secs(30)))
                .http_status_as_error(false)
                .user_agent(USER_AGENT)
                .build(),
        )
    }

    fn check_status<B>(resp: &ureq::http::Response<B>, url: &str) -> Result<(), String> {
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            return Ok(());
        }
        if status == 403 {
            // GitHub rate-limit. Tell the user concretely what knob to turn.
            if resp
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|v| v.to_str().ok())
                == Some("0")
            {
                return Err(format!(
                    "GitHub API rate limit reached (this is shared with your network). Set GITHUB_TOKEN=<personal access token> and try again. URL: {}",
                    url
                ));
            }
        }
        Err(format!("HTTP {} fetching {}", status, url))
    }
}

impl UpdateHttp for UreqUpdateHttp {
    fn fetch_text(&self, url: &str) -> Result<String, String> {
        let resp = Self::agent()
            .get(url)
            .call()
            .map_err(|e| format!("HTTP error fetching {}: {}", url, e))?;
        Self::check_status(&resp, url)?;
        resp.into_body()
            .read_to_string()
            .map_err(|e| format!("read body from {}: {}", url, e))
    }

    fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, String> {
        let resp = Self::agent()
            .get(url)
            .call()
            .map_err(|e| format!("HTTP error fetching {}: {}", url, e))?;
        Self::check_status(&resp, url)?;
        resp.into_body()
            .read_to_vec()
            .map_err(|e| format!("read body from {}: {}", url, e))
    }
}

// ---------------------------------------------------------------------------
// Atomic install (Unix) and rename-self-aside (Windows)
// ---------------------------------------------------------------------------

/// Stage `bytes` as the new binary in `target`'s parent directory and
/// atomically replace `target`. On Unix the staged file gets mode 0755 and
/// is fsynced before rename. On Windows the running `secrt.exe` is renamed
/// to `secrt.exe.old` first; cleanup of `.old` happens via the hidden
/// `--cleanup` startup hook on the next launch.
pub fn atomic_install(target: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| format!("install target has no parent: {}", target.display()))?;

    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;

        let staged = staged_path(target);
        // 0o755 = rwxr-xr-x; standard for executables.
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o755)
            .open(&staged)
            .map_err(|e| io_err("create staged binary", &staged, e))?;
        f.write_all(bytes)
            .map_err(|e| io_err("write staged binary", &staged, e))?;
        f.sync_all()
            .map_err(|e| io_err("fsync staged binary", &staged, e))?;
        drop(f);

        // rename(2) is atomic within the same filesystem; the running
        // process's old inode is kept alive by the kernel until exit.
        fs::rename(&staged, target)
            .map_err(|e| io_err("atomic rename over running binary", target, e))?;

        // Fsync the directory so the rename is durable across crash.
        // Best-effort: on platforms or filesystems that refuse to open the
        // directory for fsync (Linux requires it; macOS allows it; some
        // environments deny it), we ignore the error.
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        let _ = parent;
        let staged = staged_path(target);
        // Write the new binary to a staging path next to the install
        // target. Same dir = same drive = atomic-ish rename below.
        fs::write(&staged, bytes).map_err(|e| io_err("write staged binary", &staged, e))?;
        if let Ok(f) = fs::OpenOptions::new().write(true).open(&staged) {
            let _ = f.sync_all();
        }

        let old = old_path(target);
        // Best-effort: clean up any leftover `.old` from a previous
        // upgrade so the rename below doesn't trip over it.
        let _ = fs::remove_file(&old);

        // Try the rustup pattern first: rename the running .exe aside.
        match fs::rename(target, &old) {
            Ok(()) => {
                // Move the staged binary into place. If this step fails,
                // restore the original to keep the install usable.
                if let Err(e) = fs::rename(&staged, target) {
                    let _ = fs::rename(&old, target);
                    return Err(io_err("install staged binary", target, e));
                }
                Ok(())
            }
            Err(_) => {
                // Antivirus or another process holds `secrt.exe`; fall
                // back to delay-until-reboot. The install lands on next
                // reboot. Inform the caller via an Err so the UX surfaces
                // it.
                schedule_replace_on_reboot(&staged, target)
                    .map(|()| ())
                    .map_err(|e| {
                        format!(
                            "could not replace {} now and could not schedule reboot replacement: {}",
                            target.display(),
                            e
                        )
                    })
            }
        }
    }
}

#[cfg(unix)]
fn staged_path(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_owned();
    s.push(STAGED_SUFFIX);
    PathBuf::from(s)
}

#[cfg(windows)]
fn staged_path(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_owned();
    s.push(".new");
    PathBuf::from(s)
}

#[cfg(windows)]
fn old_path(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_owned();
    s.push(WINDOWS_OLD_SUFFIX);
    PathBuf::from(s)
}

fn io_err(action: &str, p: &Path, e: std::io::Error) -> String {
    format!("{} ({}): {}", action, p.display(), e)
}

#[cfg(windows)]
mod win {
    //! Minimal Win32 FFI for the rename-self-aside fallback path. We avoid
    //! pulling in the `windows` crate for these few entry points.
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    pub const MOVEFILE_DELAY_UNTIL_REBOOT: u32 = 0x4;
    pub const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;

    extern "system" {
        fn MoveFileExW(
            lpExistingFileName: *const u16,
            lpNewFileName: *const u16,
            dwFlags: u32,
        ) -> i32;
    }

    fn to_utf16_null(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// `MoveFileExW` wrapper. Errors return `Err(last error code as String)`.
    pub fn move_file_ex(src: &Path, dst: Option<&Path>, flags: u32) -> Result<(), String> {
        let src_w = to_utf16_null(src);
        let dst_w = dst.map(to_utf16_null);
        let dst_ptr = dst_w
            .as_ref()
            .map(|v| v.as_ptr())
            .unwrap_or(std::ptr::null());
        let ok = unsafe { MoveFileExW(src_w.as_ptr(), dst_ptr, flags) };
        if ok != 0 {
            Ok(())
        } else {
            Err(format!(
                "MoveFileExW failed (GetLastError code = {})",
                unsafe { GetLastError() }
            ))
        }
    }

    extern "system" {
        fn GetLastError() -> u32;
    }
}

#[cfg(windows)]
fn schedule_replace_on_reboot(staged: &Path, target: &Path) -> Result<(), String> {
    // Delay-until-reboot: the kernel renames `staged` over `target` at
    // next boot. Gives us a path forward when AV holds the running exe.
    win::move_file_ex(
        staged,
        Some(target),
        win::MOVEFILE_DELAY_UNTIL_REBOOT | win::MOVEFILE_REPLACE_EXISTING,
    )
}

// ---------------------------------------------------------------------------
// Install lock (flock(2) / LockFileEx) — exit code 5 on contention
// ---------------------------------------------------------------------------

/// RAII handle for the install lock. Drop releases the lock automatically
/// (via close-on-drop semantics).
pub struct InstallLock {
    /// Held to keep the kernel-level lock alive; released on drop when the
    /// underlying fd/handle closes. Unused by name.
    #[allow(dead_code)]
    file: fs::File,
    #[allow(dead_code)]
    path: PathBuf,
}

impl InstallLock {
    /// Try to acquire an exclusive non-blocking lock on the install
    /// directory's lockfile. Returns `Ok(None)` on contention so callers
    /// can map it to exit code 5.
    pub fn try_acquire(install_dir: &Path) -> Result<Option<Self>, String> {
        fs::create_dir_all(install_dir)
            .map_err(|e| io_err("create install dir for lock", install_dir, e))?;
        let path = install_dir.join(LOCK_FILENAME);
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| io_err("open lockfile", &path, e))?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // LOCK_EX | LOCK_NB
            let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if r == 0 {
                return Ok(Some(InstallLock { file, path }));
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Ok(None);
            }
            Err(format!("flock {}: {}", path.display(), err))
        }

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x2;
            const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x1;
            #[repr(C)]
            struct Overlapped {
                internal: usize,
                internal_high: usize,
                offset: u32,
                offset_high: u32,
                h_event: *mut std::ffi::c_void,
            }
            extern "system" {
                fn LockFileEx(
                    h_file: *mut std::ffi::c_void,
                    dw_flags: u32,
                    dw_reserved: u32,
                    n_number_of_bytes_to_lock_low: u32,
                    n_number_of_bytes_to_lock_high: u32,
                    lp_overlapped: *mut Overlapped,
                ) -> i32;
                fn GetLastError() -> u32;
            }
            const ERROR_LOCK_VIOLATION: u32 = 33;
            let mut overlapped = Overlapped {
                internal: 0,
                internal_high: 0,
                offset: 0,
                offset_high: 0,
                h_event: std::ptr::null_mut(),
            };
            let r = unsafe {
                LockFileEx(
                    file.as_raw_handle() as *mut _,
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    !0u32,
                    !0u32,
                    &mut overlapped,
                )
            };
            if r != 0 {
                return Ok(Some(InstallLock { file, path }));
            }
            let code = unsafe { GetLastError() };
            if code == ERROR_LOCK_VIOLATION {
                return Ok(None);
            }
            Err(format!(
                "LockFileEx {}: GetLastError={}",
                path.display(),
                code
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level orchestration
// ---------------------------------------------------------------------------

/// Exit codes per `spec/v1/cli.md § secrt update Subcommand § Exit codes`.
pub mod exit {
    pub const OK: i32 = 0;
    pub const GENERIC: i32 = 1;
    pub const CHECKSUM_MISMATCH: i32 = 2;
    pub const MANAGED_INSTALL: i32 = 3;
    pub const PERMISSION_DENIED: i32 = 4;
    pub const LOCK_CONTENTION: i32 = 5;
    /// Bad argument / usage error. Matches other subcommands' exit code 2,
    /// but keep distinct from CHECKSUM_MISMATCH(2): we never emit USAGE
    /// when CHECKSUM_MISMATCH would also apply, so the reuse is safe.
    pub const USAGE: i32 = 2;
}

/// Entry point invoked from `cli.rs` dispatch. Constructs the production
/// HTTP backend; tests use [`run_update_with`] with a mock.
pub fn run_update(args: &[String], deps: &mut Deps) -> i32 {
    run_update_with(args, deps, &UreqUpdateHttp)
}

/// Run-update with an injectable HTTP backend. Used by integration tests.
pub fn run_update_with(args: &[String], deps: &mut Deps, http: &dyn UpdateHttp) -> i32 {
    let parsed = match parse_update_args(args) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(deps.stderr, "error: {}", e);
            return exit::USAGE;
        }
    };

    if parsed.help {
        print_update_help(deps);
        return exit::OK;
    }

    if parsed.cleanup {
        return run_cleanup(deps);
    }

    // 1. Resolve current binary + classify install kind.
    let current = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(
                deps.stderr,
                "error: cannot resolve current executable: {}",
                e
            );
            return exit::GENERIC;
        }
    };
    let canonical = fs::canonicalize(&current).unwrap_or_else(|_| current.clone());
    let home = dirs::home_dir();
    let kind = classify_install(&current, &canonical, home.as_deref());
    if kind != InstallKind::Plain {
        let _ = writeln!(deps.stderr, "{}", kind.refusal_message(&canonical));
        return exit::MANAGED_INSTALL;
    }

    // 2. Determine the install target.
    // - No `--install-dir`: replace the running binary in place (same name).
    // - With `--install-dir`: place the binary at `<dir>/secrt[.exe]` —
    //   the canonical product name, regardless of the running binary's
    //   filename. Without this rule, integration tests (which run inside
    //   `cargo test`'s test binary) would install as the test binary's
    //   own name.
    let (install_dir, install_target) = match parsed.install_dir.clone() {
        Some(dir) => {
            let target = dir.join(default_exe_name());
            (dir, target)
        }
        None => {
            let dir = canonical
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("."));
            (dir, canonical.clone())
        }
    };

    // 3. Determine target version. `--version` pins; otherwise resolve via
    // the GitHub Releases API. `Channel::Stable` accepts only strict
    // triplets; `Channel::Prerelease` accepts both stable and prerelease
    // tags, picking the highest by `update_check::compare_semver`. The
    // implicit update-check banner is unaffected — it stays stable-only
    // by design.
    let target_version = match parsed.version.clone() {
        Some(v) => v,
        None => match resolve_latest_for_channel(http, parsed.channel) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(deps.stderr, "error: {}", e);
                return exit::GENERIC;
            }
        },
    };

    let current_version = update_check::CURRENT_VERSION;
    let cmp = update_check::compare_semver(current_version, &target_version);

    if parsed.check {
        if cmp == std::cmp::Ordering::Less {
            // Same shape as the implicit banner so users see the same
            // copy-pasteable command they would see passively.
            let info = update_check::BannerInfo {
                current: current_version.to_string(),
                latest: target_version.clone(),
                below_min_supported: false,
            };
            let _ = writeln!(
                deps.stdout,
                "{}",
                update_check::format_banner_line(&info, (deps.is_stdout_tty)())
            );
        } else {
            let c = crate::color::color_func((deps.is_stdout_tty)());
            let _ = writeln!(
                deps.stdout,
                "{}",
                c(
                    crate::color::DIM,
                    &format!("secrt {} is up to date.", current_version)
                )
            );
        }
        return exit::OK;
    }

    if cmp != std::cmp::Ordering::Less && !parsed.force {
        let c = crate::color::color_func((deps.is_stdout_tty)());
        let _ = writeln!(
            deps.stdout,
            "{}",
            c(
                crate::color::DIM,
                &format!(
                    "secrt {} is up to date. Use --force to reinstall.",
                    current_version
                )
            )
        );
        return exit::OK;
    }

    // 4. Asset name for current OS+arch.
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let asset = match raw_asset_name(os, arch) {
        Some(a) => a,
        None => {
            let _ = writeln!(
                deps.stderr,
                "error: no published self-update asset for ({}, {}). Download manually from {}/cli/v{}",
                os, arch, DEFAULT_RELEASE_DOWNLOAD_BASE, target_version
            );
            return exit::GENERIC;
        }
    };

    // 5. Fetch + verify checksum file, then the binary itself.
    let base = parsed
        .release_base_url
        .clone()
        .unwrap_or_else(|| DEFAULT_RELEASE_DOWNLOAD_BASE.to_string());
    let release_url = format!("{}/cli/v{}", base.trim_end_matches('/'), target_version);
    let checksum_url = format!("{}/{}", release_url, CHECKSUM_FILENAME);
    let asset_url = format!("{}/{}", release_url, asset);

    let checksum_text = match http.fetch_text(&checksum_url) {
        Ok(t) => t,
        Err(e) => {
            let _ = writeln!(
                deps.stderr,
                "error: fetching checksum file: {}\nhint: download manually from {}",
                e, release_url
            );
            return exit::GENERIC;
        }
    };
    let table = parse_checksum_file(&checksum_text);
    let expected = match checksum_for_asset(&table, asset) {
        Some(h) => h.to_string(),
        None => {
            let _ = writeln!(
                deps.stderr,
                "error: no entry for {} in checksum file {}",
                asset, checksum_url
            );
            return exit::CHECKSUM_MISMATCH;
        }
    };

    let bytes = match http.fetch_bytes(&asset_url) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                deps.stderr,
                "error: downloading {}: {}\nhint: download manually from {}",
                asset, e, release_url
            );
            return exit::GENERIC;
        }
    };

    let actual = sha256_hex(&bytes);
    if actual != expected {
        let _ = writeln!(
            deps.stderr,
            "error: SHA-256 mismatch for {}\n  expected: {}\n  actual:   {}\n  source:   {}",
            asset, expected, actual, checksum_url
        );
        return exit::CHECKSUM_MISMATCH;
    }

    // 6. Acquire install lock, then atomic install.
    let lock = match InstallLock::try_acquire(&install_dir) {
        Ok(Some(l)) => l,
        Ok(None) => {
            let _ = writeln!(deps.stderr, "error: another secrt update is in progress");
            return exit::LOCK_CONTENTION;
        }
        Err(e) => {
            // Permission to even create/open the lockfile — most likely
            // the install dir is read-only for this user.
            if looks_like_permission(&e) {
                let _ = writeln!(
                    deps.stderr,
                    "error: cannot write to {}. Try: secrt update --install-dir ~/.local/bin (and add ~/.local/bin to your PATH), or download manually from {}",
                    install_dir.display(),
                    release_url
                );
                return exit::PERMISSION_DENIED;
            }
            let _ = writeln!(deps.stderr, "error: acquiring install lock: {}", e);
            return exit::GENERIC;
        }
    };

    if let Err(e) = atomic_install(&install_target, &bytes) {
        if looks_like_permission(&e) {
            let _ = writeln!(
                deps.stderr,
                "error: cannot write to {}. Try: secrt update --install-dir ~/.local/bin (and add ~/.local/bin to your PATH), or download manually from {}",
                install_dir.display(),
                release_url
            );
            return exit::PERMISSION_DENIED;
        }
        let _ = writeln!(deps.stderr, "error: installing new binary: {}", e);
        return exit::GENERIC;
    }
    drop(lock);

    let _ = writeln!(
        deps.stdout,
        "secrt {} installed to {}",
        target_version,
        install_target.display()
    );
    exit::OK
}

fn default_exe_name() -> &'static str {
    if cfg!(windows) {
        "secrt.exe"
    } else {
        "secrt"
    }
}

fn looks_like_permission(e: &str) -> bool {
    let s = e.to_ascii_lowercase();
    s.contains("permission denied") || s.contains("access is denied") || s.contains("readonly")
}

/// Resolve the highest published release for the requested channel via the
/// GitHub Releases API. Mirrors the server-side
/// `release_poller::pick_highest_stable` logic for `Channel::Stable`, and
/// extends it to accept prerelease tags for `Channel::Prerelease`.
/// `Stable` accepts only strict-triplet `cli/v\d+\.\d+\.\d+` tags;
/// `Prerelease` additionally accepts `cli/v\d+\.\d+\.\d+-(rc|beta|alpha)\.\d+`
/// and picks the highest via `update_check::compare_semver`.
fn resolve_latest_for_channel(http: &dyn UpdateHttp, channel: Channel) -> Result<String, String> {
    let url = format!(
        "{}/repos/getsecrt/secrt/releases?per_page=30",
        DEFAULT_GITHUB_API_BASE
    );
    let body = http.fetch_text(&url)?;
    pick_highest_from_releases_json(&body, channel).ok_or_else(|| {
        let kind = match channel {
            Channel::Stable => "stable",
            Channel::Prerelease => "stable or prerelease",
        };
        format!("no {} cli/v* release found at {}", kind, url)
    })
}

/// Pure JSON parser for the GitHub Releases response shape we care about.
/// Skips drafts.
///
/// - `Channel::Stable`: skips entries with `prerelease == true` and only
///   accepts tags matching `^cli/v\d+\.\d+\.\d+$`. This is the production
///   path for both the implicit banner and `secrt update`.
/// - `Channel::Prerelease`: accepts both stable and prerelease tags
///   matching `^cli/v\d+\.\d+\.\d+(-(rc|beta|alpha)\.\d+)?$`, picking the
///   highest via `update_check::compare_semver`. This function is exposed
///   for the next revision's auto-discovery work; tonight `run_update_with`
///   does not invoke it for `Channel::Prerelease` (callers MUST pin
///   `--version`).
pub fn pick_highest_from_releases_json(body: &str, channel: Channel) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Release {
        tag_name: String,
        #[serde(default)]
        draft: bool,
        #[serde(default)]
        prerelease: bool,
    }
    let releases: Vec<Release> = serde_json::from_str(body).ok()?;
    let mut best: Option<String> = None;
    for r in releases {
        if r.draft {
            continue;
        }
        if matches!(channel, Channel::Stable) && r.prerelease {
            continue;
        }
        let Some(rest) = r.tag_name.strip_prefix("cli/v") else {
            continue;
        };
        let acceptable = match channel {
            Channel::Stable => is_strict_triplet(rest),
            Channel::Prerelease => is_strict_triplet(rest) || is_pre_release_form(rest),
        };
        if !acceptable {
            continue;
        }
        match best.as_deref() {
            None => best = Some(rest.to_string()),
            Some(current_best) => {
                if update_check::compare_semver(rest, current_best) == std::cmp::Ordering::Greater {
                    best = Some(rest.to_string());
                }
            }
        }
    }
    best
}

/// Back-compat alias kept for any out-of-tree call site; thin wrapper around
/// [`pick_highest_from_releases_json`] with `Channel::Stable`.
pub fn pick_highest_stable_from_releases_json(body: &str) -> Option<String> {
    pick_highest_from_releases_json(body, Channel::Stable)
}

/// Hidden Windows cleanup: delete `<install_dir>/secrt.exe.old` if present.
/// Cheap no-op on non-Windows. Wired from `cli.rs` startup so a successful
/// upgrade leaves no stale `.old` after the first follow-up command.
pub fn run_cleanup(deps: &mut Deps) -> i32 {
    let _ = deps;
    #[cfg(windows)]
    {
        if let Ok(current) = std::env::current_exe() {
            let canonical = fs::canonicalize(&current).unwrap_or_else(|_| current.clone());
            let old = old_path(&canonical);
            let _ = fs::remove_file(&old);
        }
    }
    exit::OK
}

/// Best-effort startup hook: clean up any leftover `secrt.exe.old` from a
/// previous `secrt update` cycle. Called from `cli::run` once per
/// invocation. Cheap no-op when the file isn't there.
pub fn cleanup_at_startup() {
    #[cfg(windows)]
    {
        if let Ok(current) = std::env::current_exe() {
            let canonical = fs::canonicalize(&current).unwrap_or_else(|_| current.clone());
            let old = old_path(&canonical);
            let _ = fs::remove_file(&old);
        }
    }
}

/// Help text for `secrt update`.
pub fn print_update_help(deps: &mut Deps) {
    use crate::cli::write_option_rows;
    use crate::color::{color_func, ARG, CMD, HEADING};
    let c = color_func((deps.is_stdout_tty)());
    let w = &mut deps.stderr;
    let _ = writeln!(
        w,
        "{} {} — Self-update against published GitHub Releases\n",
        c(CMD, "secrt"),
        c(CMD, "update")
    );
    let _ = writeln!(
        w,
        "{}\n  {} {} {}\n",
        c(HEADING, "USAGE"),
        c(CMD, "secrt"),
        c(CMD, "update"),
        c(ARG, "[options]")
    );
    let _ = writeln!(w, "{}", c(HEADING, "OPTIONS"));
    write_option_rows(
        w,
        &c,
        &[
            (
                "--check",
                "",
                "Print whether an update is available; do not download.",
            ),
            (
                "--force",
                "",
                "Re-download and reinstall even if already up to date.",
            ),
            (
                "--version",
                "<X.Y.Z>",
                "Install a specific version. Stable: X.Y.Z. Prerelease: X.Y.Z[-(rc|beta|alpha).N].",
            ),
            (
                "--install-dir",
                "<path>",
                "Install to a directory other than the running binary's.",
            ),
            (
                "--channel",
                "<stable|prerelease>",
                "Channel to install from (default: stable). With 'prerelease', auto-resolves to the highest published prerelease tag unless --version is given.",
            ),
            ("-h, --help", "", "Show this help."),
        ],
    );
    let _ = writeln!(w, "\n{}", c(HEADING, "EXIT CODES"));
    let _ = writeln!(w, "  0  success or --check ran cleanly");
    let _ = writeln!(w, "  1  generic error (network, parse, etc.)");
    let _ = writeln!(w, "  2  SHA-256 verification failure");
    let _ = writeln!(w, "  3  managed install detected; refused");
    let _ = writeln!(w, "  4  permission denied writing to install dir");
    let _ = writeln!(w, "  5  install lock contention");
}

// ---------------------------------------------------------------------------
// Tests (pure-logic only — full HTTP + install paths live in tests/cli_update.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_defaults() {
        let p = parse_update_args(&[]).unwrap();
        assert_eq!(p, UpdateArgs::default());
    }

    #[test]
    fn parse_args_check_force() {
        let args = vec!["--check".into(), "--force".into()];
        let p = parse_update_args(&args).unwrap();
        assert!(p.check);
        assert!(p.force);
    }

    #[test]
    fn parse_args_version_strict() {
        let args = vec!["--version".into(), "0.16.0".into()];
        let p = parse_update_args(&args).unwrap();
        assert_eq!(p.version.as_deref(), Some("0.16.0"));
    }

    #[test]
    fn parse_args_version_rejects_prerelease_on_stable_channel() {
        // No --channel flag → defaults to Channel::Stable → reject suffix.
        let args = vec!["--version".into(), "0.16.0-rc.1".into()];
        let err = parse_update_args(&args).unwrap_err();
        assert!(
            err.contains("strict semver") && err.contains("--channel prerelease"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_args_version_rejects_garbage() {
        let args = vec!["--version".into(), "garbage".into()];
        assert!(parse_update_args(&args).is_err());
    }

    #[test]
    fn parse_args_channel_prerelease_accepted() {
        let args = vec!["--channel".into(), "prerelease".into()];
        let p = parse_update_args(&args).unwrap();
        assert_eq!(p.channel, Channel::Prerelease);
    }

    #[test]
    fn parse_args_channel_invalid_value_errors() {
        let args = vec!["--channel".into(), "beta".into()];
        let err = parse_update_args(&args).unwrap_err();
        assert!(err.contains("must be 'stable' or 'prerelease'"), "{err}");
    }

    #[test]
    fn parse_args_channel_stable_ok() {
        let args = vec!["--channel".into(), "stable".into()];
        let p = parse_update_args(&args).unwrap();
        assert_eq!(p.channel, Channel::Stable);
    }

    #[test]
    fn parse_args_prerelease_with_version_pin() {
        let args = vec![
            "--channel".into(),
            "prerelease".into(),
            "--version".into(),
            "0.16.0-rc.1".into(),
        ];
        let p = parse_update_args(&args).unwrap();
        assert_eq!(p.channel, Channel::Prerelease);
        assert_eq!(p.version.as_deref(), Some("0.16.0-rc.1"));
    }

    #[test]
    fn parse_args_prerelease_rejects_bad_suffix() {
        let args = vec![
            "--channel".into(),
            "prerelease".into(),
            "--version".into(),
            "0.16.0-pre.1".into(),
        ];
        assert!(parse_update_args(&args).is_err());
    }

    #[test]
    fn is_valid_version_for_channel_table() {
        // Mirrors spec/v1/update.vectors.json#channel_resolution.
        let cases = [
            (Channel::Stable, "0.16.0", true),
            (Channel::Stable, "0.16.0-rc.1", false),
            (Channel::Prerelease, "0.16.0", true),
            (Channel::Prerelease, "0.16.0-rc.1", true),
            (Channel::Prerelease, "0.16.0-beta.10", true),
            (Channel::Prerelease, "0.16.0-alpha.1", true),
            (Channel::Prerelease, "0.16.0-rc.foo", false),
            (Channel::Prerelease, "0.16.0-pre.1", false),
            (Channel::Prerelease, "0.16.0+sha", false),
        ];
        for (ch, v, want) in cases {
            assert_eq!(
                is_valid_version_for_channel(v, ch),
                want,
                "channel={:?} version={:?}",
                ch,
                v
            );
        }
    }

    #[test]
    fn parse_args_eq_form() {
        let args = vec!["--version=0.16.0".into(), "--install-dir=/tmp/foo".into()];
        let p = parse_update_args(&args).unwrap();
        assert_eq!(p.version.as_deref(), Some("0.16.0"));
        assert_eq!(p.install_dir, Some(PathBuf::from("/tmp/foo")));
    }

    #[test]
    fn parse_args_release_base_url_hidden() {
        let args = vec!["--release-base-url".into(), "http://localhost:9".into()];
        let p = parse_update_args(&args).unwrap();
        assert_eq!(p.release_base_url.as_deref(), Some("http://localhost:9"));
    }

    #[test]
    fn parse_args_unknown_flag() {
        let args = vec!["--explode".into()];
        assert!(parse_update_args(&args).is_err());
    }

    #[test]
    fn strict_triplet_validator() {
        assert!(is_strict_triplet("0.0.0"));
        assert!(is_strict_triplet("123.45.6"));
        assert!(!is_strict_triplet("0.0"));
        assert!(!is_strict_triplet("0.0.0.0"));
        assert!(!is_strict_triplet("0.0.0-rc.1"));
        assert!(!is_strict_triplet(""));
        assert!(!is_strict_triplet("v0.0.0"));
    }

    #[test]
    fn raw_asset_name_table() {
        // One row per supported (os, arch) tuple.
        let rows = [
            (("linux", "x86_64"), "secrt-linux-amd64"),
            (("linux", "aarch64"), "secrt-linux-arm64"),
            (("macos", "x86_64"), "secrt-darwin-amd64"),
            (("macos", "aarch64"), "secrt-darwin-arm64"),
            (("windows", "x86_64"), "secrt-windows-amd64.exe"),
            (("windows", "aarch64"), "secrt-windows-arm64.exe"),
        ];
        for ((os, arch), want) in rows {
            assert_eq!(raw_asset_name(os, arch), Some(want), "({}, {})", os, arch);
        }
        assert_eq!(raw_asset_name("freebsd", "x86_64"), None);
        assert_eq!(raw_asset_name("linux", "riscv64"), None);
    }

    #[test]
    fn classify_install_homebrew() {
        let p = PathBuf::from("/opt/homebrew/Cellar/secrt/0.15.0/bin/secrt");
        let kind = classify_install(&p, &p, None);
        assert_eq!(kind, InstallKind::Homebrew);
    }

    #[test]
    fn classify_install_asdf() {
        let p = PathBuf::from("/Users/jdlien/.asdf/installs/secrt/0.15.0/bin/secrt");
        let kind = classify_install(&p, &p, None);
        assert_eq!(kind, InstallKind::Asdf);
    }

    #[test]
    fn classify_install_mise() {
        let p = PathBuf::from("/Users/jdlien/.local/share/mise/installs/secrt/0.15.0/bin/secrt");
        let kind = classify_install(&p, &p, None);
        assert_eq!(kind, InstallKind::Mise);
    }

    #[test]
    fn classify_install_nix() {
        let p = PathBuf::from("/nix/store/abc123-secrt-0.15.0/bin/secrt");
        let kind = classify_install(&p, &p, None);
        assert_eq!(kind, InstallKind::Nix);
    }

    #[test]
    fn classify_install_cargo() {
        let home = PathBuf::from("/Users/jdlien");
        let p = PathBuf::from("/Users/jdlien/.cargo/bin/secrt");
        let kind = classify_install(&p, &p, Some(&home));
        assert_eq!(kind, InstallKind::Cargo);
    }

    #[test]
    fn classify_install_generic_symlink() {
        let symlink = PathBuf::from("/usr/local/bin/secrt");
        let canonical = PathBuf::from("/opt/secrt-custom/secrt-0.15.0");
        let kind = classify_install(&symlink, &canonical, None);
        assert_eq!(kind, InstallKind::GenericSymlink);
    }

    #[test]
    fn classify_install_plain() {
        let p = PathBuf::from("/usr/local/bin/secrt");
        let kind = classify_install(&p, &p, Some(&PathBuf::from("/Users/x")));
        assert_eq!(kind, InstallKind::Plain);
    }

    #[test]
    fn refusal_messages_carry_actionable_command() {
        let canon = PathBuf::from("/opt/whatever");
        assert!(InstallKind::Homebrew
            .refusal_message(&canon)
            .contains("brew upgrade secrt"));
        assert!(InstallKind::Asdf
            .refusal_message(&canon)
            .contains("asdf install secrt latest"));
        assert!(InstallKind::Mise
            .refusal_message(&canon)
            .contains("mise upgrade secrt"));
        assert!(InstallKind::Nix
            .refusal_message(&canon)
            .contains("nix profile upgrade secrt"));
        assert!(InstallKind::Cargo
            .refusal_message(&canon)
            .contains("cargo install --force secrt-cli"));
        assert!(InstallKind::GenericSymlink
            .refusal_message(&canon)
            .contains(&canon.display().to_string()));
        assert_eq!(InstallKind::Plain.refusal_message(&canon), "");
    }

    #[test]
    fn parse_checksum_file_basic() {
        let body = "\
abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  secrt-linux-amd64
1111111111111111111111111111111111111111111111111111111111111111 *secrt-darwin-arm64

# comment line
short  bad-line
";
        let table = parse_checksum_file(body);
        assert_eq!(table.len(), 2);
        assert_eq!(
            checksum_for_asset(&table, "secrt-linux-amd64"),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );
        assert_eq!(
            checksum_for_asset(&table, "secrt-darwin-arm64"),
            Some("1111111111111111111111111111111111111111111111111111111111111111")
        );
        assert_eq!(checksum_for_asset(&table, "secrt-windows-amd64.exe"), None);
    }

    #[test]
    fn parse_checksum_file_rejects_bad_hex_length() {
        let body = "ABCDEF  short\n0000000000  short2\n";
        assert!(parse_checksum_file(body).is_empty());
    }

    #[test]
    fn sha256_of_known_input() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn pick_highest_stable_skips_drafts_and_prereleases() {
        let body = r#"[
            {"tag_name":"cli/v0.16.0","draft":false,"prerelease":false},
            {"tag_name":"cli/v0.17.0-rc.1","draft":false,"prerelease":true},
            {"tag_name":"cli/v0.18.0","draft":true,"prerelease":false},
            {"tag_name":"server/v0.16.0","draft":false,"prerelease":false},
            {"tag_name":"cli/v0.15.10","draft":false,"prerelease":false},
            {"tag_name":"cli/v0.16.0-beta.2","draft":false,"prerelease":false}
        ]"#;
        assert_eq!(
            pick_highest_stable_from_releases_json(body).as_deref(),
            Some("0.16.0")
        );
    }

    #[test]
    fn pick_highest_stable_returns_none_when_all_excluded() {
        let body = r#"[
            {"tag_name":"cli/v0.18.0","draft":true,"prerelease":false},
            {"tag_name":"server/v0.16.0","draft":false,"prerelease":false}
        ]"#;
        assert!(pick_highest_stable_from_releases_json(body).is_none());
    }

    #[test]
    fn pick_highest_stable_handles_invalid_json() {
        assert!(pick_highest_stable_from_releases_json("not json").is_none());
    }

    #[test]
    fn pick_highest_from_releases_json_stable_matches_legacy() {
        let body = r#"[
            {"tag_name":"cli/v0.16.0","draft":false,"prerelease":false},
            {"tag_name":"cli/v0.17.0-rc.1","draft":false,"prerelease":true},
            {"tag_name":"cli/v0.18.0","draft":true,"prerelease":false},
            {"tag_name":"cli/v0.16.0-beta.2","draft":false,"prerelease":false}
        ]"#;
        assert_eq!(
            pick_highest_from_releases_json(body, Channel::Stable).as_deref(),
            Some("0.16.0"),
        );
    }

    #[test]
    fn pick_highest_from_releases_json_prerelease_picks_higher_across_set() {
        let body = r#"[
            {"tag_name":"cli/v0.15.0","draft":false,"prerelease":false},
            {"tag_name":"cli/v0.16.0-rc.1","draft":false,"prerelease":true},
            {"tag_name":"cli/v0.16.0-rc.2","draft":false,"prerelease":true},
            {"tag_name":"cli/v0.16.0-beta.5","draft":false,"prerelease":true},
            {"tag_name":"cli/v0.18.0-rc.1","draft":true,"prerelease":true}
        ]"#;
        assert_eq!(
            pick_highest_from_releases_json(body, Channel::Prerelease).as_deref(),
            Some("0.16.0-rc.2"),
        );
    }

    #[test]
    fn pick_highest_from_releases_json_rejects_non_conforming_suffix() {
        let body = r#"[
            {"tag_name":"cli/v0.16.0-pre.1","draft":false,"prerelease":true},
            {"tag_name":"cli/v0.16.0-foo","draft":false,"prerelease":true}
        ]"#;
        assert!(pick_highest_from_releases_json(body, Channel::Prerelease).is_none());
    }

    /// Canonical regression for the `compare_semver` lexicographic bug:
    /// `rc.10` MUST sort above `rc.2` and the picker MUST surface it.
    #[test]
    fn pick_highest_from_releases_json_rc10_beats_rc2() {
        let body = r#"[
            {"tag_name":"cli/v0.16.0-rc.2","draft":false,"prerelease":true},
            {"tag_name":"cli/v0.16.0-rc.10","draft":false,"prerelease":true}
        ]"#;
        assert_eq!(
            pick_highest_from_releases_json(body, Channel::Prerelease).as_deref(),
            Some("0.16.0-rc.10"),
        );
    }

    #[test]
    fn pick_highest_from_releases_json_prerelease_prefers_stable_over_prerelease() {
        // A stable and a same-triplet prerelease coexist; prerelease channel
        // still picks the higher version (stable > its own prerelease per
        // compare_semver).
        let body = r#"[
            {"tag_name":"cli/v0.16.0","draft":false,"prerelease":false},
            {"tag_name":"cli/v0.16.0-rc.5","draft":false,"prerelease":true}
        ]"#;
        assert_eq!(
            pick_highest_from_releases_json(body, Channel::Prerelease).as_deref(),
            Some("0.16.0"),
        );
    }

    /// `atomic_install` should write the bytes and overwrite the previous
    /// file, leaving no `.new` artifact. Unix-only because Windows uses a
    /// rename-self-aside path that needs more setup.
    #[cfg(unix)]
    #[test]
    fn atomic_install_unix_replaces_target() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let target = dir.join("secrt");
        fs::write(&target, b"old contents").unwrap();
        atomic_install(&target, b"new contents").expect("install");
        assert_eq!(fs::read(&target).unwrap(), b"new contents");
        let mode = fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "0o{:o}", mode & 0o777);
        // No staged file left over.
        assert!(!target.with_extension("new").exists());
    }

    /// Two `try_acquire` calls on the same install dir from the same
    /// process must not block: the second returns `Ok(None)`. We can't
    /// rely on `flock` semantics across threads in the same process on
    /// every libc, so this test runs the second acquire from a child
    /// process via a thread + `std::process::Command` — too heavy here.
    /// Instead, exercise the same-process path by locking the same file
    /// from a child shell through `flock(1)` — but that's also fragile.
    /// We simply verify the lock path is created and Drop releases it.
    #[cfg(unix)]
    #[test]
    fn install_lock_creates_lockfile() {
        let dir = tempdir();
        let lock = InstallLock::try_acquire(&dir)
            .expect("acquire")
            .expect("got lock");
        assert!(dir.join(LOCK_FILENAME).exists());
        drop(lock);
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "secrt_update_test_{}_{:?}_{}",
            std::process::id(),
            std::thread::current().id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }
}
