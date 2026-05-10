//! Instance-trust enforcement for the CLI.
//!
//! Two layered checks against malicious API-compatible secrt forks:
//!
//! - [`warn_if_unofficial`] emits a loud stderr warning whenever the
//!   resolved `base_url` classifies as `Untrusted`. Fired by every
//!   command that talks to a server (send/get/list/info/burn/sync/auth).
//! - [`block_if_cross_instance`] refuses to send an API key to a host
//!   that argv overrode silently — i.e., when `pa.base_url_source`
//!   is `UrlDerived` and the derived host doesn't match what the user
//!   configured. Fired by the credential-bearing commands
//!   (sync/burn/info). Get is unauthenticated so it warns only.
//!
//! Both helpers take `&mut dyn Write` for stderr so tests can capture
//! the output without standing up a full `Deps` rig.

use std::io::Write;

use secrt_core::{classify_origin, host_of, TrustDecision};

use crate::cli::{BaseUrlSource, ParsedArgs};
use crate::color::{color_func, CMD, ERROR, OPT, URL, WARN};

/// Emit a loud warning to `stderr` when `base_url` classifies as
/// `Untrusted`. No-op for `Official`, `TrustedCustom`, and `DevLocal`.
///
/// `is_stderr_tty` gates ANSI color codes — pass `false` for piped or
/// redirected stderr so the warning stays plain text.
pub fn warn_if_unofficial(
    base_url: &str,
    trusted_servers: &[String],
    stderr: &mut dyn Write,
    is_stderr_tty: bool,
) {
    if !matches!(
        classify_origin(base_url, trusted_servers),
        TrustDecision::Untrusted
    ) {
        return;
    }
    let host = host_of(base_url).unwrap_or_else(|| base_url.to_string());
    let c = color_func(is_stderr_tty);
    let _ = writeln!(
        stderr,
        "{} {} is not an official secrt instance.",
        c(WARN, "Warning:"),
        c(URL, &host),
    );
    let _ = writeln!(stderr);
    let _ = writeln!(
        stderr,
        "  We can't verify who operates it. If you don't know, exercise caution."
    );
    let _ = writeln!(stderr);
    let _ = writeln!(
        stderr,
        "  Silence: {}",
        c(OPT, &format!("trusted_servers = [\"{host}\"]")),
    );
    let _ = writeln!(stderr, "  in {}", c(URL, "~/.config/secrt/config.toml"));
}

/// Refuse to proceed when argv overrode the configured `base_url` with a
/// share/sync URL whose host points at a *different* instance than the
/// one the user is configured for. The API key is registered against
/// the configured server; sending it to the URL-derived host would leak
/// credentials.
///
/// Returns `Err(2)` (with a diagnostic written to `stderr`) when the
/// block fires; otherwise `Ok(())`. Wildcard subdomains of the same
/// official apex are *not* a mismatch (the wildcard-trust invariant).
///
/// `command` is one of "sync" / "burn" / "info" — used in the message.
/// Callers that don't send an API key (`get`, `auth`) MUST NOT call
/// this — warn-only is the right behavior there.
pub fn block_if_cross_instance(
    pa: &ParsedArgs,
    command: &str,
    stderr: &mut dyn Write,
    is_stderr_tty: bool,
) -> Result<(), i32> {
    if pa.base_url_source != BaseUrlSource::UrlDerived {
        return Ok(());
    }
    if same_logical_instance(&pa.base_url, &pa.configured_base_url) {
        return Ok(());
    }

    let derived_host = host_of(&pa.base_url).unwrap_or_else(|| pa.base_url.clone());
    let configured_host =
        host_of(&pa.configured_base_url).unwrap_or_else(|| pa.configured_base_url.clone());

    let c = color_func(is_stderr_tty);
    let _ = writeln!(
        stderr,
        "{} this {command} URL is for {}, but you're configured for {}.",
        c(ERROR, "error:"),
        c(URL, &derived_host),
        c(URL, &configured_host),
    );
    let _ = writeln!(stderr, "  To switch instances, run:");
    let _ = writeln!(
        stderr,
        "  {} {} {}",
        c(CMD, "secrt auth login"),
        c(OPT, "--base-url"),
        c(URL, &pa.base_url),
    );
    Err(2)
}

/// Decorate a server error string with a host-mismatch hint when a
/// 401 likely means "your auto-loaded API key is for a different
/// host," not "your key is invalid." The hint fires when the user
/// passed an explicit `--base-url` (`Flag` source) AND that host
/// differs from the one their key was registered against.
///
/// Returns `err` unchanged when the error isn't a 401, when no flag
/// was passed, or when the flagged host equals the configured one.
pub fn decorate_auth_error(err: &str, pa: &ParsedArgs, is_stderr_tty: bool) -> String {
    if !err.contains("(401)") {
        return err.to_string();
    }
    if pa.base_url_source != BaseUrlSource::Flag {
        return err.to_string();
    }
    if same_logical_instance(&pa.base_url, &pa.configured_base_url) {
        return err.to_string();
    }
    let flagged = match host_of(&pa.base_url) {
        Some(h) => h,
        None => return err.to_string(),
    };
    let configured = match host_of(&pa.configured_base_url) {
        Some(h) => h,
        None => return err.to_string(),
    };
    let c = color_func(is_stderr_tty);
    format!(
        "{err}\n  Your API key is for {}, not {}. To switch, run:\n  {} {} {}",
        c(URL, &configured),
        c(URL, &flagged),
        c(CMD, "secrt auth login"),
        c(OPT, "--base-url"),
        c(URL, &pa.base_url),
    )
}

/// Two URLs refer to the same logical secrt instance when:
///   - they classify as the same Official apex (wildcard-trust invariant),
///     OR
///   - their hosts (lowercased, port-aware via the `url` crate) match.
fn same_logical_instance(a: &str, b: &str) -> bool {
    match (classify_origin(a, &[]), classify_origin(b, &[])) {
        (TrustDecision::Official { apex: ax }, TrustDecision::Official { apex: bx }) => ax == bx,
        _ => host_of(a).is_some() && host_of(a) == host_of(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{BaseUrlSource, ParsedArgs};

    fn pa_with(base: &str, configured: &str, source: BaseUrlSource) -> ParsedArgs {
        ParsedArgs {
            base_url: base.to_string(),
            configured_base_url: configured.to_string(),
            base_url_source: source,
            ..ParsedArgs::default()
        }
    }

    fn capture<F: FnOnce(&mut dyn Write)>(f: F) -> String {
        let mut buf: Vec<u8> = Vec::new();
        f(&mut buf);
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn warn_silent_for_official() {
        let out = capture(|w| warn_if_unofficial("https://secrt.ca", &[], w, false));
        assert!(out.is_empty(), "got: {out:?}");
    }

    #[test]
    fn warn_silent_for_official_wildcard() {
        let out = capture(|w| warn_if_unofficial("https://my.secrt.is", &[], w, false));
        assert!(out.is_empty(), "got: {out:?}");
    }

    #[test]
    fn warn_silent_for_devlocal() {
        let out = capture(|w| warn_if_unofficial("http://localhost:8080", &[], w, false));
        assert!(out.is_empty(), "got: {out:?}");
    }

    #[test]
    fn warn_silent_for_trusted_server() {
        let out = capture(|w| {
            warn_if_unofficial(
                "https://my-self.example",
                &["my-self.example".into()],
                w,
                false,
            )
        });
        assert!(out.is_empty(), "got: {out:?}");
    }

    #[test]
    fn warn_fires_for_evil_tld() {
        let out = capture(|w| warn_if_unofficial("https://evil.tld", &[], w, false));
        assert!(
            out.contains("not an official secrt instance"),
            "got: {out:?}"
        );
        assert!(out.contains("evil.tld"), "got: {out:?}");
        assert!(out.contains("trusted_servers"), "got: {out:?}");
        assert!(out.contains("~/.config/secrt/config.toml"), "got: {out:?}");
    }

    #[test]
    fn warn_fires_for_lookalike() {
        let out = capture(|w| warn_if_unofficial("https://foosecrt.is", &[], w, false));
        assert!(out.contains("foosecrt.is"), "got: {out:?}");
    }

    #[test]
    fn warn_uses_ansi_when_stderr_is_tty() {
        let out = capture(|w| warn_if_unofficial("https://evil.tld", &[], w, true));
        assert!(
            out.contains("\x1b["),
            "should contain ANSI escapes: {out:?}"
        );
        assert!(
            out.contains("\x1b[33mWarning:\x1b[0m"),
            "yellow Warning: prefix; got: {out:?}"
        );
        assert!(
            out.contains("\x1b[1;36mevil.tld\x1b[0m"),
            "bold cyan host; got: {out:?}"
        );
    }

    #[test]
    fn warn_plain_text_when_stderr_not_tty() {
        let out = capture(|w| warn_if_unofficial("https://evil.tld", &[], w, false));
        assert!(!out.contains("\x1b["), "should not contain ANSI: {out:?}");
    }

    #[test]
    fn block_no_op_when_source_not_url_derived() {
        let pa = pa_with("https://secrt.is", "https://secrt.ca", BaseUrlSource::Flag);
        let out = capture(|w| {
            assert_eq!(block_if_cross_instance(&pa, "sync", w, false), Ok(()));
        });
        assert!(out.is_empty(), "got: {out:?}");
    }

    #[test]
    fn block_no_op_when_same_official_apex() {
        // Wildcard subdomain of the same apex — apex collapses, no block.
        let pa = pa_with(
            "https://my.secrt.ca",
            "https://secrt.ca",
            BaseUrlSource::UrlDerived,
        );
        let out = capture(|w| {
            assert_eq!(block_if_cross_instance(&pa, "sync", w, false), Ok(()));
        });
        assert!(out.is_empty(), "got: {out:?}");
    }

    #[test]
    fn block_fires_for_cross_official_apex() {
        let pa = pa_with(
            "https://secrt.is",
            "https://secrt.ca",
            BaseUrlSource::UrlDerived,
        );
        let out = capture(|w| {
            assert_eq!(block_if_cross_instance(&pa, "sync", w, false), Err(2));
        });
        assert!(
            out.contains("this sync URL is for secrt.is"),
            "got: {out:?}"
        );
        assert!(
            out.contains("you're configured for secrt.ca"),
            "got: {out:?}"
        );
        assert!(
            out.contains("secrt auth login --base-url https://secrt.is"),
            "got: {out:?}"
        );
        assert!(out.contains("To switch instances"), "got: {out:?}");
    }

    #[test]
    fn block_uses_semantic_colors_when_stderr_is_tty() {
        let pa = pa_with(
            "https://secrt.is",
            "https://secrt.ca",
            BaseUrlSource::UrlDerived,
        );
        let out = capture(|w| {
            let _ = block_if_cross_instance(&pa, "sync", w, true);
        });
        // error: in red (31)
        assert!(out.contains("\x1b[31merror:\x1b[0m"), "red error: {out:?}");
        // hosts in bold cyan (1;36)
        assert!(
            out.contains("\x1b[1;36msecrt.is\x1b[0m"),
            "host in bold cyan: {out:?}"
        );
        // command in cyan (36)
        assert!(
            out.contains("\x1b[36msecrt auth login\x1b[0m"),
            "command in cyan: {out:?}"
        );
        // option in yellow (33)
        assert!(
            out.contains("\x1b[33m--base-url\x1b[0m"),
            "option in yellow: {out:?}"
        );
    }

    #[test]
    fn block_message_carries_command_name() {
        let pa = pa_with(
            "https://evil.tld",
            "https://secrt.ca",
            BaseUrlSource::UrlDerived,
        );
        for cmd in ["sync", "burn", "info"] {
            let out = capture(|w| {
                let _ = block_if_cross_instance(&pa, cmd, w, false);
            });
            assert!(
                out.contains(&format!("this {cmd} URL is for evil.tld")),
                "cmd={cmd} got: {out:?}"
            );
        }
    }

    #[test]
    fn decorate_auth_error_passes_through_non_401() {
        let pa = pa_with("https://secrt.is", "https://secrt.ca", BaseUrlSource::Flag);
        let err = "server error (404): not found";
        assert_eq!(decorate_auth_error(err, &pa, false), err);
    }

    #[test]
    fn decorate_auth_error_no_op_when_source_not_flag() {
        // Default source — user didn't pass --base-url, so a 401 means
        // their key is genuinely invalid. No host-mismatch hint.
        let pa = pa_with(
            "https://secrt.ca",
            "https://secrt.ca",
            BaseUrlSource::Default,
        );
        let err = "server error (401): unauthorized";
        assert_eq!(decorate_auth_error(err, &pa, false), err);
    }

    #[test]
    fn decorate_auth_error_no_op_when_flag_matches_configured() {
        let pa = pa_with("https://secrt.ca", "https://secrt.ca", BaseUrlSource::Flag);
        let err = "server error (401): unauthorized";
        assert_eq!(decorate_auth_error(err, &pa, false), err);
    }

    #[test]
    fn decorate_auth_error_appends_hint_for_flag_cross_instance() {
        let pa = pa_with("https://secrt.is", "https://secrt.ca", BaseUrlSource::Flag);
        let err = "server error (401): unauthorized";
        let out = decorate_auth_error(err, &pa, false);
        assert!(out.starts_with(err), "should preserve original: {out:?}");
        assert!(
            out.contains("Your API key is for secrt.ca, not secrt.is"),
            "missing host names: {out:?}"
        );
        assert!(
            out.contains("secrt auth login --base-url https://secrt.is"),
            "missing register command: {out:?}"
        );
    }

    #[test]
    fn decorate_auth_error_uses_semantic_colors_when_stderr_is_tty() {
        let pa = pa_with("https://secrt.is", "https://secrt.ca", BaseUrlSource::Flag);
        let err = "server error (401): unauthorized";
        let out = decorate_auth_error(err, &pa, true);
        assert!(
            out.contains("\x1b[1;36msecrt.ca\x1b[0m"),
            "configured host bold cyan: {out:?}"
        );
        assert!(
            out.contains("\x1b[1;36msecrt.is\x1b[0m"),
            "flagged host bold cyan: {out:?}"
        );
        assert!(
            out.contains("\x1b[36msecrt auth login\x1b[0m"),
            "command in cyan: {out:?}"
        );
        assert!(
            out.contains("\x1b[33m--base-url\x1b[0m"),
            "option in yellow: {out:?}"
        );
    }
}
