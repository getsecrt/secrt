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
use crate::color::{color_func, OPT, URL, WARN};

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

    let _ = writeln!(
        stderr,
        "error: this {command} URL is for {derived_host}, but you're configured for {configured_host}."
    );
    let _ = writeln!(
        stderr,
        "  this won't work — your API key isn't registered on {derived_host},"
    );
    let _ = writeln!(
        stderr,
        "  and sending it there would leak credentials to a server you didn't choose."
    );
    let _ = writeln!(stderr, "  if you really meant to switch instances, run:");
    let _ = writeln!(stderr, "    secrt auth login --base-url {}", pa.base_url);
    Err(2)
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
            assert_eq!(block_if_cross_instance(&pa, "sync", w), Ok(()));
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
            assert_eq!(block_if_cross_instance(&pa, "sync", w), Ok(()));
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
            assert_eq!(block_if_cross_instance(&pa, "sync", w), Err(2));
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
                let _ = block_if_cross_instance(&pa, cmd, w);
            });
            assert!(
                out.contains(&format!("this {cmd} URL is for evil.tld")),
                "cmd={cmd} got: {out:?}"
            );
        }
    }
}
