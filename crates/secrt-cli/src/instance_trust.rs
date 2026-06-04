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
use crate::color::{color_func, CMD, DIM, ERROR, OPT, URL, WARN};

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

/// Rewrite a 401 server error into an actionable auth-failure message: a
/// headline naming the host that rejected the key, the same identity block
/// `secrt auth status` prints (key + source, server + "key not recognized"),
/// a hypothesis line, and a `secrt auth login` recommendation.
///
/// `masked_key`/`key_source` come from [`crate::auth::masked_key_and_source`]
/// (empty when no key is configured). In `json` mode a single terse line is
/// returned so machine consumers stay parseable. Non-401 errors pass through
/// unchanged.
pub fn decorate_auth_error(
    err: &str,
    pa: &ParsedArgs,
    masked_key: &str,
    key_source: &str,
    json: bool,
    is_stderr_tty: bool,
) -> String {
    if !err.contains("(401)") {
        return err.to_string();
    }
    let host = host_of(&pa.base_url).unwrap_or_else(|| pa.base_url.clone());
    let has_key = !masked_key.is_empty();

    // Machine consumers get one terse, parseable line — no block, no color.
    if json {
        return if has_key {
            format!(
                "{host} rejected your API key (401); it may be for a different secrt \
                 instance or was revoked — run `secrt auth login`"
            )
        } else {
            format!("{host} requires authentication (401) — run `secrt auth login`")
        };
    }

    let c = color_func(is_stderr_tty);

    // No key configured: a 401 means the request needed auth it didn't have,
    // not that a key was rejected. Keep it short and point at sign-in.
    if !has_key {
        return format!(
            "{host} requires authentication (401)\n  Run {} to sign in.",
            c(CMD, "secrt auth login")
        );
    }

    // Headline is plain — the red `error:` prefix (added by `write_error`)
    // and the red hypothesis line below carry the "this failed" weight, so
    // the rest of the block stays quiet (dim) to avoid burying it in color.
    let mut out = format!("{host} rejected your API key (401)\n");
    out.push_str(&crate::auth::fmt_key_line(
        masked_key,
        key_source,
        DIM,
        is_stderr_tty,
    ));
    out.push_str(&crate::auth::fmt_server_line(
        &pa.base_url,
        "key not recognized",
        DIM,
        DIM,
        is_stderr_tty,
    ));

    // Hypothesis — the actionable takeaway, in red so it stands out from the
    // dim context. When an explicit `--base-url` points at a different host
    // than the user's configured home instance, we can name both sides;
    // otherwise fall back to the generic wrong-instance/revoked guess.
    let cross_instance = pa.base_url_source == BaseUrlSource::Flag
        && !same_logical_instance(&pa.base_url, &pa.configured_base_url);
    let hypothesis = match (
        cross_instance,
        host_of(&pa.base_url),
        host_of(&pa.configured_base_url),
    ) {
        (true, Some(flagged), Some(configured)) => {
            format!("Your key is configured for {configured}, not {flagged}.")
        }
        _ => "Your key may belong to a different instance, or it was revoked.".to_string(),
    };
    out.push_str(&format!("  {}\n", c(ERROR, &hypothesis)));

    out.push_str(&format!(
        "  Run {} to re-authenticate.",
        c(CMD, "secrt auth login")
    ));
    out
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
        assert_eq!(
            decorate_auth_error(err, &pa, "sk2_abcd••••••••", "config", false, false),
            err
        );
    }

    #[test]
    fn decorate_auth_error_generic_401_shows_identity_and_recommendation() {
        // Default source — user didn't pass --base-url. Still rewrite the
        // 401 into the identity block + generic hypothesis + login hint.
        let pa = pa_with(
            "https://secrt.ca",
            "https://secrt.ca",
            BaseUrlSource::Default,
        );
        let err = "server error (401): unauthorized";
        let out = decorate_auth_error(err, &pa, "sk2_abcd••••••••", "keychain", false, false);
        assert!(
            out.starts_with("secrt.ca rejected your API key (401)"),
            "headline: {out:?}"
        );
        assert!(
            out.contains("Key: sk2_abcd•••••••• (from: keychain)"),
            "key line: {out:?}"
        );
        assert!(
            out.contains("Server: https://secrt.ca (key not recognized)"),
            "server line: {out:?}"
        );
        assert!(
            out.contains("may belong to a different instance, or it was revoked"),
            "hypothesis: {out:?}"
        );
        assert!(
            out.contains("Run secrt auth login to re-authenticate"),
            "login hint: {out:?}"
        );
    }

    #[test]
    fn decorate_auth_error_flag_match_uses_generic_hypothesis() {
        // Flag points at the same host as configured — not cross-instance,
        // so the generic (revoked-or-wrong-instance) hypothesis applies.
        let pa = pa_with("https://secrt.ca", "https://secrt.ca", BaseUrlSource::Flag);
        let err = "server error (401): unauthorized";
        let out = decorate_auth_error(err, &pa, "sk2_abcd••••••••", "config", false, false);
        assert!(
            out.contains("may belong to a different instance, or it was revoked"),
            "generic hypothesis: {out:?}"
        );
        assert!(
            !out.contains("Your key is configured for"),
            "should not claim a specific cross-instance mismatch: {out:?}"
        );
    }

    #[test]
    fn decorate_auth_error_cross_instance_names_both_hosts() {
        let pa = pa_with("https://secrt.is", "https://secrt.ca", BaseUrlSource::Flag);
        let err = "server error (401): unauthorized";
        let out = decorate_auth_error(err, &pa, "sk2_abcd••••••••", "config", false, false);
        assert!(
            out.starts_with("secrt.is rejected your API key (401)"),
            "headline names the host that rejected the key: {out:?}"
        );
        assert!(
            out.contains("Your key is configured for secrt.ca, not secrt.is"),
            "cross-instance hypothesis: {out:?}"
        );
        assert!(
            out.contains("Run secrt auth login to re-authenticate"),
            "login hint: {out:?}"
        );
    }

    #[test]
    fn decorate_auth_error_json_is_terse_single_line() {
        let pa = pa_with("https://secrt.is", "https://secrt.ca", BaseUrlSource::Flag);
        let err = "server error (401): unauthorized";
        let out = decorate_auth_error(err, &pa, "sk2_abcd••••••••", "config", true, false);
        assert!(
            !out.contains('\n'),
            "json message must be one line: {out:?}"
        );
        assert!(
            out.contains("secrt.is rejected your API key (401)"),
            "headline: {out:?}"
        );
        assert!(out.contains("secrt auth login"), "login hint: {out:?}");
        // No color escapes and no multi-line identity block in json mode.
        assert!(
            !out.contains('\x1b'),
            "json message must be uncolored: {out:?}"
        );
    }

    #[test]
    fn decorate_auth_error_uses_semantic_colors_when_stderr_is_tty() {
        let pa = pa_with("https://secrt.is", "https://secrt.ca", BaseUrlSource::Flag);
        let err = "server error (401): unauthorized";
        let out = decorate_auth_error(err, &pa, "sk2_abcd••••••••", "config", false, true);
        // The hypothesis line is red so the takeaway stands out from the
        // dim context block.
        assert!(
            out.contains("\x1b[31mYour key is configured for secrt.ca, not secrt.is.\x1b[0m"),
            "hypothesis should be red: {out:?}"
        );
        // The recommended command keeps its cyan accent.
        assert!(
            out.contains("\x1b[36msecrt auth login\x1b[0m"),
            "command in cyan: {out:?}"
        );
        // Identity labels are dimmed, not yellow, to keep the block quiet.
        assert!(
            out.contains("\x1b[2mKey\x1b[0m") && out.contains("\x1b[2mServer\x1b[0m"),
            "identity labels should be dim: {out:?}"
        );
        // The headline host is no longer bold-cyan — red carries emphasis.
        assert!(
            !out.contains("\x1b[1;36msecrt.is\x1b[0m"),
            "headline host should be plain, not bold cyan: {out:?}"
        );
    }
}
