use std::io::Write;

use crate::amk_store;
use crate::cli::{derive_base_url_from_url, parse_flags, resolve_globals, CliError, Deps};
use crate::color::{color_func, SUCCESS};
use crate::passphrase::write_error;

/// Shared logic for handling a sync URL: claim the secret, decrypt, import AMK.
/// Used by both `secrt get <sync-url>` and `secrt sync <url>`.
pub(crate) fn handle_sync_url(
    id: &str,
    url_key: &[u8],
    base_url: &str,
    api_key: &str,
    deps: &mut Deps,
    json: bool,
    silent: bool,
) -> i32 {
    let is_tty = (deps.is_tty)();
    let c = color_func(is_tty);

    if api_key.is_empty() {
        write_error(
            &mut deps.stderr,
            json,
            is_tty,
            "sync requires authentication (hint: secrt auth login)",
        );
        return 1;
    }

    // Derive claim token
    let claim_token = match crate::envelope::derive_claim_token(url_key) {
        Ok(t) => t,
        Err(e) => {
            write_error(
                &mut deps.stderr,
                json,
                is_tty,
                &format!("key derivation failed: {}", e),
            );
            return 1;
        }
    };

    // Claim the sync secret from the server
    let client = (deps.make_api)(base_url, api_key);
    let resp = match client.claim(id, &claim_token) {
        Ok(r) => r,
        Err(e) => {
            write_error(
                &mut deps.stderr,
                json,
                is_tty,
                &format!("sync failed: {}", e),
            );
            return 1;
        }
    };

    // Decrypt the envelope to get raw AMK bytes
    let opened = match crate::envelope::open(crate::envelope::OpenParams {
        envelope: resp.envelope,
        url_key: url_key.to_vec(),
        passphrase: String::new(),
    }) {
        Ok(o) => o,
        Err(e) => {
            write_error(
                &mut deps.stderr,
                json,
                is_tty,
                &format!("decrypt sync secret: {}", e),
            );
            return 1;
        }
    };

    // Precondition for AMK import: the server must recognize our API
    // key (`authenticated == true`) AND it must be linked to a user
    // (`user_id.is_some()`). Diagnose each case distinctly — the
    // `cross-instance` block above already covers the silent-host-
    // override case; what's left here is "user opted in via --base-url"
    // (key not registered on this server) and the legacy unlinked-key
    // case (registered but no user account).
    let info = match client.info() {
        Ok(i) => i,
        Err(e) => {
            write_error(
                &mut deps.stderr,
                json,
                is_tty,
                &format!("fetch user info: {}", e),
            );
            return 1;
        }
    };
    if !info.authenticated {
        write_error(
            &mut deps.stderr,
            json,
            is_tty,
            &format!(
                "this API key is not registered on {base_url}; \
                 generate the sync link from the server your key is registered on, \
                 or run `secrt auth login --base-url {base_url}` to register here"
            ),
        );
        return 1;
    }
    let user_id = match info.user_id {
        Some(id) => id,
        None => {
            write_error(
                &mut deps.stderr,
                json,
                is_tty,
                "server did not return user_id (API key may not be linked to a user)",
            );
            return 1;
        }
    };

    // Import the AMK. Sync historically used `SystemRandom` directly; route
    // through `amk_store::import_amk` with the same RNG so all three import
    // paths (sync / login / pair) share one wrapping path.
    let rand_bytes = |buf: &mut [u8]| -> Result<(), secrt_core::types::EnvelopeError> {
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new()
            .fill(buf)
            .map_err(|_| secrt_core::types::EnvelopeError::RngError("rng failed".into()))
    };
    match amk_store::import_amk(&opened.content, api_key, &user_id, &*client, &rand_bytes) {
        Ok(()) => {
            if !silent {
                let _ = writeln!(
                    deps.stderr,
                    "{} Account key synced successfully",
                    c(SUCCESS, "\u{2713}")
                );
            }
            0
        }
        Err(e) => {
            write_error(
                &mut deps.stderr,
                json,
                is_tty,
                &format!("import account key: {}", e),
            );
            1
        }
    }
}

/// Entry point for `secrt sync <url>`.
pub fn run_sync(args: &[String], deps: &mut Deps) -> i32 {
    let mut pa = match parse_flags(args) {
        Ok(pa) => pa,
        Err(CliError::ShowHelp) => {
            print_sync_help(deps);
            return 0;
        }
        Err(CliError::Error(e)) => {
            write_error(&mut deps.stderr, false, (deps.is_tty)(), &e);
            return 2;
        }
    };
    resolve_globals(&mut pa, deps);

    if pa.args.is_empty() {
        let base = pa.base_url.trim_end_matches('/');
        write_error(
            &mut deps.stderr,
            pa.json,
            (deps.is_tty)(),
            &format!(
                "sync URL is required\n       Visit {base}/pair on a device with your \
                 account key and click \"Get a one-time sync link\"."
            ),
        );
        return 2;
    }

    let raw_url = pa.args[0].clone();

    // Parse the URL
    let parsed = match crate::envelope::parse_secret_url(&raw_url) {
        Ok(p) => p,
        Err(e) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                (deps.is_tty)(),
                &format!("invalid sync URL: {}", e),
            );
            return 2;
        }
    };

    let (id, url_key) = match parsed {
        crate::envelope::ParsedSecretUrl::Sync { id, url_key } => (id, url_key),
        crate::envelope::ParsedSecretUrl::Share { .. } => {
            write_error(
                &mut deps.stderr,
                pa.json,
                (deps.is_tty)(),
                "this is a share URL, not a sync URL (hint: use `secrt get` to retrieve shared secrets)",
            );
            return 2;
        }
    };

    // Derive base URL from the sync URL if not explicitly set via flag/env.
    derive_base_url_from_url(&raw_url, &mut pa);
    let stderr_tty = (deps.is_stderr_tty)();
    crate::instance_trust::warn_if_unofficial(
        &pa.base_url,
        &pa.trusted_servers,
        &mut deps.stderr,
        stderr_tty,
    );
    if let Err(code) =
        crate::instance_trust::block_if_cross_instance(&pa, "sync", &mut deps.stderr, stderr_tty)
    {
        return code;
    }

    handle_sync_url(
        &id,
        &url_key,
        &pa.base_url,
        &pa.api_key,
        deps,
        pa.json,
        pa.silent,
    )
}

pub fn print_sync_help(deps: &mut Deps) {
    use crate::color::{ARG, CMD, HEADING, OPT};
    let c = color_func((deps.is_stdout_tty)());
    let w = &mut deps.stderr;
    let _ = writeln!(
        w,
        "{}\n  [LEGACY] Import account key from a one-time link.\n",
        c(HEADING, "SYNC")
    );
    let _ = writeln!(
        w,
        "{}\n  {} is kept for headless or scripted setups where no human is",
        c(HEADING, "LEGACY"),
        c(CMD, "secrt sync"),
    );
    let _ = writeln!(
        w,
        "  at the terminal to approve a pair code. For everyday device"
    );
    let _ = writeln!(
        w,
        "  setup, use {} instead — it doesn't require generating",
        c(CMD, "secrt pair")
    );
    let _ = writeln!(w, "  or sharing a link.\n");
    let _ = writeln!(
        w,
        "  To get a sync link, visit https://secrt.ca/pair (or your"
    );
    let _ = writeln!(
        w,
        "  configured instance) on a device with your account key and"
    );
    let _ = writeln!(w, "  click \"Get a one-time sync link\".\n");
    let _ = writeln!(
        w,
        "{}\n  {} {} {}\n",
        c(HEADING, "USAGE"),
        c(CMD, "secrt"),
        c(CMD, "sync"),
        c(ARG, "<url>")
    );
    let _ = writeln!(w, "{}", c(HEADING, "OPTIONS"));
    let _ = writeln!(
        w,
        "  {}  Server URL  [env: SECRET_BASE_URL]",
        c(OPT, "--base-url <url>")
    );
    let _ = writeln!(
        w,
        "  {}       API key  [env: SECRET_API_KEY]",
        c(OPT, "--api-key <key>")
    );
    let _ = writeln!(w, "  {}            Output as JSON", c(OPT, "--json"));
    let _ = writeln!(w, "  {}            Suppress output", c(OPT, "--silent"));
    let _ = writeln!(
        w,
        "  {}, {}          Show this help",
        c(OPT, "-h"),
        c(OPT, "--help")
    );
    let _ = writeln!(w, "\n{}", c(HEADING, "EXAMPLES"));
    let _ = writeln!(
        w,
        "  {} {} https://secrt.ca/sync/abc123#...",
        c(CMD, "secrt"),
        c(CMD, "sync")
    );
}
