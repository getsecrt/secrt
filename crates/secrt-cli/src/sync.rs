use std::io::Write;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::SecureRandom;

use crate::cli::{parse_flags, resolve_globals, CliError, Deps};
use crate::color::{color_func, SUCCESS};
use crate::passphrase::write_error;

/// Import a raw 32-byte AMK: wrap it with the caller's API key and upload to the server.
pub(crate) fn import_amk(
    amk_bytes: &[u8],
    api_key: &str,
    client: &dyn secrt_core::api::SecretApi,
) -> Result<(), String> {
    use secrt_core::amk;

    if amk_bytes.len() != amk::AMK_LEN {
        return Err(format!(
            "invalid AMK length: expected {}, got {}",
            amk::AMK_LEN,
            amk_bytes.len()
        ));
    }

    let local_key = secrt_core::parse_local_api_key(api_key)
        .map_err(|e| format!("cannot parse API key: {}", e))?;

    let wrap_key = amk::derive_amk_wrap_key(&local_key.root_key)
        .map_err(|e| format!("derive wrap key: {}", e))?;

    // Fetch user_id from the info endpoint (API key auth)
    let info = client
        .info()
        .map_err(|e| format!("fetch user info: {}", e))?;
    let user_id = info.user_id.ok_or_else(|| {
        "server did not return user_id (API key may not be linked to a user)".to_string()
    })?;

    let aad = amk::build_wrap_aad(&user_id, &local_key.prefix, 1);
    let wrapped = amk::wrap_amk(amk_bytes, &wrap_key, &aad, &|buf| {
        ring::rand::SystemRandom::new()
            .fill(buf)
            .map_err(|_| secrt_core::types::EnvelopeError::RngError("rng failed".into()))
    })
    .map_err(|e| format!("wrap AMK: {}", e))?;

    let commit = amk::compute_amk_commit(amk_bytes);

    client.upsert_amk_wrapper(
        &local_key.prefix,
        &URL_SAFE_NO_PAD.encode(&wrapped.ct),
        &URL_SAFE_NO_PAD.encode(&wrapped.nonce),
        &URL_SAFE_NO_PAD.encode(commit),
        1,
    )
}

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

    // Import the AMK
    match import_amk(&opened.content, api_key, &*client) {
        Ok(()) => {
            if !silent {
                let _ = writeln!(
                    deps.stderr,
                    "{} Notes key synced successfully",
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
                &format!("import notes key: {}", e),
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
        write_error(
            &mut deps.stderr,
            pa.json,
            (deps.is_tty)(),
            "sync URL is required",
        );
        return 2;
    }

    let raw_url = &pa.args[0];

    // Parse the URL
    let parsed = match crate::envelope::parse_secret_url(raw_url) {
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

    // Derive base URL from the sync URL if not explicitly set
    let base_url = if !pa.base_url_from_flag && (deps.getenv)("SECRET_BASE_URL").is_none() {
        if raw_url.contains("://") {
            if let Some(scheme_end) = raw_url.find("://") {
                let after_scheme = &raw_url[scheme_end + 3..];
                if let Some(path_start) = after_scheme.find('/') {
                    raw_url[..scheme_end + 3 + path_start].to_string()
                } else {
                    pa.base_url.clone()
                }
            } else {
                pa.base_url.clone()
            }
        } else {
            pa.base_url.clone()
        }
    } else {
        pa.base_url.clone()
    };

    handle_sync_url(
        &id,
        &url_key,
        &base_url,
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
        "{}\n  Import your notes encryption key from a sync link.\n",
        c(HEADING, "SYNC")
    );
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
