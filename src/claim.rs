use std::io::Write;

use crate::cli::{parse_flags, print_claim_help, resolve_globals, CliError, Deps};
use crate::envelope::{self, OpenParams};
use crate::passphrase::{resolve_passphrase, write_error};

pub fn run_claim(args: &[String], deps: &mut Deps) -> i32 {
    let mut pa = match parse_flags(args) {
        Ok(pa) => pa,
        Err(CliError::ShowHelp) => {
            print_claim_help(deps);
            return 0;
        }
        Err(CliError::Error(e)) => {
            write_error(&mut deps.stderr, false, &e);
            return 2;
        }
    };
    resolve_globals(&mut pa, deps);

    if pa.args.is_empty() {
        write_error(&mut deps.stderr, pa.json, "share URL is required");
        return 2;
    }

    let share_url = &pa.args[0];

    // Parse URL to extract ID and url_key
    let (id, url_key) = match envelope::parse_share_url(share_url) {
        Ok(r) => r,
        Err(e) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                &format!("invalid share URL: {}", e),
            );
            return 2;
        }
    };

    // Derive base URL from share URL if not explicitly set via flag/env
    let base_url = if !pa.base_url_from_flag && (deps.getenv)("SECRET_BASE_URL").is_none() {
        // Try to extract base URL from share URL
        if share_url.contains("://") {
            if let Some(scheme_end) = share_url.find("://") {
                let after_scheme = &share_url[scheme_end + 3..];
                if let Some(path_start) = after_scheme.find('/') {
                    share_url[..scheme_end + 3 + path_start].to_string()
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

    // Derive claim token from url_key alone
    let claim_token = match envelope::derive_claim_token(&url_key) {
        Ok(t) => t,
        Err(e) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                &format!("key derivation failed: {}", e),
            );
            return 1;
        }
    };

    // Claim from server
    let client = (deps.make_api)(&base_url, &pa.api_key);

    let resp = match client.claim(&id, &claim_token) {
        Ok(r) => r,
        Err(e) => {
            write_error(&mut deps.stderr, pa.json, &format!("claim failed: {}", e));
            return 1;
        }
    };

    // Resolve passphrase for decryption
    let passphrase = match resolve_passphrase(&pa, deps) {
        Ok(p) => p,
        Err(e) => {
            write_error(&mut deps.stderr, pa.json, &e);
            return 1;
        }
    };

    // Decrypt envelope
    let plaintext = match envelope::open(OpenParams {
        envelope: resp.envelope,
        url_key,
        passphrase,
    }) {
        Ok(p) => p,
        Err(e) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                &format!("decryption failed: {}", e),
            );
            return 1;
        }
    };

    // Output
    if pa.json {
        let out = serde_json::json!({
            "expires_at": resp.expires_at,
        });
        let _ = writeln!(deps.stdout, "{}", serde_json::to_string(&out).unwrap());
    } else {
        let _ = deps.stdout.write_all(&plaintext);
    }

    0
}
