use std::io::Write;

use crate::cli::{parse_flags, print_burn_help, resolve_globals, CliError, Deps};
use crate::client::ApiClient;
use crate::envelope;
use crate::passphrase::write_error;

pub fn run_burn(args: &[String], deps: &mut Deps) -> i32 {
    let mut pa = match parse_flags(args) {
        Ok(pa) => pa,
        Err(CliError::ShowHelp) => {
            print_burn_help(deps);
            return 0;
        }
        Err(CliError::Error(e)) => {
            write_error(&mut deps.stderr, false, &e);
            return 2;
        }
    };
    resolve_globals(&mut pa, deps);

    if pa.args.is_empty() {
        write_error(
            &mut deps.stderr,
            pa.json,
            "secret ID or share URL is required",
        );
        return 2;
    }

    if pa.api_key.is_empty() {
        write_error(&mut deps.stderr, pa.json, "--api-key is required for burn");
        return 2;
    }

    // Extract ID: might be a share URL or bare ID
    let id_or_url = &pa.args[0];
    let mut secret_id = id_or_url.clone();
    let mut base_url = pa.base_url.clone();

    if id_or_url.contains('/') || id_or_url.contains('#') {
        match envelope::parse_share_url(id_or_url) {
            Ok((id, _)) => {
                secret_id = id;
                // Derive base URL from share URL if not explicitly set via flag/env
                if !pa.base_url_from_flag
                    && (deps.getenv)("SECRET_BASE_URL").is_none()
                    && id_or_url.contains("://")
                {
                    if let Some(scheme_end) = id_or_url.find("://") {
                        let after_scheme = &id_or_url[scheme_end + 3..];
                        if let Some(path_start) = after_scheme.find('/') {
                            base_url = id_or_url[..scheme_end + 3 + path_start].to_string();
                        }
                    }
                }
            }
            Err(e) => {
                write_error(&mut deps.stderr, pa.json, &format!("invalid URL: {}", e));
                return 2;
            }
        }
    }

    let client = ApiClient {
        base_url,
        api_key: pa.api_key.clone(),
    };

    if let Err(e) = client.burn(&secret_id) {
        write_error(&mut deps.stderr, pa.json, &format!("burn failed: {}", e));
        return 1;
    }

    if pa.json {
        let _ = writeln!(
            deps.stdout,
            "{}",
            serde_json::to_string(&serde_json::json!({"ok": true})).unwrap()
        );
    } else {
        let _ = writeln!(deps.stderr, "Secret burned.");
    }

    0
}
