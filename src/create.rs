use std::fs;
use std::io::{Read, Write};

use crate::cli::{parse_flags, print_create_help, resolve_globals, CliError, Deps, ParsedArgs};
use crate::client::CreateRequest;
use crate::envelope::{self, format_share_link, SealParams};
use crate::passphrase::{resolve_passphrase_for_create, write_error};

pub fn run_create(args: &[String], deps: &mut Deps) -> i32 {
    let mut pa = match parse_flags(args) {
        Ok(pa) => pa,
        Err(CliError::ShowHelp) => {
            print_create_help(deps);
            return 0;
        }
        Err(CliError::Error(e)) => {
            write_error(&mut deps.stderr, false, &e);
            return 2;
        }
    };
    resolve_globals(&mut pa, deps);

    // Read plaintext from exactly one source
    let plaintext = match read_plaintext(&pa, deps) {
        Ok(p) => p,
        Err(e) => {
            write_error(&mut deps.stderr, pa.json, &e);
            return 2;
        }
    };

    // Parse TTL
    let ttl_seconds = if !pa.ttl.is_empty() {
        match envelope::parse_ttl(&pa.ttl) {
            Ok(ttl) => Some(ttl),
            Err(e) => {
                write_error(&mut deps.stderr, pa.json, &format!("invalid TTL: {}", e));
                return 2;
            }
        }
    } else {
        None
    };

    // Resolve passphrase
    let passphrase = match resolve_passphrase_for_create(&pa, deps) {
        Ok(p) => p,
        Err(e) => {
            write_error(&mut deps.stderr, pa.json, &e);
            return 2;
        }
    };

    // Seal envelope
    let result = envelope::seal(SealParams {
        plaintext,
        passphrase,
        rand_bytes: &*deps.rand_bytes,
        hint: None,
        iterations: 0,
    });

    let result = match result {
        Ok(r) => r,
        Err(e) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                &format!("encryption failed: {}", e),
            );
            return 1;
        }
    };

    // Upload to server
    let client = (deps.make_api)(&pa.base_url, &pa.api_key);

    let resp = match client.create(CreateRequest {
        envelope: result.envelope,
        claim_hash: result.claim_hash,
        ttl_seconds,
    }) {
        Ok(r) => r,
        Err(e) => {
            write_error(&mut deps.stderr, pa.json, &e);
            return 1;
        }
    };

    // Output
    let share_link = format_share_link(&resp.share_url, &result.url_key);

    if pa.json {
        let out = serde_json::json!({
            "id": resp.id,
            "share_url": resp.share_url,
            "share_link": share_link,
            "expires_at": resp.expires_at,
        });
        let _ = writeln!(deps.stdout, "{}", serde_json::to_string(&out).unwrap());
    } else {
        let _ = writeln!(deps.stdout, "{}", share_link);
    }

    0
}

fn read_plaintext(pa: &ParsedArgs, deps: &mut Deps) -> Result<Vec<u8>, String> {
    let mut sources = 0;
    if !pa.text.is_empty() {
        sources += 1;
    }
    if !pa.file.is_empty() {
        sources += 1;
    }

    if sources > 1 {
        return Err("specify exactly one input source (stdin, --text, or --file)".into());
    }

    if !pa.text.is_empty() {
        return Ok(pa.text.as_bytes().to_vec());
    }

    if !pa.file.is_empty() {
        let data = fs::read(&pa.file).map_err(|e| format!("read file: {}", e))?;
        if data.is_empty() {
            return Err("file is empty".into());
        }
        return Ok(data);
    }

    // stdin
    if (deps.is_tty)() {
        let _ = writeln!(deps.stderr, "Enter secret (Ctrl+D to finish):");
    }

    let mut data = Vec::new();
    deps.stdin
        .read_to_end(&mut data)
        .map_err(|e| format!("read stdin: {}", e))?;
    if data.is_empty() {
        return Err("input is empty".into());
    }
    Ok(data)
}
