use std::fs;
use std::io::Write;

use crate::cli::{parse_flags, print_get_help, resolve_globals, CliError, Deps};
use crate::color::{color_func, DIM, LABEL, SUCCESS, WARN};
use crate::envelope::{self, EnvelopeError, OpenParams, PayloadMeta};
use crate::fileutil::{extract_file_hint, resolve_output_path};
use crate::passphrase::{resolve_passphrase, write_error};

pub fn run_get(args: &[String], deps: &mut Deps) -> i32 {
    let mut pa = match parse_flags(args) {
        Ok(pa) => pa,
        Err(CliError::ShowHelp) => {
            print_get_help(deps);
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
            "share URL is required",
        );
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
                (deps.is_tty)(),
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
                (deps.is_tty)(),
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
            write_error(
                &mut deps.stderr,
                pa.json,
                (deps.is_tty)(),
                &format!("get failed: {}", e),
            );
            return 1;
        }
    };

    let is_tty = (deps.is_tty)();
    let needs_pass = envelope::requires_passphrase(&resp.envelope);

    // Determine if an explicit passphrase flag was set
    let explicit_flag =
        pa.passphrase_prompt || !pa.passphrase_env.is_empty() || !pa.passphrase_file.is_empty();

    // --- Phase A: Explicit flag set → use only that passphrase ---
    if explicit_flag {
        let mut passphrase = match resolve_passphrase(&pa, deps) {
            Ok(p) => p,
            Err(e) => {
                write_error(&mut deps.stderr, pa.json, is_tty, &e);
                return 1;
            }
        };

        let can_retry = pa.passphrase_prompt && is_tty && needs_pass;
        let opened = loop {
            match envelope::open(OpenParams {
                envelope: resp.envelope.clone(),
                url_key: url_key.clone(),
                passphrase: passphrase.clone(),
            }) {
                Ok(v) => break v,
                Err(EnvelopeError::DecryptionFailed) if can_retry => {
                    let c = color_func(is_tty);
                    let _ = writeln!(deps.stderr, "{}", c(WARN, "Wrong passphrase, try again."));
                    let prompt_c = color_func(true);
                    let prompt = format!("{} ", prompt_c(LABEL, "Passphrase:"));
                    match (deps.read_pass)(&prompt, &mut deps.stderr) {
                        Ok(p) if !p.is_empty() => passphrase = p,
                        Ok(_) => {
                            write_error(
                                &mut deps.stderr,
                                pa.json,
                                is_tty,
                                "passphrase must not be empty",
                            );
                            return 1;
                        }
                        Err(e) => {
                            write_error(
                                &mut deps.stderr,
                                pa.json,
                                is_tty,
                                &format!("read passphrase: {}", e),
                            );
                            return 1;
                        }
                    }
                }
                Err(e) => {
                    write_error(&mut deps.stderr, pa.json, is_tty, &e.to_string());
                    return 1;
                }
            }
        };

        return output_plaintext(
            &opened.content,
            &pa,
            deps,
            &resp.expires_at,
            &opened.metadata,
        );
    }

    // --- Phase B: Try configured passphrases (default + decryption list) ---
    {
        // Build candidate list: default passphrase first, then decryption_passphrases, deduped
        let mut candidates: Vec<String> = Vec::new();
        if !pa.passphrase_default.is_empty() {
            candidates.push(pa.passphrase_default.clone());
        }
        for p in &pa.decryption_passphrases {
            if !p.is_empty() && !candidates.contains(p) {
                candidates.push(p.clone());
            }
        }

        // If envelope doesn't need a passphrase, try empty passphrase (no-passphrase path)
        if !needs_pass {
            match envelope::open(OpenParams {
                envelope: resp.envelope.clone(),
                url_key: url_key.clone(),
                passphrase: String::new(),
            }) {
                Ok(opened) => {
                    return output_plaintext(
                        &opened.content,
                        &pa,
                        deps,
                        &resp.expires_at,
                        &opened.metadata,
                    )
                }
                Err(EnvelopeError::DecryptionFailed) => {
                    // Fall through to candidates or prompt
                }
                Err(e) => {
                    write_error(&mut deps.stderr, pa.json, is_tty, &e.to_string());
                    return 1;
                }
            }
        }

        // Try each candidate
        for candidate in &candidates {
            match envelope::open(OpenParams {
                envelope: resp.envelope.clone(),
                url_key: url_key.clone(),
                passphrase: candidate.clone(),
            }) {
                Ok(opened) => {
                    return output_plaintext(
                        &opened.content,
                        &pa,
                        deps,
                        &resp.expires_at,
                        &opened.metadata,
                    )
                }
                Err(EnvelopeError::DecryptionFailed) => continue,
                Err(e) => {
                    write_error(&mut deps.stderr, pa.json, is_tty, &e.to_string());
                    return 1;
                }
            }
        }

        // All candidates failed (or no candidates existed)
        let tried = candidates.len();

        // --- Phase C: Fallback to interactive prompt or error ---
        if !needs_pass && tried == 0 {
            // No passphrase needed and decryption failed with empty passphrase — this is
            // a genuine decryption error (wrong URL key), not a passphrase issue
            write_error(&mut deps.stderr, pa.json, is_tty, "decryption failed");
            return 1;
        }

        if !is_tty {
            if tried > 0 {
                write_error(
                    &mut deps.stderr,
                    pa.json,
                    false,
                    &format!(
                        "this secret is passphrase-protected; tried {} configured passphrase(s) \
                         but none matched. Use -p, --passphrase-env, or --passphrase-file",
                        tried,
                    ),
                );
            } else {
                write_error(
                    &mut deps.stderr,
                    pa.json,
                    false,
                    "this secret is passphrase-protected; use -p, --passphrase-env, or --passphrase-file",
                );
            }
            return 1;
        }

        // TTY: show notice and prompt interactively
        if !pa.silent {
            let c = color_func(true);
            if tried > 0 {
                let _ = writeln!(
                    deps.stderr,
                    "{} {}",
                    c(WARN, "\u{26b7}"),
                    c(
                        DIM,
                        &format!(
                        "Passphrase-protected \u{2014} {} configured passphrase(s) didn't match",
                        tried,
                    )
                    )
                );
            } else {
                let _ = writeln!(
                    deps.stderr,
                    "{} {}",
                    c(WARN, "\u{26b7}"),
                    c(DIM, "This secret is passphrase-protected")
                );
            }
        }

        // Interactive retry loop
        loop {
            let c = color_func(true);
            let prompt = format!("{} ", c(LABEL, "Passphrase:"));
            let passphrase = match (deps.read_pass)(&prompt, &mut deps.stderr) {
                Ok(p) if !p.is_empty() => p,
                Ok(_) => {
                    write_error(
                        &mut deps.stderr,
                        pa.json,
                        is_tty,
                        "passphrase must not be empty",
                    );
                    return 1;
                }
                Err(e) => {
                    write_error(
                        &mut deps.stderr,
                        pa.json,
                        is_tty,
                        &format!("read passphrase: {}", e),
                    );
                    return 1;
                }
            };

            match envelope::open(OpenParams {
                envelope: resp.envelope.clone(),
                url_key: url_key.clone(),
                passphrase,
            }) {
                Ok(opened) => {
                    return output_plaintext(
                        &opened.content,
                        &pa,
                        deps,
                        &resp.expires_at,
                        &opened.metadata,
                    )
                }
                Err(EnvelopeError::DecryptionFailed) => {
                    let c = color_func(is_tty);
                    let _ = writeln!(deps.stderr, "{}", c(WARN, "Wrong passphrase, try again."));
                    continue;
                }
                Err(e) => {
                    write_error(&mut deps.stderr, pa.json, is_tty, &e.to_string());
                    return 1;
                }
            }
        }
    }
}

/// Output decrypted plaintext to stdout in the appropriate format.
///
/// Decision matrix:
/// 1. `--json`             → JSON output (with file hint fields and base64 for binary)
/// 2. `--output -`         → raw bytes to stdout (no label)
/// 3. `--output <path>`    → write file, show success on stderr
/// 4. file hint + TTY      → auto-save to `./hint.filename`, show success on stderr
/// 5. piped stdout         → raw bytes to stdout
/// 6. no hint + TTY        → "Secret:" label + text
fn output_plaintext(
    plaintext: &[u8],
    pa: &crate::cli::ParsedArgs,
    deps: &mut Deps,
    expires_at: &str,
    metadata: &PayloadMeta,
) -> i32 {
    let file_hint = extract_file_hint(metadata);

    // 1. JSON mode
    if pa.json {
        let mut out = serde_json::Map::new();

        // Use base64 for binary data, plain string for valid UTF-8
        if let Some(ref fh) = file_hint {
            out.insert("type".into(), serde_json::json!("file"));
            out.insert("filename".into(), serde_json::json!(fh.filename.clone()));
            out.insert("mime".into(), serde_json::json!(fh.mime.clone()));
        }

        match std::str::from_utf8(plaintext) {
            Ok(text) => {
                out.insert("plaintext".into(), serde_json::json!(text));
            }
            Err(_) => {
                use base64::engine::general_purpose::STANDARD;
                use base64::Engine;
                out.insert(
                    "plaintext_base64".into(),
                    serde_json::json!(STANDARD.encode(plaintext)),
                );
            }
        }

        out.insert("expires_at".into(), serde_json::json!(expires_at));
        let _ = writeln!(
            deps.stdout,
            "{}",
            serde_json::to_string(&serde_json::Value::Object(out)).unwrap()
        );
        return 0;
    }

    // 2. --output - → raw bytes to stdout
    if pa.output == "-" {
        let _ = deps.stdout.write_all(plaintext);
        return 0;
    }

    // 3. --output <path> → write to explicit path
    if !pa.output.is_empty() {
        return write_file_output(&pa.output, plaintext, None, pa, deps);
    }

    // 4. File hint + stdout is TTY → auto-save
    if let Some(ref fh) = file_hint {
        if (deps.is_stdout_tty)() {
            let path = match resolve_output_path(&fh.filename) {
                Ok(p) => p,
                Err(e) => {
                    let _ = writeln!(deps.stderr, "error: {}", e);
                    return 1;
                }
            };
            return write_file_output(&path.to_string_lossy(), plaintext, Some(&fh.mime), pa, deps);
        }
    }

    // 5. Piped stdout (any hint) → raw bytes
    if !(deps.is_stdout_tty)() {
        let _ = deps.stdout.write_all(plaintext);
        return 0;
    }

    // 6. No hint, TTY → text output (with binary detection)
    match std::str::from_utf8(plaintext) {
        Ok(text) => {
            if !pa.silent {
                let c = color_func(true);
                let _ = writeln!(deps.stderr, "{}", c(LABEL, "Secret:"));
            }
            let _ = deps.stdout.write_all(text.as_bytes());
            if !text.ends_with('\n') {
                let _ = writeln!(deps.stdout);
            }
        }
        Err(_) => {
            // Binary data without a hint — auto-save since the secret is already burned
            let filename = "secret.bin";
            let path = match resolve_output_path(filename) {
                Ok(p) => p,
                Err(e) => {
                    let _ = writeln!(deps.stderr, "error: {}", e);
                    return 1;
                }
            };
            return write_file_output(&path.to_string_lossy(), plaintext, None, pa, deps);
        }
    }
    0
}

/// Write plaintext to a file and show a success message on stderr.
fn write_file_output(
    path: &str,
    plaintext: &[u8],
    mime: Option<&str>,
    pa: &crate::cli::ParsedArgs,
    deps: &mut Deps,
) -> i32 {
    if let Err(e) = fs::write(path, plaintext) {
        let _ = writeln!(deps.stderr, "error: write file: {}", e);
        return 1;
    }

    if !pa.silent {
        let c = color_func((deps.is_tty)());
        let size = plaintext.len();
        let detail = match mime {
            Some(m) => format!("{}, {} bytes", m, size),
            None => format!("{} bytes", size),
        };
        let _ = writeln!(
            deps.stderr,
            "{} Saved to {} ({})",
            c(SUCCESS, "\u{2713}"),
            path,
            c(DIM, &detail),
        );
    }
    0
}
