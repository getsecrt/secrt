use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crate::cli::{
    derive_base_url_from_url, parse_flags, print_get_help, resolve_globals, CliError, Deps,
};
use crate::color::{color_func, DIM, LABEL, SUCCESS, WARN};
use crate::envelope::{self, EnvelopeError, OpenParams, PayloadMeta};
use crate::fileutil::{extract_file_hint, preflight_writable, resolve_output_path};
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

    let share_url = pa.args[0].clone();

    // Parse URL to extract ID, url_key, and detect sync URLs
    let parsed = match envelope::parse_secret_url(&share_url) {
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

    // Derive base URL from share/sync URL if not explicitly set via flag/env.
    derive_base_url_from_url(&share_url, &mut pa);
    let stderr_tty = (deps.is_stderr_tty)();
    crate::instance_trust::warn_if_unofficial(
        &pa.base_url,
        &pa.trusted_servers,
        &mut deps.stderr,
        stderr_tty,
    );
    let base_url = pa.base_url.clone();

    // If this is a sync URL, delegate to the sync handler — but first
    // refuse to send the API key cross-instance (unauthenticated share
    // get is warn-only; sync sends credentials).
    let (id, url_key) = match parsed {
        envelope::ParsedSecretUrl::Sync { id, url_key } => {
            if let Err(code) = crate::instance_trust::block_if_cross_instance(
                &pa,
                "sync",
                &mut deps.stderr,
                stderr_tty,
            ) {
                return code;
            }
            return crate::sync::handle_sync_url(
                &id,
                &url_key,
                &base_url,
                &pa.api_key,
                deps,
                pa.json,
                pa.silent,
            );
        }
        envelope::ParsedSecretUrl::Share { id, url_key } => (id, url_key),
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

    // Pre-flight: when the caller pinned an explicit output file, confirm we
    // can write it *before* claiming. A one-time secret must not be consumed
    // if we already know we can't deliver it. (`--output -` is stdout; `--json`
    // ignores `--output`.)
    if !pa.json && !pa.output.is_empty() && pa.output != "-" {
        if let Err(e) = preflight_writable(&pa.output) {
            write_error(
                &mut deps.stderr,
                pa.json,
                (deps.is_tty)(),
                &format!(
                    "can't write to {}: {} — the secret was not retrieved; \
                     fix the path and try again",
                    pa.output, e
                ),
            );
            return 1;
        }
    }

    // Claim from server
    let client = (deps.make_api)(&base_url, &pa.api_key);

    let resp = match client.claim(&id, &claim_token) {
        Ok(r) => r,
        Err(e) => {
            // The server returns an indistinguishable 404 for expired /
            // already-claimed / unknown / bad-token (a deliberate
            // zero-knowledge property — see spec/v1/api.md §Claim). Since we
            // can't tell which, give the recipient a calm explanation of the
            // union rather than a raw "server error (404): not found".
            let msg = if e.contains("(404)") {
                "Secret unavailable. It may have already been opened, expired, \
                 or the link is incomplete."
                    .to_string()
            } else {
                format!("get failed: {}", e)
            };
            write_error(&mut deps.stderr, pa.json, (deps.is_tty)(), &msg);
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
        // Skip when --no-passphrase / -n is set — the user explicitly opted out.
        let mut candidates: Vec<String> = Vec::new();
        if !pa.no_passphrase {
            if !pa.passphrase_default.is_empty() {
                candidates.push(pa.passphrase_default.clone());
            }
            for p in &pa.decryption_passphrases {
                if !p.is_empty() && !candidates.contains(p) {
                    candidates.push(p.clone());
                }
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
        let filename = clean_filename(&pa.output);
        return write_file_output(&pa.output, &filename, plaintext, None, pa, deps);
    }

    // 4. File hint + stdout is TTY → auto-save
    if let Some(ref fh) = file_hint {
        if (deps.is_stdout_tty)() {
            let path = match resolve_output_path(&fh.filename) {
                Ok(p) => p,
                Err(e) => {
                    return rescue_save(
                        &fh.filename,
                        &fh.filename,
                        &e,
                        plaintext,
                        Some(&fh.mime),
                        pa,
                        deps,
                    )
                }
            };
            return write_file_output(
                &path.to_string_lossy(),
                &fh.filename,
                plaintext,
                Some(&fh.mime),
                pa,
                deps,
            );
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
                Err(e) => return rescue_save(filename, filename, &e, plaintext, None, pa, deps),
            };
            return write_file_output(&path.to_string_lossy(), filename, plaintext, None, pa, deps);
        }
    }
    0
}

/// Write plaintext to a file and show a success message on stderr. On write
/// failure the secret is *already claimed* (consumed server-side), so we never
/// just error — we hand off to [`rescue_save`] to land it somewhere else.
fn write_file_output(
    path: &str,
    filename: &str,
    plaintext: &[u8],
    mime: Option<&str>,
    pa: &crate::cli::ParsedArgs,
    deps: &mut Deps,
) -> i32 {
    if let Err(e) = fs::write(path, plaintext) {
        return rescue_save(filename, path, &e.to_string(), plaintext, mime, pa, deps);
    }
    report_saved(path, plaintext.len(), mime, pa, deps);
    0
}

/// Print the "Saved to <path> (<detail>)" confirmation on stderr.
fn report_saved(
    path: &str,
    size: usize,
    mime: Option<&str>,
    pa: &crate::cli::ParsedArgs,
    deps: &mut Deps,
) {
    if pa.silent {
        return;
    }
    let c = color_func((deps.is_tty)());
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

/// Ordered fallback directories for a post-claim rescue, mirroring how a
/// browser handles a download: the OS Downloads folder, then the home
/// directory, then the temp dir. An explicit `XDG_DOWNLOAD_DIR`/`HOME` env
/// wins over the platform default (and keeps this testable). `dirs::*` returns
/// `None` on, e.g., a bare server with no Downloads configured — we simply skip
/// that rung rather than fabricate a folder.
fn fallback_dirs(deps: &Deps) -> Vec<PathBuf> {
    let mut dirs_list = Vec::new();

    match (deps.getenv)("XDG_DOWNLOAD_DIR").filter(|s| !s.is_empty()) {
        Some(d) => dirs_list.push(PathBuf::from(d)),
        None => {
            if let Some(d) = dirs::download_dir() {
                dirs_list.push(d);
            }
        }
    }

    match (deps.getenv)("HOME")
        .or_else(|| (deps.getenv)("USERPROFILE"))
        .filter(|s| !s.is_empty())
    {
        Some(h) => dirs_list.push(PathBuf::from(h)),
        None => {
            if let Some(h) = dirs::home_dir() {
                dirs_list.push(h);
            }
        }
    }

    dirs_list.push(std::env::temp_dir());
    dirs_list
}

/// Last-resort delivery when a file write fails *after* the secret has been
/// claimed (and so deleted server-side). The in-memory plaintext is the only
/// copy, so never return without trying to land it somewhere: walk the
/// fallback chain (Downloads → home → temp), writing to the first that accepts
/// it and reporting where it went. Errors only if every location fails.
fn rescue_save(
    filename: &str,
    attempted: &str,
    reason: &str,
    plaintext: &[u8],
    mime: Option<&str>,
    pa: &crate::cli::ParsedArgs,
    deps: &mut Deps,
) -> i32 {
    if !pa.silent {
        let c = color_func((deps.is_stderr_tty)());
        // Name the *directory* that failed, not the collision-resolved file
        // name — "couldn't save rm to /bin" is clearer than "…to rm (1)".
        let _ = writeln!(
            deps.stderr,
            "{} couldn't save {} to {}: {}",
            c(WARN, "!"),
            filename,
            failed_location(attempted),
            reason,
        );
        let _ = writeln!(
            deps.stderr,
            "  this secret has already been retrieved and can't be fetched again.",
        );
    }

    for dir in fallback_dirs(deps) {
        if fs::create_dir_all(&dir).is_err() {
            continue;
        }
        // Re-resolve collisions from the *clean* filename in each fallback dir,
        // so a suffix earned in one directory doesn't leak into another.
        let candidate = match resolve_output_path(&dir.join(filename).to_string_lossy()) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if fs::write(&candidate, plaintext).is_ok() {
            report_saved(
                &candidate.to_string_lossy(),
                plaintext.len(),
                mime,
                pa,
                deps,
            );
            return 0;
        }
    }

    write_error(
        &mut deps.stderr,
        pa.json,
        (deps.is_tty)(),
        &format!(
            "couldn't save {} to {} or any fallback location ({}); \
             it has already been retrieved and cannot be recovered",
            filename,
            failed_location(attempted),
            reason
        ),
    );
    1
}

/// The basename to reuse when rescuing a write to another directory. Falls
/// back to `secret.bin` for odd inputs (trailing slash, empty).
fn clean_filename(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("secret.bin")
        .to_string()
}

/// Describe the directory a failed write was aimed at, for the rescue warning.
/// A bare relative name (e.g. `rm` or `rm (1)`) has no parent, so report the
/// current working directory instead of an empty string.
fn failed_location(attempted: &str) -> String {
    match std::path::Path::new(attempted)
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
    {
        Some(d) => d.display().to_string(),
        None => std::env::current_dir()
            .map(|d| d.display().to_string())
            .unwrap_or_else(|_| ".".to_string()),
    }
}
