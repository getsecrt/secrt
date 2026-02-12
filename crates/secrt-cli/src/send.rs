use std::fs;
use std::io::{Read, Write};

use crate::cli::{parse_flags, print_send_help, resolve_globals, CliError, Deps, ParsedArgs};
use crate::client::CreateRequest;
use crate::color::{color_func, DIM, LABEL, SUCCESS, URL, WARN};
use crate::envelope::{self, format_share_link, SealParams};
use crate::gen::generate_password_from_args;
use crate::passphrase::{resolve_passphrase_for_send, write_error};

fn is_gen_mode(pa: &ParsedArgs) -> bool {
    pa.args
        .first()
        .map(|a| a == "gen" || a == "generate")
        .unwrap_or(false)
}

pub fn run_send(args: &[String], deps: &mut Deps) -> i32 {
    let mut pa = match parse_flags(args) {
        Ok(pa) => pa,
        Err(CliError::ShowHelp) => {
            print_send_help(deps);
            return 0;
        }
        Err(CliError::Error(e)) => {
            write_error(&mut deps.stderr, false, (deps.is_tty)(), &e);
            return 2;
        }
    };
    resolve_globals(&mut pa, deps);

    // Read plaintext from exactly one source
    let mut plaintext = match read_plaintext(&pa, deps) {
        Ok(p) => p,
        Err(e) => {
            write_error(&mut deps.stderr, pa.json, (deps.is_tty)(), &e);
            return 2;
        }
    };

    // In combined gen+create mode, capture the generated password for display
    let generated_password = if is_gen_mode(&pa) {
        Some(String::from_utf8(plaintext.clone()).unwrap_or_default())
    } else {
        None
    };

    // Apply --trim if requested
    if pa.trim {
        let trimmed = String::from_utf8_lossy(&plaintext);
        let trimmed = trimmed.trim();
        if trimmed.is_empty() {
            write_error(
                &mut deps.stderr,
                pa.json,
                (deps.is_tty)(),
                "input is empty after trimming",
            );
            return 2;
        }
        plaintext = trimmed.as_bytes().to_vec();
    }

    // Parse TTL
    let ttl_seconds = if !pa.ttl.is_empty() {
        match envelope::parse_ttl(&pa.ttl) {
            Ok(ttl) => Some(ttl),
            Err(e) => {
                write_error(&mut deps.stderr, pa.json, (deps.is_tty)(), &e.to_string());
                return 2;
            }
        }
    } else {
        None
    };

    // Resolve passphrase
    let passphrase = match resolve_passphrase_for_send(&pa, deps) {
        Ok(p) => p,
        Err(e) => {
            write_error(&mut deps.stderr, pa.json, (deps.is_tty)(), &e);
            return 2;
        }
    };
    let has_passphrase = !passphrase.is_empty();

    // Build file hint when encrypting a file
    let hint = if !pa.file.is_empty() {
        crate::fileutil::build_file_hint(&pa.file)
    } else {
        None
    };

    // Seal envelope
    let result = envelope::seal(SealParams {
        plaintext,
        passphrase,
        rand_bytes: &*deps.rand_bytes,
        hint,
        iterations: 0,
    });

    let result = match result {
        Ok(r) => r,
        Err(e) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                (deps.is_tty)(),
                &format!("encryption failed: {}", e),
            );
            return 1;
        }
    };

    // Upload to server
    let is_tty = (deps.is_tty)();

    // Show generated password before upload
    if let Some(ref pw) = generated_password {
        if !pa.json && !pa.silent {
            if is_tty {
                let c = color_func(true);
                let _ = writeln!(deps.stderr, "{} Generated:\n{}", c(SUCCESS, "\u{2726}"), pw);
            } else {
                let _ = writeln!(deps.stderr, "{}", pw);
            }
        }
    }

    if is_tty && !pa.silent {
        let c = color_func(true);
        let _ = write!(
            deps.stderr,
            "{} Encrypting and uploading...",
            c(WARN, "\u{25CB}")
        );
        let _ = deps.stderr.flush();
    }
    let client = (deps.make_api)(&pa.base_url, &pa.api_key);

    let resp = match client.create(CreateRequest {
        envelope: result.envelope,
        claim_hash: result.claim_hash,
        ttl_seconds,
    }) {
        Ok(r) => {
            if is_tty && !pa.silent {
                let c = color_func(true);
                let expires_fmt = format_expires(&r.expires_at);
                let msg = if has_passphrase {
                    "Encrypted and uploaded with passphrase."
                } else {
                    "Encrypted and uploaded."
                };
                let _ = write!(
                    deps.stderr,
                    "\r{} {}  {}\n",
                    c(SUCCESS, "\u{2713}"),
                    msg,
                    c(DIM, &expires_fmt)
                );
            }
            r
        }
        Err(e) => {
            if is_tty && !pa.silent {
                let _ = writeln!(deps.stderr);
            }
            write_error(&mut deps.stderr, pa.json, is_tty, &e);
            return 1;
        }
    };

    // Output
    let share_link = format_share_link(&resp.share_url, &result.url_key);

    if pa.json {
        let mut out = serde_json::json!({
            "id": resp.id,
            "share_url": resp.share_url,
            "share_link": share_link,
            "expires_at": resp.expires_at,
        });
        if let Some(ref pw) = generated_password {
            out["password"] = serde_json::Value::String(pw.clone());
        }
        let _ = writeln!(deps.stdout, "{}", serde_json::to_string(&out).unwrap());
    } else if (deps.is_stdout_tty)() {
        let c = color_func(true);
        let _ = writeln!(deps.stdout, "{}", c(URL, &share_link));
    } else {
        let _ = writeln!(deps.stdout, "{}", share_link);
    }

    0
}

/// Format ISO 8601 UTC timestamp to "Expires YYYY-MM-DD HH:MM TZ" in local time.
fn format_expires(iso: &str) -> String {
    use chrono::{DateTime, Local, Utc};

    if let Ok(utc) = iso.parse::<DateTime<Utc>>() {
        let local = utc.with_timezone(&Local);
        format!("Expires {}", local.format("%Y-%m-%d %H:%M %Z"))
    } else if iso.len() >= 16 {
        format!("Expires {} {} UTC", &iso[0..10], &iso[11..16])
    } else {
        format!("Expires {}", iso)
    }
}

fn read_plaintext(pa: &ParsedArgs, deps: &mut Deps) -> Result<Vec<u8>, String> {
    let gen_mode = is_gen_mode(pa);
    let mut sources = 0;
    if !pa.text.is_empty() {
        sources += 1;
    }
    if !pa.file.is_empty() {
        sources += 1;
    }
    if gen_mode {
        sources += 1;
    }

    if sources > 1 {
        return Err("specify exactly one input source (stdin, --text, --file, or gen)".into());
    }

    if gen_mode {
        if pa.gen_count > 1 {
            return Err("--count cannot be used with send".into());
        }
        let password = generate_password_from_args(pa, &*deps.rand_bytes)?;
        return Ok(password.into_bytes());
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
    if (deps.is_tty)() && !pa.multi_line {
        let c = color_func((deps.is_tty)());
        // Determine effective show mode
        let show_input = if pa.hidden {
            false
        } else if pa.show {
            true
        } else {
            pa.show_default
        };

        if show_input {
            if !pa.silent {
                let _ = writeln!(
                    deps.stderr,
                    "{}",
                    c(WARN, "Enter your secret below (input will be shown)")
                );
            }
            let prompt = if pa.silent { "" } else { "Secret: " };
            if !pa.silent {
                let _ = write!(deps.stderr, "{}", c(DIM, prompt));
                let _ = deps.stderr.flush();
            }
            let mut line = String::new();
            std::io::BufRead::read_line(&mut std::io::BufReader::new(&mut *deps.stdin), &mut line)
                .map_err(|e| format!("read secret: {}", e))?;
            // Strip trailing newline from the input line
            if line.ends_with('\n') {
                line.pop();
                if line.ends_with('\r') {
                    line.pop();
                }
            }
            if line.is_empty() {
                return Err("input is empty".into());
            }
            return Ok(line.into_bytes());
        } else {
            if !pa.silent {
                let _ = writeln!(
                    deps.stderr,
                    "{}",
                    c(DIM, "Enter your secret below (input is hidden)")
                );
            }
            let prompt = if pa.silent {
                String::new()
            } else {
                format!("{} ", c(LABEL, "Secret:"))
            };
            let secret = (deps.read_pass)(&prompt, &mut deps.stderr)
                .map_err(|e| format!("read secret: {}", e))?;
            if secret.is_empty() {
                return Err("input is empty".into());
            }
            return Ok(secret.into_bytes());
        }
    }

    if (deps.is_tty)() && pa.multi_line {
        let c = color_func(true);
        if !pa.silent {
            let _ = writeln!(
                deps.stderr,
                "{}",
                c(DIM, "Enter secret (Ctrl+D on empty line to finish):")
            );
        }
    }

    // Multi-line TTY or piped/redirected stdin: read all bytes
    let mut data = Vec::new();
    deps.stdin
        .read_to_end(&mut data)
        .map_err(|e| format!("read stdin: {}", e))?;
    if data.is_empty() {
        return Err("input is empty".into());
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_expires_valid_iso() {
        let result = format_expires("2026-02-09T00:00:00Z");
        assert!(result.starts_with("Expires "), "result: {}", result);
        assert!(result.contains("2026"), "result: {}", result);
    }

    #[test]
    fn format_expires_short_string() {
        let result = format_expires("2026-02");
        assert_eq!(result, "Expires 2026-02");
    }

    #[test]
    fn format_expires_exactly_16_chars() {
        // len >= 16, uses the substring fallback: [0..10] and [11..16]
        let result = format_expires("2026-02-09T12:34");
        assert_eq!(result, "Expires 2026-02-09 12:34 UTC");
    }

    #[test]
    fn format_expires_malformed_long() {
        // len >= 16 but not valid ISO — exercises the fallback path
        let result = format_expires("not-a-valid-date-but-long");
        assert!(result.starts_with("Expires "), "result: {}", result);
        assert!(result.contains("UTC"), "should use fallback: {}", result);
    }

    #[test]
    fn format_expires_empty() {
        let result = format_expires("");
        assert_eq!(result, "Expires ");
    }

    #[test]
    fn format_expires_15_chars() {
        // Just under 16 chars — uses the short fallback
        let result = format_expires("2026-02-09T12:3");
        assert_eq!(result, "Expires 2026-02-09T12:3");
    }
}
