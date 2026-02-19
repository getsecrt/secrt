use std::fs;
use std::io::{Read, Write};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::cli::{parse_flags, print_send_help, resolve_globals, CliError, Deps, ParsedArgs};
use crate::client::CreateRequest;
use crate::color::{color_func, DIM, LABEL, SUCCESS, URL, WARN};
use crate::envelope::{self, format_share_link, CompressionPolicy, PayloadMeta, SealParams};
use crate::gen::generate_password_from_args;
use crate::passphrase::{resolve_passphrase_for_send, write_error};

fn is_gen_mode(pa: &ParsedArgs) -> bool {
    pa.args
        .first()
        .map(|a| a == "gen" || a == "generate")
        .unwrap_or(false)
}

fn trim_plaintext_utf8(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(plaintext)
        .map_err(|_| "--trim requires valid UTF-8 input".to_string())?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("input is empty after trimming".to_string());
    }
    Ok(trimmed.as_bytes().to_vec())
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
        plaintext = match trim_plaintext_utf8(&plaintext) {
            Ok(v) => v,
            Err(e) => {
                write_error(&mut deps.stderr, pa.json, (deps.is_tty)(), &e);
                return 2;
            }
        };
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

    // Build encrypted payload metadata (stored inside ciphertext frame).
    let metadata = if !pa.file.is_empty() {
        crate::fileutil::build_file_metadata(&pa.file).unwrap_or_else(PayloadMeta::binary)
    } else if std::str::from_utf8(&plaintext).is_ok() {
        PayloadMeta::text()
    } else {
        PayloadMeta::binary()
    };

    // Seal envelope
    let result = envelope::seal(SealParams {
        content: plaintext,
        metadata,
        passphrase,
        rand_bytes: &*deps.rand_bytes,
        compression_policy: CompressionPolicy::default(),
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

    // Attach encrypted note if --note was provided
    if !pa.note.is_empty() {
        attach_note(&pa, deps, &*client, &resp.id, is_tty);
    }

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

    // Render QR code to stderr if requested and TTY (skip in --json mode)
    if pa.qr && !pa.json && is_tty {
        if let Ok(code) = qrcode::QrCode::new(&share_link) {
            let qr_string = crate::qr::render_qr_compact(&code);
            let _ = write!(deps.stderr, "\n{}", qr_string);
        }
    }

    0
}

/// Parse a subset of ISO 8601 UTC timestamps ("2026-02-09T00:00:00Z") to unix epoch seconds.
pub(crate) fn parse_iso_to_epoch(iso: &str) -> Option<u64> {
    let b = iso.as_bytes();
    if b.len() < 16 {
        return None;
    }
    let y: u64 = iso[0..4].parse().ok()?;
    let m: u64 = iso[5..7].parse().ok()?;
    let d: u64 = iso[8..10].parse().ok()?;
    let hh: u64 = iso[11..13].parse().ok()?;
    let mm: u64 = iso[14..16].parse().ok()?;
    let ss: u64 = if b.len() >= 19 {
        iso[17..19].parse().unwrap_or(0)
    } else {
        0
    };
    // Days from civil date (Euclidean affine algorithm)
    let (y2, m2) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y2 / 400;
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hh * 3600 + mm * 60 + ss)
}

/// Format seconds into a human-readable relative duration, e.g. "3 days, 2 hours".
pub(crate) fn humanize_seconds(secs: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 3600;
    const DAY: u64 = 86400;

    let (val, unit, remainder) = if secs >= DAY {
        (secs / DAY, "day", secs % DAY)
    } else if secs >= HOUR {
        (secs / HOUR, "hour", secs % HOUR)
    } else if secs >= MINUTE {
        (secs / MINUTE, "minute", secs % MINUTE)
    } else {
        return format!("{secs} second{}", if secs == 1 { "" } else { "s" });
    };

    let primary = format!("{val} {unit}{}", if val == 1 { "" } else { "s" });

    // Add a secondary unit if meaningful
    let secondary = if unit == "day" && remainder >= HOUR {
        let h = remainder / HOUR;
        Some(format!("{h} hour{}", if h == 1 { "" } else { "s" }))
    } else if unit == "hour" && remainder >= MINUTE {
        let m = remainder / MINUTE;
        Some(format!("{m} minute{}", if m == 1 { "" } else { "s" }))
    } else {
        None
    };

    match secondary {
        Some(s) => format!("{primary}, {s}"),
        None => primary,
    }
}

/// Format ISO 8601 UTC expiry to "Expires in 3 days, 2 hours (2026-02-09 00:00 UTC)".
fn format_expires(iso: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let utc_display = if iso.len() >= 16 {
        format!("{} {} UTC", &iso[0..10], &iso[11..16])
    } else {
        iso.to_string()
    };

    let Some(expires) = parse_iso_to_epoch(iso) else {
        return format!("Expires {utc_display}");
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if expires <= now {
        return format!("Expired ({utc_display})");
    }

    let remaining = expires - now;
    format!("Expires in {} ({utc_display})", humanize_seconds(remaining))
}

/// Resolve the AMK from the server by fetching the wrapper and unwrapping with the local root key.
pub(crate) fn resolve_amk(
    pa: &ParsedArgs,
    client: &(dyn crate::client::SecretApi + '_),
) -> Result<Vec<u8>, String> {
    use secrt_core::amk::{build_wrap_aad, derive_amk_wrap_key, unwrap_amk, WrappedAmk};

    // Parse the local API key to get root_key and prefix
    let local_key = secrt_core::parse_local_api_key(&pa.api_key)
        .map_err(|e| format!("cannot parse API key for AMK: {}", e))?;

    // Fetch the wrapper from the server (includes user_id for AAD reconstruction)
    let wrapper_resp = client.get_amk_wrapper()?.ok_or_else(|| {
        "no notes key found; create one via web settings or `secrt auth login`".to_string()
    })?;

    // Derive the wrap key from root_key
    let wrap_key =
        derive_amk_wrap_key(&local_key.root_key).map_err(|e| format!("derive wrap key: {}", e))?;

    // Decode the wrapper fields
    let ct = URL_SAFE_NO_PAD
        .decode(&wrapper_resp.wrapped_amk)
        .map_err(|e| format!("decode wrapped_amk: {}", e))?;
    let nonce = URL_SAFE_NO_PAD
        .decode(&wrapper_resp.nonce)
        .map_err(|e| format!("decode nonce: {}", e))?;

    // Build AAD using user_id from the wrapper response
    let aad = build_wrap_aad(
        &wrapper_resp.user_id,
        &local_key.prefix,
        wrapper_resp.version as u16,
    );

    let wrapped = WrappedAmk {
        ct,
        nonce,
        version: wrapper_resp.version as u16,
    };

    unwrap_amk(&wrapped, &wrap_key, &aad).map_err(|e| format!("unwrap AMK: {}", e))
}

/// Attach an encrypted note to a secret after creation. Non-fatal on failure.
fn attach_note(
    pa: &ParsedArgs,
    deps: &mut Deps,
    client: &(dyn crate::client::SecretApi + '_),
    secret_id: &str,
    is_tty: bool,
) {
    let c = color_func(is_tty);

    // Require authentication
    if pa.api_key.is_empty() {
        if !pa.silent {
            let _ = writeln!(
                deps.stderr,
                "{} --note requires authentication (--api-key)",
                c(WARN, "!")
            );
        }
        return;
    }

    // Resolve AMK
    let amk = match resolve_amk(pa, client) {
        Ok(amk) => amk,
        Err(e) => {
            if !pa.silent {
                let _ = writeln!(deps.stderr, "{} note not attached: {}", c(WARN, "!"), e);
            }
            return;
        }
    };

    // Encrypt the note
    let encrypted =
        match secrt_core::amk::encrypt_note(&amk, secret_id, pa.note.as_bytes(), &*deps.rand_bytes)
        {
            Ok(enc) => enc,
            Err(e) => {
                if !pa.silent {
                    let _ = writeln!(
                        deps.stderr,
                        "{} note encryption failed: {}",
                        c(WARN, "!"),
                        e
                    );
                }
                return;
            }
        };

    // Build enc_meta JSON
    let enc_meta = secrt_core::api::EncMetaV1 {
        v: 1,
        note: secrt_core::api::EncMetaNoteV1 {
            ct: URL_SAFE_NO_PAD.encode(&encrypted.ct),
            nonce: URL_SAFE_NO_PAD.encode(&encrypted.nonce),
            salt: URL_SAFE_NO_PAD.encode(&encrypted.salt),
        },
    };

    // Upload
    if let Err(e) = client.update_secret_meta(secret_id, &enc_meta, 1) {
        if !pa.silent {
            let _ = writeln!(deps.stderr, "{} note not attached: {}", c(WARN, "!"), e);
        }
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
    fn format_expires_future_iso() {
        let result = format_expires("2099-12-31T23:59:59Z");
        assert!(result.starts_with("Expires in "), "result: {}", result);
        assert!(
            result.contains("(2099-12-31 23:59 UTC)"),
            "result: {}",
            result
        );
    }

    #[test]
    fn format_expires_past_iso() {
        let result = format_expires("2020-01-01T00:00:00Z");
        assert!(result.starts_with("Expired ("), "result: {}", result);
    }

    #[test]
    fn format_expires_short_string() {
        let result = format_expires("2026-02");
        assert_eq!(result, "Expires 2026-02");
    }

    #[test]
    fn format_expires_malformed_long() {
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
        let result = format_expires("2026-02-09T12:3");
        assert_eq!(result, "Expires 2026-02-09T12:3");
    }

    #[test]
    fn parse_iso_known_epoch() {
        // 2000-01-01T00:00:00Z = 946684800
        assert_eq!(parse_iso_to_epoch("2000-01-01T00:00:00Z"), Some(946684800));
    }

    #[test]
    fn parse_iso_unix_epoch() {
        assert_eq!(parse_iso_to_epoch("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn humanize_days_and_hours() {
        assert_eq!(humanize_seconds(3 * 86400 + 2 * 3600), "3 days, 2 hours");
    }

    #[test]
    fn humanize_one_day() {
        assert_eq!(humanize_seconds(86400), "1 day");
    }

    #[test]
    fn humanize_hours_and_minutes() {
        assert_eq!(humanize_seconds(2 * 3600 + 30 * 60), "2 hours, 30 minutes");
    }

    #[test]
    fn humanize_seconds_only() {
        assert_eq!(humanize_seconds(45), "45 seconds");
        assert_eq!(humanize_seconds(1), "1 second");
    }
}
