use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::burn::{resolve_prefix, strip_ellipsis};
use crate::cli::{parse_flags, resolve_globals, CliError, Deps};
use crate::color::{color_func, DIM, HEADING, OPT, WARN};
use crate::envelope;
use crate::passphrase::write_error;
use crate::send::resolve_amk;

/// Format a byte count as a human-readable size (e.g. "1.2 KB").
fn format_size(bytes: i64) -> String {
    if bytes < 0 {
        return "0 B".into();
    }
    let b = bytes as u64;
    if b >= 1_048_576 {
        let whole = b / 1_048_576;
        let frac = (b % 1_048_576) * 10 / 1_048_576;
        if frac == 0 {
            format!("{} MB", whole)
        } else {
            format!("{}.{} MB", whole, frac)
        }
    } else if b >= 1024 {
        let whole = b / 1024;
        let frac = (b % 1024) * 10 / 1024;
        if frac == 0 {
            format!("{} KB", whole)
        } else {
            format!("{}.{} KB", whole, frac)
        }
    } else {
        format!("{} B", b)
    }
}

/// Format an ISO timestamp into a friendly date like "Feb 14, 2026 10:30".
fn format_datetime(iso: &str) -> String {
    if iso.len() < 16 {
        return iso.to_string();
    }
    let month = match &iso[5..7] {
        "01" => "Jan",
        "02" => "Feb",
        "03" => "Mar",
        "04" => "Apr",
        "05" => "May",
        "06" => "Jun",
        "07" => "Jul",
        "08" => "Aug",
        "09" => "Sep",
        "10" => "Oct",
        "11" => "Nov",
        "12" => "Dec",
        _ => return iso[0..16].to_string(),
    };
    let year = &iso[0..4];
    let day: u32 = iso[8..10].parse().unwrap_or(0);
    let time = &iso[11..16]; // "HH:MM"
    format!("{} {}, {} {}", month, day, year, time)
}

/// Format an ISO "expires_at" into a relative duration string like "23h 15m".
fn format_expires_relative(iso: &str) -> String {
    let Some(expires) = crate::send::parse_iso_to_epoch(iso) else {
        return "unknown".into();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if expires <= now {
        return "expired".into();
    }

    let remaining = expires - now;
    let days = remaining / 86400;
    let hours = (remaining % 86400) / 3600;
    let mins = (remaining % 3600) / 60;

    if days > 0 {
        format!("{}d {}h", days, hours)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m", mins)
    }
}

/// Try to decrypt a note from enc_meta. Returns `None` if AMK is missing or decryption fails.
fn decrypt_note(
    amk: &Option<Vec<u8>>,
    secret_id: &str,
    enc_meta: Option<&secrt_core::api::EncMetaV1>,
) -> Option<String> {
    let amk = amk.as_ref()?;
    let meta = enc_meta?;
    if meta.v != 1 {
        return None;
    }

    let ct = URL_SAFE_NO_PAD.decode(&meta.note.ct).ok()?;
    let nonce = URL_SAFE_NO_PAD.decode(&meta.note.nonce).ok()?;
    let salt = URL_SAFE_NO_PAD.decode(&meta.note.salt).ok()?;

    let encrypted = secrt_core::amk::EncryptedNote {
        ct,
        nonce,
        salt,
        version: meta.v,
    };

    let plaintext = secrt_core::amk::decrypt_note(amk, secret_id, &encrypted).ok()?;
    String::from_utf8(plaintext).ok()
}

pub fn run_info(args: &[String], deps: &mut Deps) -> i32 {
    let mut pa = match parse_flags(args) {
        Ok(pa) => pa,
        Err(CliError::ShowHelp) => {
            print_info_help(deps);
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
            "secret ID or share URL is required",
        );
        return 2;
    }

    if pa.api_key.is_empty() {
        write_error(
            &mut deps.stderr,
            pa.json,
            (deps.is_tty)(),
            "--api-key is required for info (hint: secrt auth login)",
        );
        return 2;
    }

    // Extract ID from URL or bare input
    let id_or_url = &pa.args[0];
    let mut secret_id = strip_ellipsis(id_or_url).to_string();
    let mut base_url = pa.base_url.clone();

    if id_or_url.contains('/') || id_or_url.contains('#') {
        match envelope::parse_share_url(id_or_url) {
            Ok((id, _)) => {
                secret_id = id;
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
                write_error(
                    &mut deps.stderr,
                    pa.json,
                    (deps.is_tty)(),
                    &format!("invalid URL: {}", e),
                );
                return 2;
            }
        }
    }

    let client = (deps.make_api)(&base_url, &pa.api_key);

    // Try exact ID first; on 404, attempt prefix resolution
    let meta = match client.get_secret_metadata(&secret_id) {
        Ok(m) => m,
        Err(e) if e.contains("404") => match resolve_prefix(client.as_ref(), &secret_id) {
            Ok(full_id) => match client.get_secret_metadata(&full_id) {
                Ok(m) => m,
                Err(e2) => {
                    write_error(
                        &mut deps.stderr,
                        pa.json,
                        (deps.is_tty)(),
                        &format!("info failed: {}", e2),
                    );
                    return 1;
                }
            },
            Err(resolve_err) => {
                write_error(
                    &mut deps.stderr,
                    pa.json,
                    (deps.is_tty)(),
                    &format!("info failed: {}", resolve_err),
                );
                return 1;
            }
        },
        Err(e) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                (deps.is_tty)(),
                &format!("info failed: {}", e),
            );
            return 1;
        }
    };

    // JSON output
    if pa.json {
        let _ = writeln!(
            deps.stdout,
            "{}",
            serde_json::to_string(&meta).unwrap_or_else(|_| "{}".into())
        );
        return 0;
    }

    let is_tty = (deps.is_tty)();
    let c = color_func(is_tty);

    // Try to decrypt note if enc_meta is present
    let amk = if meta.enc_meta.is_some() {
        resolve_amk(&pa, &*client).ok()
    } else {
        None
    };
    let note = decrypt_note(&amk, &meta.id, meta.enc_meta.as_ref());

    // Display
    let _ = writeln!(deps.stdout, "  {}  {}", c(OPT, "ID:"), meta.id);
    let _ = writeln!(deps.stdout, "  {}  {}", c(OPT, "URL:"), meta.share_url);
    let _ = writeln!(
        deps.stdout,
        "  {} {}",
        c(OPT, "Created:"),
        c(DIM, &format_datetime(&meta.created_at))
    );
    let _ = writeln!(
        deps.stdout,
        "  {} {} {}",
        c(OPT, "Expires:"),
        c(DIM, &format_datetime(&meta.expires_at)),
        c(
            DIM,
            &format!("({})", format_expires_relative(&meta.expires_at))
        )
    );
    let _ = writeln!(
        deps.stdout,
        "  {}  {}",
        c(OPT, "Size:"),
        format_size(meta.ciphertext_size)
    );

    if meta.passphrase_protected {
        let _ = writeln!(
            deps.stdout,
            "  {} Passphrase-protected",
            c(WARN, "\u{26b7}")
        );
    }

    if let Some(ref n) = note {
        let _ = writeln!(deps.stdout, "  {}\n  {}", c(OPT, "Note:"), c(DIM, n));
    } else if meta.enc_meta.is_some() {
        let _ = writeln!(
            deps.stdout,
            "  {}  {}",
            c(OPT, "Note:"),
            c(WARN, "(encrypted)")
        );
    }

    0
}

pub fn print_info_help(deps: &mut Deps) {
    use crate::color::{ARG, CMD};
    let c = color_func((deps.is_stdout_tty)());
    let w = &mut deps.stderr;
    let _ = writeln!(
        w,
        "{}\n  Show metadata for an active secret.\n",
        c(HEADING, "INFO")
    );
    let _ = writeln!(
        w,
        "{}\n  {} {} {}\n",
        c(HEADING, "USAGE"),
        c(CMD, "secrt"),
        c(CMD, "info"),
        c(ARG, "<id | url>")
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
    let _ = writeln!(w, "\n{}", c(HEADING, "NOTES"));
    let _ = writeln!(
        w,
        "  Accepts a full ID, a prefix (from {}), or a share URL.",
        c(CMD, "secrt list")
    );
    let _ = writeln!(w, "\n{}", c(HEADING, "EXAMPLES"));
    let _ = writeln!(w, "  {} {} abc123", c(CMD, "secrt"), c(CMD, "info"));
    let _ = writeln!(w, "  {} {} abc", c(CMD, "secrt"), c(CMD, "info"));
    let _ = writeln!(
        w,
        "  {} {} {} https://secrt.ca/s/abc123#...",
        c(CMD, "secrt"),
        c(CMD, "info"),
        c(DIM, "# from a share URL")
    );
}
