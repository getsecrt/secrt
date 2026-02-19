use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::cli::{parse_flags, print_list_help, resolve_globals, CliError, Deps};
use crate::color::{color_func, ColorFn, DIM, HEADING, WARN};
use crate::passphrase::write_error;
use crate::send::{parse_iso_to_epoch, resolve_amk};

/// Format bytes into a compact human-readable size (e.g. "1.2 KB", "256 B").
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

/// Format ISO 8601 "created_at" into a short date, e.g. "Feb 14, 10:30".
fn format_created(iso: &str) -> String {
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
    let day: u32 = iso[8..10].parse().unwrap_or(0);
    let time = &iso[11..16]; // "HH:MM"
    format!("{} {}, {}", month, day, time)
}

/// Format ISO 8601 "expires_at" into a relative duration, e.g. "23:15:30".
/// Returns `(display_string, visual_width)` — the display string may contain
/// ANSI escapes so visual width is tracked separately.
fn format_expires_in(iso: &str, c: &ColorFn) -> (String, usize) {
    let Some(expires) = parse_iso_to_epoch(iso) else {
        return ("?".into(), 1);
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if expires <= now {
        return ("expired".into(), 7);
    }

    let remaining = expires - now;
    humanize_compact(remaining, c)
}

/// Compact relative duration as `[Nd ]HH:MM:SS` with `:SS` dimmed.
/// Returns `(display_string, visual_width)`.
fn humanize_compact(secs: u64, c: &ColorFn) -> (String, usize) {
    const HOUR: u64 = 3600;
    const DAY: u64 = 86400;

    let d = secs / DAY;
    let rem = secs % DAY;
    let h = rem / HOUR;
    let m = (rem % HOUR) / 60;
    let s = rem % 60;

    let dim_sec = c(DIM, &format!(":{:02}", s));

    if d > 0 {
        let plain = format!("{}d {:02}:{:02}", d, h, m);
        let visual = plain.len() + 3; // +3 for ":SS"
        (format!("{}{}", plain, dim_sec), visual)
    } else {
        let plain = format!("{:02}:{:02}", h, m);
        let visual = plain.len() + 3; // +3 for ":SS"
        (format!("{}{}", plain, dim_sec), visual)
    }
}

/// Truncate an ID to at most `max` chars, appending `…` if truncated.
fn truncate_id(id: &str, max: usize) -> String {
    if id.len() <= max {
        id.to_string()
    } else {
        format!("{}\u{2026}", &id[..max])
    }
}

struct ListRow {
    id: String,
    created: String,
    expires_display: String,
    expires_vw: usize,
    size: String,
    passphrase: bool,
    note: Option<String>,
    has_enc_meta: bool,
}

/// Try to decrypt a note from enc_meta. Returns `None` if AMK is missing or decryption fails.
fn decrypt_note_text(
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

pub fn run_list(args: &[String], deps: &mut Deps) -> i32 {
    let mut pa = match parse_flags(args) {
        Ok(pa) => pa,
        Err(CliError::ShowHelp) => {
            print_list_help(deps);
            return 0;
        }
        Err(CliError::Error(e)) => {
            write_error(&mut deps.stderr, false, (deps.is_tty)(), &e);
            return 2;
        }
    };
    resolve_globals(&mut pa, deps);

    if pa.api_key.is_empty() {
        write_error(
            &mut deps.stderr,
            pa.json,
            (deps.is_tty)(),
            "--api-key is required for list (hint: secrt auth login)",
        );
        return 2;
    }

    let limit = pa.list_limit;
    let offset = pa.list_offset;

    let client = (deps.make_api)(&pa.base_url, &pa.api_key);

    let resp = match client.list(limit, offset) {
        Ok(r) => r,
        Err(e) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                (deps.is_tty)(),
                &format!("list failed: {}", e),
            );
            return 1;
        }
    };

    if pa.json {
        let _ = writeln!(
            deps.stdout,
            "{}",
            serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into())
        );
        return 0;
    }

    if resp.secrets.is_empty() {
        if !pa.silent {
            let _ = writeln!(deps.stderr, "No active secrets.");
        }
        return 0;
    }

    let is_tty = (deps.is_tty)();
    let c = color_func(is_tty);

    // Check if any secrets have enc_meta — if so, try to resolve the AMK for note decryption
    let any_enc_meta = resp.secrets.iter().any(|s| s.enc_meta.is_some());
    let amk_result = if any_enc_meta {
        Some(resolve_amk(&pa, &*client))
    } else {
        None
    };
    let amk = amk_result.as_ref().and_then(|r| r.as_ref().ok().cloned());

    // Build table rows
    let id_max = 16;
    let rows: Vec<ListRow> = resp
        .secrets
        .iter()
        .map(|s| {
            let (exp_display, exp_width) = format_expires_in(&s.expires_at, &c);
            let note = decrypt_note_text(&amk, &s.id, s.enc_meta.as_ref());
            ListRow {
                id: truncate_id(&s.id, id_max),
                created: format_created(&s.created_at),
                expires_display: exp_display,
                expires_vw: exp_width,
                size: format_size(s.ciphertext_size),
                passphrase: s.passphrase_protected,
                note,
                has_enc_meta: s.enc_meta.is_some(),
            }
        })
        .collect();

    // Show Note column when any secret has encrypted metadata (even if we couldn't decrypt)
    let show_notes = rows.iter().any(|r| r.has_enc_meta);

    // Measure column widths
    let hdr = ("ID", "Created", "Expires In", "Size", "\u{26b7}");
    let w_id = rows
        .iter()
        .map(|r| r.id.len())
        .max()
        .unwrap_or(0)
        .max(hdr.0.len());
    let w_created = rows
        .iter()
        .map(|r| r.created.len())
        .max()
        .unwrap_or(0)
        .max(hdr.1.len());
    let w_expires = rows
        .iter()
        .map(|r| r.expires_vw)
        .max()
        .unwrap_or(0)
        .max(hdr.2.len());
    let w_size = rows
        .iter()
        .map(|r| r.size.len())
        .max()
        .unwrap_or(0)
        .max(hdr.3.len());

    // Print header (centered above each column)
    let note_hdr = if show_notes { "  Note" } else { "" };
    let _ = writeln!(
        deps.stdout,
        "{}",
        c(
            HEADING,
            &format!(
                "{:^w_id$}  {:^w_created$}  {:^w_expires$}  {:^w_size$}  {}{}",
                hdr.0, hdr.1, hdr.2, hdr.3, hdr.4, note_hdr
            )
        )
    );

    // Print rows
    for row in &rows {
        let pp_display = if row.passphrase {
            c(WARN, "\u{26b7}")
        } else {
            String::new()
        };
        let note_display = if show_notes {
            match &row.note {
                Some(n) => format!("  {}", c(DIM, n)),
                None if row.has_enc_meta => format!("  {}", c(WARN, "(encrypted)")),
                None => String::new(),
            }
        } else {
            String::new()
        };
        // Right-align expires column manually since the display string contains ANSI escapes
        let exp_pad = w_expires.saturating_sub(row.expires_vw);
        let _ = writeln!(
            deps.stdout,
            "{:<w_id$}  {:<w_created$}  {}{}  {:>w_size$}  {}{}",
            row.id,
            c(DIM, &row.created),
            " ".repeat(exp_pad),
            row.expires_display,
            row.size,
            pp_display,
            note_display
        );
    }

    // Hint when notes exist but AMK is unavailable
    let has_encrypted_notes = rows.iter().any(|r| r.has_enc_meta && r.note.is_none());
    if has_encrypted_notes && !pa.silent {
        let _ = writeln!(
            deps.stderr,
            "{}",
            c(
                WARN,
                "Sync your notes key from another browser/device to view your notes (secrt sync)"
            )
        );
    }

    // Pagination info
    let shown = resp.offset + resp.secrets.len() as i64;
    if shown < resp.total && !pa.silent {
        let _ = writeln!(
            deps.stderr,
            "{}",
            c(
                DIM,
                &format!(
                    "Showing {}-{} of {} (use --offset {} to see more)",
                    resp.offset + 1,
                    shown,
                    resp.total,
                    shown
                )
            )
        );
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_size_bytes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(256), "256 B");
        assert_eq!(format_size(1023), "1023 B");
    }

    #[test]
    fn format_size_kb() {
        assert_eq!(format_size(1024), "1 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(10240), "10 KB");
    }

    #[test]
    fn format_size_mb() {
        assert_eq!(format_size(1048576), "1 MB");
        assert_eq!(format_size(1572864), "1.5 MB");
    }

    #[test]
    fn format_size_negative() {
        assert_eq!(format_size(-1), "0 B");
    }

    #[test]
    fn format_created_normal() {
        assert_eq!(format_created("2026-02-14T10:30:00Z"), "Feb 14, 10:30");
        assert_eq!(format_created("2026-01-01T00:00:00Z"), "Jan 1, 00:00");
        assert_eq!(format_created("2026-12-25T23:59:00Z"), "Dec 25, 23:59");
    }

    #[test]
    fn format_created_short() {
        assert_eq!(format_created("short"), "short");
    }

    #[test]
    fn truncate_id_short() {
        assert_eq!(truncate_id("abc", 16), "abc");
    }

    #[test]
    fn truncate_id_long() {
        let long = "abcdefghijklmnopqrstuvwxyz";
        let result = truncate_id(long, 16);
        assert_eq!(result, "abcdefghijklmnop\u{2026}");
        assert_eq!(result.chars().count(), 17); // 16 + ellipsis
    }

    #[test]
    fn humanize_compact_various() {
        let c = crate::color::color_func(false);
        assert_eq!(humanize_compact(30, &c).0, "00:00:30");
        assert_eq!(humanize_compact(300, &c).0, "00:05:00");
        assert_eq!(humanize_compact(3600, &c).0, "01:00:00");
        assert_eq!(humanize_compact(3600 + 900, &c).0, "01:15:00");
        assert_eq!(humanize_compact(86400, &c).0, "1d 00:00:00");
        assert_eq!(humanize_compact(6 * 86400 + 22 * 3600, &c).0, "6d 22:00:00");
        assert_eq!(
            humanize_compact(300 * 86400 + 23 * 3600 + 20 * 60 + 30, &c).0,
            "300d 23:20:30"
        );
    }

    #[test]
    fn humanize_compact_visual_width() {
        let c = crate::color::color_func(false);
        // Without color, display len == visual width
        let (display, vw) = humanize_compact(3661, &c);
        assert_eq!(display, "01:01:01");
        assert_eq!(vw, 8);

        let (display, vw) = humanize_compact(86400 + 3661, &c);
        assert_eq!(display, "1d 01:01:01");
        assert_eq!(vw, 11);
    }
}
