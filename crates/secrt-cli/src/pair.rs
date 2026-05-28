//! `secrt pair` — share the account key between devices.
//!
//! Auto-detects mode based on local account-key presence:
//!
//! - **Send** — this device already has the account key. Prompt for an
//!   8-character code shown on the other device (or accept it via a
//!   positional argument / pasted pair URL), then send the account key.
//! - **Receive** — this device does NOT have the account key. Show a code
//!   and QR; poll the server until another signed-in device delivers the
//!   account key.
//!
//! Wire crypto is identical to the web pair flow: P-256 ECDH, HKDF-SHA256
//! (info = `"secrt-amk-transfer-v1"`, empty salt), AES-256-GCM with AAD
//! `"secrt-amk-transfer-v1"`. Server endpoints under `/api/v1/auth/pair/*`
//! accept either session bearer or linked API-key auth; the CLI uses the
//! API-key path via the existing `X-API-Key` header.

use std::io::{BufRead, BufReader, Write};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::agreement;
use ring::rand::SystemRandom;

use crate::amk_store::{self, AccountKeyState};
use crate::cli::{parse_flags, resolve_globals, CliError, Deps, ParsedArgs};
use crate::client::SecretApi;
use crate::color::{color_func, CMD, DIM, HEADING, SUCCESS};
use crate::envelope::api::{
    PairApproveRequest, PairChallengeOutcome, PairPollOutcome, PairStartRequest, PairTransferBlob,
};
use crate::instance_trust;
use crate::passphrase::write_error;

/// User-code alphabet — must match the server's `generate_user_code`
/// (`crates/secrt-server/src/http/mod.rs`). Excludes ambiguous characters
/// (`0`, `O`, `I`, `L`, `1`).
const USER_CODE_ALPHABET: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const USER_CODE_LEN: usize = 8;

const POLL_INTERVAL: Duration = Duration::from_millis(1500);
const PAIR_EXPIRY_SECS: u64 = 600;

pub fn run_pair(args: &[String], deps: &mut Deps) -> i32 {
    let mut pa = match parse_flags(args) {
        Ok(pa) => pa,
        Err(CliError::ShowHelp) => {
            print_pair_help(deps);
            return 0;
        }
        Err(CliError::Error(e)) => {
            write_error(&mut deps.stderr, false, (deps.is_tty)(), &e);
            return 2;
        }
    };
    resolve_globals(&mut pa, deps);

    let is_tty = (deps.is_tty)();
    let stderr_tty = (deps.is_stderr_tty)();

    // Reject extra positionals before any network or auth work. `secrt
    // pair CODE stray` is a usage error, not a silent ignore.
    if pa.args.len() > 1 {
        write_error(
            &mut deps.stderr,
            pa.json,
            is_tty,
            "too many arguments (expected at most one code or pair URL)",
        );
        return 2;
    }
    let positional = pa.args.first().cloned();

    crate::instance_trust::warn_if_unofficial(
        &pa.base_url,
        &pa.trusted_servers,
        &mut deps.stderr,
        stderr_tty,
    );

    // If the positional is a URL, derive the base URL onto `pa` and run
    // the cross-instance leak guard BEFORE creating the API client.
    // Otherwise the client (and `get_amk_wrapper`, `pair_challenge`,
    // `pair_approve`) would still address the original configured base
    // even when the URL pointed at an allowed sibling (e.g. wildcard
    // subdomain of the same logical instance).
    let positional_code = if let Some(arg) = positional.as_deref() {
        match extract_code_with_url_handling(arg, &mut pa, deps) {
            Ok(code) => Some(code),
            Err(exit_code) => return exit_code,
        }
    } else {
        None
    };

    let client = (deps.make_api)(&pa.base_url, &pa.api_key);
    let state = amk_store::resolve_account_key_state(&pa, &*client);

    match (&state, positional_code) {
        (AccountKeyState::Present(amk), Some(code)) => {
            run_send_mode(&pa, deps, &*client, amk, &code)
        }
        (AccountKeyState::Present(amk), None) => {
            if !is_tty {
                write_error(
                    &mut deps.stderr,
                    pa.json,
                    is_tty,
                    "pass the 8-character code as a positional argument when stdin is not a TTY",
                );
                return 2;
            }
            let raw = match prompt_for_code(deps) {
                Ok(r) => r,
                Err(e) => {
                    write_error(&mut deps.stderr, pa.json, is_tty, &e);
                    return 1;
                }
            };
            let code = match extract_code_with_url_handling(&raw, &mut pa, deps) {
                Ok(c) => c,
                Err(exit_code) => return exit_code,
            };
            // If the prompt URL changed the base, rebuild the client so
            // subsequent pair_challenge / pair_approve hit the right host.
            let send_client = (deps.make_api)(&pa.base_url, &pa.api_key);
            run_send_mode(&pa, deps, &*send_client, amk, &code)
        }
        (AccountKeyState::Missing, Some(_)) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                is_tty,
                "this device does not have the account key; run `secrt pair` (with no code) to receive it from another device",
            );
            1
        }
        (AccountKeyState::Missing, None) => run_receive_mode(&pa, deps, &*client),
        (AccountKeyState::NoApiKey, _) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                is_tty,
                "not signed in (run `secrt auth login` first)",
            );
            1
        }
        (AccountKeyState::InvalidApiKey(msg), _) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                is_tty,
                &format!("API key rejected: {msg} — try `secrt auth login`"),
            );
            1
        }
        (AccountKeyState::CorruptWrapper(msg), _) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                is_tty,
                &format!(
                    "your stored account key wrapper is corrupted: {msg} — try `secrt auth login` to re-link"
                ),
            );
            1
        }
        (AccountKeyState::NetworkError(msg), _) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                is_tty,
                &format!("could not reach the server: {msg}"),
            );
            1
        }
    }
}

/// Parse a raw user-supplied code or URL into a canonical `XXXX-XXXX`.
/// If the input is URL-shaped, derive the base URL onto `pa` and run the
/// cross-instance leak guard before extracting the code. Mutates `pa`
/// directly so the rest of `run_pair` builds its API client from the
/// final base URL.
///
/// Returns `Err(exit_code)` when the input is malformed (`2`) or the
/// leak guard fires (`2`). The leak guard's exit code matches the
/// existing `sync` / `burn` / `info` callers for consistency.
fn extract_code_with_url_handling(
    raw: &str,
    pa: &mut ParsedArgs,
    deps: &mut Deps,
) -> Result<String, i32> {
    let trimmed = raw.trim();
    let is_tty = (deps.is_tty)();
    let stderr_tty = (deps.is_stderr_tty)();

    if let Some(url_input) = normalize_pair_url(trimmed) {
        crate::cli::derive_base_url_from_url(&url_input, pa);
        instance_trust::block_if_cross_instance(pa, "pair", &mut deps.stderr, stderr_tty)?;
        parse_pair_url(&url_input).ok_or_else(|| {
            write_error(
                &mut deps.stderr,
                pa.json,
                is_tty,
                "could not extract a pair code from the URL (expected `/pair?code=XXXX-XXXX`)",
            );
            2
        })
    } else {
        canonicalize_code(trimmed).ok_or_else(|| {
            write_error(
                &mut deps.stderr,
                pa.json,
                is_tty,
                "invalid pair code (expected 8 characters from the alphabet ABCDEFGHJKLMNPQRSTUVWXYZ23456789, optionally with a hyphen in the middle)",
            );
            2
        })
    }
}

// --- Send mode --------------------------------------------------------------

fn run_send_mode(
    pa: &ParsedArgs,
    deps: &mut Deps,
    client: &(dyn SecretApi + '_),
    amk: &[u8],
    canonical_code: &str,
) -> i32 {
    let is_tty = (deps.is_tty)();
    let stderr_tty = (deps.is_stderr_tty)();
    let c = color_func(stderr_tty);

    // Look up the slot — get the displayer's pubkey. URL parsing and the
    // cross-instance leak guard have already run upstream in `run_pair`
    // via `extract_code_with_url_handling`, so the API client is already
    // pointed at the right host by the time we get here.
    let displayer_pk_b64 = match client.pair_challenge(canonical_code) {
        Ok(PairChallengeOutcome::Pending {
            displayer_ecdh_public_key,
        }) => displayer_ecdh_public_key,
        Ok(PairChallengeOutcome::NotFound) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                is_tty,
                "no pairing slot for that code; check the code on the other device or have them start a new pair",
            );
            return 1;
        }
        Ok(PairChallengeOutcome::Terminal { state }) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                is_tty,
                &format!("this pairing slot is no longer joinable (state: {state})"),
            );
            return 1;
        }
        Err(e) => {
            write_error(&mut deps.stderr, pa.json, is_tty, &e);
            return 1;
        }
    };

    // Generate our ephemeral keypair, derive the transfer key, encrypt the AMK.
    let transfer_blob = match build_transfer_blob(amk, &displayer_pk_b64) {
        Ok(t) => t,
        Err(e) => {
            write_error(&mut deps.stderr, pa.json, is_tty, &e);
            return 1;
        }
    };

    let req = PairApproveRequest {
        user_code: canonical_code.to_string(),
        amk_transfer: transfer_blob,
    };

    if let Err(e) = client.pair_approve(req) {
        write_error(&mut deps.stderr, pa.json, is_tty, &e);
        return 1;
    }

    if pa.json {
        let _ = writeln!(deps.stdout, "{{\"status\":\"sent\"}}");
    } else if !pa.silent {
        let _ = writeln!(deps.stderr, "{} Account key sent.", c(SUCCESS, "\u{2713}"));
    }
    0
}

fn build_transfer_blob(amk: &[u8], displayer_pk_b64: &str) -> Result<PairTransferBlob, String> {
    let rng = SystemRandom::new();
    let own_private = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
        .map_err(|_| "ECDH key generation failed".to_string())?;
    let own_public = own_private
        .compute_public_key()
        .map_err(|_| "ECDH public-key derivation failed".to_string())?;
    let own_pk_b64 = URL_SAFE_NO_PAD.encode(own_public.as_ref());

    let peer_bytes = URL_SAFE_NO_PAD
        .decode(displayer_pk_b64)
        .map_err(|e| format!("decode displayer public key: {}", e))?;
    let peer_pk = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &peer_bytes);

    let shared_secret = agreement::agree_ephemeral(own_private, &peer_pk, |s| s.to_vec())
        .map_err(|_| "ECDH agreement failed".to_string())?;

    let transfer_key = secrt_core::amk::derive_transfer_key(&shared_secret)
        .map_err(|e| format!("derive transfer key: {}", e))?;

    // Random 12-byte nonce.
    let mut nonce = [0u8; 12];
    use ring::rand::SecureRandom;
    rng.fill(&mut nonce)
        .map_err(|_| "RNG failed to produce nonce".to_string())?;

    let ct =
        secrt_core::amk::aes256gcm_encrypt(&transfer_key, &nonce, b"secrt-amk-transfer-v1", amk)
            .map_err(|e| format!("encrypt account key: {}", e))?;

    Ok(PairTransferBlob {
        ct: URL_SAFE_NO_PAD.encode(&ct),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ecdh_public_key: own_pk_b64,
    })
}

// --- Receive mode -----------------------------------------------------------

fn run_receive_mode(pa: &ParsedArgs, deps: &mut Deps, client: &(dyn SecretApi + '_)) -> i32 {
    let is_tty = (deps.is_tty)();
    let stderr_tty = (deps.is_stderr_tty)();
    let c = color_func(stderr_tty);

    // Generate ephemeral ECDH keypair.
    let rng = SystemRandom::new();
    let own_private = match agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng) {
        Ok(k) => k,
        Err(_) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                is_tty,
                "ECDH key generation failed",
            );
            return 1;
        }
    };
    let own_public = match own_private.compute_public_key() {
        Ok(pk) => pk,
        Err(_) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                is_tty,
                "ECDH public-key derivation failed",
            );
            return 1;
        }
    };
    let own_pk_b64 = URL_SAFE_NO_PAD.encode(own_public.as_ref());

    let start_resp = match client.pair_start(PairStartRequest {
        ecdh_public_key: own_pk_b64,
    }) {
        Ok(r) => r,
        Err(e) => {
            write_error(&mut deps.stderr, pa.json, is_tty, &e);
            return 1;
        }
    };

    // Render code + URL + QR — always on stderr, regardless of `--json`
    // or `--silent`. They're the point of the command: without them the
    // other device has nothing to type. `--json` puts only the final
    // `{"status":"received"}` on stdout; everything else stays on stderr.
    let pair_url = format!(
        "{}/pair?code={}",
        trim_slash(&pa.base_url),
        start_resp.user_code
    );
    let _ = writeln!(
        deps.stderr,
        "On another signed-in device, visit {}",
        c(URL_LIKE, &pair_url)
    );
    let _ = writeln!(deps.stderr, "and enter this code:");
    let _ = writeln!(deps.stderr);
    let _ = writeln!(deps.stderr, "  {}", c(HEADING, &start_resp.user_code));
    if stderr_tty {
        if let Ok(qr) = qrcode::QrCode::new(pair_url.as_bytes()) {
            let _ = writeln!(deps.stderr, "\n{}", crate::qr::render_qr_compact(&qr));
        }
    }

    // Resolve user_id for the AMK wrap AAD; surface a clear error if the key
    // isn't linked rather than failing late inside `import_amk`.
    let user_id = match client.info() {
        Ok(info) => match info.user_id {
            Some(uid) => uid,
            None => {
                write_error(
                    &mut deps.stderr,
                    pa.json,
                    is_tty,
                    "API key is not linked to a user account",
                );
                return 1;
            }
        },
        Err(e) => {
            write_error(&mut deps.stderr, pa.json, is_tty, &e);
            return 1;
        }
    };

    // Poll loop. Countdown and \r-overwrite progress only render to a
    // TTY (so piped stderr stays clean) and respect `--silent`. `--json`
    // does NOT suppress them: the spec puts progress on stderr in JSON
    // mode and only the final status on stdout.
    let show_progress = !pa.silent && stderr_tty;
    let started = Instant::now();
    let expiry = Duration::from_secs(PAIR_EXPIRY_SECS);
    loop {
        if started.elapsed() >= expiry {
            if show_progress {
                let _ = writeln!(deps.stderr); // newline after the \r line
            }
            write_error(
                &mut deps.stderr,
                pa.json,
                is_tty,
                "pairing expired before approval",
            );
            return 1;
        }
        if show_progress {
            let remaining = expiry.saturating_sub(started.elapsed()).as_secs();
            let mins = remaining / 60;
            let secs = remaining % 60;
            let _ = write!(
                deps.stderr,
                "\r{} Waiting for approval ({mins}:{secs:02} remaining)…",
                c(DIM, "\u{25CB}")
            );
            let _ = deps.stderr.flush();
        }

        // Use the injected sleep so tests don't wait in real time.
        (deps.sleep)(POLL_INTERVAL);

        let outcome = match client.pair_poll(&start_resp.displayer_poll_token) {
            Ok(o) => o,
            Err(e) => {
                if show_progress {
                    let _ = writeln!(deps.stderr);
                }
                write_error(&mut deps.stderr, pa.json, is_tty, &e);
                return 1;
            }
        };

        match outcome {
            PairPollOutcome::Pending => continue,
            PairPollOutcome::Cancelled => {
                if show_progress {
                    let _ = writeln!(deps.stderr);
                }
                write_error(
                    &mut deps.stderr,
                    pa.json,
                    is_tty,
                    "the other device cancelled the pairing",
                );
                return 1;
            }
            PairPollOutcome::Expired => {
                if show_progress {
                    let _ = writeln!(deps.stderr);
                }
                write_error(
                    &mut deps.stderr,
                    pa.json,
                    is_tty,
                    "pairing slot expired before approval",
                );
                return 1;
            }
            PairPollOutcome::Approved { amk_transfer } => {
                if show_progress {
                    let _ = writeln!(deps.stderr);
                }
                // Persist the AMK.
                let rand_bytes = |buf: &mut [u8]| -> Result<(), secrt_core::types::EnvelopeError> {
                    use ring::rand::SecureRandom;
                    SystemRandom::new().fill(buf).map_err(|_| {
                        secrt_core::types::EnvelopeError::RngError("rng failed".into())
                    })
                };
                if let Err(e) = amk_store::decrypt_and_persist_transfer(
                    &amk_transfer.ecdh_public_key,
                    &amk_transfer.ct,
                    &amk_transfer.nonce,
                    own_private,
                    &pa.api_key,
                    &user_id,
                    client,
                    &rand_bytes,
                ) {
                    write_error(&mut deps.stderr, pa.json, is_tty, &e);
                    return 1;
                }
                if pa.json {
                    let _ = writeln!(deps.stdout, "{{\"status\":\"received\"}}");
                } else if !pa.silent {
                    let _ = writeln!(
                        deps.stderr,
                        "{} Account key received.",
                        c(SUCCESS, "\u{2713}")
                    );
                }
                return 0;
            }
        }
    }
}

// --- Helpers ----------------------------------------------------------------

const URL_LIKE: &str = "1;36";

/// Strip a trailing `/` so URL concat doesn't double up.
fn trim_slash(s: &str) -> &str {
    s.trim_end_matches('/')
}

/// Decide whether the input looks like a pair URL and, if so, normalize it
/// to a `scheme://host…` form `parse_pair_url` and `derive_base_url_from_url`
/// can both consume. Returns `None` for bare codes (so the caller falls
/// through to `canonicalize_code`).
///
/// Recognised shapes:
/// - `http://…/pair…` or `https://…/pair…` — used as-is.
/// - `host/pair…` (no scheme) — prepended with `https://` so URL helpers
///   downstream can parse it. The cross-instance leak guard still applies.
///
/// Heuristic: presence of `/pair` is a strong signal it's a URL even when
/// there's no scheme. Plain codes don't contain `/`. If a user pastes
/// something ambiguous (e.g. `secrt.ca/pair`, no `?code=`), we treat it as
/// a URL and let `parse_pair_url` fail with a specific "no code" error
/// rather than the less useful "invalid pair code".
fn normalize_pair_url(s: &str) -> Option<String> {
    if s.starts_with("http://") || s.starts_with("https://") {
        return Some(s.to_string());
    }
    // Scheme-less, but path includes a `/pair` segment somewhere. Don't
    // require the user to remember the scheme.
    if s.contains("/pair") {
        return Some(format!("https://{s}"));
    }
    None
}

/// Parse a `/pair?code=XXXX-XXXX` URL into a canonical code. Tolerates
/// case, surrounding whitespace, percent-encoded `-`, extra query params,
/// trailing slashes, fragments, and ports. Rejects URLs whose path isn't
/// `/pair`. Hand-rolled to avoid pulling in a URL-parsing dependency just
/// for this one helper — the URLs we accept here are well-formed and ASCII.
fn parse_pair_url(input: &str) -> Option<String> {
    // Strip scheme://. Callers go through `normalize_pair_url` first which
    // guarantees `https://` or `http://`.
    let rest = input
        .strip_prefix("https://")
        .or_else(|| input.strip_prefix("http://"))?;
    // Drop host (and optional port): everything up to the first `/` or `?`.
    let after_host = match rest.find(['/', '?']) {
        Some(i) => &rest[i..],
        // No path at all (`https://secrt.ca`) — definitely not a pair URL.
        None => return None,
    };

    // Split path and query.
    let (path, query) = match after_host.find('?') {
        Some(i) => (&after_host[..i], &after_host[i + 1..]),
        None => (after_host, ""),
    };

    // Strip optional fragment from query (`#...`).
    let query = match query.find('#') {
        Some(i) => &query[..i],
        None => query,
    };

    // Path must be `/pair` (with optional trailing slash, case-insensitive).
    let path_trimmed = path.trim_end_matches('/');
    if !path_trimmed.eq_ignore_ascii_case("/pair") {
        return None;
    }

    // Walk `code=...` out of the query string — anywhere, not just first.
    let raw_code = query.split('&').find_map(|kv| {
        kv.split_once('=')
            .filter(|(k, _)| k.eq_ignore_ascii_case("code"))
            .map(|(_, v)| v)
    })?;

    // Minimal percent-decode covering only what the pair alphabet might
    // produce (`%2D` for `-`); pass everything else through unchanged.
    let decoded = raw_code.replace("%2D", "-").replace("%2d", "-");
    canonicalize_code(&decoded)
}

/// Normalize a user-supplied pair code: strip whitespace and dashes,
/// uppercase, then validate length + alphabet, then canonicalize to
/// `XXXX-XXXX`.
fn canonicalize_code(input: &str) -> Option<String> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.len() != USER_CODE_LEN {
        return None;
    }
    if !cleaned.chars().all(|c| USER_CODE_ALPHABET.contains(c)) {
        return None;
    }
    Some(format!("{}-{}", &cleaned[..4], &cleaned[4..]))
}

/// Prompt the user for either an 8-character code or a full pair URL —
/// the web pair page copies the URL form by default. The raw line is
/// returned trimmed; `run_send_mode` does the URL-vs-code dispatch
/// (including the cross-instance leak guard for URL inputs).
fn prompt_for_code(deps: &mut Deps) -> Result<String, String> {
    let _ = write!(
        deps.stderr,
        "Enter the 8-character code or URL from the other device:\n> "
    );
    let _ = deps.stderr.flush();
    let mut line = String::new();
    let mut reader = BufReader::new(&mut deps.stdin);
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read stdin: {e}"))?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err("no input".to_string());
    }
    Ok(trimmed.to_string())
}

// --- Help -------------------------------------------------------------------

pub fn print_pair_help(deps: &mut Deps) {
    use crate::color::{ARG, HEADING as H, OPT as O};
    let c = color_func((deps.is_stdout_tty)());
    let w = &mut deps.stderr;
    let _ = writeln!(
        w,
        "{} {} — Share your account key between devices\n",
        c(CMD, "secrt"),
        c(CMD, "pair")
    );
    let _ = writeln!(
        w,
        "{}\n  {} {} {} {}\n",
        c(H, "USAGE"),
        c(CMD, "secrt"),
        c(CMD, "pair"),
        c(ARG, "[<code-or-url>]"),
        c(ARG, "[options]")
    );
    let _ = writeln!(w, "{}", c(H, "DESCRIPTION"));
    let _ = writeln!(
        w,
        "  Shares your account key with another device signed in to the"
    );
    let _ = writeln!(
        w,
        "  same account, so paired devices can read and write your"
    );
    let _ = writeln!(w, "  encrypted data.");
    let _ = writeln!(w);
    let _ = writeln!(w, "  Two modes, picked automatically:");
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "    {}    This device already has the account key.",
        c(H, "Send:")
    );
    let _ = writeln!(
        w,
        "             Enter the 8-character code shown on the other device."
    );
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "    {} This device does not have the account key yet.",
        c(H, "Receive:")
    );
    let _ = writeln!(
        w,
        "             Shows a code and QR. On another signed-in device"
    );
    let _ = writeln!(
        w,
        "             that already has your account key, enter the code"
    );
    let _ = writeln!(w, "             to send your account key here.");
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "  The account key is transferred end-to-end encrypted via ECDH."
    );
    let _ = writeln!(
        w,
        "  The server temporarily stores only public rendezvous data and"
    );
    let _ = writeln!(
        w,
        "  the encrypted transfer material; it never sees plaintext"
    );
    let _ = writeln!(w, "  account key bytes.");
    let _ = writeln!(w);
    let _ = writeln!(w, "  Both devices must be signed in as the same account.");
    let _ = writeln!(w);
    let _ = writeln!(w, "{}", c(H, "OPTIONS"));
    let _ = writeln!(w, "  {}     Server URL", c(O, "--base-url <url>"));
    let _ = writeln!(
        w,
        "  {}      API key (defaults to the configured key)",
        c(O, "--api-key <key>")
    );
    let _ = writeln!(
        w,
        "  {}               Output as JSON (status on stdout)",
        c(O, "--json")
    );
    let _ = writeln!(
        w,
        "  {}             Suppress progress output (code + QR still print)",
        c(O, "--silent")
    );
    let _ = writeln!(
        w,
        "  {}, {}           Show this help",
        c(O, "-h"),
        c(O, "--help")
    );
    let _ = writeln!(w, "\n{}", c(H, "EXAMPLES"));
    let _ = writeln!(w, "  {} {}", c(CMD, "secrt"), c(CMD, "pair"));
    let _ = writeln!(w, "  {} {} K7MQ-QX2Z", c(CMD, "secrt"), c(CMD, "pair"));
    let _ = writeln!(
        w,
        "  {} {} https://secrt.ca/pair?code=K7MQ-QX2Z",
        c(CMD, "secrt"),
        c(CMD, "pair")
    );
    let _ = writeln!(
        w,
        "  {} {} {} https://secrt.is",
        c(CMD, "secrt"),
        c(CMD, "pair"),
        c(O, "--base-url")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_lenient_lowercase() {
        assert_eq!(canonicalize_code("k7mq-qx2z").as_deref(), Some("K7MQ-QX2Z"));
    }

    #[test]
    fn canonicalize_lenient_no_dash() {
        assert_eq!(canonicalize_code("K7MQQX2Z").as_deref(), Some("K7MQ-QX2Z"));
    }

    #[test]
    fn canonicalize_lenient_whitespace() {
        assert_eq!(
            canonicalize_code("  K7MQ QX2Z  ").as_deref(),
            Some("K7MQ-QX2Z")
        );
    }

    #[test]
    fn canonicalize_rejects_wrong_length() {
        assert!(canonicalize_code("K7MQQX2").is_none());
        assert!(canonicalize_code("K7MQQX2ZZ").is_none());
    }

    #[test]
    fn canonicalize_rejects_off_alphabet() {
        // The four ambiguous characters excluded from the alphabet:
        // `0`, `1`, `I`, `O` (lowercase `o` becomes upper-case `O`).
        assert!(canonicalize_code("K7M0-QX2Z").is_none());
        assert!(canonicalize_code("K7M1-QX2Z").is_none());
        assert!(canonicalize_code("K7MI-QX2Z").is_none());
        assert!(canonicalize_code("K7MO-QX2Z").is_none());
    }

    #[test]
    fn parse_pair_url_happy() {
        assert_eq!(
            parse_pair_url("https://secrt.ca/pair?code=K7MQ-QX2Z").as_deref(),
            Some("K7MQ-QX2Z")
        );
    }

    #[test]
    fn parse_pair_url_lowercase_code() {
        assert_eq!(
            parse_pair_url("https://secrt.ca/pair?code=k7mqqx2z").as_deref(),
            Some("K7MQ-QX2Z")
        );
    }

    #[test]
    fn parse_pair_url_rejects_wrong_path() {
        assert!(parse_pair_url("https://secrt.ca/sync?code=K7MQ-QX2Z").is_none());
    }

    // --- parse_pair_url breadth ---------------------------------------------

    #[test]
    fn parse_pair_url_http_scheme() {
        assert_eq!(
            parse_pair_url("http://localhost:5173/pair?code=K7MQ-QX2Z").as_deref(),
            Some("K7MQ-QX2Z")
        );
    }

    #[test]
    fn parse_pair_url_with_port() {
        assert_eq!(
            parse_pair_url("https://secrt.ca:8443/pair?code=K7MQ-QX2Z").as_deref(),
            Some("K7MQ-QX2Z")
        );
    }

    #[test]
    fn parse_pair_url_trailing_slash_on_path() {
        assert_eq!(
            parse_pair_url("https://secrt.ca/pair/?code=K7MQ-QX2Z").as_deref(),
            Some("K7MQ-QX2Z")
        );
    }

    #[test]
    fn parse_pair_url_uppercase_path() {
        assert_eq!(
            parse_pair_url("https://secrt.ca/PAIR?code=K7MQ-QX2Z").as_deref(),
            Some("K7MQ-QX2Z")
        );
    }

    #[test]
    fn parse_pair_url_uppercase_query_key() {
        // `code` matched case-insensitively.
        assert_eq!(
            parse_pair_url("https://secrt.ca/pair?CODE=K7MQ-QX2Z").as_deref(),
            Some("K7MQ-QX2Z")
        );
    }

    #[test]
    fn parse_pair_url_extra_query_before_code() {
        assert_eq!(
            parse_pair_url("https://secrt.ca/pair?ref=mobile&code=K7MQ-QX2Z").as_deref(),
            Some("K7MQ-QX2Z")
        );
    }

    #[test]
    fn parse_pair_url_extra_query_after_code() {
        assert_eq!(
            parse_pair_url("https://secrt.ca/pair?code=K7MQ-QX2Z&ref=mobile").as_deref(),
            Some("K7MQ-QX2Z")
        );
    }

    #[test]
    fn parse_pair_url_strips_fragment() {
        assert_eq!(
            parse_pair_url("https://secrt.ca/pair?code=K7MQ-QX2Z#fragment").as_deref(),
            Some("K7MQ-QX2Z")
        );
    }

    #[test]
    fn parse_pair_url_percent_encoded_dash() {
        assert_eq!(
            parse_pair_url("https://secrt.ca/pair?code=K7MQ%2DQX2Z").as_deref(),
            Some("K7MQ-QX2Z")
        );
        assert_eq!(
            parse_pair_url("https://secrt.ca/pair?code=K7MQ%2dQX2Z").as_deref(),
            Some("K7MQ-QX2Z")
        );
    }

    #[test]
    fn parse_pair_url_self_hosted_host() {
        // Different sites — host is not validated by `parse_pair_url`; the
        // cross-instance leak guard lives upstream in `run_send_mode`.
        assert_eq!(
            parse_pair_url("https://secrt.is/pair?code=K7MQ-QX2Z").as_deref(),
            Some("K7MQ-QX2Z")
        );
        assert_eq!(
            parse_pair_url("https://team.example.com/pair?code=K7MQ-QX2Z").as_deref(),
            Some("K7MQ-QX2Z")
        );
    }

    #[test]
    fn parse_pair_url_rejects_missing_code_param() {
        assert!(parse_pair_url("https://secrt.ca/pair").is_none());
        assert!(parse_pair_url("https://secrt.ca/pair?other=x").is_none());
    }

    #[test]
    fn parse_pair_url_rejects_invalid_code_alphabet() {
        // Code value present but off-alphabet.
        assert!(parse_pair_url("https://secrt.ca/pair?code=BAD!CODE").is_none());
        // Wrong length.
        assert!(parse_pair_url("https://secrt.ca/pair?code=ABC").is_none());
    }

    #[test]
    fn parse_pair_url_rejects_no_path() {
        // No path component at all (just scheme://host).
        assert!(parse_pair_url("https://secrt.ca").is_none());
    }

    // --- normalize_pair_url -------------------------------------------------

    #[test]
    fn normalize_passes_full_url_through() {
        assert_eq!(
            normalize_pair_url("https://secrt.ca/pair?code=K7MQ-QX2Z").as_deref(),
            Some("https://secrt.ca/pair?code=K7MQ-QX2Z")
        );
        assert_eq!(
            normalize_pair_url("http://localhost:5173/pair?code=K7MQ-QX2Z").as_deref(),
            Some("http://localhost:5173/pair?code=K7MQ-QX2Z")
        );
    }

    #[test]
    fn normalize_adds_https_for_schemeless_url() {
        assert_eq!(
            normalize_pair_url("secrt.ca/pair?code=K7MQ-QX2Z").as_deref(),
            Some("https://secrt.ca/pair?code=K7MQ-QX2Z")
        );
        assert_eq!(
            normalize_pair_url("secrt.is/pair?code=K7MQ-QX2Z").as_deref(),
            Some("https://secrt.is/pair?code=K7MQ-QX2Z")
        );
    }

    #[test]
    fn normalize_returns_none_for_bare_codes() {
        // Bare codes have no `/` and no scheme — should fall through to
        // `canonicalize_code`, not be treated as URLs.
        assert!(normalize_pair_url("K7MQ-QX2Z").is_none());
        assert!(normalize_pair_url("k7mqqx2z").is_none());
        assert!(normalize_pair_url("K7MQ QX2Z").is_none());
    }

    // --- End-to-end via normalize → parse: the full prompt path -------------

    fn full_pipeline(input: &str) -> Option<String> {
        normalize_pair_url(input).and_then(|u| parse_pair_url(&u))
    }

    #[test]
    fn pipeline_accepts_schemeless_urls() {
        assert_eq!(
            full_pipeline("secrt.ca/pair?code=K7MQ-QX2Z").as_deref(),
            Some("K7MQ-QX2Z")
        );
        assert_eq!(
            full_pipeline("secrt.ca/pair?code=k7mqqx2z").as_deref(),
            Some("K7MQ-QX2Z")
        );
        assert_eq!(
            full_pipeline("localhost:5173/pair?code=K7MQ-QX2Z").as_deref(),
            Some("K7MQ-QX2Z")
        );
    }

    #[test]
    fn pipeline_accepts_realistic_variations() {
        let cases = [
            "https://secrt.ca/pair?code=K7MQ-QX2Z",
            "http://secrt.ca/pair?code=K7MQ-QX2Z",
            "https://secrt.ca/pair/?code=K7MQ-QX2Z",
            "https://secrt.ca:8443/pair?code=K7MQ-QX2Z",
            "https://secrt.ca/pair?code=K7MQ-QX2Z&utm_source=qr",
            "https://secrt.ca/pair?ref=mobile&code=K7MQ-QX2Z",
            "https://secrt.is/pair?code=K7MQ-QX2Z",
            "https://my.secrt.ca/pair?code=K7MQ-QX2Z",
        ];
        for case in cases {
            assert_eq!(
                full_pipeline(case).as_deref(),
                Some("K7MQ-QX2Z"),
                "pipeline rejected: {case}"
            );
        }
    }
}
