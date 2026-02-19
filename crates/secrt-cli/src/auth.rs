use std::io::Write;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::cli::Deps;
use crate::client::ApiClient;
use crate::color::{color_func, CMD, DIM, HEADING, OPT, SUCCESS};
use crate::qr::render_qr_compact;

const DEFAULT_BASE_URL: &str = "https://secrt.ca";

/// Entry point for `secrt auth <subcommand>`.
pub fn run_auth(args: &[String], deps: &mut Deps) -> i32 {
    if args.is_empty() {
        crate::cli::print_auth_help(deps);
        return 0;
    }

    match args[0].as_str() {
        "-h" | "--help" | "help" => {
            crate::cli::print_auth_help(deps);
            0
        }
        "login" => run_auth_login(&args[1..], deps),
        "setup" => run_auth_setup(&args[1..], deps),
        "status" => run_auth_status(&args[1..], deps),
        "logout" => run_auth_logout(&args[1..], deps),
        _ => {
            let _ = writeln!(
                deps.stderr,
                "error: unknown auth subcommand {:?} (try: login, setup, status, logout)",
                args[0]
            );
            2
        }
    }
}

/// Resolve base_url from flags, env, or config.
fn resolve_base_url(args: &[String], deps: &Deps) -> String {
    // Check --base-url flag
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--base-url" {
            if i + 1 < args.len() {
                return args[i + 1].clone();
            }
        } else if let Some(val) = args[i].strip_prefix("--base-url=") {
            return val.to_string();
        }
        i += 1;
    }
    // Check env
    if let Some(env) = (deps.getenv)("SECRET_BASE_URL") {
        return env;
    }
    // Check config
    let config = crate::config::load_config_with(&*deps.getenv, &mut std::io::sink());
    if let Some(ref url) = config.base_url {
        return url.clone();
    }
    DEFAULT_BASE_URL.into()
}

/// Shared logic: store an API key in keychain or config file.
/// Returns 0 on success, 1 on error.
fn store_api_key(api_key: &str, deps: &mut Deps) -> i32 {
    let c = color_func((deps.is_tty)());
    let config = crate::config::load_config_with(&*deps.getenv, &mut std::io::sink());
    let use_kc = config.use_keychain.unwrap_or(false);

    if use_kc {
        // Already configured to use keychain
        let _ = write!(deps.stderr, "  Storing API key in OS keychain...");
        let _ = deps.stderr.flush();
        match (deps.set_keychain_secret)("api_key", api_key) {
            Ok(()) => {
                let _ = writeln!(
                    deps.stderr,
                    "\r{} API key stored in OS keychain      ",
                    c(SUCCESS, "\u{2713}")
                );
                return 0;
            }
            Err(e) => {
                let _ = writeln!(deps.stderr);
                let _ = writeln!(deps.stderr, "warning: keychain store failed: {}", e);
                // Fall through to config file
            }
        }
    } else if (deps.is_tty)() {
        // Interactive: ask about keychain
        let _ = write!(
            deps.stderr,
            "Store API key in OS keychain? (recommended for security) [y/N]: "
        );
        let _ = deps.stderr.flush();

        let answer = read_stdin_line(&mut *deps.stdin).to_ascii_lowercase();
        {
            if answer == "y" || answer == "yes" {
                let _ = write!(deps.stderr, "  Storing API key in OS keychain...");
                let _ = deps.stderr.flush();
                match (deps.set_keychain_secret)("api_key", api_key) {
                    Ok(()) => {
                        // Also set use_keychain = true in config
                        let _ =
                            crate::config::set_config_key(&*deps.getenv, "use_keychain", "true");
                        let _ = writeln!(
                            deps.stderr,
                            "\r{} API key stored in OS keychain      ",
                            c(SUCCESS, "\u{2713}")
                        );
                        return 0;
                    }
                    Err(e) => {
                        let _ = writeln!(deps.stderr);
                        let _ = writeln!(deps.stderr, "warning: keychain store failed: {}", e);
                        // Fall through to config file
                    }
                }
            }
        }
    }

    // Store in config file
    match crate::config::set_config_key(&*deps.getenv, "api_key", api_key) {
        Ok(()) => {
            let _ = writeln!(
                deps.stderr,
                "{} API key stored in config file",
                c(SUCCESS, "\u{2713}")
            );
            0
        }
        Err(e) => {
            let _ = writeln!(deps.stderr, "error: failed to save API key: {}", e);
            1
        }
    }
}

/// `secrt auth login` — Browser-based device authorization.
fn run_auth_login(args: &[String], deps: &mut Deps) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        crate::cli::print_auth_help(deps);
        return 0;
    }

    // Check for existing credentials
    if !confirm_if_authenticated(deps) {
        return 0;
    }

    let c = color_func((deps.is_tty)());
    let base_url = resolve_base_url(args, deps);

    // 1. Generate root_key (32 bytes random)
    let mut root_key = vec![0u8; secrt_core::API_KEY_ROOT_LEN];
    if let Err(e) = (deps.rand_bytes)(&mut root_key) {
        let _ = writeln!(deps.stderr, "error: failed to generate key material: {}", e);
        return 1;
    }

    // 2. Derive auth_token from root_key
    let auth_token = match secrt_core::derive_auth_token(&root_key) {
        Ok(t) => t,
        Err(e) => {
            let _ = writeln!(deps.stderr, "error: key derivation failed: {}", e);
            return 1;
        }
    };
    let auth_token_b64 = URL_SAFE_NO_PAD.encode(&auth_token);

    // 3. POST /device/start
    let client = ApiClient {
        base_url: base_url.clone(),
        api_key: String::new(),
    };
    let start = match client.device_start(&auth_token_b64) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(deps.stderr, "error: {}", e);
            return 1;
        }
    };

    // 4. Print user code prominently
    let _ = writeln!(deps.stderr);
    let _ = writeln!(
        deps.stderr,
        "  {} Open this URL to authorize:",
        c(HEADING, "DEVICE LOGIN")
    );
    let _ = writeln!(deps.stderr, "  {}", c(CMD, &start.verification_url));
    let _ = writeln!(deps.stderr);
    let _ = writeln!(deps.stderr, "  Your code: {}", c(HEADING, &start.user_code));

    // 5. Render QR code if TTY
    if (deps.is_tty)() {
        if let Ok(code) = qrcode::QrCode::new(&start.verification_url) {
            let qr_string = render_qr_compact(&code);
            let _ = write!(deps.stderr, "\n{}", qr_string);
        }
    } else {
        let _ = writeln!(deps.stderr);
    }

    // 6. Open browser (best-effort)
    if (deps.open_browser)(&start.verification_url).is_err() {
        let _ = writeln!(
            deps.stderr,
            "  {} could not open browser; visit the URL above",
            c(DIM, "hint:")
        );
    }

    let _ = writeln!(
        deps.stderr,
        "  Waiting for authorization (expires in {}s)...",
        start.expires_in
    );

    // 7. Poll loop
    let interval = Duration::from_secs(start.interval.max(3));
    let max_polls = (start.expires_in / start.interval.max(3)) + 2;

    for _ in 0..max_polls {
        (deps.sleep)(interval);

        match client.device_poll(&start.device_code) {
            Ok(resp) => {
                if resp.status == "complete" {
                    let prefix = resp.prefix.unwrap_or_default();
                    let root_b64 = URL_SAFE_NO_PAD.encode(&root_key);
                    let api_key = format!(
                        "{}{}.{}",
                        secrt_core::LOCAL_API_KEY_PREFIX,
                        prefix,
                        root_b64
                    );

                    let _ = writeln!(deps.stderr);
                    let _ = writeln!(
                        deps.stderr,
                        "{} Authenticated successfully!",
                        c(SUCCESS, "\u{2713}")
                    );
                    let masked = crate::config::mask_secret(&api_key, true);
                    let _ = writeln!(deps.stderr, "  Key: {}", c(DIM, &masked));

                    return store_api_key(&api_key, deps);
                }
                // status == "authorization_pending" → keep polling
            }
            Err(e) => {
                if e.contains("expired_token") {
                    let _ = writeln!(
                        deps.stderr,
                        "\nerror: authorization expired; please try again"
                    );
                    return 1;
                }
                let _ = writeln!(deps.stderr, "\nerror: {}", e);
                return 1;
            }
        }
    }

    let _ = writeln!(deps.stderr, "\nerror: authorization timed out");
    1
}

/// `secrt auth setup` — Interactively paste an API key.
fn run_auth_setup(args: &[String], deps: &mut Deps) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        crate::cli::print_auth_help(deps);
        return 0;
    }

    // Check for existing credentials
    if !confirm_if_authenticated(deps) {
        return 0;
    }

    let c = color_func((deps.is_tty)());
    let base_url = resolve_base_url(args, deps);

    // Prompt for API key
    let api_key = match (deps.read_pass)("Paste your API key (sk2_...): ", &mut deps.stderr) {
        Ok(k) => k.trim().to_string(),
        Err(e) => {
            let _ = writeln!(deps.stderr, "error: failed to read input: {}", e);
            return 1;
        }
    };

    if api_key.is_empty() {
        let _ = writeln!(deps.stderr, "error: no API key provided");
        return 1;
    }

    // Validate format
    if let Err(e) = secrt_core::parse_local_api_key(&api_key) {
        let _ = writeln!(deps.stderr, "error: invalid API key format: {}", e);
        return 1;
    }

    // Optionally verify against server
    let wire_key = match secrt_core::derive_wire_api_key(&api_key) {
        Ok(wk) => wk,
        Err(e) => {
            let _ = writeln!(deps.stderr, "error: key derivation failed: {}", e);
            return 1;
        }
    };

    let api = (deps.make_api)(&base_url, &wire_key);
    match api.info() {
        Ok(info) => {
            if info.authenticated {
                let _ = writeln!(
                    deps.stderr,
                    "{} Key verified with {}",
                    c(SUCCESS, "\u{2713}"),
                    c(DIM, &base_url)
                );
            } else {
                let _ = writeln!(
                    deps.stderr,
                    "warning: key not recognized by server (it may still be valid)"
                );
            }
        }
        Err(_) => {
            let _ = writeln!(
                deps.stderr,
                "{} Could not verify key (server unreachable); saving anyway",
                c(DIM, "hint:")
            );
        }
    }

    store_api_key(&api_key, deps)
}

/// `secrt auth status` — Show current auth state.
fn run_auth_status(args: &[String], deps: &mut Deps) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        crate::cli::print_auth_help(deps);
        return 0;
    }

    let c = color_func((deps.is_tty)());
    let base_url = resolve_base_url(args, deps);
    let (api_key, source) = resolve_existing_key(deps);

    if api_key.is_empty() {
        let _ = writeln!(deps.stderr, "Not authenticated");
        let _ = writeln!(
            deps.stderr,
            "Run {} or {} to set up.",
            c(CMD, "secrt auth login"),
            c(CMD, "secrt auth setup")
        );
        return 0;
    }

    let masked = crate::config::mask_secret(&api_key, true);
    let _ = writeln!(
        deps.stderr,
        "  {}: {} {}",
        c(OPT, "Key"),
        masked,
        c(DIM, &format!("(from: {})", source))
    );

    // Check server connectivity
    let wire_key = secrt_core::derive_wire_api_key(&api_key).unwrap_or_default();
    let api = (deps.make_api)(&base_url, &wire_key);
    match api.info() {
        Ok(info) => {
            let status = if info.authenticated {
                "connected, authenticated"
            } else {
                "connected, key not recognized"
            };
            let _ = writeln!(
                deps.stderr,
                "  {}: {} {}",
                c(OPT, "Server"),
                c(DIM, &base_url),
                c(SUCCESS, &format!("({})", status))
            );
        }
        Err(_) => {
            let _ = writeln!(
                deps.stderr,
                "  {}: {} {}",
                c(OPT, "Server"),
                c(DIM, &base_url),
                c(DIM, "(unreachable)")
            );
        }
    }

    0
}

/// `secrt auth logout` — Clear stored credentials.
fn run_auth_logout(args: &[String], deps: &mut Deps) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        crate::cli::print_auth_help(deps);
        return 0;
    }

    let c = color_func((deps.is_tty)());

    // Delete from keychain (best-effort)
    let _ = (deps.delete_keychain_secret)("api_key");

    // Comment out in config file
    let _ = crate::config::remove_config_key(&*deps.getenv, "api_key");

    let _ = writeln!(
        deps.stderr,
        "{} Credentials cleared",
        c(SUCCESS, "\u{2713}")
    );
    0
}

/// Read a single line from stdin (for y/n prompts). Returns the trimmed line.
fn read_stdin_line(stdin: &mut dyn Read) -> String {
    let mut buf = [0u8; 1];
    let mut line = String::new();
    loop {
        match stdin.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {
                if buf[0] == b'\n' {
                    break;
                }
                line.push(buf[0] as char);
            }
            Err(_) => break,
        }
    }
    line.trim().to_string()
}

/// Resolve existing API key from all sources. Returns (key, source) or empty
/// strings if no key is configured.
fn resolve_existing_key(deps: &Deps) -> (String, &'static str) {
    let config = crate::config::load_config_with(&*deps.getenv, &mut std::io::sink());
    let use_kc = config.use_keychain.unwrap_or(false);

    if let Some(env) = (deps.getenv)("SECRET_API_KEY") {
        (env, "env")
    } else if use_kc {
        if let Some(val) = (deps.get_keychain_secret)("api_key") {
            (val, "keychain")
        } else if let Some(ref key) = config.api_key {
            (key.clone(), "config")
        } else {
            (String::new(), "")
        }
    } else if let Some(ref key) = config.api_key {
        (key.clone(), "config")
    } else {
        (String::new(), "")
    }
}

/// Check if the user is already authenticated and prompt for confirmation.
/// Returns true if the caller should proceed, false if the user cancelled.
fn confirm_if_authenticated(deps: &mut Deps) -> bool {
    let (existing_key, source) = resolve_existing_key(deps);
    if existing_key.is_empty() {
        return true;
    }

    let c = color_func((deps.is_tty)());
    let masked = crate::config::mask_secret(&existing_key, true);
    let _ = writeln!(
        deps.stderr,
        "Already authenticated: {} {}",
        masked,
        c(DIM, &format!("(from: {})", source))
    );

    if !(deps.is_tty)() {
        // Non-interactive: proceed silently (matches gh behavior with --non-interactive)
        return true;
    }

    let _ = write!(deps.stderr, "Re-authenticate? [y/N]: ");
    let _ = deps.stderr.flush();
    let answer = read_stdin_line(&mut *deps.stdin).to_ascii_lowercase();
    answer == "y" || answer == "yes"
}

use std::io::Read;
