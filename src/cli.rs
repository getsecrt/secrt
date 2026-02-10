use std::io::{self, Read, Write};

use crate::burn::run_burn;
use crate::claim::run_claim;
use crate::client::SecretApi;
use crate::color::{color_func, ARG, CMD, DIM, HEADING, OPT, SUCCESS};
use crate::completion::{BASH_COMPLETION, FISH_COMPLETION, ZSH_COMPLETION};
use crate::create::run_create;

const DEFAULT_BASE_URL: &str = "https://secrt.ca";
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub type GetenvFn = Box<dyn Fn(&str) -> Option<String>>;
pub type RandBytesFn = Box<dyn Fn(&mut [u8]) -> Result<(), crate::envelope::EnvelopeError>>;
pub type ReadPassFn = Box<dyn Fn(&str, &mut dyn Write) -> io::Result<String>>;
pub type MakeApiFn = Box<dyn Fn(&str, &str) -> Box<dyn SecretApi>>;
pub type KeychainGetFn = Box<dyn Fn(&str) -> Option<String>>;
pub type KeychainListFn = Box<dyn Fn(&str) -> Vec<String>>;

/// Injectable dependencies for testing.
pub struct Deps {
    pub stdin: Box<dyn Read>,
    pub stdout: Box<dyn Write>,
    pub stderr: Box<dyn Write>,
    pub is_tty: Box<dyn Fn() -> bool>,
    pub is_stdout_tty: Box<dyn Fn() -> bool>,
    pub getenv: GetenvFn,
    pub rand_bytes: RandBytesFn,
    pub read_pass: ReadPassFn,
    pub make_api: MakeApiFn,
    pub get_keychain_secret: KeychainGetFn,
    pub get_keychain_secret_list: KeychainListFn,
}

/// Parsed global and command-specific flags.
#[derive(Default)]
pub struct ParsedArgs {
    pub args: Vec<String>,

    // Global
    pub base_url: String,
    pub base_url_from_flag: bool,
    pub api_key: String,
    pub json: bool,

    // Create
    pub ttl: String,
    pub text: String,
    pub file: String,
    pub multi_line: bool,
    pub trim: bool,

    // Input visibility
    pub show: bool,
    pub hidden: bool,

    // Global
    pub silent: bool,

    // Passphrase
    pub passphrase_prompt: bool,
    pub passphrase_env: String,
    pub passphrase_file: String,

    // Populated from config file (not from CLI flags)
    pub passphrase_default: String,
    pub show_default: bool,

    // Decryption passphrase list (from config/keychain, not CLI flags)
    pub decryption_passphrases: Vec<String>,
}

#[derive(Debug)]
pub enum CliError {
    ShowHelp,
    Error(String),
}

/// Main entry point. Returns exit code.
pub fn run(args: &[String], deps: &mut Deps) -> i32 {
    if args.len() < 2 {
        print_usage(deps);
        return 2;
    }

    match args[1].as_str() {
        "--version" | "-v" => {
            let _ = writeln!(deps.stdout, "secrt {}", VERSION);
            return 0;
        }
        "--help" | "-h" => {
            print_help(deps);
            return 0;
        }
        _ => {}
    }

    let command = &args[1];
    let remaining = &args[2..];

    match command.as_str() {
        "version" => {
            let _ = writeln!(deps.stdout, "secrt {}", VERSION);
            0
        }
        "help" => run_help(remaining, deps),
        "completion" => run_completion(remaining, deps),
        "config" => run_config(remaining, deps),
        "create" => run_create(remaining, deps),
        "claim" => run_claim(remaining, deps),
        "burn" => run_burn(remaining, deps),
        _ => {
            let _ = writeln!(deps.stderr, "error: unknown command {:?}", command);
            print_usage(deps);
            2
        }
    }
}

fn run_help(args: &[String], deps: &mut Deps) -> i32 {
    if args.is_empty() {
        print_help(deps);
        return 0;
    }
    match args[0].as_str() {
        "create" => print_create_help(deps),
        "claim" => print_claim_help(deps),
        "burn" => print_burn_help(deps),
        "config" => print_config_help(deps),
        _ => {
            let _ = writeln!(deps.stderr, "error: unknown command {:?}", args[0]);
            return 2;
        }
    }
    0
}

fn run_completion(args: &[String], deps: &mut Deps) -> i32 {
    if args.len() != 1 {
        let _ = writeln!(
            deps.stderr,
            "error: specify a shell (supported: bash, zsh, fish)"
        );
        return 2;
    }
    match args[0].as_str() {
        "bash" => {
            let _ = write!(deps.stdout, "{}", BASH_COMPLETION);
        }
        "zsh" => {
            let _ = write!(deps.stdout, "{}", ZSH_COMPLETION);
        }
        "fish" => {
            let _ = write!(deps.stdout, "{}", FISH_COMPLETION);
        }
        _ => {
            let _ = writeln!(
                deps.stderr,
                "error: unsupported shell {:?} (supported: bash, zsh, fish)",
                args[0]
            );
            return 2;
        }
    }
    0
}

/// Parse command-specific flags from args.
pub fn parse_flags(args: &[String]) -> Result<ParsedArgs, CliError> {
    let mut pa = ParsedArgs::default();
    let mut positional = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if !arg.starts_with('-') {
            positional.push(arg.clone());
            i += 1;
            continue;
        }

        match arg.as_str() {
            "--help" | "-h" => return Err(CliError::ShowHelp),
            "--json" => pa.json = true,
            "--base-url" => {
                i += 1;
                if i >= args.len() {
                    return Err(CliError::Error("--base-url requires a value".into()));
                }
                pa.base_url = args[i].clone();
                pa.base_url_from_flag = true;
            }
            "--api-key" => {
                i += 1;
                if i >= args.len() {
                    return Err(CliError::Error("--api-key requires a value".into()));
                }
                pa.api_key = args[i].clone();
            }
            "--ttl" => {
                i += 1;
                if i >= args.len() {
                    return Err(CliError::Error("--ttl requires a value".into()));
                }
                pa.ttl = args[i].clone();
            }
            "--text" => {
                i += 1;
                if i >= args.len() {
                    return Err(CliError::Error("--text requires a value".into()));
                }
                pa.text = args[i].clone();
            }
            "--file" => {
                i += 1;
                if i >= args.len() {
                    return Err(CliError::Error("--file requires a value".into()));
                }
                pa.file = args[i].clone();
            }
            "--multi-line" | "-m" => pa.multi_line = true,
            "--trim" => pa.trim = true,
            "--show" | "-s" => pa.show = true,
            "--hidden" => pa.hidden = true,
            "--silent" => pa.silent = true,
            "--passphrase-prompt" | "-p" => pa.passphrase_prompt = true,
            "--passphrase-env" => {
                i += 1;
                if i >= args.len() {
                    return Err(CliError::Error("--passphrase-env requires a value".into()));
                }
                pa.passphrase_env = args[i].clone();
            }
            "--passphrase-file" => {
                i += 1;
                if i >= args.len() {
                    return Err(CliError::Error("--passphrase-file requires a value".into()));
                }
                pa.passphrase_file = args[i].clone();
            }
            _ => return Err(CliError::Error(format!("unknown flag: {}", arg))),
        }
        i += 1;
    }

    pa.args = positional;
    Ok(pa)
}

/// Fill in defaults: CLI flag > env var > config file > built-in default.
pub fn resolve_globals(pa: &mut ParsedArgs, deps: &mut Deps) {
    let config = crate::config::load_config_with(&*deps.getenv, &mut deps.stderr);
    resolve_globals_with_config(pa, deps, &config);
}

/// Inner function that accepts an explicit Config (used by tests).
pub fn resolve_globals_with_config(
    pa: &mut ParsedArgs,
    deps: &Deps,
    config: &crate::config::Config,
) {
    if pa.base_url.is_empty() {
        if let Some(env) = (deps.getenv)("SECRET_BASE_URL") {
            pa.base_url = env;
        } else if let Some(ref url) = config.base_url {
            pa.base_url = url.clone();
        } else {
            pa.base_url = DEFAULT_BASE_URL.into();
        }
    }
    if pa.api_key.is_empty() {
        if let Some(env) = (deps.getenv)("SECRET_API_KEY") {
            pa.api_key = env;
        } else if let Some(val) = (deps.get_keychain_secret)("api_key") {
            pa.api_key = val;
        } else if let Some(ref key) = config.api_key {
            pa.api_key = key.clone();
        }
    }
    if pa.passphrase_default.is_empty() {
        if let Some(val) = (deps.get_keychain_secret)("passphrase") {
            pa.passphrase_default = val;
        } else if let Some(ref pass) = config.passphrase {
            pa.passphrase_default = pass.clone();
        }
    }
    if let Some(show) = config.show_input {
        pa.show_default = show;
    }

    // default_ttl: only if no --ttl flag was provided
    if pa.ttl.is_empty() {
        if let Some(ref ttl) = config.default_ttl {
            pa.ttl = ttl.clone();
        }
    }

    // decryption_passphrases: keychain (JSON array) then config, merged + deduped
    {
        let mut dp = (deps.get_keychain_secret_list)("decryption_passphrases");
        for p in &config.decryption_passphrases {
            if !dp.contains(p) {
                dp.push(p.clone());
            }
        }
        if !dp.is_empty() {
            pa.decryption_passphrases = dp;
        }
    }
}

// --- Config subcommands ---

fn run_config(args: &[String], deps: &mut Deps) -> i32 {
    if args.is_empty() {
        return run_config_show(deps);
    }
    match args[0].as_str() {
        "-h" | "--help" | "help" => {
            print_config_help(deps);
            0
        }
        "init" => {
            let force = args.iter().any(|a| a == "--force");
            run_config_init(force, deps)
        }
        "path" => run_config_path(deps),
        "set-passphrase" => run_config_set_passphrase(deps),
        "delete-passphrase" => run_config_delete_passphrase(deps),
        _ => {
            let _ = writeln!(
                deps.stderr,
                "error: unknown config subcommand {:?} (try: init, path, set-passphrase, delete-passphrase, --help)",
                args[0]
            );
            2
        }
    }
}

fn run_config_init(force: bool, deps: &mut Deps) -> i32 {
    let c = color_func((deps.is_tty)());
    let path = crate::config::config_path_with(&*deps.getenv);
    match crate::config::init_config_at(path, force) {
        Ok(path) => {
            let _ = writeln!(
                deps.stderr,
                "{} Created config file at: {}",
                c(SUCCESS, "\u{2713}"),
                path.display()
            );
            0
        }
        Err(e) => {
            let _ = writeln!(deps.stderr, "{}", e);
            1
        }
    }
}

fn run_config_path(deps: &mut Deps) -> i32 {
    match crate::config::config_path_with(&*deps.getenv) {
        Some(p) => {
            let _ = writeln!(deps.stdout, "{}", p.display());
            0
        }
        None => {
            let _ = writeln!(deps.stderr, "error: could not determine config directory");
            1
        }
    }
}

fn run_config_set_passphrase(deps: &mut Deps) -> i32 {
    let c = color_func((deps.is_tty)());

    let p1 = match (deps.read_pass)("Passphrase: ", &mut deps.stderr) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(deps.stderr, "error: failed to read passphrase: {}", e);
            return 1;
        }
    };

    if p1.is_empty() {
        let _ = writeln!(deps.stderr, "error: passphrase must not be empty");
        return 1;
    }

    let p2 = match (deps.read_pass)("   Confirm: ", &mut deps.stderr) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(deps.stderr, "error: failed to read confirmation: {}", e);
            return 1;
        }
    };

    if p1 != p2 {
        let _ = writeln!(deps.stderr, "error: passphrases do not match");
        return 1;
    }

    match crate::keychain::set_secret("passphrase", &p1) {
        Ok(()) => {
            let _ = writeln!(
                deps.stderr,
                "{} Passphrase saved to OS keychain",
                c(SUCCESS, "\u{2713}")
            );
            0
        }
        Err(e) => {
            let _ = writeln!(deps.stderr, "error: {}", e);
            let _ = writeln!(
                deps.stderr,
                "hint: use --passphrase-env or config file passphrase instead"
            );
            1
        }
    }
}

fn run_config_delete_passphrase(deps: &mut Deps) -> i32 {
    let c = color_func((deps.is_tty)());
    match crate::keychain::delete_secret("passphrase") {
        Ok(()) => {
            let _ = writeln!(
                deps.stderr,
                "{} Passphrase removed from OS keychain",
                c(SUCCESS, "\u{2713}")
            );
            0
        }
        Err(e) => {
            let _ = writeln!(deps.stderr, "error: {}", e);
            1
        }
    }
}

/// Format seconds into a human-readable TTL string (e.g. "24h", "365d").
fn format_ttl_seconds(secs: i64) -> String {
    if secs <= 0 {
        return "0s".into();
    }
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let remaining_secs = secs % 60;

    if days > 0 && secs % 86400 == 0 {
        format!("{}d", days)
    } else if hours > 0 && secs % 3600 == 0 {
        format!("{}h", hours + days * 24)
    } else if minutes > 0 && secs % 60 == 0 {
        format!("{}m", minutes + hours * 60 + days * 1440)
    } else {
        // Fallback: show full breakdown
        let mut parts = Vec::new();
        if days > 0 {
            parts.push(format!("{}d", days));
        }
        if hours > 0 {
            parts.push(format!("{}h", hours));
        }
        if minutes > 0 {
            parts.push(format!("{}m", minutes));
        }
        if remaining_secs > 0 {
            parts.push(format!("{}s", remaining_secs));
        }
        parts.join("")
    }
}

/// Format bytes into a human-readable string (e.g. "256 KB", "1 MB").
fn format_bytes(b: i64) -> String {
    if b >= 1024 * 1024 && b % (1024 * 1024) == 0 {
        format!("{} MB", b / (1024 * 1024))
    } else if b >= 1024 && b % 1024 == 0 {
        format!("{} KB", b / 1024)
    } else {
        format!("{} bytes", b)
    }
}

/// Format a limit value, showing "unlimited" for zero.
fn format_limit(n: i64) -> String {
    if n == 0 {
        "unlimited".into()
    } else {
        n.to_string()
    }
}

fn run_config_show(deps: &mut Deps) -> i32 {
    let c = color_func((deps.is_stdout_tty)());
    let config = crate::config::load_config_with(&*deps.getenv, &mut deps.stderr);

    // Config file path
    let resolved_path = crate::config::config_path_with(&*deps.getenv);
    let config_path = resolved_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(unknown)".into());
    let config_exists = resolved_path.as_ref().map(|p| p.exists()).unwrap_or(false);

    let _ = writeln!(
        deps.stderr,
        "{}\n  {} {}",
        c(HEADING, "CONFIG FILE"),
        c(DIM, &config_path),
        if config_exists { "" } else { "(not found)" },
    );
    if !config_exists {
        let _ = writeln!(
            deps.stderr,
            "  Run {} to create one.",
            c(CMD, "secrt config init"),
        );
    }

    let _ = writeln!(deps.stderr);
    let _ = writeln!(deps.stderr, "{}", c(HEADING, "EFFECTIVE SETTINGS"));

    // base_url: flag/env/config/default
    let (base_url_val, base_url_src) = if let Some(env) = (deps.getenv)("SECRET_BASE_URL") {
        (env, "env SECRET_BASE_URL")
    } else if let Some(ref url) = config.base_url {
        (url.clone(), "config file")
    } else {
        (DEFAULT_BASE_URL.into(), "default")
    };
    let _ = writeln!(
        deps.stderr,
        "  {}: {} {}",
        c(OPT, "base_url"),
        base_url_val,
        c(DIM, &format!("({})", base_url_src)),
    );

    // api_key: env/keychain/config/none
    let (api_key_display, api_key_src) = if let Some(env) = (deps.getenv)("SECRET_API_KEY") {
        (crate::config::mask_secret(&env, true), "env SECRET_API_KEY")
    } else if let Some(val) = (deps.get_keychain_secret)("api_key") {
        (crate::config::mask_secret(&val, true), "keychain")
    } else if let Some(ref key) = config.api_key {
        (crate::config::mask_secret(key, true), "config file")
    } else {
        ("(not set)".into(), "")
    };
    if api_key_src.is_empty() {
        let _ = writeln!(
            deps.stderr,
            "  {}: {}",
            c(OPT, "api_key"),
            c(DIM, &api_key_display),
        );
    } else {
        let _ = writeln!(
            deps.stderr,
            "  {}: {} {}",
            c(OPT, "api_key"),
            api_key_display,
            c(DIM, &format!("({})", api_key_src)),
        );
    }

    // passphrase: keychain/config/none
    let (pass_display, pass_src) = if let Some(val) = (deps.get_keychain_secret)("passphrase") {
        (crate::config::mask_secret(&val, false), "keychain")
    } else if let Some(ref pass) = config.passphrase {
        (crate::config::mask_secret(pass, false), "config file")
    } else {
        ("(not set)".into(), "")
    };
    if pass_src.is_empty() {
        let _ = writeln!(
            deps.stderr,
            "  {}: {}",
            c(OPT, "passphrase"),
            c(DIM, &pass_display),
        );
    } else {
        let _ = writeln!(
            deps.stderr,
            "  {}: {} {}",
            c(OPT, "passphrase"),
            pass_display,
            c(DIM, &format!("({})", pass_src)),
        );
    }

    // Fetch server info (best-effort, non-fatal)
    let api_key_for_info = if let Some(env) = (deps.getenv)("SECRET_API_KEY") {
        env
    } else if let Some(val) = (deps.get_keychain_secret)("api_key") {
        val
    } else if let Some(ref key) = config.api_key {
        key.clone()
    } else {
        String::new()
    };
    let api = (deps.make_api)(&base_url_val, &api_key_for_info);
    let server_info = api.info().ok();

    // default_ttl: config/server default
    if let Some(ref ttl) = config.default_ttl {
        let _ = writeln!(
            deps.stderr,
            "  {}: {} {}",
            c(OPT, "default_ttl"),
            ttl,
            c(DIM, "(config file)"),
        );
    } else if let Some(ref info) = server_info {
        let _ = writeln!(
            deps.stderr,
            "  {}: {} {}",
            c(OPT, "default_ttl"),
            format_ttl_seconds(info.ttl.default_seconds),
            c(DIM, "(server default)"),
        );
    } else {
        let _ = writeln!(
            deps.stderr,
            "  {}: {}",
            c(OPT, "default_ttl"),
            c(DIM, "server default"),
        );
    }

    // show_input: config/default
    let (show_val, show_src) = if let Some(show) = config.show_input {
        (show.to_string(), "config file")
    } else {
        ("false".into(), "default")
    };
    let _ = writeln!(
        deps.stderr,
        "  {}: {} {}",
        c(OPT, "show_input"),
        show_val,
        c(DIM, &format!("({})", show_src)),
    );

    // decryption_passphrases: keychain/config/both/none
    let kc_list = (deps.get_keychain_secret_list)("decryption_passphrases");
    let cfg_list = &config.decryption_passphrases;
    let has_kc = !kc_list.is_empty();
    let has_cfg = !cfg_list.is_empty();
    if !has_kc && !has_cfg {
        let _ = writeln!(
            deps.stderr,
            "  {}: {}",
            c(OPT, "decryption_passphrases"),
            c(DIM, "(not set)"),
        );
    } else {
        // Merge for display: keychain first, then config (deduped)
        let mut merged = kc_list.clone();
        for p in cfg_list {
            if !merged.contains(p) {
                merged.push(p.clone());
            }
        }
        let masked = crate::config::mask_secret_list(&merged);
        let src = match (has_kc, has_cfg) {
            (true, true) => "keychain + config file",
            (true, false) => "keychain",
            (false, true) => "config file",
            (false, false) => unreachable!(),
        };
        let _ = writeln!(
            deps.stderr,
            "  {}: {} {}",
            c(OPT, "decryption_passphrases"),
            masked,
            c(DIM, &format!("({} entries, {})", merged.len(), src)),
        );
    }

    // SERVER LIMITS section
    let _ = writeln!(deps.stderr);
    if let Some(ref info) = server_info {
        let _ = writeln!(
            deps.stderr,
            "{} {}",
            c(HEADING, "SERVER LIMITS"),
            c(DIM, &format!("(from {})", base_url_val)),
        );

        let _ = writeln!(
            deps.stderr,
            "  {}: {} {}",
            c(OPT, "default_ttl"),
            format_ttl_seconds(info.ttl.default_seconds),
            c(DIM, &format!("({}s)", info.ttl.default_seconds)),
        );
        let _ = writeln!(
            deps.stderr,
            "  {}: {} {}",
            c(OPT, "max_ttl"),
            format_ttl_seconds(info.ttl.max_seconds),
            c(DIM, &format!("({}s)", info.ttl.max_seconds)),
        );
        let _ = writeln!(
            deps.stderr,
            "  {}: {}",
            c(OPT, "authenticated"),
            if info.authenticated { "yes" } else { "no" },
        );

        let has_key = !api_key_for_info.is_empty();
        let (primary, secondary) = if has_key {
            (&info.limits.authed, &info.limits.public)
        } else {
            (&info.limits.public, &info.limits.authed)
        };
        let (primary_label, secondary_label) = if has_key {
            ("authed", "public")
        } else {
            ("public", "authed")
        };

        let _ = writeln!(
            deps.stderr,
            "  {}: {} {} / {} {}",
            c(OPT, "max_envelope"),
            format_bytes(primary.max_envelope_bytes),
            c(DIM, &format!("({})", primary_label)),
            format_bytes(secondary.max_envelope_bytes),
            c(DIM, &format!("({})", secondary_label)),
        );
        let _ = writeln!(
            deps.stderr,
            "  {}: {} {} / {} {}",
            c(OPT, "max_secrets"),
            format_limit(primary.max_secrets),
            c(DIM, &format!("({})", primary_label)),
            format_limit(secondary.max_secrets),
            c(DIM, &format!("({})", secondary_label)),
        );
        let _ = writeln!(
            deps.stderr,
            "  {}: {} {} / {} {}",
            c(OPT, "max_total"),
            format_bytes(primary.max_total_bytes),
            c(DIM, &format!("({})", primary_label)),
            format_bytes(secondary.max_total_bytes),
            c(DIM, &format!("({})", secondary_label)),
        );
        let _ = writeln!(
            deps.stderr,
            "  {}: {}/s burst {} {} / {}/s burst {} {}",
            c(OPT, "create_rate"),
            primary.rate.requests_per_second,
            primary.rate.burst,
            c(DIM, &format!("({})", primary_label)),
            secondary.rate.requests_per_second,
            secondary.rate.burst,
            c(DIM, &format!("({})", secondary_label)),
        );
        let _ = writeln!(
            deps.stderr,
            "  {}: {}/s burst {}",
            c(OPT, "claim_rate"),
            info.claim_rate.requests_per_second,
            info.claim_rate.burst,
        );
    } else {
        let _ = writeln!(
            deps.stderr,
            "{} {}",
            c(HEADING, "SERVER LIMITS"),
            c(DIM, "(server does not support info endpoint)"),
        );
    }

    0
}

// --- Help text ---

fn print_usage(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let _ = write!(
        deps.stderr,
        "{} — one-time secret sharing\n\n  {}            share a secret (interactive)\n  {} {}       retrieve a secret\n\nRun '{}' for full usage.\n",
        c(CMD, "secrt"),
        c(CMD, "secrt create"),
        c(CMD, "secrt claim"),
        c(ARG, "<url>"),
        c(CMD, "secrt help")
    );
}

pub fn print_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let _ = write!(
        deps.stderr,
        "{} — one-time secret sharing\n\n\
{}\n  {} {} {}\n\n\
{}\n\
  {}            Encrypt and upload a secret\n\
  {}             Retrieve and decrypt a secret\n\
  {}              Destroy a secret (requires API key)\n\
  {}            Show config / init / path\n\
  {}           Show version\n\
  {}              Show this help\n\
  {}        Output shell completion script\n\n\
{}\n\
  {} {}          Server URL (default: https://secrt.ca)\n\
  {} {}           API key for authenticated access\n\
  {}                    Output as JSON\n\
  {}                  Suppress status output\n\
  {}                Show help\n\
  {}             Show version\n\n\
{}\n\
  echo \"pw123\" | {} {}\n\
  {} https://secrt.ca/s/abc#v1.key\n\n\
{}\n\
  {} {}     Create template config file\n\
  {}               Print config file path\n\
  Settings are loaded from {}.\n\
  Supported keys: api_key, base_url, default_ttl, passphrase,\n\
  decryption_passphrases, show_input.\n\
  Precedence: CLI flag > env var > config file > default.\n",
        c(CMD, "secrt"),
        c(HEADING, "USAGE"),
        c(CMD, "secrt"),
        c(CMD, "<command>"),
        c(ARG, "[options]"),
        c(HEADING, "COMMANDS"),
        c(CMD, "create"),
        c(CMD, "claim"),
        c(CMD, "burn"),
        c(CMD, "config"),
        c(CMD, "version"),
        c(CMD, "help"),
        c(CMD, "completion"),
        c(HEADING, "GLOBAL OPTIONS"),
        c(OPT, "--base-url"),
        c(ARG, "<url>"),
        c(OPT, "--api-key"),
        c(ARG, "<key>"),
        c(OPT, "--json"),
        c(OPT, "--silent"),
        c(OPT, "-h, --help"),
        c(OPT, "-v, --version"),
        c(HEADING, "EXAMPLES"),
        c(CMD, "secrt"),
        c(CMD, "create"),
        c(CMD, "secrt claim"),
        c(HEADING, "CONFIG"),
        c(CMD, "config init"),
        c(OPT, "[--force]"),
        c(CMD, "config path"),
        c(DIM, "~/.config/secrt/config.toml"),
    );
}

pub fn print_create_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let _ = write!(
        deps.stderr,
        "{} {} — Encrypt and upload a secret\n\n\
{}\n  {} {} {}\n\n\
{}\n\
  {} {}                   TTL for the secret (e.g., 5m, 2h, 1d)\n\
  {} {}                Secret text (visible in shell history)\n\
  {} {}                 Read secret from file\n\
  {}              Multi-line input (read until Ctrl+D)\n\
  {}                        Trim leading/trailing whitespace\n\
  {}                    Show input as you type\n\
  {}                      Hide input (default, overrides --show)\n\
  {}       Prompt for passphrase\n\
  {} {}       Read passphrase from env var\n\
  {} {}      Read passphrase from file\n\
  {} {}              Server URL\n\
  {} {}               API key\n\
  {}                        Output as JSON\n\
  {}                      Suppress status output\n\
  {}                    Show help\n\n\
{}\n\
  Interactive: single-line hidden input (like a password).\n\
  Use {} for multi-line input, {} or {} for alternatives.\n\
  Set show_input = true in config to show input by default.\n\n\
{}\n\
  echo \"secret\" | {} {}\n\
  {} {} {} \"my secret\" {} 5m\n",
        c(CMD, "secrt"),
        c(CMD, "create"),
        c(HEADING, "USAGE"),
        c(CMD, "secrt"),
        c(CMD, "create"),
        c(ARG, "[options]"),
        c(HEADING, "OPTIONS"),
        c(OPT, "--ttl"),
        c(ARG, "<ttl>"),
        c(OPT, "--text"),
        c(ARG, "<value>"),
        c(OPT, "--file"),
        c(ARG, "<path>"),
        c(OPT, "-m, --multi-line"),
        c(OPT, "--trim"),
        c(OPT, "-s, --show"),
        c(OPT, "--hidden"),
        c(OPT, "-p, --passphrase-prompt"),
        c(OPT, "--passphrase-env"),
        c(ARG, "<name>"),
        c(OPT, "--passphrase-file"),
        c(ARG, "<path>"),
        c(OPT, "--base-url"),
        c(ARG, "<url>"),
        c(OPT, "--api-key"),
        c(ARG, "<key>"),
        c(OPT, "--json"),
        c(OPT, "--silent"),
        c(OPT, "-h, --help"),
        c(HEADING, "INPUT"),
        c(OPT, "-m"),
        c(OPT, "--text"),
        c(OPT, "--file"),
        c(HEADING, "EXAMPLES"),
        c(CMD, "secrt"),
        c(CMD, "create"),
        c(CMD, "secrt"),
        c(CMD, "create"),
        c(OPT, "--text"),
        c(OPT, "--ttl"),
    );
}

pub fn print_claim_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let _ = write!(
        deps.stderr,
        "{} {} — Retrieve and decrypt a secret\n\n\
{}\n  {} {} {} {}\n\n\
{}\n\
  {}       Prompt for passphrase\n\
  {} {}       Read passphrase from env var\n\
  {} {}      Read passphrase from file\n\
  {} {}              Server URL\n\
  {}                        Output as JSON\n\
  {}                      Suppress status output\n\
  {}                    Show help\n\n\
{}\n\
  {} {} https://secrt.ca/s/abc#v1.key\n",
        c(CMD, "secrt"),
        c(CMD, "claim"),
        c(HEADING, "USAGE"),
        c(CMD, "secrt"),
        c(CMD, "claim"),
        c(ARG, "<share-url>"),
        c(ARG, "[options]"),
        c(HEADING, "OPTIONS"),
        c(OPT, "-p, --passphrase-prompt"),
        c(OPT, "--passphrase-env"),
        c(ARG, "<name>"),
        c(OPT, "--passphrase-file"),
        c(ARG, "<path>"),
        c(OPT, "--base-url"),
        c(ARG, "<url>"),
        c(OPT, "--json"),
        c(OPT, "--silent"),
        c(OPT, "-h, --help"),
        c(HEADING, "EXAMPLES"),
        c(CMD, "secrt"),
        c(CMD, "claim"),
    );
}

pub fn print_burn_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let _ = write!(
        deps.stderr,
        "{} {} — Destroy a secret (requires API key)\n\n\
{}\n  {} {} {} {}\n\n\
{}\n\
  {} {}          API key (required)\n\
  {} {}         Server URL\n\
  {}                   Output as JSON\n\
  {}                 Suppress status output\n\
  {}               Show help\n\n\
{}\n\
  {} {} test-id {} sk_prefix.secret\n",
        c(CMD, "secrt"),
        c(CMD, "burn"),
        c(HEADING, "USAGE"),
        c(CMD, "secrt"),
        c(CMD, "burn"),
        c(ARG, "<id-or-url>"),
        c(ARG, "[options]"),
        c(HEADING, "OPTIONS"),
        c(OPT, "--api-key"),
        c(ARG, "<key>"),
        c(OPT, "--base-url"),
        c(ARG, "<url>"),
        c(OPT, "--json"),
        c(OPT, "--silent"),
        c(OPT, "-h, --help"),
        c(HEADING, "EXAMPLES"),
        c(CMD, "secrt"),
        c(CMD, "burn"),
        c(OPT, "--api-key"),
    );
}

pub fn print_config_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let _ = write!(
        deps.stderr,
        "{} {} — Show config / init / path\n\n\
{}\n\
  {} {}                    Show effective config and file path\n\
  {} {} {}               Create template config file\n\
  {} {} {}               Print config file path\n\
  {} {} {}     Store passphrase in OS keychain\n\
  {} {} {}  Remove passphrase from OS keychain\n\n\
{}\n\
  {}          Overwrite existing config file (for init)\n\
  {}       Show help\n\n\
{}\n\
  Settings are loaded from ~/.config/secrt/config.toml.\n\
  Supported keys: api_key, base_url, default_ttl, passphrase,\n\
  decryption_passphrases, show_input.\n\
  Precedence: CLI flag > env var > config file > default.\n",
        c(CMD, "secrt"),
        c(CMD, "config"),
        c(HEADING, "SUBCOMMANDS"),
        c(CMD, "secrt"),
        c(CMD, "config"),
        c(CMD, "secrt"),
        c(CMD, "config"),
        c(CMD, "init"),
        c(CMD, "secrt"),
        c(CMD, "config"),
        c(CMD, "path"),
        c(CMD, "secrt"),
        c(CMD, "config"),
        c(CMD, "set-passphrase"),
        c(CMD, "secrt"),
        c(CMD, "config"),
        c(CMD, "delete-passphrase"),
        c(HEADING, "OPTIONS"),
        c(OPT, "--force"),
        c(OPT, "-h, --help"),
        c(HEADING, "CONFIG"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // --- parse_flags tests ---

    #[test]
    fn flags_empty() {
        let pa = parse_flags(&s(&[])).unwrap();
        assert!(pa.args.is_empty());
        assert!(!pa.json);
        assert!(pa.base_url.is_empty());
        assert!(pa.api_key.is_empty());
    }

    #[test]
    fn flags_json() {
        let pa = parse_flags(&s(&["--json"])).unwrap();
        assert!(pa.json);
    }

    #[test]
    fn flags_base_url() {
        let pa = parse_flags(&s(&["--base-url", "https://example.com"])).unwrap();
        assert_eq!(pa.base_url, "https://example.com");
        assert!(pa.base_url_from_flag);
    }

    #[test]
    fn flags_api_key() {
        let pa = parse_flags(&s(&["--api-key", "sk_test"])).unwrap();
        assert_eq!(pa.api_key, "sk_test");
    }

    #[test]
    fn flags_ttl() {
        let pa = parse_flags(&s(&["--ttl", "5m"])).unwrap();
        assert_eq!(pa.ttl, "5m");
    }

    #[test]
    fn flags_text() {
        let pa = parse_flags(&s(&["--text", "hello"])).unwrap();
        assert_eq!(pa.text, "hello");
    }

    #[test]
    fn flags_file() {
        let pa = parse_flags(&s(&["--file", "/tmp/secret.txt"])).unwrap();
        assert_eq!(pa.file, "/tmp/secret.txt");
    }

    #[test]
    fn flags_multi_line() {
        let pa = parse_flags(&s(&["--multi-line"])).unwrap();
        assert!(pa.multi_line);
    }

    #[test]
    fn flags_multi_line_short() {
        let pa = parse_flags(&s(&["-m"])).unwrap();
        assert!(pa.multi_line);
    }

    #[test]
    fn flags_trim() {
        let pa = parse_flags(&s(&["--trim"])).unwrap();
        assert!(pa.trim);
    }

    #[test]
    fn flags_show() {
        let pa = parse_flags(&s(&["--show"])).unwrap();
        assert!(pa.show);
    }

    #[test]
    fn flags_show_short() {
        let pa = parse_flags(&s(&["-s"])).unwrap();
        assert!(pa.show);
    }

    #[test]
    fn flags_hidden() {
        let pa = parse_flags(&s(&["--hidden"])).unwrap();
        assert!(pa.hidden);
    }

    #[test]
    fn flags_silent() {
        let pa = parse_flags(&s(&["--silent"])).unwrap();
        assert!(pa.silent);
    }

    #[test]
    fn flags_multi_line_and_trim() {
        let pa = parse_flags(&s(&["--multi-line", "--trim"])).unwrap();
        assert!(pa.multi_line);
        assert!(pa.trim);
    }

    #[test]
    fn flags_passphrase_prompt() {
        let pa = parse_flags(&s(&["--passphrase-prompt"])).unwrap();
        assert!(pa.passphrase_prompt);
    }

    #[test]
    fn flags_passphrase_prompt_short() {
        let pa = parse_flags(&s(&["-p"])).unwrap();
        assert!(pa.passphrase_prompt);
    }

    #[test]
    fn flags_passphrase_env() {
        let pa = parse_flags(&s(&["--passphrase-env", "MY_PASS"])).unwrap();
        assert_eq!(pa.passphrase_env, "MY_PASS");
    }

    #[test]
    fn flags_passphrase_file() {
        let pa = parse_flags(&s(&["--passphrase-file", "/tmp/pass"])).unwrap();
        assert_eq!(pa.passphrase_file, "/tmp/pass");
    }

    #[test]
    fn flags_missing_value_base_url() {
        let err = parse_flags(&s(&["--base-url"]));
        assert!(matches!(err, Err(CliError::Error(_))));
    }

    #[test]
    fn flags_missing_value_api_key() {
        let err = parse_flags(&s(&["--api-key"]));
        assert!(matches!(err, Err(CliError::Error(_))));
    }

    #[test]
    fn flags_missing_value_ttl() {
        let err = parse_flags(&s(&["--ttl"]));
        assert!(matches!(err, Err(CliError::Error(_))));
    }

    #[test]
    fn flags_missing_value_text() {
        let err = parse_flags(&s(&["--text"]));
        assert!(matches!(err, Err(CliError::Error(_))));
    }

    #[test]
    fn flags_missing_value_file() {
        let err = parse_flags(&s(&["--file"]));
        assert!(matches!(err, Err(CliError::Error(_))));
    }

    #[test]
    fn flags_missing_value_passphrase_env() {
        let err = parse_flags(&s(&["--passphrase-env"]));
        assert!(matches!(err, Err(CliError::Error(_))));
    }

    #[test]
    fn flags_missing_value_passphrase_file() {
        let err = parse_flags(&s(&["--passphrase-file"]));
        assert!(matches!(err, Err(CliError::Error(_))));
    }

    #[test]
    fn flags_help() {
        let err = parse_flags(&s(&["--help"]));
        assert!(matches!(err, Err(CliError::ShowHelp)));
    }

    #[test]
    fn flags_help_short() {
        let err = parse_flags(&s(&["-h"]));
        assert!(matches!(err, Err(CliError::ShowHelp)));
    }

    #[test]
    fn flags_unknown() {
        let err = parse_flags(&s(&["--bogus"]));
        assert!(matches!(err, Err(CliError::Error(_))));
    }

    #[test]
    fn flags_positional() {
        let pa = parse_flags(&s(&["foo", "bar"])).unwrap();
        assert_eq!(pa.args, vec!["foo", "bar"]);
    }

    #[test]
    fn flags_mixed() {
        let pa = parse_flags(&s(&["myurl", "--json", "--ttl", "5m"])).unwrap();
        assert_eq!(pa.args, vec!["myurl"]);
        assert!(pa.json);
        assert_eq!(pa.ttl, "5m");
    }

    // --- resolve_globals tests ---

    fn make_deps_for_globals(env: std::collections::HashMap<String, String>) -> Deps {
        Deps {
            stdin: Box::new(std::io::Cursor::new(Vec::new())),
            stdout: Box::new(Vec::new()),
            stderr: Box::new(Vec::new()),
            is_tty: Box::new(|| false),
            is_stdout_tty: Box::new(|| false),
            getenv: Box::new(move |key: &str| env.get(key).cloned()),
            rand_bytes: Box::new(|_buf: &mut [u8]| Ok(())),
            read_pass: Box::new(|_prompt: &str, _w: &mut dyn Write| {
                Err(io::Error::new(io::ErrorKind::Other, "no pass"))
            }),
            make_api: Box::new(|base_url: &str, api_key: &str| {
                Box::new(crate::client::ApiClient {
                    base_url: base_url.to_string(),
                    api_key: api_key.to_string(),
                })
            }),
            get_keychain_secret: Box::new(|_key: &str| None),
            get_keychain_secret_list: Box::new(|_key: &str| Vec::new()),
        }
    }

    #[test]
    fn globals_default_base_url() {
        let deps = make_deps_for_globals(std::collections::HashMap::new());
        let config = crate::config::Config::default();
        let mut pa = ParsedArgs::default();
        resolve_globals_with_config(&mut pa, &deps, &config);
        assert_eq!(pa.base_url, "https://secrt.ca");
    }

    #[test]
    fn globals_env_base_url() {
        let mut env = std::collections::HashMap::new();
        env.insert("SECRET_BASE_URL".into(), "https://test.example.com".into());
        let deps = make_deps_for_globals(env);
        let config = crate::config::Config::default();
        let mut pa = ParsedArgs::default();
        resolve_globals_with_config(&mut pa, &deps, &config);
        assert_eq!(pa.base_url, "https://test.example.com");
    }

    #[test]
    fn globals_flag_overrides_env() {
        let mut env = std::collections::HashMap::new();
        env.insert("SECRET_BASE_URL".into(), "https://env.example.com".into());
        let deps = make_deps_for_globals(env);
        let config = crate::config::Config::default();
        let mut pa = ParsedArgs::default();
        pa.base_url = "https://flag.example.com".into();
        resolve_globals_with_config(&mut pa, &deps, &config);
        assert_eq!(pa.base_url, "https://flag.example.com");
    }

    #[test]
    fn globals_env_api_key() {
        let mut env = std::collections::HashMap::new();
        env.insert("SECRET_API_KEY".into(), "sk_from_env".into());
        let deps = make_deps_for_globals(env);
        let config = crate::config::Config::default();
        let mut pa = ParsedArgs::default();
        resolve_globals_with_config(&mut pa, &deps, &config);
        assert_eq!(pa.api_key, "sk_from_env");
    }

    #[test]
    fn globals_no_env_api_key() {
        let deps = make_deps_for_globals(std::collections::HashMap::new());
        let config = crate::config::Config::default();
        let mut pa = ParsedArgs::default();
        resolve_globals_with_config(&mut pa, &deps, &config);
        assert!(pa.api_key.is_empty());
    }

    #[test]
    fn globals_config_base_url() {
        let deps = make_deps_for_globals(std::collections::HashMap::new());
        let config = crate::config::Config {
            base_url: Some("https://config.example.com".into()),
            ..Default::default()
        };
        let mut pa = ParsedArgs::default();
        resolve_globals_with_config(&mut pa, &deps, &config);
        assert_eq!(pa.base_url, "https://config.example.com");
    }

    #[test]
    fn globals_config_api_key() {
        let deps = make_deps_for_globals(std::collections::HashMap::new());
        let config = crate::config::Config {
            api_key: Some("sk_from_config".into()),
            ..Default::default()
        };
        let mut pa = ParsedArgs::default();
        resolve_globals_with_config(&mut pa, &deps, &config);
        assert_eq!(pa.api_key, "sk_from_config");
    }

    #[test]
    fn globals_env_overrides_config() {
        let mut env = std::collections::HashMap::new();
        env.insert("SECRET_API_KEY".into(), "sk_from_env".into());
        let deps = make_deps_for_globals(env);
        let config = crate::config::Config {
            api_key: Some("sk_from_config".into()),
            ..Default::default()
        };
        let mut pa = ParsedArgs::default();
        resolve_globals_with_config(&mut pa, &deps, &config);
        assert_eq!(pa.api_key, "sk_from_env");
    }

    #[test]
    fn globals_flag_overrides_config() {
        let deps = make_deps_for_globals(std::collections::HashMap::new());
        let config = crate::config::Config {
            base_url: Some("https://config.example.com".into()),
            ..Default::default()
        };
        let mut pa = ParsedArgs::default();
        pa.base_url = "https://flag.example.com".into();
        resolve_globals_with_config(&mut pa, &deps, &config);
        assert_eq!(pa.base_url, "https://flag.example.com");
    }

    #[test]
    fn globals_config_show_input() {
        let deps = make_deps_for_globals(std::collections::HashMap::new());
        let config = crate::config::Config {
            show_input: Some(true),
            ..Default::default()
        };
        let mut pa = ParsedArgs::default();
        resolve_globals_with_config(&mut pa, &deps, &config);
        assert!(pa.show_default);
    }

    #[test]
    fn globals_config_default_ttl() {
        let deps = make_deps_for_globals(std::collections::HashMap::new());
        let config = crate::config::Config {
            default_ttl: Some("2h".into()),
            ..Default::default()
        };
        let mut pa = ParsedArgs::default();
        resolve_globals_with_config(&mut pa, &deps, &config);
        assert_eq!(pa.ttl, "2h");
    }

    #[test]
    fn globals_flag_ttl_overrides_config() {
        let deps = make_deps_for_globals(std::collections::HashMap::new());
        let config = crate::config::Config {
            default_ttl: Some("2h".into()),
            ..Default::default()
        };
        let mut pa = ParsedArgs::default();
        pa.ttl = "5m".into();
        resolve_globals_with_config(&mut pa, &deps, &config);
        assert_eq!(pa.ttl, "5m", "--ttl flag should override config");
    }

    #[test]
    fn globals_config_decryption_passphrases() {
        let deps = make_deps_for_globals(std::collections::HashMap::new());
        let config = crate::config::Config {
            decryption_passphrases: vec!["pass1".into(), "pass2".into()],
            ..Default::default()
        };
        let mut pa = ParsedArgs::default();
        resolve_globals_with_config(&mut pa, &deps, &config);
        assert_eq!(pa.decryption_passphrases, vec!["pass1", "pass2"]);
    }

    #[test]
    fn globals_config_no_default_ttl() {
        let deps = make_deps_for_globals(std::collections::HashMap::new());
        let config = crate::config::Config::default();
        let mut pa = ParsedArgs::default();
        resolve_globals_with_config(&mut pa, &deps, &config);
        assert!(pa.ttl.is_empty(), "ttl should remain empty when no config");
    }
}
