use std::io::{self, Read, Write};

use crate::burn::run_burn;
use crate::client::SecretApi;
use crate::color::{color_func, ARG, CMD, DIM, HEADING, OPT, SUCCESS};
use crate::completion::{BASH_COMPLETION, FISH_COMPLETION, ZSH_COMPLETION};
use crate::gen::run_gen;
use crate::get::run_get;
use crate::send::run_send;

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

    // Send
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
    pub no_passphrase: bool,

    // Get
    pub output: String,

    // Gen
    pub gen_length: u32,
    pub gen_no_symbols: bool,
    pub gen_no_numbers: bool,
    pub gen_no_caps: bool,
    pub gen_grouped: bool,
    pub gen_count: u32,

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
        "send" => run_send(remaining, deps),
        "get" => run_get(remaining, deps),
        "burn" => run_burn(remaining, deps),
        "gen" | "generate" => run_gen(remaining, deps),
        _ if looks_like_share_url(command) => {
            // Implicit get: treat share URLs/bare IDs as `secrt get <url>`
            run_get(&args[1..], deps)
        }
        _ => {
            let _ = writeln!(deps.stderr, "error: unknown command {:?}", command);
            print_usage(deps);
            2
        }
    }
}

/// Detect whether a string looks like a share URL (contains `#` followed by
/// a base64url string of >= 22 chars). The threshold prevents false positives
/// on short fragments while being well below the actual 43-char key length.
fn looks_like_share_url(s: &str) -> bool {
    let Some(hash_pos) = s.find('#') else {
        return false;
    };
    let frag = &s[hash_pos + 1..];
    frag.len() >= 22
        && frag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn run_help(args: &[String], deps: &mut Deps) -> i32 {
    if args.is_empty() {
        print_help(deps);
        return 0;
    }
    match args[0].as_str() {
        "send" => print_send_help(deps),
        "get" => print_get_help(deps),
        "burn" => print_burn_help(deps),
        "gen" | "generate" => print_gen_help(deps),
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

        // `--` stops flag parsing; everything after is positional
        if arg == "--" {
            positional.extend_from_slice(&args[i + 1..]);
            break;
        }

        if !arg.starts_with('-') {
            positional.push(arg.clone());
            i += 1;
            continue;
        }

        // Support --flag=value and -Xvalue syntax
        let (flag, inline_val) = if arg.starts_with("--") {
            // Long flags: split on first '='
            if let Some(eq) = arg.find('=') {
                (&arg[..eq], Some(arg[eq + 1..].to_string()))
            } else {
                (arg.as_str(), None)
            }
        } else if arg.len() > 2 {
            // Short flags: -X<value> or -X=<value>
            let val = &arg[2..];
            let val = val.strip_prefix('=').unwrap_or(val);
            (&arg[..2], Some(val.to_string()))
        } else {
            (arg.as_str(), None)
        };

        /// Read the value for a flag that requires one, preferring an inline
        /// `--flag=value` if present, otherwise consuming the next argument.
        macro_rules! next_val {
            ($flag_name:expr) => {{
                if let Some(ref v) = inline_val {
                    v.clone()
                } else {
                    i += 1;
                    if i >= args.len() {
                        return Err(CliError::Error(format!("{} requires a value", $flag_name)));
                    }
                    args[i].clone()
                }
            }};
        }

        match flag {
            "--help" | "-h" => return Err(CliError::ShowHelp),
            "--json" => pa.json = true,
            "--base-url" => {
                pa.base_url = next_val!("--base-url");
                pa.base_url_from_flag = true;
            }
            "--api-key" => pa.api_key = next_val!("--api-key"),
            "--ttl" => pa.ttl = next_val!("--ttl"),
            "--text" => pa.text = next_val!("--text"),
            "--file" | "-f" => pa.file = next_val!("-f/--file"),
            "--multi-line" | "-m" => pa.multi_line = true,
            "--trim" => pa.trim = true,
            "--show" | "-s" => pa.show = true,
            "--hidden" => pa.hidden = true,
            "--silent" => pa.silent = true,
            "--output" | "-o" => pa.output = next_val!("--output"),
            "--passphrase-prompt" | "-p" => pa.passphrase_prompt = true,
            "--no-passphrase" | "-n" => pa.no_passphrase = true,
            "--passphrase-env" => pa.passphrase_env = next_val!("--passphrase-env"),
            "--passphrase-file" => pa.passphrase_file = next_val!("--passphrase-file"),
            // Gen flags
            "--length" | "-L" => {
                let val = next_val!("--length");
                pa.gen_length = val.parse::<u32>().ok().filter(|&n| n >= 1).ok_or_else(|| {
                    CliError::Error(format!(
                        "--length requires a positive integer, got {:?}",
                        val
                    ))
                })?;
            }
            "--no-symbols" | "-S" => pa.gen_no_symbols = true,
            "--no-numbers" | "-N" => pa.gen_no_numbers = true,
            "--no-caps" | "-C" => pa.gen_no_caps = true,
            "--grouped" | "-G" => pa.gen_grouped = true,
            "--count" => {
                let val = next_val!("--count");
                pa.gen_count = val.parse::<u32>().ok().filter(|&n| n >= 1).ok_or_else(|| {
                    CliError::Error(format!(
                        "--count requires a positive integer, got {:?}",
                        val
                    ))
                })?;
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
    let use_kc = config.use_keychain.unwrap_or(false);

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
        } else if use_kc {
            if let Some(val) = (deps.get_keychain_secret)("api_key") {
                pa.api_key = val;
            }
        }
        if pa.api_key.is_empty() {
            if let Some(ref key) = config.api_key {
                pa.api_key = key.clone();
            }
        }
    }
    if pa.passphrase_default.is_empty() {
        if use_kc {
            if let Some(val) = (deps.get_keychain_secret)("passphrase") {
                pa.passphrase_default = val;
            }
        }
        if pa.passphrase_default.is_empty() {
            if let Some(ref pass) = config.passphrase {
                pa.passphrase_default = pass.clone();
            }
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
        let mut dp = if use_kc {
            (deps.get_keychain_secret_list)("decryption_passphrases")
        } else {
            Vec::new()
        };
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
            if args.iter().any(|a| a == "-h" || a == "--help") {
                print_config_help(deps);
                return 0;
            }
            let force = args.iter().any(|a| a == "--force");
            run_config_init(force, deps)
        }
        "path" | "set-passphrase" | "delete-passphrase"
            if args.iter().any(|a| a == "-h" || a == "--help") =>
        {
            print_config_help(deps);
            0
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

    let use_kc = config.use_keychain.unwrap_or(false);

    let _ = writeln!(deps.stderr);
    let _ = writeln!(deps.stderr, "{}", c(HEADING, "EFFECTIVE SETTINGS"));

    // use_keychain: config/default
    let (use_kc_val, use_kc_src) = if let Some(v) = config.use_keychain {
        (v.to_string(), "config file")
    } else {
        ("false".into(), "default")
    };
    let _ = writeln!(
        deps.stderr,
        "  {}: {} {}",
        c(OPT, "use_keychain"),
        use_kc_val,
        c(DIM, &format!("({})", use_kc_src)),
    );

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
    } else if use_kc {
        if let Some(val) = (deps.get_keychain_secret)("api_key") {
            (crate::config::mask_secret(&val, true), "keychain")
        } else if let Some(ref key) = config.api_key {
            (crate::config::mask_secret(key, true), "config file")
        } else {
            ("(not set)".into(), "")
        }
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
    let (pass_display, pass_src) = if use_kc {
        if let Some(val) = (deps.get_keychain_secret)("passphrase") {
            (crate::config::mask_secret(&val, false), "keychain")
        } else if let Some(ref pass) = config.passphrase {
            (crate::config::mask_secret(pass, false), "config file")
        } else {
            ("(not set)".into(), "")
        }
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
    } else if use_kc {
        if let Some(val) = (deps.get_keychain_secret)("api_key") {
            val
        } else {
            config.api_key.clone().unwrap_or_default()
        }
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
    let kc_list = if use_kc {
        (deps.get_keychain_secret_list)("decryption_passphrases")
    } else {
        Vec::new()
    };
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

// --- Help text formatting ---

use crate::color::ColorFn;

/// Write auto-aligned option rows:  flag [arg]   description
fn write_option_rows(w: &mut dyn Write, c: &ColorFn, rows: &[(&str, &str, &str)]) {
    let widths: Vec<usize> = rows
        .iter()
        .map(|(f, a, _)| {
            if a.is_empty() {
                f.len()
            } else {
                f.len() + 1 + a.len()
            }
        })
        .collect();
    let max = widths.iter().copied().max().unwrap_or(0);
    for (i, (flags, arg, desc)) in rows.iter().enumerate() {
        let pad = max - widths[i] + 2;
        if arg.is_empty() {
            let _ = writeln!(w, "  {}{:pad$}{}", c(OPT, flags), "", desc);
        } else {
            let _ = writeln!(w, "  {} {}{:pad$}{}", c(OPT, flags), c(ARG, arg), "", desc);
        }
    }
}

/// Write auto-aligned command rows:  command   description
fn write_cmd_rows(w: &mut dyn Write, c: &ColorFn, rows: &[(&str, &str)]) {
    let max = rows.iter().map(|(cmd, _)| cmd.len()).max().unwrap_or(0);
    for (cmd, desc) in rows {
        let pad = max - cmd.len() + 2;
        let _ = writeln!(w, "  {}{:pad$}{}", c(CMD, cmd), "", desc);
    }
}

// --- Help text ---

fn print_usage(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let _ = write!(
        deps.stderr,
        "{} — one-time secret sharing\n\n  {}              share a secret (interactive)\n  {} {}       retrieve a secret\n\nRun '{}' for full usage.\n",
        c(CMD, "secrt"),
        c(CMD, "secrt send"),
        c(CMD, "secrt get"),
        c(ARG, "<url>"),
        c(CMD, "secrt help")
    );
}

pub fn print_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let w = &mut deps.stderr;
    let _ = writeln!(w, "{} — one-time secret sharing\n", c(CMD, "secrt"));
    let _ = writeln!(
        w,
        "{}\n  {} {} {}\n",
        c(HEADING, "USAGE"),
        c(CMD, "secrt"),
        c(CMD, "<command>"),
        c(ARG, "[options]")
    );
    let _ = writeln!(w, "{}", c(HEADING, "COMMANDS"));
    write_cmd_rows(
        w,
        &c,
        &[
            ("send", "Encrypt and upload a secret"),
            ("get", "Retrieve and decrypt a secret"),
            ("burn", "Destroy a secret (requires API key)"),
            ("gen", "Generate a random password"),
            ("config", "Show or initialize configuration"),
            ("version", "Show version"),
            ("help", "Show this help"),
            ("completion", "Output shell completion script"),
        ],
    );
    let _ = writeln!(w, "\n{}", c(HEADING, "GLOBAL OPTIONS"));
    write_option_rows(
        w,
        &c,
        &[
            (
                "--base-url",
                "<url>",
                "Server URL (default: https://secrt.ca)",
            ),
            ("--api-key", "<key>", "API key for authenticated access"),
            ("--json", "", "Output as JSON"),
            ("--silent", "", "Suppress status output"),
            ("-h, --help", "", "Show help"),
            ("-v, --version", "", "Show version"),
        ],
    );
    let _ = writeln!(w, "\n{}", c(HEADING, "EXAMPLES"));
    let _ = writeln!(w, "  {} Share a secret from stdin:", c(DIM, "#"));
    let _ = writeln!(
        w,
        "  echo \"pw123\" | {} {}",
        c(CMD, "secrt"),
        c(CMD, "send")
    );
    let _ = writeln!(
        w,
        "\n  {} Generate and share a 32-char password (1h TTL):",
        c(DIM, "#")
    );
    let _ = writeln!(
        w,
        "  {} {} {} 32 {} 1h",
        c(CMD, "secrt"),
        c(CMD, "send gen"),
        c(OPT, "-L"),
        c(OPT, "--ttl")
    );
    let _ = writeln!(w, "\n  {} Retrieve a secret:", c(DIM, "#"));
    let _ = writeln!(w, "  {} https://secrt.ca/s/abc#key", c(CMD, "secrt get"));
}

pub fn print_send_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let w = &mut deps.stderr;
    let _ = writeln!(
        w,
        "{} {} — Encrypt and upload a secret\n",
        c(CMD, "secrt"),
        c(CMD, "send")
    );
    let _ = writeln!(
        w,
        "{}\n  {} {} {}\n",
        c(HEADING, "USAGE"),
        c(CMD, "secrt"),
        c(CMD, "send"),
        c(ARG, "[options]")
    );
    let _ = writeln!(w, "{}", c(HEADING, "OPTIONS"));
    write_option_rows(
        w,
        &c,
        &[
            ("--ttl", "<ttl>", "TTL for the secret (e.g., 5m, 2h, 1d)"),
            (
                "--text",
                "<value>",
                "Secret text (visible in shell history)",
            ),
            ("-f, --file", "<path>", "Read secret from a file"),
            (
                "-m, --multi-line",
                "",
                "Multi-line input (read until Ctrl+D)",
            ),
            ("--trim", "", "Trim leading/trailing whitespace"),
            ("-s, --show", "", "Show input as you type"),
            ("--hidden", "", "Hide input (default, overrides --show)"),
            ("-p, --passphrase-prompt", "", "Prompt for passphrase"),
            ("-n, --no-passphrase", "", "Skip default passphrase"),
            ("--passphrase-env", "<name>", "Read passphrase from env var"),
            ("--passphrase-file", "<path>", "Read passphrase from file"),
            ("--base-url", "<url>", "Server URL"),
            ("--api-key", "<key>", "API key"),
            ("--json", "", "Output as JSON"),
            ("--silent", "", "Suppress status output"),
            ("-h, --help", "", "Show help"),
        ],
    );
    let _ = writeln!(w, "\n{}", c(HEADING, "INPUT"));
    let _ = writeln!(
        w,
        "  Interactive: single-line hidden input (like a password)."
    );
    let _ = writeln!(
        w,
        "  Use {} for multi-line input, {} or {} for alternatives.",
        c(OPT, "-m"),
        c(OPT, "--text"),
        c(OPT, "-f/--file")
    );
    let _ = writeln!(
        w,
        "  Use {} or {} to generate and share a random password.",
        c(CMD, "gen"),
        c(CMD, "generate")
    );
    let _ = writeln!(
        w,
        "  Set show_input = true in config to show input by default."
    );
    let _ = writeln!(w, "\n{}", c(HEADING, "EXAMPLES"));
    let _ = writeln!(
        w,
        "  echo \"secret\" | {} {}",
        c(CMD, "secrt"),
        c(CMD, "send")
    );
    let _ = writeln!(
        w,
        "  {} {} {} \"my secret\" {} 5m",
        c(CMD, "secrt"),
        c(CMD, "send"),
        c(OPT, "--text"),
        c(OPT, "--ttl")
    );
    let _ = writeln!(
        w,
        "  {} {} {} 32 {} 1h",
        c(CMD, "secrt"),
        c(CMD, "send gen"),
        c(OPT, "-L"),
        c(OPT, "--ttl")
    );
}

pub fn print_get_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let w = &mut deps.stderr;
    let _ = writeln!(
        w,
        "{} {} — Retrieve and decrypt a secret\n",
        c(CMD, "secrt"),
        c(CMD, "get")
    );
    let _ = writeln!(
        w,
        "{}\n  {} {} {} {}\n",
        c(HEADING, "USAGE"),
        c(CMD, "secrt"),
        c(CMD, "get"),
        c(ARG, "<share-url>"),
        c(ARG, "[options]")
    );
    let _ = writeln!(w, "{}", c(HEADING, "OPTIONS"));
    write_option_rows(
        w,
        &c,
        &[
            (
                "-o, --output",
                "<path>",
                "Write output to file (use - for stdout)",
            ),
            ("-p, --passphrase-prompt", "", "Prompt for passphrase"),
            (
                "-n, --no-passphrase",
                "",
                "Skip configured decryption passphrases",
            ),
            ("--passphrase-env", "<name>", "Read passphrase from env var"),
            ("--passphrase-file", "<path>", "Read passphrase from file"),
            ("--base-url", "<url>", "Server URL"),
            ("--json", "", "Output as JSON"),
            ("--silent", "", "Suppress status output"),
            ("-h, --help", "", "Show help"),
        ],
    );
    let _ = writeln!(w, "\n{}", c(HEADING, "EXAMPLES"));
    let _ = writeln!(
        w,
        "  {} {} https://secrt.ca/s/abc#key",
        c(CMD, "secrt"),
        c(CMD, "get")
    );
    let _ = writeln!(
        w,
        "\n  {} The {} subcommand is optional:",
        c(DIM, "#"),
        c(CMD, "get")
    );
    let _ = writeln!(
        w,
        "  {} https://secrt.ca/s/abc#key {} mysecret.txt",
        c(CMD, "secrt"),
        c(OPT, "-o")
    );
}

pub fn print_burn_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let w = &mut deps.stderr;
    let _ = writeln!(
        w,
        "{} {} — Destroy a secret (requires API key)\n",
        c(CMD, "secrt"),
        c(CMD, "burn")
    );
    let _ = writeln!(
        w,
        "{}\n  {} {} {} {}\n",
        c(HEADING, "USAGE"),
        c(CMD, "secrt"),
        c(CMD, "burn"),
        c(ARG, "<id-or-url>"),
        c(ARG, "[options]")
    );
    let _ = writeln!(w, "{}", c(HEADING, "OPTIONS"));
    write_option_rows(
        w,
        &c,
        &[
            ("--api-key", "<key>", "API key (required)"),
            ("--base-url", "<url>", "Server URL"),
            ("--json", "", "Output as JSON"),
            ("--silent", "", "Suppress status output"),
            ("-h, --help", "", "Show help"),
        ],
    );
    let _ = writeln!(w, "\n{}", c(HEADING, "EXAMPLES"));
    let _ = writeln!(
        w,
        "  {} {} test-id {} sk_prefix.secret",
        c(CMD, "secrt"),
        c(CMD, "burn"),
        c(OPT, "--api-key")
    );
}

pub fn print_gen_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let w = &mut deps.stderr;
    let _ = writeln!(
        w,
        "{} {} — Generate a random password\n",
        c(CMD, "secrt"),
        c(CMD, "gen")
    );
    let _ = writeln!(
        w,
        "{}\n  {} {} {}\n",
        c(HEADING, "USAGE"),
        c(CMD, "secrt"),
        c(CMD, "gen"),
        c(ARG, "[options]")
    );
    let _ = writeln!(w, "{}", c(HEADING, "OPTIONS"));
    write_option_rows(
        w,
        &c,
        &[
            ("-L, --length", "<n>", "Password length (default: 20)"),
            ("-S, --no-symbols", "", "Exclude symbols"),
            ("-N, --no-numbers", "", "Exclude digits"),
            ("-C, --no-caps", "", "Exclude uppercase letters"),
            ("-G, --grouped", "", "Group characters by type"),
            ("--count", "<n>", "Generate multiple passwords"),
            ("--json", "", "Output as JSON"),
            ("-h, --help", "", "Show help"),
        ],
    );
    let _ = writeln!(w, "\n{}", c(HEADING, "CHARACTER SETS"));
    let _ = writeln!(w, "  Lowercase: a-z  (always included)");
    let _ = writeln!(w, "  Uppercase: A-Z");
    let _ = writeln!(w, "  Digits:    0-9");
    let _ = writeln!(w, "  Symbols:   !@*^_+-=?");
    let _ = writeln!(w, "\n{}", c(HEADING, "EXAMPLES"));
    let _ = writeln!(
        w,
        "  {} {}                 20-char password, all classes",
        c(CMD, "secrt"),
        c(CMD, "gen")
    );
    let _ = writeln!(
        w,
        "  {} {} {} 32          32-char password",
        c(CMD, "secrt"),
        c(CMD, "gen"),
        c(OPT, "-L")
    );
    let _ = writeln!(
        w,
        "  {} {} {}              no symbols",
        c(CMD, "secrt"),
        c(CMD, "gen"),
        c(OPT, "-S")
    );
    let _ = writeln!(
        w,
        "  {} {} {}              grouped by char type",
        c(CMD, "secrt"),
        c(CMD, "gen"),
        c(OPT, "-G")
    );
    let _ = writeln!(
        w,
        "  {} {} {} 5    five passwords",
        c(CMD, "secrt"),
        c(CMD, "gen"),
        c(OPT, "--count")
    );
    let _ = writeln!(w, "\n{}", c(HEADING, "COMBINED MODE"));
    let _ = writeln!(
        w,
        "  Generate a password and immediately share it as a secret."
    );
    let _ = writeln!(
        w,
        "  {} {} {} 1h",
        c(CMD, "secrt"),
        c(CMD, "gen send"),
        c(OPT, "--ttl")
    );
    let _ = writeln!(
        w,
        "  All {} and {} options can be combined.",
        c(CMD, "gen"),
        c(CMD, "send")
    );
}

pub fn print_config_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let w = &mut deps.stderr;
    let _ = writeln!(
        w,
        "{} {} — Show config / init / path\n",
        c(CMD, "secrt"),
        c(CMD, "config")
    );
    let _ = writeln!(w, "{}", c(HEADING, "SUBCOMMANDS"));
    write_cmd_rows(
        w,
        &c,
        &[
            ("secrt config", "Show effective config and file path"),
            ("secrt config init", "Create template config file"),
            ("secrt config path", "Print config file path"),
            (
                "secrt config set-passphrase",
                "Store passphrase in OS keychain",
            ),
            (
                "secrt config delete-passphrase",
                "Remove passphrase from OS keychain",
            ),
        ],
    );
    let _ = writeln!(w, "\n{}", c(HEADING, "OPTIONS"));
    write_option_rows(
        w,
        &c,
        &[
            ("--force", "", "Overwrite existing config file (for init)"),
            ("-h, --help", "", "Show help"),
        ],
    );
    let _ = writeln!(w, "\n{}", c(HEADING, "CONFIG"));
    let _ = writeln!(w, "  Settings are loaded from ~/.config/secrt/config.toml.");
    let _ = writeln!(
        w,
        "  Supported keys: api_key, base_url, default_ttl, passphrase,"
    );
    let _ = writeln!(w, "  decryption_passphrases, show_input, use_keychain.");
    let _ = writeln!(
        w,
        "  Precedence: CLI flag {} env var {} config file {} default.",
        c(DIM, "\u{203a}"),
        c(DIM, "\u{203a}"),
        c(DIM, "\u{203a}"),
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
    fn flags_output() {
        let pa = parse_flags(&s(&["--output", "/tmp/out.bin"])).unwrap();
        assert_eq!(pa.output, "/tmp/out.bin");
    }

    #[test]
    fn flags_output_short() {
        let pa = parse_flags(&s(&["-o", "out.txt"])).unwrap();
        assert_eq!(pa.output, "out.txt");
    }

    #[test]
    fn flags_missing_value_output() {
        let err = parse_flags(&s(&["--output"]));
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

    #[test]
    fn flags_no_passphrase() {
        let pa = parse_flags(&s(&["--no-passphrase"])).unwrap();
        assert!(pa.no_passphrase);
    }

    #[test]
    fn flags_no_passphrase_short() {
        let pa = parse_flags(&s(&["-n"])).unwrap();
        assert!(pa.no_passphrase);
    }

    // --- --flag=value tests ---

    #[test]
    fn flags_eq_ttl() {
        let pa = parse_flags(&s(&["--ttl=5m"])).unwrap();
        assert_eq!(pa.ttl, "5m");
    }

    #[test]
    fn flags_eq_base_url() {
        let pa = parse_flags(&s(&["--base-url=https://example.com"])).unwrap();
        assert_eq!(pa.base_url, "https://example.com");
        assert!(pa.base_url_from_flag);
    }

    #[test]
    fn flags_eq_api_key() {
        let pa = parse_flags(&s(&["--api-key=sk_test"])).unwrap();
        assert_eq!(pa.api_key, "sk_test");
    }

    #[test]
    fn flags_eq_text() {
        let pa = parse_flags(&s(&["--text=hello world"])).unwrap();
        assert_eq!(pa.text, "hello world");
    }

    #[test]
    fn flags_eq_file() {
        let pa = parse_flags(&s(&["--file=/tmp/secret.txt"])).unwrap();
        assert_eq!(pa.file, "/tmp/secret.txt");
    }

    #[test]
    fn flags_eq_output() {
        let pa = parse_flags(&s(&["--output=/tmp/out.bin"])).unwrap();
        assert_eq!(pa.output, "/tmp/out.bin");
    }

    #[test]
    fn flags_eq_passphrase_env() {
        let pa = parse_flags(&s(&["--passphrase-env=MY_PASS"])).unwrap();
        assert_eq!(pa.passphrase_env, "MY_PASS");
    }

    #[test]
    fn flags_eq_passphrase_file() {
        let pa = parse_flags(&s(&["--passphrase-file=/tmp/pass"])).unwrap();
        assert_eq!(pa.passphrase_file, "/tmp/pass");
    }

    #[test]
    fn flags_eq_empty_value() {
        let pa = parse_flags(&s(&["--text="])).unwrap();
        assert_eq!(pa.text, "");
    }

    #[test]
    fn flags_eq_value_with_equals() {
        let pa = parse_flags(&s(&["--text=a=b=c"])).unwrap();
        assert_eq!(pa.text, "a=b=c");
    }

    #[test]
    fn flags_eq_mixed_with_space() {
        let pa = parse_flags(&s(&["--ttl=5m", "--text", "hello"])).unwrap();
        assert_eq!(pa.ttl, "5m");
        assert_eq!(pa.text, "hello");
    }

    // --- short flag -Xvalue tests ---

    #[test]
    fn flags_short_concat_value() {
        let pa = parse_flags(&s(&["-L20"])).unwrap();
        assert_eq!(pa.gen_length, 20);
    }

    #[test]
    fn flags_short_eq_value() {
        let pa = parse_flags(&s(&["-L=20"])).unwrap();
        assert_eq!(pa.gen_length, 20);
    }

    #[test]
    fn flags_short_concat_file() {
        let pa = parse_flags(&s(&["-f/tmp/secret.txt"])).unwrap();
        assert_eq!(pa.file, "/tmp/secret.txt");
    }

    #[test]
    fn flags_short_eq_file() {
        let pa = parse_flags(&s(&["-f=/tmp/secret.txt"])).unwrap();
        assert_eq!(pa.file, "/tmp/secret.txt");
    }

    #[test]
    fn flags_short_concat_output() {
        let pa = parse_flags(&s(&["-oout.txt"])).unwrap();
        assert_eq!(pa.output, "out.txt");
    }

    // --- `--` end-of-flags tests ---

    #[test]
    fn flags_double_dash_stops_flags() {
        let pa = parse_flags(&s(&["--json", "--", "--not-a-flag"])).unwrap();
        assert!(pa.json);
        assert_eq!(pa.args, vec!["--not-a-flag"]);
    }

    #[test]
    fn flags_double_dash_all_positional() {
        let pa = parse_flags(&s(&["--", "-m", "--ttl", "5m"])).unwrap();
        assert!(!pa.multi_line);
        assert!(pa.ttl.is_empty());
        assert_eq!(pa.args, vec!["-m", "--ttl", "5m"]);
    }

    #[test]
    fn flags_double_dash_empty() {
        let pa = parse_flags(&s(&["--"])).unwrap();
        assert!(pa.args.is_empty());
    }

    #[test]
    fn flags_double_dash_preserves_earlier() {
        let pa = parse_flags(&s(&["--ttl", "1h", "--", "myurl"])).unwrap();
        assert_eq!(pa.ttl, "1h");
        assert_eq!(pa.args, vec!["myurl"]);
    }

    // --- help text drift tests ---
    //
    // Every flag accepted by parse_flags() must appear in at least one help
    // screen. When adding a new flag, add it here too — the parser test
    // verifies parse_flags accepts it, and the help test verifies it's
    // documented.

    /// All flags accepted by parse_flags, grouped by which help screen(s)
    /// must mention them. Each entry is (flag, needs_value, help_fns) where
    /// help_fns lists which print_*_help functions should contain the flag.
    ///   "main" = print_help
    ///   "send" = print_send_help
    ///   "get"  = print_get_help
    ///   "burn" = print_burn_help
    const FLAG_REGISTRY: &[(&str, bool, &[&str])] = &[
        // Global flags — should appear in main help
        ("--base-url", true, &["main", "send", "get", "burn"]),
        ("--api-key", true, &["main", "send", "burn"]),
        ("--json", false, &["main", "send", "get", "burn"]),
        ("--silent", false, &["main", "send", "get", "burn"]),
        ("-h", false, &["main", "send", "get", "burn"]),
        ("--help", false, &["main", "send", "get", "burn"]),
        // Send flags
        ("--ttl", true, &["send"]),
        ("--text", true, &["send"]),
        ("--file", true, &["send"]),
        ("-f", true, &["send"]),
        ("-m", false, &["send"]),
        ("--multi-line", false, &["send"]),
        ("--trim", false, &["send"]),
        ("-s", false, &["send"]),
        ("--show", false, &["send"]),
        ("--hidden", false, &["send"]),
        // Passphrase flags — send + get
        ("-p", false, &["send", "get"]),
        ("--passphrase-prompt", false, &["send", "get"]),
        ("-n", false, &["send", "get"]),
        ("--no-passphrase", false, &["send", "get"]),
        ("--passphrase-env", true, &["send", "get"]),
        ("--passphrase-file", true, &["send", "get"]),
        // Get flags
        ("-o", true, &["get"]),
        ("--output", true, &["get"]),
        // Gen flags
        ("-L", true, &["gen"]),
        ("--length", true, &["gen"]),
        ("-S", false, &["gen"]),
        ("--no-symbols", false, &["gen"]),
        ("-N", false, &["gen"]),
        ("--no-numbers", false, &["gen"]),
        ("-C", false, &["gen"]),
        ("--no-caps", false, &["gen"]),
        ("-G", false, &["gen"]),
        ("--grouped", false, &["gen"]),
        ("--count", true, &["gen"]),
    ];

    /// parse_flags must accept every flag in the registry without error.
    #[test]
    fn registry_flags_accepted_by_parser() {
        for &(flag, needs_value, _) in FLAG_REGISTRY {
            let test_val = match flag {
                "--length" | "-L" | "--count" => "10",
                _ => "test_val",
            };
            let args = if needs_value {
                s(&[flag, test_val])
            } else {
                s(&[flag])
            };
            let result = parse_flags(&args);
            // --help / -h returns ShowHelp, which is fine — it's still "accepted"
            match result {
                Ok(_) => {}
                Err(CliError::ShowHelp) => {}
                Err(CliError::Error(e)) => {
                    panic!("parse_flags rejected registered flag {}: {}", flag, e);
                }
            }
        }
    }

    fn capture_help(f: fn(&mut Deps)) -> String {
        let buf = std::rc::Rc::new(std::cell::RefCell::new(Vec::<u8>::new()));
        struct Capture(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                self.0.borrow_mut().write(data)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.0.borrow_mut().flush()
            }
        }
        let mut deps = Deps {
            stdin: Box::new(std::io::Cursor::new(Vec::new())),
            stdout: Box::new(Vec::new()),
            stderr: Box::new(Capture(std::rc::Rc::clone(&buf))),
            is_tty: Box::new(|| false),
            is_stdout_tty: Box::new(|| false),
            getenv: Box::new(|_: &str| None),
            rand_bytes: Box::new(|_: &mut [u8]| Ok(())),
            read_pass: Box::new(|_: &str, _: &mut dyn Write| {
                Err(io::Error::new(io::ErrorKind::Other, "unused"))
            }),
            make_api: Box::new(|base_url: &str, api_key: &str| {
                Box::new(crate::client::ApiClient {
                    base_url: base_url.to_string(),
                    api_key: api_key.to_string(),
                })
            }),
            get_keychain_secret: Box::new(|_: &str| None),
            get_keychain_secret_list: Box::new(|_: &str| Vec::new()),
        };
        f(&mut deps);
        drop(deps);
        let bytes = buf.borrow();
        String::from_utf8_lossy(&bytes).to_string()
    }

    /// Every flag in the registry must appear in its designated help screen(s).
    #[test]
    fn registry_flags_appear_in_help() {
        let screens: std::collections::HashMap<&str, String> = [
            ("main", capture_help(print_help)),
            ("send", capture_help(print_send_help)),
            ("get", capture_help(print_get_help)),
            ("burn", capture_help(print_burn_help)),
            ("gen", capture_help(print_gen_help)),
        ]
        .into_iter()
        .collect();

        for &(flag, _, expected_screens) in FLAG_REGISTRY {
            for &screen in expected_screens {
                let text = screens.get(screen).unwrap();
                assert!(
                    text.contains(flag),
                    "flag {} not found in {} help text",
                    flag,
                    screen,
                );
            }
        }
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

    // --- format_ttl_seconds tests ---

    #[test]
    fn ttl_zero() {
        assert_eq!(format_ttl_seconds(0), "0s");
    }

    #[test]
    fn ttl_negative() {
        assert_eq!(format_ttl_seconds(-5), "0s");
    }

    #[test]
    fn ttl_seconds_only() {
        assert_eq!(format_ttl_seconds(30), "30s");
    }

    #[test]
    fn ttl_exact_minutes() {
        assert_eq!(format_ttl_seconds(90), "1m30s");
    }

    #[test]
    fn ttl_exact_minutes_boundary() {
        assert_eq!(format_ttl_seconds(60), "1m");
    }

    #[test]
    fn ttl_exact_hours() {
        assert_eq!(format_ttl_seconds(3600), "1h");
    }

    #[test]
    fn ttl_hours_and_seconds() {
        assert_eq!(format_ttl_seconds(3661), "1h1m1s");
    }

    #[test]
    fn ttl_two_hours() {
        assert_eq!(format_ttl_seconds(7200), "2h");
    }

    #[test]
    fn ttl_two_days() {
        assert_eq!(format_ttl_seconds(172800), "2d");
    }

    #[test]
    fn ttl_day_and_hour() {
        // 90000 = 25 * 3600, evenly divisible by 3600 → outputs "25h"
        assert_eq!(format_ttl_seconds(90000), "25h");
    }

    // --- format_bytes tests ---

    #[test]
    fn bytes_small() {
        assert_eq!(format_bytes(500), "500 bytes");
    }

    #[test]
    fn bytes_exact_kb() {
        assert_eq!(format_bytes(1024), "1 KB");
    }

    #[test]
    fn bytes_non_exact_kb() {
        assert_eq!(format_bytes(1500), "1500 bytes");
    }

    #[test]
    fn bytes_exact_mb() {
        assert_eq!(format_bytes(1048576), "1 MB");
    }

    #[test]
    fn bytes_multi_mb() {
        assert_eq!(format_bytes(20971520), "20 MB");
    }

    // --- format_limit tests ---

    #[test]
    fn limit_zero_unlimited() {
        assert_eq!(format_limit(0), "unlimited");
    }

    #[test]
    fn limit_nonzero() {
        assert_eq!(format_limit(42), "42");
    }

    // --- looks_like_share_url tests ---

    #[test]
    fn share_url_full() {
        assert!(looks_like_share_url(
            "https://secrt.ca/s/abc123#AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
        ));
    }

    #[test]
    fn share_url_bare_id() {
        assert!(looks_like_share_url(
            "abc123#AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
        ));
    }

    #[test]
    fn share_url_no_hash() {
        assert!(!looks_like_share_url("send"));
    }

    #[test]
    fn share_url_short_fragment() {
        assert!(!looks_like_share_url("abc#short"));
    }

    #[test]
    fn share_url_subcommand_names() {
        assert!(!looks_like_share_url("send"));
        assert!(!looks_like_share_url("get"));
        assert!(!looks_like_share_url("burn"));
        assert!(!looks_like_share_url("gen"));
        assert!(!looks_like_share_url("help"));
        assert!(!looks_like_share_url("version"));
    }

    #[test]
    fn share_url_fragment_with_invalid_chars() {
        assert!(!looks_like_share_url("abc#aaaa!bbbbbbbbbbbbbbbbbbb"));
    }

    #[test]
    fn share_url_exactly_22_char_fragment() {
        // 22 base64url chars = exactly the threshold
        assert!(looks_like_share_url("id#abcdefghijklmnopqrstuv"));
    }

    #[test]
    fn share_url_21_char_fragment() {
        // 21 chars = below threshold
        assert!(!looks_like_share_url("id#abcdefghijklmnopqrstu"));
    }
}
