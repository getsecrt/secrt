use std::io::{self, Read, Write};

use crate::burn::run_burn;
use crate::claim::run_claim;
use crate::client::SecretApi;
use crate::color::color_func;
use crate::completion::{BASH_COMPLETION, FISH_COMPLETION, ZSH_COMPLETION};
use crate::create::run_create;

const DEFAULT_BASE_URL: &str = "https://secrt.ca";
const VERSION: &str = "dev";

pub type GetenvFn = Box<dyn Fn(&str) -> Option<String>>;
pub type RandBytesFn = Box<dyn Fn(&mut [u8]) -> Result<(), crate::envelope::EnvelopeError>>;
pub type ReadPassFn = Box<dyn Fn(&str, &mut dyn Write) -> io::Result<String>>;
pub type MakeApiFn = Box<dyn Fn(&str, &str) -> Box<dyn SecretApi>>;

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

    // Passphrase
    pub passphrase_prompt: bool,
    pub passphrase_env: String,
    pub passphrase_file: String,

    // Populated from config file (not from CLI flags)
    pub passphrase_default: String,
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
            "--passphrase-prompt" => pa.passphrase_prompt = true,
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
    let config = crate::config::load_config(&mut deps.stderr);
    resolve_globals_with_config(pa, deps, &config);
}

/// Inner function that accepts an explicit Config (used by tests).
pub fn resolve_globals_with_config(pa: &mut ParsedArgs, deps: &Deps, config: &crate::config::Config) {
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
        } else if let Some(val) = crate::keychain::get_secret("api_key") {
            pa.api_key = val;
        } else if let Some(ref key) = config.api_key {
            pa.api_key = key.clone();
        }
    }
    if pa.passphrase_default.is_empty() {
        if let Some(val) = crate::keychain::get_secret("passphrase") {
            pa.passphrase_default = val;
        } else if let Some(ref pass) = config.passphrase {
            pa.passphrase_default = pass.clone();
        }
    }
}

// --- Help text ---

fn print_usage(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let _ = write!(
        deps.stderr,
        "{} — one-time secret sharing\n\n  {}            {}\n  {} {}       {}\n\nRun '{}' for full usage.\n",
        c("36", "secrt"),
        c("36", "secrt create"),
        c("2", "share a secret (interactive)"),
        c("36", "secrt claim"),
        c("33", "<url>"),
        c("2", "retrieve a secret"),
        c("36", "secrt help")
    );
}

pub fn print_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let _ = write!(
        deps.stderr,
        "{} — one-time secret sharing\n\n\
{}\n  {} {} {}\n\n\
{}\n\
  {}       Encrypt and upload a secret\n\
  {}        Retrieve and decrypt a secret\n\
  {}         Destroy a secret (requires API key)\n\
  {}      Show version\n\
  {}         Show this help\n\
  {}   Output shell completion script\n\n\
{}\n\
  {} {}     Server URL (default: https://secrt.ca)\n\
  {} {}      API key for authenticated access\n\
  {}               Output as JSON\n\
  {}           Show help\n\
  {}        Show version\n\n\
{}\n\
  echo \"pw123\" | {} {}\n\
  {} https://secrt.ca/s/abc#v1.key\n\n\
{}\n\
  Settings are loaded from {}.\n\
  Supported keys: api_key, base_url, passphrase.\n\
  Precedence: CLI flag > env var > config file > default.\n",
        c("36", "secrt"),
        c("1", "USAGE"),
        c("36", "secrt"),
        c("36", "<command>"),
        c("2", "[options]"),
        c("1", "COMMANDS"),
        c("36", "create"),
        c("36", "claim"),
        c("36", "burn"),
        c("36", "version"),
        c("36", "help"),
        c("36", "completion"),
        c("1", "GLOBAL OPTIONS"),
        c("33", "--base-url"),
        c("2", "<url>"),
        c("33", "--api-key"),
        c("2", "<key>"),
        c("33", "--json"),
        c("33", "-h, --help"),
        c("33", "-v, --version"),
        c("1", "EXAMPLES"),
        c("36", "secrt"),
        c("36", "create"),
        c("36", "secrt claim"),
        c("1", "CONFIG"),
        c("2", "~/.config/secrt/config.toml"),
    );
}

pub fn print_create_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let _ = write!(
        deps.stderr,
        "{} {} — Encrypt and upload a secret\n\n\
{}\n  {} {} {}\n\n\
{}\n\
  {} {}         TTL for the secret (e.g., 5m, 2h, 1d)\n\
  {} {}     Secret text (visible in shell history)\n\
  {} {}     Read secret from file\n\
  {}     Prompt for passphrase\n\
  {} {}  Read passphrase from env var\n\
  {} {}  Read passphrase from file\n\
  {} {}     Server URL\n\
  {} {}      API key\n\
  {}               Output as JSON\n\
  {}           Show help\n\n\
{}\n\
  Reads from stdin by default. Use {} or {} for alternatives.\n\
  Exactly one input source must be selected.\n\n\
{}\n\
  echo \"secret\" | {} {}\n\
  {} {} {} \"my secret\" {} 5m\n",
        c("36", "secrt"),
        c("36", "create"),
        c("1", "USAGE"),
        c("36", "secrt"),
        c("36", "create"),
        c("2", "[options]"),
        c("1", "OPTIONS"),
        c("33", "--ttl"),
        c("2", "<ttl>"),
        c("33", "--text"),
        c("2", "<value>"),
        c("33", "--file"),
        c("2", "<path>"),
        c("33", "--passphrase-prompt"),
        c("33", "--passphrase-env"),
        c("2", "<name>"),
        c("33", "--passphrase-file"),
        c("2", "<path>"),
        c("33", "--base-url"),
        c("2", "<url>"),
        c("33", "--api-key"),
        c("2", "<key>"),
        c("33", "--json"),
        c("33", "-h, --help"),
        c("1", "INPUT"),
        c("33", "--text"),
        c("33", "--file"),
        c("1", "EXAMPLES"),
        c("36", "secrt"),
        c("36", "create"),
        c("36", "secrt"),
        c("36", "create"),
        c("33", "--text"),
        c("33", "--ttl"),
    );
}

pub fn print_claim_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let _ = write!(
        deps.stderr,
        "{} {} — Retrieve and decrypt a secret\n\n\
{}\n  {} {} {} {}\n\n\
{}\n\
  {}     Prompt for passphrase\n\
  {} {}  Read passphrase from env var\n\
  {} {}  Read passphrase from file\n\
  {} {}     Server URL\n\
  {}               Output as JSON\n\
  {}           Show help\n\n\
{}\n\
  {} {} https://secrt.ca/s/abc#v1.key\n",
        c("36", "secrt"),
        c("36", "claim"),
        c("1", "USAGE"),
        c("36", "secrt"),
        c("36", "claim"),
        c("2", "<share-url>"),
        c("2", "[options]"),
        c("1", "OPTIONS"),
        c("33", "--passphrase-prompt"),
        c("33", "--passphrase-env"),
        c("2", "<name>"),
        c("33", "--passphrase-file"),
        c("2", "<path>"),
        c("33", "--base-url"),
        c("2", "<url>"),
        c("33", "--json"),
        c("33", "-h, --help"),
        c("1", "EXAMPLES"),
        c("36", "secrt"),
        c("36", "claim"),
    );
}

pub fn print_burn_help(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let _ = write!(
        deps.stderr,
        "{} {} — Destroy a secret (requires API key)\n\n\
{}\n  {} {} {} {}\n\n\
{}\n\
  {} {}      API key (required)\n\
  {} {}     Server URL\n\
  {}               Output as JSON\n\
  {}           Show help\n\n\
{}\n\
  {} {} test-id {} sk_prefix.secret\n",
        c("36", "secrt"),
        c("36", "burn"),
        c("1", "USAGE"),
        c("36", "secrt"),
        c("36", "burn"),
        c("2", "<id-or-url>"),
        c("2", "[options]"),
        c("1", "OPTIONS"),
        c("33", "--api-key"),
        c("2", "<key>"),
        c("33", "--base-url"),
        c("2", "<url>"),
        c("33", "--json"),
        c("33", "-h, --help"),
        c("1", "EXAMPLES"),
        c("36", "secrt"),
        c("36", "burn"),
        c("33", "--api-key"),
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
    fn flags_passphrase_prompt() {
        let pa = parse_flags(&s(&["--passphrase-prompt"])).unwrap();
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
}
