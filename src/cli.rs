use std::io::{self, Read, Write};

use crate::burn::run_burn;
use crate::claim::run_claim;
use crate::color::color_func;
use crate::completion::{BASH_COMPLETION, FISH_COMPLETION, ZSH_COMPLETION};
use crate::create::run_create;

const DEFAULT_BASE_URL: &str = "https://secrt.ca";
const VERSION: &str = "dev";

pub type GetenvFn = Box<dyn Fn(&str) -> Option<String>>;
pub type RandBytesFn = Box<dyn Fn(&mut [u8]) -> Result<(), crate::envelope::EnvelopeError>>;
pub type ReadPassFn = Box<dyn Fn(&str, &mut dyn Write) -> io::Result<String>>;

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

/// Fill in defaults from env vars.
pub fn resolve_globals(pa: &mut ParsedArgs, deps: &Deps) {
    if pa.base_url.is_empty() {
        if let Some(env) = (deps.getenv)("SECRET_BASE_URL") {
            pa.base_url = env;
        } else {
            pa.base_url = DEFAULT_BASE_URL.into();
        }
    }
    if pa.api_key.is_empty() {
        if let Some(env) = (deps.getenv)("SECRET_API_KEY") {
            pa.api_key = env;
        }
    }
}

// --- Help text ---

fn print_usage(deps: &mut Deps) {
    let c = color_func((deps.is_stdout_tty)());
    let _ = write!(
        deps.stderr,
        "{} — one-time secret sharing\n\nRun '{}' for usage.\n",
        c("36", "secrt"),
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
  {} https://secrt.ca/s/abc#v1.key\n",
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
