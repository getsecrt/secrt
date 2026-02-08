use std::fs;
use std::io::Write;

use crate::cli::{Deps, ParsedArgs};

/// Extract a passphrase from flags using the provided Deps.
/// Returns (passphrase, error). Empty passphrase means none requested.
pub fn resolve_passphrase(args: &ParsedArgs, deps: &mut Deps) -> Result<String, String> {
    let mut count = 0;
    if args.passphrase_prompt {
        count += 1;
    }
    if !args.passphrase_env.is_empty() {
        count += 1;
    }
    if !args.passphrase_file.is_empty() {
        count += 1;
    }
    if count > 1 {
        return Err(
            "specify at most one of --passphrase-prompt, --passphrase-env, --passphrase-file"
                .into(),
        );
    }
    if count == 0 {
        return Ok(String::new());
    }

    if !args.passphrase_env.is_empty() {
        let p = (deps.getenv)(&args.passphrase_env);
        match p {
            Some(val) if !val.is_empty() => return Ok(val),
            _ => {
                return Err(format!(
                    "environment variable {:?} is empty or not set",
                    args.passphrase_env
                ))
            }
        }
    }

    if !args.passphrase_file.is_empty() {
        let data = fs::read_to_string(&args.passphrase_file)
            .map_err(|e| format!("read passphrase file: {}", e))?;
        let p = data.trim_end_matches(['\r', '\n'].as_ref());
        if p.is_empty() {
            return Err("passphrase file is empty".into());
        }
        return Ok(p.to_string());
    }

    // Prompt
    let p = (deps.read_pass)("Passphrase: ", &mut deps.stderr)
        .map_err(|e| format!("read passphrase: {}", e))?;
    if p.is_empty() {
        return Err("passphrase must not be empty".into());
    }

    Ok(p)
}

/// Like resolve_passphrase but prompts for confirmation on create.
pub fn resolve_passphrase_for_create(args: &ParsedArgs, deps: &mut Deps) -> Result<String, String> {
    // Check for conflicting flags first
    let mut count = 0;
    if args.passphrase_prompt {
        count += 1;
    }
    if !args.passphrase_env.is_empty() {
        count += 1;
    }
    if !args.passphrase_file.is_empty() {
        count += 1;
    }
    if count > 1 {
        return Err(
            "specify at most one of --passphrase-prompt, --passphrase-env, --passphrase-file"
                .into(),
        );
    }

    if !args.passphrase_prompt {
        return resolve_passphrase(args, deps);
    }

    let p1 = (deps.read_pass)("Passphrase: ", &mut deps.stderr)
        .map_err(|e| format!("read passphrase: {}", e))?;
    if p1.is_empty() {
        return Err("passphrase must not be empty".into());
    }

    let p2 = (deps.read_pass)("Confirm passphrase: ", &mut deps.stderr)
        .map_err(|e| format!("read passphrase confirmation: {}", e))?;
    if p1 != p2 {
        return Err("passphrases do not match".into());
    }

    Ok(p1)
}

/// Write an error message to the writer, in JSON or plain format.
pub fn write_error(w: &mut dyn Write, json_mode: bool, msg: &str) {
    if json_mode {
        let _ = writeln!(w, "{{\"error\":{}}}", serde_json::to_string(msg).unwrap());
    } else {
        let _ = writeln!(w, "error: {}", msg);
    }
}
