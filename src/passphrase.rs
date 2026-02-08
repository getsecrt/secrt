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
        // Fall back to config file passphrase if set
        if !args.passphrase_default.is_empty() {
            return Ok(args.passphrase_default.clone());
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{self, Cursor};
    use std::sync::{Arc, Mutex};

    fn make_deps(
        env: HashMap<String, String>,
        read_pass_responses: Vec<String>,
        read_pass_err: Option<String>,
    ) -> Deps {
        let responses = Arc::new(Mutex::new(read_pass_responses));
        Deps {
            stdin: Box::new(Cursor::new(Vec::new())),
            stdout: Box::new(Vec::new()),
            stderr: Box::new(Vec::new()),
            is_tty: Box::new(|| false),
            is_stdout_tty: Box::new(|| false),
            getenv: Box::new(move |key: &str| env.get(key).cloned()),
            rand_bytes: Box::new(|_buf: &mut [u8]| Ok(())),
            read_pass: Box::new(move |_prompt: &str, _w: &mut dyn Write| {
                if let Some(ref msg) = read_pass_err {
                    return Err(io::Error::new(io::ErrorKind::Other, msg.clone()));
                }
                let mut r = responses.lock().unwrap();
                if r.is_empty() {
                    Err(io::Error::new(io::ErrorKind::Other, "no input"))
                } else {
                    Ok(r.remove(0))
                }
            }),
            make_api: Box::new(|base_url: &str, api_key: &str| {
                Box::new(crate::client::ApiClient {
                    base_url: base_url.to_string(),
                    api_key: api_key.to_string(),
                })
            }),
        }
    }

    fn default_deps() -> Deps {
        make_deps(HashMap::new(), Vec::new(), None)
    }

    // --- resolve_passphrase tests ---

    #[test]
    fn no_flags_empty_string() {
        let pa = ParsedArgs::default();
        let mut deps = default_deps();
        let result = resolve_passphrase(&pa, &mut deps).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn multiple_flags_error() {
        let mut pa = ParsedArgs::default();
        pa.passphrase_prompt = true;
        pa.passphrase_env = "MY_VAR".into();
        let mut deps = default_deps();
        let err = resolve_passphrase(&pa, &mut deps);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("at most one"));
    }

    #[test]
    fn env_happy() {
        let mut env = HashMap::new();
        env.insert("MY_PASS".into(), "secret123".into());
        let mut deps = make_deps(env, Vec::new(), None);
        let mut pa = ParsedArgs::default();
        pa.passphrase_env = "MY_PASS".into();
        let result = resolve_passphrase(&pa, &mut deps).unwrap();
        assert_eq!(result, "secret123");
    }

    #[test]
    fn env_missing() {
        let mut deps = default_deps();
        let mut pa = ParsedArgs::default();
        pa.passphrase_env = "NONEXISTENT".into();
        let err = resolve_passphrase(&pa, &mut deps);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("empty or not set"));
    }

    #[test]
    fn env_empty() {
        let mut env = HashMap::new();
        env.insert("MY_PASS".into(), "".into());
        let mut deps = make_deps(env, Vec::new(), None);
        let mut pa = ParsedArgs::default();
        pa.passphrase_env = "MY_PASS".into();
        let err = resolve_passphrase(&pa, &mut deps);
        assert!(err.is_err());
    }

    #[test]
    fn file_happy() {
        let dir = std::env::temp_dir();
        let path = dir.join("secrt_test_pass_happy.txt");
        fs::write(&path, "my-passphrase\n").unwrap();
        let mut deps = default_deps();
        let mut pa = ParsedArgs::default();
        pa.passphrase_file = path.to_str().unwrap().into();
        let result = resolve_passphrase(&pa, &mut deps).unwrap();
        assert_eq!(result, "my-passphrase");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn file_empty() {
        let dir = std::env::temp_dir();
        let path = dir.join("secrt_test_pass_empty.txt");
        fs::write(&path, "").unwrap();
        let mut deps = default_deps();
        let mut pa = ParsedArgs::default();
        pa.passphrase_file = path.to_str().unwrap().into();
        let err = resolve_passphrase(&pa, &mut deps);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("empty"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn file_trims_newlines() {
        let dir = std::env::temp_dir();
        let path = dir.join("secrt_test_pass_trim.txt");
        fs::write(&path, "secret\r\n").unwrap();
        let mut deps = default_deps();
        let mut pa = ParsedArgs::default();
        pa.passphrase_file = path.to_str().unwrap().into();
        let result = resolve_passphrase(&pa, &mut deps).unwrap();
        assert_eq!(result, "secret");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn file_not_found() {
        let mut deps = default_deps();
        let mut pa = ParsedArgs::default();
        pa.passphrase_file = "/tmp/nonexistent_secrt_pass_file_xyz.txt".into();
        let err = resolve_passphrase(&pa, &mut deps);
        assert!(err.is_err());
    }

    #[test]
    fn prompt_happy() {
        let mut deps = make_deps(HashMap::new(), vec!["mypass".into()], None);
        let mut pa = ParsedArgs::default();
        pa.passphrase_prompt = true;
        let result = resolve_passphrase(&pa, &mut deps).unwrap();
        assert_eq!(result, "mypass");
    }

    #[test]
    fn prompt_empty() {
        let mut deps = make_deps(HashMap::new(), vec!["".into()], None);
        let mut pa = ParsedArgs::default();
        pa.passphrase_prompt = true;
        let err = resolve_passphrase(&pa, &mut deps);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("must not be empty"));
    }

    // --- resolve_passphrase_for_create tests ---

    #[test]
    fn create_prompt_match() {
        let mut deps = make_deps(
            HashMap::new(),
            vec!["pass123".into(), "pass123".into()],
            None,
        );
        let mut pa = ParsedArgs::default();
        pa.passphrase_prompt = true;
        let result = resolve_passphrase_for_create(&pa, &mut deps).unwrap();
        assert_eq!(result, "pass123");
    }

    #[test]
    fn create_prompt_mismatch() {
        let mut deps = make_deps(
            HashMap::new(),
            vec!["pass123".into(), "different".into()],
            None,
        );
        let mut pa = ParsedArgs::default();
        pa.passphrase_prompt = true;
        let err = resolve_passphrase_for_create(&pa, &mut deps);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("do not match"));
    }

    #[test]
    fn create_prompt_empty() {
        let mut deps = make_deps(HashMap::new(), vec!["".into()], None);
        let mut pa = ParsedArgs::default();
        pa.passphrase_prompt = true;
        let err = resolve_passphrase_for_create(&pa, &mut deps);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("must not be empty"));
    }

    #[test]
    fn create_multiple_flags_error() {
        let mut deps = default_deps();
        let mut pa = ParsedArgs::default();
        pa.passphrase_prompt = true;
        pa.passphrase_env = "MY_VAR".into();
        let err = resolve_passphrase_for_create(&pa, &mut deps);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("at most one"));
    }

    // --- write_error tests ---

    #[test]
    fn plain_format() {
        let mut buf = Vec::new();
        write_error(&mut buf, false, "something broke");
        assert_eq!(String::from_utf8(buf).unwrap(), "error: something broke\n");
    }

    #[test]
    fn json_format() {
        let mut buf = Vec::new();
        write_error(&mut buf, true, "something broke");
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("\"error\""));
        assert!(output.contains("something broke"));
    }
}
