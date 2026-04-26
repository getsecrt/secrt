use std::fs;
use std::io::Write;
use std::path::PathBuf;

use serde::Deserialize;

/// Configuration loaded from the TOML config file.
#[derive(Debug, Default, Deserialize)]
pub struct Config {
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    pub passphrase: Option<String>,
    pub default_ttl: Option<String>,
    pub show_input: Option<bool>,
    pub use_keychain: Option<bool>,
    pub auto_copy: Option<bool>,
    /// Implicit update-check banner. `Some(false)` suppresses; absent or
    /// `Some(true)` enables (default). Layered with `--no-update-check` and
    /// `SECRET_NO_UPDATE_CHECK=1`.
    pub update_check: Option<bool>,
    #[serde(default)]
    pub decryption_passphrases: Vec<String>,
}

/// Returns the config file path: $XDG_CONFIG_HOME/secrt/config.toml
/// or ~/.config/secrt/config.toml (preferred over ~/Library/Application Support
/// on macOS since CLI tools conventionally use ~/.config/).
pub fn config_path() -> Option<PathBuf> {
    config_path_with(&|key| std::env::var(key).ok())
}

/// config_path variant that uses a custom getenv (for testing/injection).
pub fn config_path_with(getenv: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let config_dir = getenv("XDG_CONFIG_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")));
    config_dir.map(|d| d.join("secrt").join("config.toml"))
}

/// Load config from the standard path. Returns default Config if file
/// doesn't exist. Writes a warning to stderr if permissions are too open.
pub fn load_config(stderr: &mut dyn Write) -> Config {
    load_config_with(&|key| std::env::var(key).ok(), stderr)
}

/// Load config using a custom getenv (for testing/injection).
pub fn load_config_with(getenv: &dyn Fn(&str) -> Option<String>, stderr: &mut dyn Write) -> Config {
    let path = match config_path_with(getenv) {
        Some(p) => p,
        None => return Config::default(),
    };

    if !path.exists() {
        return Config::default();
    }

    // Check file permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = fs::metadata(&path) {
            let mode = meta.mode() & 0o777;
            if mode & 0o077 != 0 {
                let _ = writeln!(
                    stderr,
                    "warning: {} has permissions {:04o}; should be 0600\n\
                     Secrets in this file are accessible to other users. \
                     Fix with: chmod 600 {}",
                    path.display(),
                    mode,
                    path.display()
                );
                // Still load non-secret fields, but skip secrets
                return load_config_filtered(&path, stderr);
            }
        }
    }

    load_config_from_path(&path, stderr)
}

/// Load config, but omit secret fields (api_key, passphrase,
/// decryption_passphrases) due to insecure file permissions.
fn load_config_filtered(path: &PathBuf, stderr: &mut dyn Write) -> Config {
    let mut config = load_config_from_path(path, stderr);
    config.api_key = None;
    config.passphrase = None;
    config.decryption_passphrases = Vec::new();
    config
}

/// Parse the TOML file at the given path.
fn load_config_from_path(path: &PathBuf, stderr: &mut dyn Write) -> Config {
    match fs::read_to_string(path) {
        Ok(contents) => {
            // Migrate older configs corrupted by a writer bug that quoted bool keys
            // (e.g. `use_keychain = "true"`). Silently rewrite to bool literal so
            // affected users recover keychain integration on first run after upgrade.
            let (sanitized, changed) = sanitize_string_bools(&contents);
            if changed {
                let _ = fs::write(path, &sanitized);
            }
            match toml::from_str::<Config>(&sanitized) {
                Ok(config) => config,
                Err(e) => {
                    let _ = writeln!(stderr, "warning: failed to parse {}: {}", path.display(), e);
                    Config::default()
                }
            }
        }
        Err(e) => {
            let _ = writeln!(stderr, "warning: failed to read {}: {}", path.display(), e);
            Config::default()
        }
    }
}

/// Config keys whose TOML value MUST be a bool literal (not a quoted string).
const BOOL_CONFIG_KEYS: &[&str] = &["use_keychain", "show_input", "auto_copy", "update_check"];

/// Format a value for `key = ...`. Bool-typed keys get bool literals; everything
/// else is emitted as a TOML string.
fn format_config_value(key: &str, value: &str) -> String {
    if BOOL_CONFIG_KEYS.contains(&key) {
        match value {
            "true" => return "true".to_string(),
            "false" => return "false".to_string(),
            _ => {} // unexpected; fall through to string form (will surface on load)
        }
    }
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Rewrite lines of form `<bool_key> = "true"` / `"false"` (string-quoted) to a
/// bare bool literal. Returns `(new_contents, changed)`. Used to recover from a
/// writer bug in <= 0.15.0 that quoted `use_keychain = true`, which then made
/// the entire config fail to parse.
fn sanitize_string_bools(contents: &str) -> (String, bool) {
    let mut changed = false;
    let new_lines: Vec<String> = contents
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            for &key in BOOL_CONFIG_KEYS {
                for &value in &["true", "false"] {
                    if line_is_string_bool_for(trimmed, key, value) {
                        changed = true;
                        let indent_len = line.len() - trimmed.len();
                        let indent = &line[..indent_len];
                        return format!("{}{} = {}", indent, key, value);
                    }
                }
            }
            line.to_string()
        })
        .collect();
    let mut result = new_lines.join("\n");
    if contents.ends_with('\n') && !result.ends_with('\n') {
        result.push('\n');
    }
    (result, changed)
}

/// Does `trimmed` start with `<key> = "<value>"` (with optional whitespace
/// around `=` and an optional trailing comment)?
fn line_is_string_bool_for(trimmed: &str, key: &str, value: &str) -> bool {
    let rest = match trimmed.strip_prefix(key) {
        Some(r) => r,
        None => return false,
    };
    let rest = rest.trim_start();
    let rest = match rest.strip_prefix('=') {
        Some(r) => r.trim_start(),
        None => return false,
    };
    let needle = format!("\"{}\"", value);
    let after = match rest.strip_prefix(&needle) {
        Some(r) => r.trim_start(),
        None => return false,
    };
    after.is_empty() || after.starts_with('#')
}

/// Template content for a new config file.
pub const CONFIG_TEMPLATE: &str = "\
# secrt configuration
# https://github.com/getsecrt/secrt/blob/main/crates/secrt-cli/README.md#configuration

# Server URL (default: https://secrt.ca)
# base_url = \"https://secrt.ca\"

# API key for authenticated access
# api_key = \"sk2_...\"

# Default TTL for secrets (e.g., 5m, 2h, 1d, 1w)
# default_ttl = \"24h\"

# Default passphrase for encryption and decryption
# passphrase = \"\"

# Additional passphrases to try when claiming (tried in order)
# decryption_passphrases = [\"old-passphrase\", \"team-passphrase\"]

# Show input while typing (default: false)
# show_input = false

# Auto-copy share link to clipboard after send (default: true)
# auto_copy = true

# Read secrets (api_key, passphrase) from the OS credential store
# (macOS Keychain, Linux keyutils, Windows Credential Manager).
# Requires building with --features keychain. Default: false.
# use_keychain = false

# Show a one-line banner on stderr when a newer secrt version is available
# (default: true). Layered with --no-update-check and SECRET_NO_UPDATE_CHECK=1.
# update_check = true
";

/// Create a config file from the template. Returns Ok(path) on success.
/// If the file already exists and `force` is false, returns an error message.
pub fn init_config(force: bool) -> Result<PathBuf, String> {
    init_config_at(config_path(), force)
}

/// Inner init that takes an explicit path (for testing).
pub fn init_config_at(config_path: Option<PathBuf>, force: bool) -> Result<PathBuf, String> {
    let path = config_path.ok_or("could not determine config directory")?;
    if path.exists() && !force {
        return Err(format!(
            "Config file already exists at: {}\nUse --force to overwrite.",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;
    }
    fs::write(&path, CONFIG_TEMPLATE)
        .map_err(|e| format!("failed to write {}: {}", path.display(), e))?;

    // Set permissions to 0600 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }

    Ok(path)
}

/// Mask a secret value for display. Shows a prefix then dots.
/// For API keys (typically prefixed like "sk2_abc123..."), show first 8 chars.
/// For passphrases, show only dots.
pub fn mask_secret(value: &str, is_api_key: bool) -> String {
    if value.is_empty() {
        return String::new();
    }
    if is_api_key {
        let visible = value.len().min(8);
        let dots = "\u{2022}".repeat(8);
        format!("{}{}", &value[..visible], dots)
    } else {
        "\u{2022}".repeat(8)
    }
}

/// Mask a list of secret values for display.
/// Shows `[••••••••, ••••••••]` with the count of entries.
pub fn mask_secret_list(values: &[String]) -> String {
    if values.is_empty() {
        return String::new();
    }
    let dots = "\u{2022}".repeat(8);
    let masked: Vec<&str> = values.iter().map(|_| dots.as_str()).collect();
    format!("[{}]", masked.join(", "))
}

/// Set a key in the config file. Creates the file from template if missing.
/// If the key already exists (commented or not), updates or uncomments it.
/// Otherwise, appends the key.
pub fn set_config_key(
    getenv: &dyn Fn(&str) -> Option<String>,
    key: &str,
    value: &str,
) -> Result<(), String> {
    let path = config_path_with(getenv).ok_or("could not determine config directory")?;

    // Create parent dirs + file from template if missing
    if !path.exists() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;
        }
        fs::write(&path, CONFIG_TEMPLATE)
            .map_err(|e| format!("failed to write {}: {}", path.display(), e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
    }

    let contents = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;

    let formatted_value = format_config_value(key, value);
    let new_line = format!("{} = {}", key, formatted_value);

    let mut found = false;
    let mut lines: Vec<String> = contents
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            // Match "key = ..." or "# key = ..."
            let is_match = trimmed.starts_with(&format!("{} =", key))
                || trimmed.starts_with(&format!("{} =", key))
                || trimmed.starts_with(&format!("# {} =", key))
                || trimmed.starts_with(&format!("# {} =", key));
            if is_match && !found {
                found = true;
                new_line.clone()
            } else {
                line.to_string()
            }
        })
        .collect();

    if !found {
        lines.push(new_line);
    }

    let output = lines.join("\n");
    // Ensure trailing newline
    let output = if output.ends_with('\n') {
        output
    } else {
        format!("{}\n", output)
    };

    fs::write(&path, output).map_err(|e| format!("failed to write {}: {}", path.display(), e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Comment out a key in the config file.
pub fn remove_config_key(getenv: &dyn Fn(&str) -> Option<String>, key: &str) -> Result<(), String> {
    let path = config_path_with(getenv).ok_or("could not determine config directory")?;
    if !path.exists() {
        return Ok(()); // Nothing to remove
    }

    let contents = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;

    let lines: Vec<String> = contents
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with(&format!("{} =", key)) {
                format!("# {}", trimmed)
            } else {
                line.to_string()
            }
        })
        .collect();

    let output = lines.join("\n");
    let output = if output.ends_with('\n') {
        output
    } else {
        format!("{}\n", output)
    };

    fs::write(&path, output).map_err(|e| format!("failed to write {}: {}", path.display(), e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn config_path_exists() {
        // Just verify it returns Some on a typical system
        let p = config_path();
        assert!(p.is_some());
    }

    #[test]
    fn load_missing_file() {
        let config =
            load_config_from_path(&PathBuf::from("/nonexistent/config.toml"), &mut Vec::new());
        assert!(config.api_key.is_none());
        assert!(config.base_url.is_none());
        assert!(config.passphrase.is_none());
    }

    #[test]
    fn load_valid_toml() {
        let dir = tempfile::Builder::new()
            .prefix("secrt_config_test_")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "api_key = \"sk2_test_123\"\nbase_url = \"https://example.com\"\n",
        )
        .unwrap();
        let config = load_config_from_path(&path, &mut Vec::new());
        assert_eq!(config.api_key.as_deref(), Some("sk2_test_123"));
        assert_eq!(config.base_url.as_deref(), Some("https://example.com"));
        assert!(config.passphrase.is_none());
    }

    #[test]
    fn load_partial_toml() {
        let dir = tempfile::Builder::new()
            .prefix("secrt_config_partial_")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "base_url = \"https://my.server\"\n").unwrap();
        let config = load_config_from_path(&path, &mut Vec::new());
        assert!(config.api_key.is_none());
        assert_eq!(config.base_url.as_deref(), Some("https://my.server"));
    }

    #[test]
    fn load_invalid_toml_warns() {
        let dir = tempfile::Builder::new()
            .prefix("secrt_config_invalid_")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "not valid [[ toml !!!").unwrap();
        let mut stderr = Vec::new();
        let config = load_config_from_path(&path, &mut stderr);
        assert!(config.api_key.is_none());
        let warning = String::from_utf8(stderr).unwrap();
        assert!(warning.contains("warning: failed to parse"));
    }

    #[test]
    fn filtered_strips_secrets() {
        let dir = tempfile::Builder::new()
            .prefix("secrt_config_filtered_")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "api_key = \"sk2_secret\"\nbase_url = \"https://ok.com\"\npassphrase = \"hunter2\"\n",
        )
        .unwrap();
        let config = load_config_filtered(&path, &mut Vec::new());
        assert!(config.api_key.is_none(), "api_key should be stripped");
        assert!(config.passphrase.is_none(), "passphrase should be stripped");
        assert_eq!(config.base_url.as_deref(), Some("https://ok.com"));
    }

    #[cfg(unix)]
    #[test]
    fn permissions_check() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .prefix("secrt_config_perms_")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "api_key = \"sk2_secret\"\nbase_url = \"https://ok.com\"\n",
        )
        .unwrap();

        // Set world-readable
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let mut stderr = Vec::new();
        // Verify the permission bits are as expected
        let meta = fs::metadata(&path).unwrap();
        let mode = meta.mode() & 0o777;
        assert_eq!(mode, 0o644);
        assert!(mode & 0o077 != 0, "should detect group/world bits");

        let config = load_config_filtered(&path, &mut stderr);
        assert!(config.api_key.is_none());
        assert_eq!(config.base_url.as_deref(), Some("https://ok.com"));
    }

    #[test]
    fn mask_api_key_shows_prefix() {
        let masked = mask_secret("sk2_live_abc123xyz789", true);
        assert!(masked.starts_with("sk2_live"));
        assert!(masked.contains('\u{2022}'));
        assert!(!masked.contains("xyz789"));
    }

    #[test]
    fn mask_api_key_short() {
        let masked = mask_secret("sk2_ab", true);
        assert!(masked.starts_with("sk2_ab"));
        assert!(masked.contains('\u{2022}'));
    }

    #[test]
    fn mask_passphrase_all_dots() {
        let masked = mask_secret("hunter2", false);
        assert!(!masked.contains("hunter"));
        assert!(masked.contains('\u{2022}'));
    }

    #[test]
    fn mask_empty() {
        assert_eq!(mask_secret("", true), "");
        assert_eq!(mask_secret("", false), "");
    }

    #[test]
    fn load_toml_with_default_ttl() {
        let dir = tempfile::Builder::new()
            .prefix("secrt_config_ttl_")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "default_ttl = \"24h\"\n").unwrap();
        let config = load_config_from_path(&path, &mut Vec::new());
        assert_eq!(config.default_ttl.as_deref(), Some("24h"));
    }

    #[test]
    fn load_toml_with_decryption_passphrases() {
        let dir = tempfile::Builder::new()
            .prefix("secrt_config_dp_")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "decryption_passphrases = [\"pass1\", \"pass2\", \"pass3\"]\n",
        )
        .unwrap();
        let config = load_config_from_path(&path, &mut Vec::new());
        assert_eq!(
            config.decryption_passphrases,
            vec!["pass1", "pass2", "pass3"]
        );
    }

    #[test]
    fn load_toml_missing_fields_default() {
        let dir = tempfile::Builder::new()
            .prefix("secrt_config_defaults_")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "base_url = \"https://ok.com\"\n").unwrap();
        let config = load_config_from_path(&path, &mut Vec::new());
        assert!(config.default_ttl.is_none());
        assert!(config.decryption_passphrases.is_empty());
    }

    #[test]
    fn filtered_strips_decryption_passphrases() {
        let dir = tempfile::Builder::new()
            .prefix("secrt_config_filtered_dp_")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "base_url = \"https://ok.com\"\ndefault_ttl = \"1h\"\ndecryption_passphrases = [\"secret1\"]\n",
        )
        .unwrap();
        let config = load_config_filtered(&path, &mut Vec::new());
        assert!(
            config.decryption_passphrases.is_empty(),
            "decryption_passphrases should be stripped"
        );
        assert_eq!(
            config.default_ttl.as_deref(),
            Some("1h"),
            "default_ttl should NOT be stripped"
        );
        assert_eq!(config.base_url.as_deref(), Some("https://ok.com"));
    }

    #[test]
    fn mask_secret_list_empty() {
        assert_eq!(mask_secret_list(&[]), "");
    }

    #[test]
    fn mask_secret_list_multiple() {
        let list = vec!["a".into(), "bb".into(), "ccc".into()];
        let masked = mask_secret_list(&list);
        assert!(masked.starts_with('['));
        assert!(masked.ends_with(']'));
        assert!(masked.contains('\u{2022}'));
        // Should have 3 masked entries separated by commas
        assert_eq!(masked.matches(", ").count(), 2);
    }

    #[test]
    fn template_contains_all_keys() {
        assert!(
            CONFIG_TEMPLATE.contains("base_url"),
            "template missing base_url"
        );
        assert!(
            CONFIG_TEMPLATE.contains("api_key"),
            "template missing api_key"
        );
        assert!(
            CONFIG_TEMPLATE.contains("default_ttl"),
            "template missing default_ttl"
        );
        assert!(
            CONFIG_TEMPLATE.contains("passphrase ="),
            "template missing passphrase"
        );
        assert!(
            CONFIG_TEMPLATE.contains("decryption_passphrases"),
            "template missing decryption_passphrases"
        );
        assert!(
            CONFIG_TEMPLATE.contains("show_input"),
            "template missing show_input"
        );
        assert!(
            CONFIG_TEMPLATE.contains("use_keychain"),
            "template missing use_keychain"
        );
        assert!(
            CONFIG_TEMPLATE.contains("auto_copy"),
            "template missing auto_copy"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_config_with_bad_permissions_warns_and_strips() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .prefix("secrt_config_perm_warn_")
            .tempdir()
            .expect("tempdir");
        let secrt_dir = dir.path().join("secrt");
        fs::create_dir_all(&secrt_dir).expect("create secrt subdir");
        let path = secrt_dir.join("config.toml");
        fs::write(
            &path,
            "api_key = \"sk2_secret\"\nbase_url = \"https://ok.com\"\npassphrase = \"hunter2\"\n",
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let dir_str = dir.path().to_str().unwrap().to_string();
        let getenv = move |key: &str| -> Option<String> {
            if key == "XDG_CONFIG_HOME" {
                Some(dir_str.clone())
            } else {
                None
            }
        };
        let mut stderr = Vec::new();
        let config = load_config_with(&getenv, &mut stderr);

        let warning = String::from_utf8(stderr).unwrap();
        assert!(
            warning.contains("warning:"),
            "should warn about permissions: {}",
            warning
        );
        assert!(
            warning.contains("0644"),
            "should show actual mode: {}",
            warning
        );
        assert!(
            config.api_key.is_none(),
            "api_key should be stripped for insecure file"
        );
        assert!(
            config.passphrase.is_none(),
            "passphrase should be stripped for insecure file"
        );
        assert_eq!(
            config.base_url.as_deref(),
            Some("https://ok.com"),
            "base_url should not be stripped"
        );
    }

    #[test]
    fn config_path_with_xdg_override() {
        let getenv = |key: &str| -> Option<String> {
            if key == "XDG_CONFIG_HOME" {
                Some("/custom/config".into())
            } else {
                None
            }
        };
        let path = config_path_with(&getenv).unwrap();
        assert_eq!(path, PathBuf::from("/custom/config/secrt/config.toml"));
    }

    #[test]
    fn config_path_with_empty_xdg() {
        // Empty XDG_CONFIG_HOME should fall back to ~/.config
        let getenv = |key: &str| -> Option<String> {
            if key == "XDG_CONFIG_HOME" {
                Some(String::new())
            } else {
                None
            }
        };
        let path = config_path_with(&getenv).unwrap();
        // Use Path::ends_with which compares components (cross-platform)
        let expected = std::path::Path::new(".config")
            .join("secrt")
            .join("config.toml");
        assert!(
            path.ends_with(&expected),
            "should fall back to ~/.config: {:?}",
            path
        );
    }

    #[test]
    fn set_bool_config_keys_are_unquoted() {
        // Regression for GH#42: `set_config_key("use_keychain", "true")` used to
        // write `use_keychain = "true"` (string), which then broke TOML parsing
        // on next load and silently disabled keychain integration.
        let dir = tempfile::Builder::new()
            .prefix("secrt_config_set_bool_")
            .tempdir()
            .expect("tempdir");
        let dir_str = dir.path().to_str().unwrap().to_string();
        let getenv = move |key: &str| -> Option<String> {
            if key == "XDG_CONFIG_HOME" {
                Some(dir_str.clone())
            } else {
                None
            }
        };

        for key in ["use_keychain", "show_input", "auto_copy"] {
            for value in ["true", "false"] {
                set_config_key(&getenv, key, value).unwrap();
                let contents =
                    fs::read_to_string(dir.path().join("secrt").join("config.toml")).unwrap();
                let needle = format!("{} = {}", key, value);
                assert!(
                    contents.contains(&needle),
                    "expected `{}` (bare bool) in config, got:\n{}",
                    needle,
                    contents
                );
                let bad = format!("{} = \"{}\"", key, value);
                assert!(
                    !contents.contains(&bad),
                    "found quoted bool `{}` — should be bare literal",
                    bad
                );
                // And it must round-trip through the loader.
                let config = load_config_with(&getenv, &mut Vec::new());
                let actual: Option<bool> = match key {
                    "use_keychain" => config.use_keychain,
                    "show_input" => config.show_input,
                    "auto_copy" => config.auto_copy,
                    _ => unreachable!(),
                };
                assert_eq!(actual, Some(value == "true"));
            }
        }

        // String keys still get quoted.
        set_config_key(&getenv, "base_url", "https://example.com").unwrap();
        let contents = fs::read_to_string(dir.path().join("secrt").join("config.toml")).unwrap();
        assert!(contents.contains("base_url = \"https://example.com\""));
    }

    #[test]
    fn load_migrates_string_form_bool_silently() {
        // Existing users hit by GH#42 already have a corrupted config. On load,
        // we accept the string form, rewrite the file, and parse successfully.
        let dir = tempfile::Builder::new()
            .prefix("secrt_config_migrate_")
            .tempdir()
            .expect("tempdir");
        let secrt_dir = dir.path().join("secrt");
        fs::create_dir_all(&secrt_dir).expect("create secrt subdir");
        let path = secrt_dir.join("config.toml");
        fs::write(
            &path,
            "api_key = \"sk2_x\"\nuse_keychain = \"true\"\nauto_copy = \"false\"\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        let dir_str = dir.path().to_str().unwrap().to_string();
        let getenv = move |key: &str| -> Option<String> {
            if key == "XDG_CONFIG_HOME" {
                Some(dir_str.clone())
            } else {
                None
            }
        };
        let mut stderr = Vec::new();
        let config = load_config_with(&getenv, &mut stderr);

        assert_eq!(
            config.use_keychain,
            Some(true),
            "should parse migrated bool"
        );
        assert_eq!(config.auto_copy, Some(false));
        assert_eq!(config.api_key.as_deref(), Some("sk2_x"));

        let warning = String::from_utf8(stderr).unwrap();
        assert!(
            !warning.contains("warning:"),
            "migration should be silent, got: {}",
            warning
        );

        let on_disk = fs::read_to_string(&path).unwrap();
        assert!(
            on_disk.contains("use_keychain = true"),
            "file should be rewritten with bool literal:\n{}",
            on_disk
        );
        assert!(on_disk.contains("auto_copy = false"));
        assert!(!on_disk.contains("\"true\""));
        assert!(!on_disk.contains("\"false\""));
    }

    #[test]
    fn sanitize_preserves_unrelated_lines() {
        let input = "# comment\napi_key = \"sk2_x\"\nuse_keychain = \"true\"  # ok\nbase_url = \"https://x\"\n";
        let (out, changed) = sanitize_string_bools(input);
        assert!(changed);
        assert!(out.contains("# comment"));
        assert!(out.contains("api_key = \"sk2_x\""));
        assert!(out.contains("use_keychain = true"));
        assert!(out.contains("base_url = \"https://x\""));
        // Trailing newline preserved.
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn sanitize_does_not_touch_correct_files() {
        let input = "use_keychain = true\nshow_input = false\n";
        let (out, changed) = sanitize_string_bools(input);
        assert!(!changed);
        assert_eq!(out, input);
    }

    #[test]
    fn load_config_with_injectable() {
        let dir = tempfile::Builder::new()
            .prefix("secrt_config_injectable_")
            .tempdir()
            .expect("tempdir");
        let secrt_dir = dir.path().join("secrt");
        let _ = fs::create_dir_all(&secrt_dir);
        let path = secrt_dir.join("config.toml");
        fs::write(&path, "default_ttl = \"2h\"\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        let dir_str = dir.path().to_str().unwrap().to_string();
        let getenv = move |key: &str| -> Option<String> {
            if key == "XDG_CONFIG_HOME" {
                Some(dir_str.clone())
            } else {
                None
            }
        };
        let config = load_config_with(&getenv, &mut Vec::new());
        assert_eq!(config.default_ttl.as_deref(), Some("2h"));
    }
}
