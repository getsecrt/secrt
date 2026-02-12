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
        Ok(contents) => match toml::from_str::<Config>(&contents) {
            Ok(config) => config,
            Err(e) => {
                let _ = writeln!(stderr, "warning: failed to parse {}: {}", path.display(), e);
                Config::default()
            }
        },
        Err(e) => {
            let _ = writeln!(stderr, "warning: failed to read {}: {}", path.display(), e);
            Config::default()
        }
    }
}

/// Template content for a new config file.
pub const CONFIG_TEMPLATE: &str = "\
# secrt configuration
# https://secrt.ca/docs/config

# Server URL (default: https://secrt.ca)
# base_url = \"https://secrt.ca\"

# API key for authenticated access
# api_key = \"sk_...\"

# Default TTL for secrets (e.g., 5m, 2h, 1d, 1w)
# default_ttl = \"24h\"

# Default passphrase for encryption and decryption
# passphrase = \"\"

# Additional passphrases to try when claiming (tried in order)
# decryption_passphrases = [\"old-passphrase\", \"team-passphrase\"]

# Show input while typing (default: false)
# show_input = false

# Read secrets (api_key, passphrase) from the OS credential store
# (macOS Keychain, Linux keyutils, Windows Credential Manager).
# Requires building with --features keychain. Default: false.
# use_keychain = false
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
/// For API keys (typically prefixed like "sk_abc123..."), show first 8 chars.
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
        let dir = std::env::temp_dir().join("secrt_config_test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
        fs::write(
            &path,
            "api_key = \"sk_test_123\"\nbase_url = \"https://example.com\"\n",
        )
        .unwrap();
        let config = load_config_from_path(&path, &mut Vec::new());
        assert_eq!(config.api_key.as_deref(), Some("sk_test_123"));
        assert_eq!(config.base_url.as_deref(), Some("https://example.com"));
        assert!(config.passphrase.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_partial_toml() {
        let dir = std::env::temp_dir().join("secrt_config_partial");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
        fs::write(&path, "base_url = \"https://my.server\"\n").unwrap();
        let config = load_config_from_path(&path, &mut Vec::new());
        assert!(config.api_key.is_none());
        assert_eq!(config.base_url.as_deref(), Some("https://my.server"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_invalid_toml_warns() {
        let dir = std::env::temp_dir().join("secrt_config_invalid");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
        fs::write(&path, "not valid [[ toml !!!").unwrap();
        let mut stderr = Vec::new();
        let config = load_config_from_path(&path, &mut stderr);
        assert!(config.api_key.is_none());
        let warning = String::from_utf8(stderr).unwrap();
        assert!(warning.contains("warning: failed to parse"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn filtered_strips_secrets() {
        let dir = std::env::temp_dir().join("secrt_config_filtered");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
        fs::write(
            &path,
            "api_key = \"sk_secret\"\nbase_url = \"https://ok.com\"\npassphrase = \"hunter2\"\n",
        )
        .unwrap();
        let config = load_config_filtered(&path, &mut Vec::new());
        assert!(config.api_key.is_none(), "api_key should be stripped");
        assert!(config.passphrase.is_none(), "passphrase should be stripped");
        assert_eq!(config.base_url.as_deref(), Some("https://ok.com"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn permissions_check() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join("secrt_config_perms");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
        fs::write(
            &path,
            "api_key = \"sk_secret\"\nbase_url = \"https://ok.com\"\n",
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

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mask_api_key_shows_prefix() {
        let masked = mask_secret("sk_live_abc123xyz789", true);
        assert!(masked.starts_with("sk_live_"));
        assert!(masked.contains('\u{2022}'));
        assert!(!masked.contains("xyz789"));
    }

    #[test]
    fn mask_api_key_short() {
        let masked = mask_secret("sk_ab", true);
        assert!(masked.starts_with("sk_ab"));
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
        let dir = std::env::temp_dir().join("secrt_config_ttl");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
        fs::write(&path, "default_ttl = \"24h\"\n").unwrap();
        let config = load_config_from_path(&path, &mut Vec::new());
        assert_eq!(config.default_ttl.as_deref(), Some("24h"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_toml_with_decryption_passphrases() {
        let dir = std::env::temp_dir().join("secrt_config_dp");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
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
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_toml_missing_fields_default() {
        let dir = std::env::temp_dir().join("secrt_config_defaults");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
        fs::write(&path, "base_url = \"https://ok.com\"\n").unwrap();
        let config = load_config_from_path(&path, &mut Vec::new());
        assert!(config.default_ttl.is_none());
        assert!(config.decryption_passphrases.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn filtered_strips_decryption_passphrases() {
        let dir = std::env::temp_dir().join("secrt_config_filtered_dp");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
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
        let _ = fs::remove_dir_all(&dir);
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
    }

    #[cfg(unix)]
    #[test]
    fn load_config_with_bad_permissions_warns_and_strips() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "secrt_config_perm_warn_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let secrt_dir = dir.join("secrt");
        let _ = fs::create_dir_all(&secrt_dir);
        let path = secrt_dir.join("config.toml");
        fs::write(
            &path,
            "api_key = \"sk_secret\"\nbase_url = \"https://ok.com\"\npassphrase = \"hunter2\"\n",
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let dir_str = dir.to_str().unwrap().to_string();
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

        let _ = fs::remove_dir_all(&dir);
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
    fn load_config_with_injectable() {
        let dir = std::env::temp_dir().join("secrt_config_injectable");
        let secrt_dir = dir.join("secrt");
        let _ = fs::create_dir_all(&secrt_dir);
        let path = secrt_dir.join("config.toml");
        fs::write(&path, "default_ttl = \"2h\"\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        let dir_str = dir.to_str().unwrap().to_string();
        let getenv = move |key: &str| -> Option<String> {
            if key == "XDG_CONFIG_HOME" {
                Some(dir_str.clone())
            } else {
                None
            }
        };
        let config = load_config_with(&getenv, &mut Vec::new());
        assert_eq!(config.default_ttl.as_deref(), Some("2h"));
        let _ = fs::remove_dir_all(&dir);
    }
}
