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
}

/// Returns the config file path: $XDG_CONFIG_HOME/secrt/config.toml
/// or ~/.config/secrt/config.toml
pub fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("secrt").join("config.toml"))
}

/// Load config from the standard path. Returns default Config if file
/// doesn't exist. Writes a warning to stderr if permissions are too open.
pub fn load_config(stderr: &mut dyn Write) -> Config {
    let path = match config_path() {
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

/// Load config, but omit secret fields (api_key, passphrase) due to
/// insecure file permissions.
fn load_config_filtered(path: &PathBuf, stderr: &mut dyn Write) -> Config {
    let mut config = load_config_from_path(path, stderr);
    config.api_key = None;
    config.passphrase = None;
    config
}

/// Parse the TOML file at the given path.
fn load_config_from_path(path: &PathBuf, stderr: &mut dyn Write) -> Config {
    match fs::read_to_string(path) {
        Ok(contents) => match toml::from_str::<Config>(&contents) {
            Ok(config) => config,
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "warning: failed to parse {}: {}",
                    path.display(),
                    e
                );
                Config::default()
            }
        },
        Err(e) => {
            let _ = writeln!(
                stderr,
                "warning: failed to read {}: {}",
                path.display(),
                e
            );
            Config::default()
        }
    }
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
        let config = load_config_from_path(&PathBuf::from("/nonexistent/config.toml"), &mut Vec::new());
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
}
