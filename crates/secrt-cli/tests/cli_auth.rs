mod helpers;

use std::fs;

use helpers::{args, TestDepsBuilder};
use secrt_cli::cli;
use secrt_cli::client::{InfoLimits, InfoRate, InfoResponse, InfoTTL, InfoTier};

/// A valid sk2_ API key for testing.
/// Format: sk2_<prefix>.<base64url(32 bytes)>
/// Prefix "testprefix" is 10 alphanumeric chars (minimum is 6).
/// The root key is 32 bytes of 0xAA, base64url-no-pad encoded.
const VALID_API_KEY: &str = "sk2_testprefix.qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo";

/// Build a mock InfoResponse for auth tests.
fn mock_info_response(authenticated: bool) -> InfoResponse {
    InfoResponse {
        authenticated,
        ttl: InfoTTL {
            default_seconds: 86400,
            max_seconds: 31536000,
        },
        limits: InfoLimits {
            public: InfoTier {
                max_envelope_bytes: 262144,
                max_secrets: 10,
                max_total_bytes: 2097152,
                rate: InfoRate {
                    requests_per_second: 0.5,
                    burst: 6,
                },
            },
            authed: InfoTier {
                max_envelope_bytes: 1048576,
                max_secrets: 1000,
                max_total_bytes: 20971520,
                rate: InfoRate {
                    requests_per_second: 2.0,
                    burst: 20,
                },
            },
        },
        claim_rate: InfoRate {
            requests_per_second: 1.0,
            burst: 10,
        },
    }
}

/// Helper to create a temp config dir with a config.toml containing the given TOML content.
/// Returns the path to use as XDG_CONFIG_HOME.
fn setup_config(toml_content: &str) -> std::path::PathBuf {
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("secrt_auth_test_{}", id));
    let secrt_dir = dir.join("secrt");
    let _ = fs::create_dir_all(&secrt_dir);
    let config_path = secrt_dir.join("config.toml");
    fs::write(&config_path, toml_content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600));
    }
    dir
}

// --- auth help tests ---

#[test]
fn auth_no_subcommand_shows_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "auth"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("auth login"),
        "auth with no args should show help mentioning 'auth login': {}",
        err
    );
}

#[test]
fn auth_help_flag_shows_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "auth", "--help"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("auth login"),
        "auth --help should show help mentioning 'auth login': {}",
        err
    );
    assert!(
        err.contains("auth setup"),
        "auth --help should mention 'auth setup': {}",
        err
    );
    assert!(
        err.contains("auth status"),
        "auth --help should mention 'auth status': {}",
        err
    );
    assert!(
        err.contains("auth logout"),
        "auth --help should mention 'auth logout': {}",
        err
    );
}

// --- auth setup tests ---

#[test]
fn auth_setup_stores_valid_key() {
    // Set up a temp config dir so store_api_key can write to it
    let cfg_dir = setup_config("");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&[VALID_API_KEY])
        .mock_info(Ok(mock_info_response(true)))
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "auth", "setup"]), &mut deps);
    let err = stderr.to_string();
    assert_eq!(code, 0, "auth setup should succeed; stderr: {}", err);
    assert!(
        err.contains("Key verified") || err.contains("stored"),
        "should show verification or storage success message: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn auth_setup_rejects_invalid_key() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().read_pass(&["invalid_key"]).build();
    let code = cli::run(&args(&["secrt", "auth", "setup"]), &mut deps);
    assert_ne!(code, 0, "auth setup should fail for invalid key");
    let err = stderr.to_string();
    assert!(
        err.contains("invalid") && err.contains("format"),
        "should show invalid format error: {}",
        err
    );
}

// --- auth status tests ---

#[test]
fn auth_status_no_key() {
    // Point to a nonexistent config dir so no config is loaded
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env(
            "XDG_CONFIG_HOME",
            "/tmp/secrt_auth_test_no_config_nonexistent",
        )
        .build();
    let code = cli::run(&args(&["secrt", "auth", "status"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("Not authenticated"),
        "should show 'Not authenticated' when no key: {}",
        err
    );
}

#[test]
fn auth_status_with_env_key() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", VALID_API_KEY)
        .env(
            "XDG_CONFIG_HOME",
            "/tmp/secrt_auth_test_no_config_nonexistent",
        )
        .mock_info(Ok(mock_info_response(true)))
        .build();
    let code = cli::run(&args(&["secrt", "auth", "status"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    // Should show masked key info
    assert!(
        err.contains("sk2_test"),
        "should show masked key prefix: {}",
        err
    );
    // Should show "(from: env)" source
    assert!(
        err.contains("(from: env)"),
        "should show env source: {}",
        err
    );
}

// --- auth logout tests ---

#[test]
fn auth_logout_clears_credentials() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "auth", "logout"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("Credentials cleared"),
        "should show credentials cleared message: {}",
        err
    );
}
