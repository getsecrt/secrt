mod helpers;

use std::fs;

use helpers::{args, TestDepsBuilder};
use secrt::cli;
use secrt::client::{InfoLimits, InfoRate, InfoResponse, InfoTTL, InfoTier};

#[test]
fn no_args_exit_2() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(err.contains("secrt"), "stderr should contain usage");
}

#[test]
fn version_flag() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "--version"]), &mut deps);
    assert_eq!(code, 0);
    let out = stdout.to_string();
    assert!(out.contains("secrt"), "stdout should contain version");
}

#[test]
fn version_flag_short() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "-v"]), &mut deps);
    assert_eq!(code, 0);
    assert!(stdout.to_string().contains("secrt"));
}

#[test]
fn version_command() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "version"]), &mut deps);
    assert_eq!(code, 0);
    assert!(stdout.to_string().contains("secrt"));
}

#[test]
fn help_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "--help"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("USAGE") || err.contains("secrt"));
}

#[test]
fn help_flag_short() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "-h"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().is_empty());
}

#[test]
fn help_command() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().is_empty());
}

#[test]
fn help_send() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "send"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("send") || err.contains("Encrypt"));
}

#[test]
fn help_get() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "get"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("get") || err.contains("Retrieve"));
}

#[test]
fn help_burn() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "burn"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("burn") || err.contains("Destroy"));
}

#[test]
fn help_unknown() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "bogus"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("unknown"));
}

#[test]
fn help_config() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("config") && err.contains("init"));
}

#[test]
fn config_help_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "config", "--help"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("config") && err.contains("init"));
}

#[test]
fn unknown_command() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "bogus"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("unknown"));
}

#[test]
fn config_shows_defaults() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("base_url"),
        "config should show base_url: {}",
        err
    );
    assert!(
        err.contains("https://secrt.ca"),
        "config should show default base_url: {}",
        err
    );
    assert!(
        err.contains("api_key"),
        "config should show api_key: {}",
        err
    );
    assert!(
        err.contains("show_input"),
        "config should show show_input: {}",
        err
    );
}

#[test]
fn config_shows_env_api_key_masked() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", "sk_live_abc123xyz789")
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("sk_live_"),
        "config should show masked api_key prefix: {}",
        err
    );
    assert!(
        !err.contains("xyz789"),
        "config should NOT show full api_key: {}",
        err
    );
    assert!(
        err.contains("env SECRET_API_KEY"),
        "config should show source: {}",
        err
    );
}

#[test]
fn config_shows_env_base_url() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_BASE_URL", "https://custom.example.com")
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("https://custom.example.com"),
        "config should show env base_url: {}",
        err
    );
    assert!(
        err.contains("env SECRET_BASE_URL"),
        "config should show source: {}",
        err
    );
}

#[test]
fn config_path_prints_path() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "config", "path"]), &mut deps);
    assert_eq!(code, 0);
    let out = stdout.to_string();
    assert!(
        out.contains("config.toml"),
        "config path should contain config.toml: {}",
        out
    );
}

#[test]
fn config_init_creates_file() {
    // Use a temp dir to avoid touching the real config
    let dir = std::env::temp_dir().join("secrt_config_init_test");
    let _ = std::fs::remove_dir_all(&dir);
    let config_path = dir.join("secrt").join("config.toml");

    // Point XDG_CONFIG_HOME to our temp dir
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config", "init"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("Created config file"),
        "should show created message: {}",
        stderr.to_string()
    );
    assert!(config_path.exists(), "config file should exist");

    let contents = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        contents.contains("# secrt configuration"),
        "should contain template header: {}",
        contents
    );
    assert!(
        contents.contains("# base_url"),
        "should contain base_url comment: {}",
        contents
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn config_init_refuses_overwrite() {
    let dir = std::env::temp_dir().join("secrt_config_init_exists");
    let secrt_dir = dir.join("secrt");
    let _ = std::fs::create_dir_all(&secrt_dir);
    let config_path = secrt_dir.join("config.toml");
    std::fs::write(&config_path, "existing content").unwrap();

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config", "init"]), &mut deps);
    assert_eq!(code, 1, "should fail: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("already exists"),
        "should show already exists: {}",
        stderr.to_string()
    );
    assert!(
        stderr.to_string().contains("--force"),
        "should mention --force: {}",
        stderr.to_string()
    );

    // Verify original content unchanged
    let contents = std::fs::read_to_string(&config_path).unwrap();
    assert_eq!(contents, "existing content");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn config_init_force_overwrites() {
    let dir = std::env::temp_dir().join("secrt_config_init_force");
    let secrt_dir = dir.join("secrt");
    let _ = std::fs::create_dir_all(&secrt_dir);
    let config_path = secrt_dir.join("config.toml");
    std::fs::write(&config_path, "old content").unwrap();

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config", "init", "--force"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("Created config file"),
        "should show created message: {}",
        stderr.to_string()
    );

    let contents = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        contents.contains("# secrt configuration"),
        "should contain template: {}",
        contents
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn config_unknown_subcommand() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "config", "bogus"]), &mut deps);
    assert_eq!(code, 2);
    assert!(
        stderr.to_string().contains("unknown config subcommand"),
        "should show error: {}",
        stderr.to_string()
    );
}

#[test]
fn completion_bash() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "completion", "bash"]), &mut deps);
    assert_eq!(code, 0);
    assert!(stdout.to_string().contains("_secrt"));
}

#[test]
fn completion_zsh() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "completion", "zsh"]), &mut deps);
    assert_eq!(code, 0);
    assert!(stdout.to_string().contains("compdef") || stdout.to_string().contains("_secrt"));
}

#[test]
fn completion_fish() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "completion", "fish"]), &mut deps);
    assert_eq!(code, 0);
    assert!(stdout.to_string().contains("complete"));
}

#[test]
fn completion_no_arg() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "completion"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("specify a shell"));
}

#[test]
fn completion_unknown() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "completion", "powershell"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("unsupported shell"));
}

// --- Config display tests for new fields ---

/// Helper to create a temp config dir with a config.toml containing the given TOML content.
fn setup_config(toml_content: &str) -> std::path::PathBuf {
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("secrt_dispatch_test_{}", id));
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

#[test]
fn config_shows_default_ttl() {
    let cfg_dir = setup_config("default_ttl = \"2h\"\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("default_ttl"),
        "config should show default_ttl: {}",
        err
    );
    assert!(
        err.contains("2h"),
        "config should show default_ttl value: {}",
        err
    );
    assert!(
        err.contains("config file"),
        "config should show source: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_shows_default_ttl_server_default() {
    let cfg_dir = setup_config("base_url = \"https://ok.com\"\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("default_ttl"),
        "config should show default_ttl field: {}",
        err
    );
    assert!(
        err.contains("server default"),
        "config should show server default: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_shows_decryption_passphrases_masked() {
    let cfg_dir = setup_config("decryption_passphrases = [\"secret1\", \"secret2\"]\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("decryption_passphrases"),
        "config should show field: {}",
        err
    );
    assert!(
        err.contains("2 entries"),
        "config should show entry count: {}",
        err
    );
    // Should NOT reveal actual values
    assert!(
        !err.contains("secret1"),
        "config should NOT reveal values: {}",
        err
    );
    assert!(
        !err.contains("secret2"),
        "config should NOT reveal values: {}",
        err
    );
    // Should contain bullet chars (masked)
    assert!(
        err.contains("\u{2022}"),
        "config should show masked values: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_shows_decryption_passphrases_not_set() {
    let cfg_dir = setup_config("base_url = \"https://ok.com\"\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("decryption_passphrases"),
        "config should show field: {}",
        err
    );
    // Should show (not set) for decryption_passphrases
    // The "(not set)" text appears for each unset field
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_init_template_has_all_fields() {
    let dir = std::env::temp_dir().join("secrt_config_template_check");
    let _ = fs::remove_dir_all(&dir);

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config", "init"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr.to_string());

    let config_path = dir.join("secrt").join("config.toml");
    let contents = fs::read_to_string(&config_path).unwrap();
    assert!(contents.contains("base_url"), "template missing base_url");
    assert!(contents.contains("api_key"), "template missing api_key");
    assert!(
        contents.contains("default_ttl"),
        "template missing default_ttl"
    );
    assert!(
        contents.contains("passphrase"),
        "template missing passphrase"
    );
    assert!(
        contents.contains("decryption_passphrases"),
        "template missing decryption_passphrases"
    );
    assert!(
        contents.contains("show_input"),
        "template missing show_input"
    );

    let _ = fs::remove_dir_all(&dir);
}

// --- config set-passphrase / delete-passphrase tests ---

#[test]
fn config_set_passphrase_empty() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().read_pass(&[""]).build();
    let code = cli::run(&args(&["secrt", "config", "set-passphrase"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("must not be empty"),
        "should reject empty passphrase: {}",
        err
    );
}

#[test]
fn config_set_passphrase_mismatch() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass(&["hunter2", "hunter3"])
        .build();
    let code = cli::run(&args(&["secrt", "config", "set-passphrase"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("do not match"),
        "should reject mismatched passphrases: {}",
        err
    );
}

#[test]
fn config_set_passphrase_read_error() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .read_pass_error("terminal not available")
        .build();
    let code = cli::run(&args(&["secrt", "config", "set-passphrase"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("failed to read passphrase"),
        "should show read error: {}",
        err
    );
}

#[test]
fn config_unknown_subcommand_lists_new_commands() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "config", "bogus"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(
        err.contains("set-passphrase"),
        "unknown subcommand error should mention set-passphrase: {}",
        err
    );
    assert!(
        err.contains("delete-passphrase"),
        "unknown subcommand error should mention delete-passphrase: {}",
        err
    );
}

#[test]
fn config_help_shows_passphrase_subcommands() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "config", "--help"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("set-passphrase"),
        "config help should list set-passphrase: {}",
        err
    );
    assert!(
        err.contains("delete-passphrase"),
        "config help should list delete-passphrase: {}",
        err
    );
}

// --- Old verb rejection tests (no aliases for removed commands) ---

#[test]
fn old_verb_create_rejected() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 2, "old 'create' command should be rejected");
    let err = stderr.to_string();
    assert!(
        err.contains("unknown command"),
        "should show unknown command error: {}",
        err
    );
}

#[test]
fn old_verb_claim_rejected() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&["secrt", "claim", "https://secrt.ca/s/abc123#key"]),
        &mut deps,
    );
    assert_eq!(code, 2, "old 'claim' command should be rejected");
    let err = stderr.to_string();
    assert!(
        err.contains("unknown command"),
        "should show unknown command error: {}",
        err
    );
}

#[test]
fn old_verb_gen_create_not_combined() {
    // `gen create` should NOT trigger combined mode (only `gen send` does).
    // `gen` ignores unknown positional args and just generates a password.
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "gen", "create"]), &mut deps);
    assert_eq!(code, 0, "gen ignores unknown positional args");
    // Should produce a password (gen output), not a share link
    let out = stdout.to_string();
    assert!(
        !out.contains("#"),
        "gen create should NOT create a secret: {}",
        out
    );
}

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

#[test]
fn config_show_with_server_info() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .mock_info(Ok(mock_info_response(false)))
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("SERVER LIMITS"),
        "should show SERVER LIMITS section: {}",
        err
    );
    assert!(
        err.contains("max_envelope"),
        "should show max_envelope: {}",
        err
    );
    assert!(
        err.contains("256 KB"),
        "should show 256 KB for public envelope: {}",
        err
    );
    assert!(
        err.contains("1 MB"),
        "should show 1 MB for authed envelope: {}",
        err
    );
    assert!(
        err.contains("claim_rate"),
        "should show claim_rate: {}",
        err
    );
}

#[test]
fn config_show_server_unreachable() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .mock_info(Err("connection refused".into()))
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("SERVER LIMITS"),
        "should still show SERVER LIMITS heading: {}",
        err
    );
    assert!(
        err.contains("server does not support info endpoint"),
        "should show fallback message: {}",
        err
    );
}

#[test]
fn config_show_server_default_ttl_from_info() {
    let cfg_dir = setup_config("base_url = \"https://ok.com\"\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .mock_info(Ok(mock_info_response(false)))
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    // In EFFECTIVE SETTINGS, default_ttl should show "1d" (86400s) from server info
    assert!(
        err.contains("1d"),
        "default_ttl should show 1d from server info: {}",
        err
    );
    assert!(
        err.contains("server default"),
        "default_ttl should indicate server default: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_show_authenticated_server_info() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", "sk_test.secret123")
        .mock_info(Ok(mock_info_response(true)))
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("authenticated"),
        "should show authenticated field: {}",
        err
    );
    assert!(err.contains("yes"), "authenticated should be yes: {}", err);
    // When authenticated, authed tier should be shown first
    // max_envelope line should start with 1 MB (authed) before 256 KB (public)
    let envelope_line = err
        .lines()
        .find(|l| l.contains("max_envelope"))
        .unwrap_or("");
    let mb_pos = envelope_line.find("1 MB").unwrap_or(usize::MAX);
    let kb_pos = envelope_line.find("256 KB").unwrap_or(usize::MAX);
    assert!(
        mb_pos < kb_pos,
        "authed (1 MB) should appear before public (256 KB): {}",
        envelope_line
    );
}

// --- Keychain-based config show tests ---

#[test]
fn config_show_passphrase_from_keychain() {
    let cfg_dir = setup_config("use_keychain = true\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .keychain_secret("passphrase", "kc-pass-secret")
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("keychain"),
        "passphrase source should be keychain: {}",
        err
    );
    assert!(
        !err.contains("kc-pass-secret"),
        "passphrase value should be masked: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_show_api_key_from_keychain() {
    let cfg_dir = setup_config("use_keychain = true\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .keychain_secret("api_key", "sk_kc_abc123secret")
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("keychain"),
        "api_key source should be keychain: {}",
        err
    );
    assert!(
        err.contains("sk_kc_ab"),
        "api_key should show masked prefix: {}",
        err
    );
    assert!(
        !err.contains("abc123secret"),
        "api_key should not show full value: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_show_use_keychain_from_config() {
    let cfg_dir = setup_config("use_keychain = true\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("use_keychain") && err.contains("true"),
        "should show use_keychain: true: {}",
        err
    );
    assert!(
        err.contains("config file"),
        "use_keychain source should be config file: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_show_decryption_passphrases_from_keychain_and_config() {
    let cfg_dir = setup_config("use_keychain = true\ndecryption_passphrases = [\"config-pass\"]\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .keychain_secret_list("decryption_passphrases", &["kc-pass1", "kc-pass2"])
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("keychain + config file"),
        "should show combined source: {}",
        err
    );
    assert!(
        err.contains("3 entries"),
        "should show merged count: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_show_passphrase_not_set() {
    let cfg_dir = setup_config("base_url = \"https://ok.com\"\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("passphrase") && err.contains("(not set)"),
        "passphrase should show (not set): {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_show_api_key_not_set() {
    let cfg_dir = setup_config("base_url = \"https://ok.com\"\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("api_key") && err.contains("(not set)"),
        "api_key should show (not set): {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_show_passphrase_from_config_file() {
    let cfg_dir = setup_config("passphrase = \"my-config-pass\"\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("config file"),
        "passphrase source should be config file: {}",
        err
    );
    assert!(
        !err.contains("my-config-pass"),
        "passphrase value should be masked: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_show_api_key_from_config_file() {
    let cfg_dir = setup_config("api_key = \"sk_test_fromcfg\"\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("config file"),
        "api_key source should be config file: {}",
        err
    );
    assert!(
        err.contains("sk_test_"),
        "api_key should show masked prefix: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_show_no_config_file() {
    // Point to a dir with no config file
    let dir = std::env::temp_dir().join(format!(
        "secrt_no_config_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::create_dir_all(&dir);
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("(not found)"),
        "should show (not found) for missing config: {}",
        err
    );
    assert!(
        err.contains("config init"),
        "should suggest config init: {}",
        err
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn config_show_show_input_from_config() {
    let cfg_dir = setup_config("show_input = true\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("show_input") && err.contains("true") && err.contains("config file"),
        "show_input should show true from config file: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

// --- Additional dispatch tests ---

#[test]
fn help_gen() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "gen"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("gen") || err.contains("Generate"));
}

#[test]
fn help_generate_alias() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "generate"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("gen") || err.contains("Generate"));
}

#[test]
fn config_path_help_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "config", "path", "--help"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("config"));
}

#[test]
fn config_set_passphrase_help_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&["secrt", "config", "set-passphrase", "--help"]),
        &mut deps,
    );
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("config"));
}

#[test]
fn config_delete_passphrase_help_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&["secrt", "config", "delete-passphrase", "--help"]),
        &mut deps,
    );
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("config"));
}

#[test]
fn config_init_help_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "config", "init", "--help"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("config"));
}

#[test]
fn config_show_server_info_success_path() {
    let cfg_dir = setup_config("api_key = \"sk_test_123\"\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .mock_info(Ok(mock_info_response(false)))
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("SERVER LIMITS"),
        "should show SERVER LIMITS: {}",
        err
    );
    assert!(err.contains("max_ttl"), "should show max_ttl: {}", err);
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_show_decryption_passphrases_from_keychain_only() {
    let cfg_dir = setup_config("use_keychain = true\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .keychain_secret_list("decryption_passphrases", &["kc-only-pass"])
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("1 entries") && err.contains("keychain"),
        "should show keychain source: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

// --- Keychain-based resolve_globals tests ---

#[test]
fn config_show_api_key_from_keychain_fallback_to_config() {
    // When keychain has no api_key, should fall back to config file
    let cfg_dir = setup_config("use_keychain = true\napi_key = \"sk_cfg_fallback\"\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("config file"),
        "api_key source should fall back to config file: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}

#[test]
fn config_show_passphrase_keychain_fallback_to_config() {
    // When keychain has no passphrase, fall back to config file
    let cfg_dir = setup_config("use_keychain = true\npassphrase = \"cfg-pass\"\n");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", cfg_dir.to_str().unwrap())
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("config file"),
        "passphrase should fall back to config file: {}",
        err
    );
    let _ = fs::remove_dir_all(&cfg_dir);
}
