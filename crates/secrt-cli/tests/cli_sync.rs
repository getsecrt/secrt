mod helpers;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use helpers::{args, TestDepsBuilder};
use secrt_cli::cli;
use secrt_cli::client::{ClaimResponse, InfoLimits, InfoRate, InfoResponse, InfoTTL, InfoTier};

#[test]
fn sync_help_shows_usage() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "sync", "--help"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("SYNC"), "should show SYNC heading");
    assert!(err.contains("sync"), "should mention sync command");
}

#[test]
fn sync_missing_url_exits_2() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "sync"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(
        err.contains("sync URL is required"),
        "should report missing URL, got: {}",
        err
    );
}

#[test]
fn sync_invalid_url_exits_2() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "sync", "not-a-url"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(
        err.contains("invalid sync URL"),
        "should report invalid URL, got: {}",
        err
    );
}

#[test]
fn sync_no_auth_exits_1() {
    // Valid URL format but no API key configured
    let key_b64 = secrt_core::b64_encode(&[42u8; 32]);
    let url = format!("https://secrt.ca/sync/abc123#{}", key_b64);

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "sync", &url]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("authentication"),
        "should require auth, got: {}",
        err
    );
}

#[test]
fn help_sync_shows_sync_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "sync"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("SYNC"), "should show SYNC heading");
}

/// Regression: share URLs (/s/...) must be rejected by sync — claiming would
/// irreversibly consume the secret before AMK validation could ever succeed.
#[test]
fn sync_rejects_share_url_without_claiming() {
    let key_b64 = secrt_core::b64_encode(&[42u8; 32]);
    let share_url = format!("https://secrt.ca/s/abc123#{}", key_b64);

    // No mock_claim registered — if sync tried to claim, it would panic.
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "sync", &share_url]), &mut deps);
    assert_eq!(code, 2, "share URL should be rejected; stderr: {}", stderr);
    let err = stderr.to_string();
    assert!(
        err.contains("share URL, not a sync URL"),
        "should explain the URL type mismatch, got: {}",
        err
    );
}

fn mock_info_response() -> InfoResponse {
    InfoResponse {
        authenticated: true,
        user_id: Some("00000000-0000-0000-0000-0000000000ab".into()),
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
        latest_cli_version: None,
        latest_cli_version_checked_at: None,
        min_supported_cli_version: None,
        server_version: None,
    }
}

#[test]
fn sync_success_claims_and_imports_amk() {
    use secrt_core::types::EnvelopeError;
    use secrt_core::{CompressionPolicy, PayloadMeta, SealParams};

    // 1. Create a 32-byte AMK as the "secret" content
    let amk_bytes = [0x11u8; 32];

    // 2. Seal it into an envelope (simulates what the web app does when creating a sync secret)
    let seal_result = secrt_core::seal(SealParams {
        content: amk_bytes.to_vec(),
        metadata: PayloadMeta::binary(),
        passphrase: String::new(),
        rand_bytes: &|buf: &mut [u8]| -> Result<(), EnvelopeError> {
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), buf)
                .map_err(|_| EnvelopeError::RngError("rng".into()))
        },
        compression_policy: CompressionPolicy::default(),
    })
    .expect("seal should succeed");

    // 3. Build a sync URL: https://secrt.ca/sync/<id>#<url_key_b64>
    let url_key_b64 = URL_SAFE_NO_PAD.encode(&seal_result.url_key);
    let secret_id = "sync_test_id_001";
    let sync_url = format!("https://secrt.ca/sync/{}#{}", secret_id, url_key_b64);

    // 4. Build a valid sk2_ API key
    let root_key = [0x22u8; 32];
    let prefix = "abcdef";
    let api_key = format!("sk2_{}.{}", prefix, URL_SAFE_NO_PAD.encode(root_key));

    // 5. Mock claim to return the sealed envelope
    let claim_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2099-12-31T23:59:59Z".into(),
    };

    // 6. Run sync
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_claim(Ok(claim_resp))
        .mock_info(Ok(mock_info_response()))
        .mock_upsert_amk_wrapper(Ok(()))
        .build();
    let code = cli::run(&args(&["secrt", "sync", &sync_url]), &mut deps);
    let err = stderr.to_string();
    assert_eq!(code, 0, "sync should succeed; stderr: {}", err);
    assert!(
        err.contains("Notes key synced successfully"),
        "should show success message: {}",
        err
    );
}

#[test]
fn sync_claim_error_exits_1() {
    let root_key = [0x22u8; 32];
    let api_key = format!("sk2_abcdef.{}", URL_SAFE_NO_PAD.encode(root_key));
    let key_b64 = secrt_core::b64_encode(&[42u8; 32]);
    let url = format!("https://secrt.ca/sync/abc123#{}", key_b64);

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_claim(Err("server error (404): not found".into()))
        .build();
    let code = cli::run(&args(&["secrt", "sync", &url]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("sync failed"),
        "should show sync error: {}",
        err
    );
}

// ---------- Anti-rogue-instance defense ----------

/// Cross-instance sync URL: configured for secrt.ca, sync URL is
/// secrt.is. With no `--base-url` flag, the URL-derived host kicks in
/// AND the cross-instance hard-block fires. Refuses without ever
/// claiming (no mock_claim registered — claiming would panic the test).
#[test]
fn sync_cross_instance_blocks_without_claim() {
    let root_key = [0x22u8; 32];
    let api_key = format!("sk2_abcdef.{}", URL_SAFE_NO_PAD.encode(root_key));
    let key_b64 = secrt_core::b64_encode(&[42u8; 32]);
    let url = format!("https://secrt.is/sync/abc123#{}", key_b64);

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .build();
    let code = cli::run(&args(&["secrt", "sync", &url]), &mut deps);
    let err = stderr.to_string();
    assert_eq!(code, 2, "should hard-block; stderr: {err}");
    assert!(
        err.contains("this sync URL is for secrt.is"),
        "names derived host; stderr: {err}"
    );
    assert!(
        err.contains("you're configured for secrt.ca"),
        "names configured host; stderr: {err}"
    );
    assert!(
        err.contains("secrt auth login --base-url https://secrt.is"),
        "suggests re-auth path; stderr: {err}"
    );
}

/// Same cross-instance URL but the user passed `--base-url` matching
/// the URL host: explicit opt-in suppresses the block. Then the sync
/// proceeds and (with mocks) succeeds.
#[test]
fn sync_cross_instance_with_explicit_flag_proceeds() {
    use secrt_core::types::EnvelopeError;
    use secrt_core::{CompressionPolicy, PayloadMeta, SealParams};

    let amk_bytes = [0x11u8; 32];
    let seal_result = secrt_core::seal(SealParams {
        content: amk_bytes.to_vec(),
        metadata: PayloadMeta::binary(),
        passphrase: String::new(),
        rand_bytes: &|buf: &mut [u8]| -> Result<(), EnvelopeError> {
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), buf)
                .map_err(|_| EnvelopeError::RngError("rng".into()))
        },
        compression_policy: CompressionPolicy::default(),
    })
    .expect("seal should succeed");
    let url_key_b64 = URL_SAFE_NO_PAD.encode(&seal_result.url_key);
    let sync_url = format!("https://secrt.is/sync/sid001#{}", url_key_b64);

    let root_key = [0x22u8; 32];
    let api_key = format!("sk2_abcdef.{}", URL_SAFE_NO_PAD.encode(root_key));
    let claim_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2099-12-31T23:59:59Z".into(),
    };

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_claim(Ok(claim_resp))
        .mock_info(Ok(mock_info_response()))
        .mock_upsert_amk_wrapper(Ok(()))
        .build();
    let code = cli::run(
        &args(&["secrt", "sync", "--base-url", "https://secrt.is", &sync_url]),
        &mut deps,
    );
    let err = stderr.to_string();
    assert_eq!(code, 0, "explicit --base-url opts in; stderr: {err}");
    assert!(
        !err.contains("this sync URL is for"),
        "should NOT hard-block; stderr: {err}"
    );
}

/// Same-instance sync URL where the server returns
/// `authenticated: false`: the user opted in via --base-url to a server
/// their key isn't registered on. Diagnose with both URLs.
#[test]
fn sync_same_host_unauthenticated_diagnoses_unregistered_key() {
    use secrt_core::types::EnvelopeError;
    use secrt_core::{CompressionPolicy, PayloadMeta, SealParams};

    let amk_bytes = [0x11u8; 32];
    let seal_result = secrt_core::seal(SealParams {
        content: amk_bytes.to_vec(),
        metadata: PayloadMeta::binary(),
        passphrase: String::new(),
        rand_bytes: &|buf: &mut [u8]| -> Result<(), EnvelopeError> {
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), buf)
                .map_err(|_| EnvelopeError::RngError("rng".into()))
        },
        compression_policy: CompressionPolicy::default(),
    })
    .expect("seal should succeed");
    let url_key_b64 = URL_SAFE_NO_PAD.encode(&seal_result.url_key);
    let sync_url = format!("https://secrt.ca/sync/sid42#{}", url_key_b64);

    let root_key = [0x22u8; 32];
    let api_key = format!("sk2_abcdef.{}", URL_SAFE_NO_PAD.encode(root_key));
    let claim_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2099-12-31T23:59:59Z".into(),
    };
    let mut info = mock_info_response();
    info.authenticated = false;
    info.user_id = None;

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_claim(Ok(claim_resp))
        .mock_info(Ok(info))
        .build();
    let code = cli::run(&args(&["secrt", "sync", &sync_url]), &mut deps);
    let err = stderr.to_string();
    assert_eq!(
        code, 1,
        "should error after unauthenticated info; stderr: {err}"
    );
    assert!(
        err.contains("not registered on https://secrt.ca"),
        "should name unregistered server; stderr: {err}"
    );
    assert!(
        !err.contains("not be linked to a user"),
        "must NOT use the legacy unlinked-key message; stderr: {err}"
    );
}

/// Same-instance sync URL where the server returns
/// `authenticated: true, user_id: None`: the legacy unlinked-key path,
/// preserved verbatim from the pre-task-72 behavior.
#[test]
fn sync_same_host_authenticated_but_no_user_id_keeps_legacy_message() {
    use secrt_core::types::EnvelopeError;
    use secrt_core::{CompressionPolicy, PayloadMeta, SealParams};

    let amk_bytes = [0x11u8; 32];
    let seal_result = secrt_core::seal(SealParams {
        content: amk_bytes.to_vec(),
        metadata: PayloadMeta::binary(),
        passphrase: String::new(),
        rand_bytes: &|buf: &mut [u8]| -> Result<(), EnvelopeError> {
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), buf)
                .map_err(|_| EnvelopeError::RngError("rng".into()))
        },
        compression_policy: CompressionPolicy::default(),
    })
    .expect("seal should succeed");
    let url_key_b64 = URL_SAFE_NO_PAD.encode(&seal_result.url_key);
    let sync_url = format!("https://secrt.ca/sync/sid42#{}", url_key_b64);

    let root_key = [0x22u8; 32];
    let api_key = format!("sk2_abcdef.{}", URL_SAFE_NO_PAD.encode(root_key));
    let claim_resp = ClaimResponse {
        envelope: seal_result.envelope,
        expires_at: "2099-12-31T23:59:59Z".into(),
    };
    let mut info = mock_info_response();
    info.user_id = None;

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_claim(Ok(claim_resp))
        .mock_info(Ok(info))
        .build();
    let code = cli::run(&args(&["secrt", "sync", &sync_url]), &mut deps);
    let err = stderr.to_string();
    assert_eq!(code, 1, "stderr: {err}");
    assert!(
        err.contains("may not be linked to a user"),
        "should keep legacy message; stderr: {err}"
    );
}

/// Untrusted base_url (configured via env) on `send` emits the warning
/// to stderr but allows the command to proceed.
#[test]
fn send_off_list_base_url_warns_but_proceeds() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_BASE_URL", "https://evil.tld")
        .mock_create(Err("network error".into()))
        .build();
    let code = cli::run(
        &args(&["secrt", "send", "--text", "hello", "--ttl", "5m"]),
        &mut deps,
    );
    let err = stderr.to_string();
    assert!(
        err.contains("unofficial secrt instance"),
        "warning fires; stderr: {err}"
    );
    assert!(err.contains("evil.tld"), "names host; stderr: {err}");
    // Send proceeds and fails at the (mocked) network call.
    assert_ne!(code, 2, "should not block; stderr: {err}");
}

/// Untrusted base_url silenced by `trusted_servers` config.
#[test]
fn send_trusted_servers_silences_warning() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let cfg_dir = tmp.path().join("secrt");
    fs::create_dir_all(&cfg_dir).unwrap();
    fs::write(
        cfg_dir.join("config.toml"),
        "trusted_servers = [\"evil.tld\"]\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            cfg_dir.join("config.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("XDG_CONFIG_HOME", tmp.path().to_str().unwrap())
        .env("SECRET_BASE_URL", "https://evil.tld")
        .mock_create(Err("network error".into()))
        .build();
    let code = cli::run(
        &args(&["secrt", "send", "--text", "hi", "--ttl", "5m"]),
        &mut deps,
    );
    let err = stderr.to_string();
    assert!(
        !err.contains("unofficial secrt instance"),
        "warning silenced by trusted_servers; stderr: {err}"
    );
    let _ = code; // exit code is from mocked network failure, not relevant here.
}
