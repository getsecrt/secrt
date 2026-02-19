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
    assert_eq!(
        code,
        2,
        "share URL should be rejected; stderr: {}",
        stderr.to_string()
    );
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
        user_id: Some("test-user-123".into()),
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
