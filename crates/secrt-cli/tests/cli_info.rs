mod helpers;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use helpers::{args, TestDepsBuilder};
use secrt_cli::cli;
use secrt_cli::client::{AmkWrapperResponse, EncMetaNoteV1, EncMetaV1, SecretMetadataItem};

fn sample_meta() -> SecretMetadataItem {
    SecretMetadataItem {
        id: "abc123def456".into(),
        share_url: "https://secrt.ca/s/abc123def456".into(),
        expires_at: "2099-12-31T23:59:59Z".into(),
        created_at: "2026-02-14T10:30:00Z".into(),
        ciphertext_size: 256,
        passphrase_protected: false,
        enc_meta: None,
    }
}

fn sample_api_key() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let root = [9u8; 32];
    format!("sk2_abcdef.{}", URL_SAFE_NO_PAD.encode(root))
}

#[test]
fn info_help_shows_usage() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "info", "--help"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("INFO"), "should show INFO heading");
    assert!(err.contains("info"), "should mention info command");
}

#[test]
fn help_info_shows_info_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "info"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("INFO"), "should show INFO heading");
}

#[test]
fn info_missing_id_exits_2() {
    let api_key = sample_api_key();
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .build();
    let code = cli::run(&args(&["secrt", "info"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(
        err.contains("secret ID or share URL is required"),
        "should report missing ID, got: {}",
        err
    );
}

#[test]
fn info_no_auth_exits_2() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "info", "abc123"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(
        err.contains("--api-key is required"),
        "should require auth, got: {}",
        err
    );
}

#[test]
fn info_displays_metadata() {
    let api_key = sample_api_key();
    let meta = sample_meta();
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_get_secret_metadata(Ok(meta.clone()))
        .build();
    let code = cli::run(&args(&["secrt", "info", "abc123def456"]), &mut deps);
    assert_eq!(code, 0);
    let out = stdout.to_string();
    assert!(out.contains("abc123def456"), "should show ID");
    assert!(
        out.contains("https://secrt.ca/s/abc123def456"),
        "should show share URL"
    );
    assert!(out.contains("256 B"), "should show size");
}

#[test]
fn info_json_outputs_metadata() {
    let api_key = sample_api_key();
    let meta = sample_meta();
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_get_secret_metadata(Ok(meta))
        .build();
    let code = cli::run(
        &args(&["secrt", "info", "--json", "abc123def456"]),
        &mut deps,
    );
    assert_eq!(code, 0);
    let out = stdout.to_string();
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(parsed["id"], "abc123def456");
    assert_eq!(parsed["ciphertext_size"], 256);
}

#[test]
fn info_passphrase_protected_shown() {
    let api_key = sample_api_key();
    let mut meta = sample_meta();
    meta.passphrase_protected = true;
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_get_secret_metadata(Ok(meta))
        .build();
    let code = cli::run(&args(&["secrt", "info", "abc123def456"]), &mut deps);
    assert_eq!(code, 0);
    let out = stdout.to_string();
    assert!(
        out.contains("Passphrase-protected"),
        "should indicate passphrase, got: {}",
        out
    );
}

#[test]
fn info_server_error_exits_1() {
    let api_key = sample_api_key();
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_get_secret_metadata(Err("server error (500): internal error".into()))
        .build();
    let code = cli::run(&args(&["secrt", "info", "abc123"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(
        err.contains("info failed"),
        "should show error, got: {}",
        err
    );
}

// ── enc_meta / AMK tests ────────────────────────────────────────────

/// Build a valid sk2_ API key, AMK wrapper response, and encrypted note
/// using real crypto so the info decrypt path works end-to-end.
fn make_amk_fixtures(secret_id: &str, note_text: &str) -> (String, AmkWrapperResponse, EncMetaV1) {
    use secrt_core::amk;
    use secrt_core::types::EnvelopeError;

    let amk_bytes = [0x11u8; 32];
    let root_key = [0x22u8; 32];
    let prefix = "abcdef";
    let api_key = format!("sk2_{}.{}", prefix, URL_SAFE_NO_PAD.encode(root_key));

    let wrap_key = amk::derive_amk_wrap_key(&root_key).unwrap();
    let user_id = "test-user-123";
    let aad = amk::build_wrap_aad(user_id, prefix, 1);

    let det_rng = |buf: &mut [u8]| -> Result<(), EnvelopeError> {
        buf.fill(0x42);
        Ok(())
    };
    let wrapped = amk::wrap_amk(&amk_bytes, &wrap_key, &aad, &det_rng).unwrap();

    let wrapper_resp = AmkWrapperResponse {
        user_id: user_id.into(),
        wrapped_amk: URL_SAFE_NO_PAD.encode(&wrapped.ct),
        nonce: URL_SAFE_NO_PAD.encode(&wrapped.nonce),
        version: 1,
    };

    let encrypted =
        amk::encrypt_note(&amk_bytes, secret_id, note_text.as_bytes(), &det_rng).unwrap();
    let enc_meta = EncMetaV1 {
        v: 1,
        note: EncMetaNoteV1 {
            ct: URL_SAFE_NO_PAD.encode(&encrypted.ct),
            nonce: URL_SAFE_NO_PAD.encode(&encrypted.nonce),
            salt: URL_SAFE_NO_PAD.encode(&encrypted.salt),
        },
    };

    (api_key, wrapper_resp, enc_meta)
}

#[test]
fn info_enc_meta_no_amk_shows_encrypted() {
    let api_key = sample_api_key();
    let mut meta = sample_meta();
    meta.enc_meta = Some(EncMetaV1 {
        v: 1,
        note: EncMetaNoteV1 {
            ct: "AAAA".into(),
            nonce: "AAAAAAAAAAAAAAAA".into(),
            salt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        },
    });

    // Mock get_amk_wrapper returns None — no wrapper available
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_get_secret_metadata(Ok(meta))
        .mock_get_amk_wrapper(Ok(None))
        .build();
    let code = cli::run(&args(&["secrt", "info", "abc123def456"]), &mut deps);
    assert_eq!(code, 0);
    let out = stdout.to_string();
    assert!(
        out.contains("(encrypted)"),
        "should show encrypted placeholder: {}",
        out
    );
    assert!(out.contains("Note:"), "should show Note label: {}", out);
}

#[test]
fn info_enc_meta_with_amk_shows_decrypted_note() {
    let (api_key, wrapper_resp, enc_meta) =
        make_amk_fixtures("abc123def456", "deployment password for staging");

    let mut meta = sample_meta();
    meta.enc_meta = Some(enc_meta);

    let (mut deps, stdout, _stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_get_secret_metadata(Ok(meta))
        .mock_get_amk_wrapper(Ok(Some(wrapper_resp)))
        .build();
    let code = cli::run(&args(&["secrt", "info", "abc123def456"]), &mut deps);
    assert_eq!(code, 0);
    let out = stdout.to_string();
    assert!(
        out.contains("deployment password for staging"),
        "should show decrypted note: {}",
        out
    );
    assert!(
        !out.contains("(encrypted)"),
        "should not show encrypted placeholder: {}",
        out
    );
}
