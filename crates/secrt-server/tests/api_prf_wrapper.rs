//! Validation tests for the PRF AMK wrapper endpoint
//! `/api/v1/auth/passkeys/{credential_id}/prf-wrapper`.
//!
//! No DB required — runs against the test MemStore. Exercises the byte-length
//! validation rules from `spec/v1/api.md` §"AMK wrapping (normative crypto)"
//! and the auth/credential-binding rules from the Phase C plan.
//!
//! Integration tests against real Postgres live in `postgres_integration.rs`
//! (DB-gated).

mod helpers;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use helpers::webauthn::TestPasskey;
use helpers::{test_app_with_store, test_config, MemStore};
use serde_json::{json, Value};
use tower::ServiceExt;

fn prf_test_config() -> secrt_server::config::Config {
    let mut cfg = test_config();
    cfg.encrypted_notes_enabled = true;
    cfg
}

#[allow(dead_code)]
async fn response_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    serde_json::from_slice(&bytes).expect("json")
}

fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Standard 48-byte ciphertext (32 AMK + 16 GCM tag), base64url.
fn valid_wrapped_amk() -> String {
    b64u(&[0xABu8; 48])
}
fn valid_nonce() -> String {
    b64u(&[0xCDu8; 12])
}
fn valid_amk_commit() -> String {
    b64u(&[0xEFu8; 32])
}

/// Register a passkey with PRF metadata. Returns the TestPasskey (so the
/// caller knows the credential_id_b64u and can log back in), the session
/// token, and the optional `prf_cred_salt` from the response.
async fn register_with_prf(
    app: &axum::Router,
    display_name: &str,
    prf_supported: bool,
) -> (TestPasskey, String, Option<String>) {
    let pk = TestPasskey::generate();
    let prf = if prf_supported {
        Some(json!({ "supported": true, "at_create": true }))
    } else {
        None
    };
    let (status, body) = pk.register_finish(app, display_name, prf).await;
    assert_eq!(status, StatusCode::OK, "register_finish: {body:?}");
    let session_token = body["session_token"]
        .as_str()
        .expect("session_token")
        .to_string();
    let prf_cred_salt = body
        .get("prf_cred_salt")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    (pk, session_token, prf_cred_salt)
}

fn put_prf_wrapper_req(credential_id: &str, session_token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/auth/passkeys/{credential_id}/prf-wrapper"))
        .header("authorization", format!("Bearer {session_token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

// ── register-finish PRF metadata path ───────────────────────────────

#[tokio::test]
async fn register_finish_returns_cred_salt_when_prf_supported() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, prf_test_config());

    let (cred_prf_1_pk, _session, prf_cred_salt) = register_with_prf(&app, "Alice", true).await;
    let _cred_prf_1_cid = cred_prf_1_pk.credential_id_b64u();
    let salt = prf_cred_salt.expect("server should return prf_cred_salt");
    let decoded = URL_SAFE_NO_PAD
        .decode(salt.as_bytes())
        .expect("base64url decodable");
    assert_eq!(decoded.len(), 32, "cred_salt must be 32 bytes");
}

#[tokio::test]
async fn register_finish_omits_cred_salt_when_prf_not_supported() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, prf_test_config());

    let (cred_prf_2_pk, _session, prf_cred_salt) = register_with_prf(&app, "Bob", false).await;
    let _cred_prf_2_cid = cred_prf_2_pk.credential_id_b64u();
    assert!(
        prf_cred_salt.is_none(),
        "cred_salt should not be present when PRF unsupported"
    );
}

#[tokio::test]
async fn register_finish_omits_cred_salt_when_prf_field_absent() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, prf_test_config());

    // Backward compat: an old client that doesn't send the prf field at all
    // must still register successfully with no PRF salt.
    let pk = TestPasskey::generate();
    let (status, body) = pk.register_finish(&app, "Cara", None).await;
    assert_eq!(status, StatusCode::OK, "register_finish: {body:?}");
    assert!(body.get("prf_cred_salt").is_none());
}

// ── PUT wrapper validation ──────────────────────────────────────────

#[tokio::test]
async fn put_prf_wrapper_unauthenticated_returns_401() {
    let app = test_app_with_store(Arc::new(MemStore::default()), prf_test_config());

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/auth/passkeys/some-cred/prf-wrapper")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "wrapped_amk": valid_wrapped_amk(),
                "nonce": valid_nonce(),
                "amk_commit": valid_amk_commit(),
                "version": 1,
            })
            .to_string(),
        ))
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn put_prf_wrapper_rejects_short_ciphertext() {
    let app = test_app_with_store(Arc::new(MemStore::default()), prf_test_config());
    let (cred_short_ct_pk, session_token, _) = register_with_prf(&app, "Alice", true).await;
    let cred_short_ct_cid = cred_short_ct_pk.credential_id_b64u();

    let req = put_prf_wrapper_req(
        &cred_short_ct_cid,
        &session_token,
        json!({
            "wrapped_amk": b64u(&[0xABu8; 47]), // 1 byte short
            "nonce": valid_nonce(),
            "amk_commit": valid_amk_commit(),
            "version": 1,
        }),
    );
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_prf_wrapper_rejects_long_ciphertext() {
    let app = test_app_with_store(Arc::new(MemStore::default()), prf_test_config());
    let (cred_long_ct_pk, session_token, _) = register_with_prf(&app, "Alice", true).await;
    let cred_long_ct_cid = cred_long_ct_pk.credential_id_b64u();

    let req = put_prf_wrapper_req(
        &cred_long_ct_cid,
        &session_token,
        json!({
            "wrapped_amk": b64u(&[0xABu8; 49]),
            "nonce": valid_nonce(),
            "amk_commit": valid_amk_commit(),
            "version": 1,
        }),
    );
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_prf_wrapper_rejects_wrong_nonce_length() {
    let app = test_app_with_store(Arc::new(MemStore::default()), prf_test_config());
    let (cred_bad_nonce_pk, session_token, _) = register_with_prf(&app, "Alice", true).await;
    let cred_bad_nonce_cid = cred_bad_nonce_pk.credential_id_b64u();

    let req = put_prf_wrapper_req(
        &cred_bad_nonce_cid,
        &session_token,
        json!({
            "wrapped_amk": valid_wrapped_amk(),
            "nonce": b64u(&[0xCDu8; 11]),
            "amk_commit": valid_amk_commit(),
            "version": 1,
        }),
    );
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_prf_wrapper_rejects_wrong_commit_length() {
    let app = test_app_with_store(Arc::new(MemStore::default()), prf_test_config());
    let (cred_bad_commit_pk, session_token, _) = register_with_prf(&app, "Alice", true).await;
    let cred_bad_commit_cid = cred_bad_commit_pk.credential_id_b64u();

    let req = put_prf_wrapper_req(
        &cred_bad_commit_cid,
        &session_token,
        json!({
            "wrapped_amk": valid_wrapped_amk(),
            "nonce": valid_nonce(),
            "amk_commit": b64u(&[0xEFu8; 31]),
            "version": 1,
        }),
    );
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_prf_wrapper_rejects_unsupported_version() {
    let app = test_app_with_store(Arc::new(MemStore::default()), prf_test_config());
    let (cred_bad_ver_pk, session_token, _) = register_with_prf(&app, "Alice", true).await;
    let cred_bad_ver_cid = cred_bad_ver_pk.credential_id_b64u();

    let req = put_prf_wrapper_req(
        &cred_bad_ver_cid,
        &session_token,
        json!({
            "wrapped_amk": valid_wrapped_amk(),
            "nonce": valid_nonce(),
            "amk_commit": valid_amk_commit(),
            "version": 2,
        }),
    );
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_prf_wrapper_rejects_malformed_base64url() {
    let app = test_app_with_store(Arc::new(MemStore::default()), prf_test_config());
    let (cred_bad_b64_pk, session_token, _) = register_with_prf(&app, "Alice", true).await;
    let cred_bad_b64_cid = cred_bad_b64_pk.credential_id_b64u();

    let req = put_prf_wrapper_req(
        &cred_bad_b64_cid,
        &session_token,
        json!({
            "wrapped_amk": "not!valid!base64url!",
            "nonce": valid_nonce(),
            "amk_commit": valid_amk_commit(),
            "version": 1,
        }),
    );
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_prf_wrapper_rejects_unknown_credential() {
    let app = test_app_with_store(Arc::new(MemStore::default()), prf_test_config());
    let (cred_known_pk, session_token, _) = register_with_prf(&app, "Alice", true).await;
    let _cred_known_cid = cred_known_pk.credential_id_b64u();

    // PUT against a credential that doesn't exist
    let req = put_prf_wrapper_req(
        "cred-does-not-exist",
        &session_token,
        json!({
            "wrapped_amk": valid_wrapped_amk(),
            "nonce": valid_nonce(),
            "amk_commit": valid_amk_commit(),
            "version": 1,
        }),
    );
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn put_prf_wrapper_rejects_credential_not_owned_by_session() {
    let app = test_app_with_store(Arc::new(MemStore::default()), prf_test_config());
    // Alice registers a credential
    let (cred_alice_pk, alice_session, _) = register_with_prf(&app, "Alice", true).await;
    let _cred_alice_cid = cred_alice_pk.credential_id_b64u();
    // Bob registers their own
    let (cred_bob_pk, _bob_session, _) = register_with_prf(&app, "Bob", true).await;
    let cred_bob_cid = cred_bob_pk.credential_id_b64u();

    // Alice tries to PUT a wrapper for Bob's credential
    let req = put_prf_wrapper_req(
        &cred_bob_cid,
        &alice_session,
        json!({
            "wrapped_amk": valid_wrapped_amk(),
            "nonce": valid_nonce(),
            "amk_commit": valid_amk_commit(),
            "version": 1,
        }),
    );
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn put_prf_wrapper_rejects_non_prf_credential() {
    let app = test_app_with_store(Arc::new(MemStore::default()), prf_test_config());
    // Register without PRF — server won't generate cred_salt or set prf_supported
    let (cred_no_prf_pk, session_token, _prf_cred_salt) =
        register_with_prf(&app, "Alice", false).await;
    let cred_no_prf_cid = cred_no_prf_pk.credential_id_b64u();

    let req = put_prf_wrapper_req(
        &cred_no_prf_cid,
        &session_token,
        json!({
            "wrapped_amk": valid_wrapped_amk(),
            "nonce": valid_nonce(),
            "amk_commit": valid_amk_commit(),
            "version": 1,
        }),
    );
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_prf_wrapper_rejects_unknown_field() {
    let app = test_app_with_store(Arc::new(MemStore::default()), prf_test_config());
    let (cred_extra_pk, session_token, _) = register_with_prf(&app, "Alice", true).await;
    let cred_extra_cid = cred_extra_pk.credential_id_b64u();

    let req = put_prf_wrapper_req(
        &cred_extra_cid,
        &session_token,
        json!({
            "wrapped_amk": valid_wrapped_amk(),
            "nonce": valid_nonce(),
            "amk_commit": valid_amk_commit(),
            "version": 1,
            "evil_field": "x",
        }),
    );
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── DELETE wrapper ──────────────────────────────────────────────────

#[tokio::test]
async fn delete_prf_wrapper_unauthenticated_returns_401() {
    let app = test_app_with_store(Arc::new(MemStore::default()), prf_test_config());
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/auth/passkeys/cred/prf-wrapper")
        .body(Body::empty())
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_prf_wrapper_returns_204_when_no_row() {
    let app = test_app_with_store(Arc::new(MemStore::default()), prf_test_config());
    let (cred_del_1_pk, session_token, _) = register_with_prf(&app, "Alice", true).await;
    let _cred_del_1_cid = cred_del_1_pk.credential_id_b64u();
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/auth/passkeys/cred-del-1/prf-wrapper")
        .header("authorization", format!("Bearer {session_token}"))
        .body(Body::empty())
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    // Idempotent: deleting a wrapper that doesn't exist is still OK.
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

// ── Method enforcement ──────────────────────────────────────────────

#[tokio::test]
async fn prf_wrapper_endpoint_rejects_get() {
    let app = test_app_with_store(Arc::new(MemStore::default()), prf_test_config());
    let (cred_get_pk, session_token, _) = register_with_prf(&app, "Alice", true).await;
    let _cred_get_cid = cred_get_pk.credential_id_b64u();
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/passkeys/cred-get/prf-wrapper")
        .header("authorization", format!("Bearer {session_token}"))
        .body(Body::empty())
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

// ── Roundtrip: PUT + login-finish returns wrapper inline ────────────

#[tokio::test]
async fn put_then_login_returns_wrapper_inline() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), prf_test_config());

    let (mut cred_rt_pk, session_token, prf_cred_salt) =
        register_with_prf(&app, "Alice", true).await;
    let cred_rt_cid = cred_rt_pk.credential_id_b64u();
    assert!(prf_cred_salt.is_some(), "register must return cred_salt");

    let put_req = put_prf_wrapper_req(
        &cred_rt_cid,
        &session_token,
        json!({
            "wrapped_amk": valid_wrapped_amk(),
            "nonce": valid_nonce(),
            "amk_commit": valid_amk_commit(),
            "version": 1,
        }),
    );
    let put_resp = app.clone().oneshot(put_req).await.expect("response");
    assert_eq!(put_resp.status(), StatusCode::OK);

    // Run a real login ceremony — register/finish issued the keypair we
    // just stored, so login_finish here exercises the full WebAuthn
    // verification path against that key.
    let json = cred_rt_pk.login(&app).await;

    let wrapper = json
        .get("prf_wrapper")
        .and_then(|v| v.as_object())
        .expect("login-finish must return prf_wrapper inline");
    assert_eq!(wrapper["version"].as_i64(), Some(1));
    assert_eq!(
        wrapper["wrapped_amk"].as_str().expect("wrapped_amk"),
        valid_wrapped_amk()
    );
    assert_eq!(wrapper["nonce"].as_str().expect("nonce"), valid_nonce());
    assert_eq!(
        wrapper["amk_commit"].as_str().expect("amk_commit"),
        valid_amk_commit()
    );
    let cred_salt_b64u = wrapper["cred_salt"].as_str().expect("cred_salt");
    assert_eq!(cred_salt_b64u, prf_cred_salt.unwrap());
}

#[tokio::test]
async fn login_without_wrapper_omits_prf_wrapper_field() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, prf_test_config());

    let (mut cred_no_wrap_pk, _session, _) = register_with_prf(&app, "Alice", true).await;
    let _cred_no_wrap_cid = cred_no_wrap_pk.credential_id_b64u();

    let json = cred_no_wrap_pk.login(&app).await;
    assert!(
        json.get("prf_wrapper").is_none(),
        "no wrapper PUT yet, response should omit prf_wrapper"
    );
}

// ── §4.5 upgrade path: pre-PRF credential gets retrofitted on next login ─

/// Helper: drive the full login start+finish ceremony for an existing
/// TestPasskey with an optional `prf` metadata block. Returns the parsed
/// login-finish JSON body.
async fn login_with_prf(
    app: &axum::Router,
    pk: &mut TestPasskey,
    prf_payload: Option<Value>,
) -> Value {
    let (status, body) = pk.login_finish(app, prf_payload).await;
    assert_eq!(status, StatusCode::OK, "login_finish: {body:?}");
    body
}

#[tokio::test]
async fn login_finish_upgrades_pre_prf_credential() {
    // Pre-PRF passkey: registered without the `prf` field, so its row has
    // `cred_salt = NULL` and `prf_supported = false`. On a later login from
    // a PRF-capable browser, the server should stamp the row with a fresh
    // salt and return it as `prf_cred_salt` so the client can wrap+PUT.
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), prf_test_config());

    // Register without PRF (mimics a 0.16.7-or-earlier registration).
    let (mut cred_upgrade_pk, _session, prf_cred_salt) =
        register_with_prf(&app, "Eve", false).await;
    let cred_upgrade_cid = cred_upgrade_pk.credential_id_b64u();
    assert!(prf_cred_salt.is_none(), "precondition: row is pre-PRF");

    // Pre-state: row has no salt, prf_supported=false.
    {
        use secrt_server::storage::AuthStore;
        let pk = store
            .get_passkey_by_credential_id(&cred_upgrade_cid)
            .await
            .expect("passkey");
        assert!(pk.cred_salt.is_none());
        assert!(!pk.prf_supported);
    }

    // Login reporting PRF support — should trigger the upgrade.
    let json = login_with_prf(
        &app,
        &mut cred_upgrade_pk,
        Some(json!({ "supported": true, "at_create": false })),
    )
    .await;

    let salt_b64u = json
        .get("prf_cred_salt")
        .and_then(|v| v.as_str())
        .expect("upgrade should return prf_cred_salt");
    let salt = URL_SAFE_NO_PAD
        .decode(salt_b64u.as_bytes())
        .expect("base64url decodable");
    assert_eq!(salt.len(), 32, "cred_salt must be 32 bytes");
    assert!(
        json.get("prf_wrapper").is_none(),
        "no wrapper exists yet on upgrade — client wraps+PUTs"
    );

    // Post-state: row has the salt and prf_supported=true.
    {
        use secrt_server::storage::AuthStore;
        let pk = store
            .get_passkey_by_credential_id(&cred_upgrade_cid)
            .await
            .expect("passkey");
        assert_eq!(
            pk.cred_salt.as_deref(),
            Some(salt.as_slice()),
            "row salt must match what server returned"
        );
        assert!(pk.prf_supported);
        assert!(
            !pk.prf_at_create,
            "upgrade is on assertion, not create — at_create=false"
        );
    }
}

#[tokio::test]
async fn login_finish_returns_existing_salt_when_capable_but_no_wrapper() {
    // Already-PRF-capable row with no wrapper (e.g., user revoked their
    // wrapper). Login should return the *existing* cred_salt so the client
    // can rewrap, without overwriting the row.
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), prf_test_config());

    let (mut cred_rewrap_pk, _session, original_salt) =
        register_with_prf(&app, "Frank", true).await;
    let _cred_rewrap_cid = cred_rewrap_pk.credential_id_b64u();
    let original_salt = original_salt.expect("registered with PRF");

    let json = login_with_prf(
        &app,
        &mut cred_rewrap_pk,
        Some(json!({ "supported": true, "at_create": false })),
    )
    .await;

    assert_eq!(
        json.get("prf_cred_salt").and_then(|v| v.as_str()),
        Some(original_salt.as_str()),
        "must return the existing salt verbatim, not a new one"
    );
    assert!(json.get("prf_wrapper").is_none());
}

#[tokio::test]
async fn login_finish_skips_upgrade_when_assertion_lacks_prf() {
    // Pre-PRF row, login reports PRF unsupported. No upgrade.
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), prf_test_config());

    let (mut cred_no_prf_pk, _session, _) = register_with_prf(&app, "Grace", false).await;
    let cred_no_prf_cid = cred_no_prf_pk.credential_id_b64u();

    let json = login_with_prf(
        &app,
        &mut cred_no_prf_pk,
        Some(json!({ "supported": false, "at_create": false })),
    )
    .await;

    assert!(json.get("prf_cred_salt").is_none());
    assert!(json.get("prf_wrapper").is_none());

    // Row remains pre-PRF.
    use secrt_server::storage::AuthStore;
    let pk = store
        .get_passkey_by_credential_id(&cred_no_prf_cid)
        .await
        .expect("passkey");
    assert!(pk.cred_salt.is_none());
    assert!(!pk.prf_supported);
}

#[tokio::test]
async fn login_finish_omits_cred_salt_when_wrapper_already_inline() {
    // PUT a wrapper, then login. Response carries `prf_wrapper` (with its
    // own cred_salt); standalone `prf_cred_salt` is omitted to avoid
    // duplicating the same value in two fields.
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), prf_test_config());

    let (mut cred_w_pk, session_token, _) = register_with_prf(&app, "Helen", true).await;
    let cred_w_cid = cred_w_pk.credential_id_b64u();
    let put_req = put_prf_wrapper_req(
        &cred_w_cid,
        &session_token,
        json!({
            "wrapped_amk": valid_wrapped_amk(),
            "nonce": valid_nonce(),
            "amk_commit": valid_amk_commit(),
            "version": 1,
        }),
    );
    let put_resp = app.clone().oneshot(put_req).await.expect("response");
    assert_eq!(put_resp.status(), StatusCode::OK);

    let json = login_with_prf(
        &app,
        &mut cred_w_pk,
        Some(json!({ "supported": true, "at_create": false })),
    )
    .await;
    assert!(json.get("prf_wrapper").is_some());
    assert!(
        json.get("prf_cred_salt").is_none(),
        "wrapper carries cred_salt; standalone field is redundant"
    );
}

// ── add-passkey-finish PRF wiring (mirrors register-finish) ─────────

#[tokio::test]
async fn add_passkey_finish_returns_cred_salt_when_prf_supported() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), prf_test_config());

    // Establish a session via register so we can call add-finish.
    let (_cred_original_pk, session_token, _) = register_with_prf(&app, "Iris", false).await;

    // add-finish: drive the full ceremony with a fresh keypair.
    let add_pk = TestPasskey::generate();
    let add_cid = add_pk.credential_id_b64u();
    let (status, body) = add_pk
        .add_finish(
            &app,
            &session_token,
            Some(json!({ "supported": true, "at_create": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "add_finish: {body:?}");

    let salt_b64u = body
        .get("prf_cred_salt")
        .and_then(|v| v.as_str())
        .expect("add-finish must return prf_cred_salt when PRF supported");
    let salt = URL_SAFE_NO_PAD
        .decode(salt_b64u.as_bytes())
        .expect("base64url decodable");
    assert_eq!(salt.len(), 32);

    use secrt_server::storage::AuthStore;
    let pk = store
        .get_passkey_by_credential_id(&add_cid)
        .await
        .expect("passkey");
    assert_eq!(pk.cred_salt.as_deref(), Some(salt.as_slice()));
    assert!(pk.prf_supported);
    assert!(pk.prf_at_create);
}
