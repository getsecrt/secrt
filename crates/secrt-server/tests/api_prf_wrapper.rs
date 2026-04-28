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
use helpers::{test_app_with_store, test_config, MemStore};
use serde_json::{json, Value};
use tower::ServiceExt;

fn prf_test_config() -> secrt_server::config::Config {
    let mut cfg = test_config();
    cfg.encrypted_notes_enabled = true;
    cfg
}

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

/// Register a passkey with PRF metadata. Returns (session_token, prf_cred_salt_b64u).
async fn register_with_prf(
    app: &axum::Router,
    display_name: &str,
    credential_id: &str,
    prf_supported: bool,
) -> (String, Option<String>) {
    let start_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/register/start")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "display_name": display_name }).to_string(),
        ))
        .expect("request");
    let start_resp = app.clone().oneshot(start_req).await.expect("response");
    assert_eq!(start_resp.status(), StatusCode::OK);
    let challenge_id = response_json(start_resp).await["challenge_id"]
        .as_str()
        .expect("challenge_id")
        .to_string();

    let mut body = json!({
        "challenge_id": challenge_id,
        "credential_id": credential_id,
        "public_key": "pk-test",
    });
    if prf_supported {
        body["prf"] = json!({ "supported": true, "at_create": true });
    }
    let finish_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/register/finish")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let finish_resp = app.clone().oneshot(finish_req).await.expect("response");
    assert_eq!(finish_resp.status(), StatusCode::OK);
    let json = response_json(finish_resp).await;
    let session_token = json["session_token"]
        .as_str()
        .expect("session_token")
        .to_string();
    let prf_cred_salt = json
        .get("prf_cred_salt")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    (session_token, prf_cred_salt)
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

    let (_session, prf_cred_salt) = register_with_prf(&app, "Alice", "cred-prf-1", true).await;
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

    let (_session, prf_cred_salt) = register_with_prf(&app, "Bob", "cred-prf-2", false).await;
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
    let start_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/register/start")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "display_name": "Cara" }).to_string()))
        .expect("request");
    let challenge_id = response_json(app.clone().oneshot(start_req).await.expect("response")).await
        ["challenge_id"]
        .as_str()
        .expect("challenge_id")
        .to_string();
    let finish_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/register/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": challenge_id,
                "credential_id": "cred-prf-3",
                "public_key": "pk-test",
            })
            .to_string(),
        ))
        .expect("request");
    let resp = app.clone().oneshot(finish_req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let json = response_json(resp).await;
    assert!(json.get("prf_cred_salt").is_none());
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
    let (session_token, _) = register_with_prf(&app, "Alice", "cred-short-ct", true).await;

    let req = put_prf_wrapper_req(
        "cred-short-ct",
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
    let (session_token, _) = register_with_prf(&app, "Alice", "cred-long-ct", true).await;

    let req = put_prf_wrapper_req(
        "cred-long-ct",
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
    let (session_token, _) = register_with_prf(&app, "Alice", "cred-bad-nonce", true).await;

    let req = put_prf_wrapper_req(
        "cred-bad-nonce",
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
    let (session_token, _) = register_with_prf(&app, "Alice", "cred-bad-commit", true).await;

    let req = put_prf_wrapper_req(
        "cred-bad-commit",
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
    let (session_token, _) = register_with_prf(&app, "Alice", "cred-bad-ver", true).await;

    let req = put_prf_wrapper_req(
        "cred-bad-ver",
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
    let (session_token, _) = register_with_prf(&app, "Alice", "cred-bad-b64", true).await;

    let req = put_prf_wrapper_req(
        "cred-bad-b64",
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
    let (session_token, _) = register_with_prf(&app, "Alice", "cred-known", true).await;

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
    let (alice_session, _) = register_with_prf(&app, "Alice", "cred-alice", true).await;
    // Bob registers their own
    let (_bob_session, _) = register_with_prf(&app, "Bob", "cred-bob", true).await;

    // Alice tries to PUT a wrapper for Bob's credential
    let req = put_prf_wrapper_req(
        "cred-bob",
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
    let (session_token, _prf_cred_salt) =
        register_with_prf(&app, "Alice", "cred-no-prf", false).await;

    let req = put_prf_wrapper_req(
        "cred-no-prf",
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
    let (session_token, _) = register_with_prf(&app, "Alice", "cred-extra", true).await;

    let req = put_prf_wrapper_req(
        "cred-extra",
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
    let (session_token, _) = register_with_prf(&app, "Alice", "cred-del-1", true).await;
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
    let (session_token, _) = register_with_prf(&app, "Alice", "cred-get", true).await;
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

    let (session_token, prf_cred_salt) = register_with_prf(&app, "Alice", "cred-rt", true).await;
    assert!(prf_cred_salt.is_some(), "register must return cred_salt");

    let put_req = put_prf_wrapper_req(
        "cred-rt",
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

    // Now run login (no real WebAuthn signature; tests the bearer flow as-is,
    // matching today's spec/v1/server.md §6 which documents this is the case).
    let login_start = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/login/start")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "credential_id": "cred-rt" }).to_string(),
        ))
        .expect("request");
    let start_resp = app.clone().oneshot(login_start).await.expect("response");
    assert_eq!(start_resp.status(), StatusCode::OK);
    let challenge_id = response_json(start_resp).await["challenge_id"]
        .as_str()
        .expect("challenge_id")
        .to_string();

    let login_finish = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/login/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": challenge_id,
                "credential_id": "cred-rt",
            })
            .to_string(),
        ))
        .expect("request");
    let finish_resp = app.clone().oneshot(login_finish).await.expect("response");
    assert_eq!(finish_resp.status(), StatusCode::OK);
    let json = response_json(finish_resp).await;

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

    let (_session, _) = register_with_prf(&app, "Alice", "cred-no-wrap", true).await;

    let login_start = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/login/start")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "credential_id": "cred-no-wrap" }).to_string(),
        ))
        .expect("request");
    let start_resp = app.clone().oneshot(login_start).await.expect("response");
    let challenge_id = response_json(start_resp).await["challenge_id"]
        .as_str()
        .expect("challenge_id")
        .to_string();

    let login_finish = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/login/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": challenge_id,
                "credential_id": "cred-no-wrap",
            })
            .to_string(),
        ))
        .expect("request");
    let finish_resp = app.clone().oneshot(login_finish).await.expect("response");
    let json = response_json(finish_resp).await;
    assert!(
        json.get("prf_wrapper").is_none(),
        "no wrapper PUT yet, response should omit prf_wrapper"
    );
}

// ── §4.5 upgrade path: pre-PRF credential gets retrofitted on next login ─

/// Helper: drive the login start+finish handshake with an optional `prf`
/// metadata block. Returns the parsed login-finish JSON body.
async fn login_with_prf(
    app: &axum::Router,
    credential_id: &str,
    prf_payload: Option<Value>,
) -> Value {
    let login_start = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/login/start")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "credential_id": credential_id }).to_string(),
        ))
        .expect("request");
    let start_resp = app.clone().oneshot(login_start).await.expect("response");
    assert_eq!(start_resp.status(), StatusCode::OK);
    let challenge_id = response_json(start_resp).await["challenge_id"]
        .as_str()
        .expect("challenge_id")
        .to_string();

    let mut body = json!({
        "challenge_id": challenge_id,
        "credential_id": credential_id,
    });
    if let Some(prf) = prf_payload {
        body["prf"] = prf;
    }
    let finish_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/login/finish")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let finish_resp = app.clone().oneshot(finish_req).await.expect("response");
    assert_eq!(finish_resp.status(), StatusCode::OK);
    response_json(finish_resp).await
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
    let (_session, prf_cred_salt) = register_with_prf(&app, "Eve", "cred-upgrade", false).await;
    assert!(prf_cred_salt.is_none(), "precondition: row is pre-PRF");

    // Pre-state: row has no salt, prf_supported=false.
    {
        use secrt_server::storage::AuthStore;
        let pk = store
            .get_passkey_by_credential_id("cred-upgrade")
            .await
            .expect("passkey");
        assert!(pk.cred_salt.is_none());
        assert!(!pk.prf_supported);
    }

    // Login reporting PRF support — should trigger the upgrade.
    let json = login_with_prf(
        &app,
        "cred-upgrade",
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
            .get_passkey_by_credential_id("cred-upgrade")
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

    let (_session, original_salt) = register_with_prf(&app, "Frank", "cred-rewrap", true).await;
    let original_salt = original_salt.expect("registered with PRF");

    let json = login_with_prf(
        &app,
        "cred-rewrap",
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

    let (_session, _) = register_with_prf(&app, "Grace", "cred-no-prf", false).await;

    let json = login_with_prf(
        &app,
        "cred-no-prf",
        Some(json!({ "supported": false, "at_create": false })),
    )
    .await;

    assert!(json.get("prf_cred_salt").is_none());
    assert!(json.get("prf_wrapper").is_none());

    // Row remains pre-PRF.
    use secrt_server::storage::AuthStore;
    let pk = store
        .get_passkey_by_credential_id("cred-no-prf")
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

    let (session_token, _) = register_with_prf(&app, "Helen", "cred-w", true).await;
    let put_req = put_prf_wrapper_req(
        "cred-w",
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
        "cred-w",
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
    let (session_token, _) = register_with_prf(&app, "Iris", "cred-original", false).await;

    // add-start
    let add_start = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/add/start")
        .header("authorization", format!("Bearer {session_token}"))
        .body(Body::empty())
        .expect("request");
    let start_resp = app.clone().oneshot(add_start).await.expect("response");
    assert_eq!(start_resp.status(), StatusCode::OK);
    let challenge_id = response_json(start_resp).await["challenge_id"]
        .as_str()
        .expect("challenge_id")
        .to_string();

    // add-finish with PRF metadata
    let add_finish = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/add/finish")
        .header("authorization", format!("Bearer {session_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": challenge_id,
                "credential_id": "cred-add-prf",
                "public_key": "pk-test",
                "prf": { "supported": true, "at_create": true },
            })
            .to_string(),
        ))
        .expect("request");
    let finish_resp = app.clone().oneshot(add_finish).await.expect("response");
    assert_eq!(finish_resp.status(), StatusCode::OK);
    let json = response_json(finish_resp).await;

    let salt_b64u = json
        .get("prf_cred_salt")
        .and_then(|v| v.as_str())
        .expect("add-finish must return prf_cred_salt when PRF supported");
    let salt = URL_SAFE_NO_PAD
        .decode(salt_b64u.as_bytes())
        .expect("base64url decodable");
    assert_eq!(salt.len(), 32);

    use secrt_server::storage::AuthStore;
    let pk = store
        .get_passkey_by_credential_id("cred-add-prf")
        .await
        .expect("passkey");
    assert_eq!(pk.cred_salt.as_deref(), Some(salt.as_slice()));
    assert!(pk.prf_supported);
    assert!(pk.prf_at_create);
}
