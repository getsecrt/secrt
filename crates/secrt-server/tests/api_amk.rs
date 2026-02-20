mod helpers;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use helpers::{test_app_with_store, test_config, with_remote, MemStore};
use secrt_server::config::Config;
use secrt_server::storage::SecretRecord;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn response_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    serde_json::from_slice(&bytes).expect("json")
}

fn amk_config() -> Config {
    let mut cfg = test_config();
    cfg.encrypted_notes_enabled = true;
    cfg
}

// --- Passkey/session helpers (mirrors api_auth_passkeys.rs pattern) ---

async fn passkey_register_flow(app: &axum::Router, display_name: &str, cred_id: &str) -> String {
    let start_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/register/start")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"display_name": display_name}).to_string(),
        ))
        .expect("request");
    let start_resp = app.clone().oneshot(start_req).await.expect("response");
    assert_eq!(start_resp.status(), StatusCode::OK);
    let start_json = response_json(start_resp).await;
    let challenge_id = start_json["challenge_id"]
        .as_str()
        .expect("challenge_id")
        .to_string();

    let finish_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/register/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"challenge_id": challenge_id, "credential_id": cred_id, "public_key": "pk"})
                .to_string(),
        ))
        .expect("request");
    let finish_resp = app.clone().oneshot(finish_req).await.expect("response");
    assert_eq!(finish_resp.status(), StatusCode::OK);
    let finish_json = response_json(finish_resp).await;
    finish_json["session_token"]
        .as_str()
        .expect("session_token")
        .to_string()
}

/// Register an API key via the /apikeys/register endpoint (session-authenticated).
async fn register_api_key(app: &axum::Router, session_token: &str, auth_token_b64: &str) -> Value {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/apikeys/register")
        .header("authorization", format!("Bearer {session_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"auth_token": auth_token_b64, "scopes": ""}).to_string(),
        ))
        .expect("request");
    let resp = app
        .clone()
        .oneshot(with_remote(req, [198, 51, 100, 1], 12345))
        .await
        .expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "apikey register should succeed"
    );
    response_json(resp).await
}

/// Create a session + API key combo. Returns (session_token, wire_api_key, key_prefix).
async fn create_user_with_api_key(
    _store: &Arc<MemStore>,
    app: &axum::Router,
    name: &str,
    cred_id: &str,
) -> (String, String, String) {
    let session_token = passkey_register_flow(app, name, cred_id).await;
    // Derive an auth token to register
    let root = [42u8; 32];
    let auth = secrt_core::derive_auth_token(&root).expect("derive auth token");
    let auth_b64 = URL_SAFE_NO_PAD.encode(&auth);
    let reg_json = register_api_key(app, &session_token, &auth_b64).await;
    let prefix = reg_json["prefix"].as_str().expect("prefix").to_string();
    let wire_key = secrt_core::format_wire_api_key(&prefix, &auth).expect("format wire key");
    (session_token, wire_key, prefix)
}

// --- Valid base64url test data generators ---

fn valid_wrapped_amk() -> String {
    URL_SAFE_NO_PAD.encode([0xABu8; 48])
}
fn valid_nonce() -> String {
    URL_SAFE_NO_PAD.encode([0xCDu8; 12])
}
fn valid_amk_commit() -> String {
    URL_SAFE_NO_PAD.encode([0xEFu8; 32])
}
fn valid_enc_meta_ct() -> String {
    URL_SAFE_NO_PAD.encode(b"encrypted-note-text")
}
fn valid_enc_meta_nonce() -> String {
    URL_SAFE_NO_PAD.encode([0x11u8; 12])
}
fn valid_enc_meta_salt() -> String {
    URL_SAFE_NO_PAD.encode([0x22u8; 32])
}

// ==========================================
// PUT /api/v1/amk/wrapper
// ==========================================

#[tokio::test]
async fn amk_wrapper_put_unauthenticated_401() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, amk_config());

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/amk/wrapper")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "wrapped_amk": valid_wrapped_amk(),
                "nonce": valid_nonce(),
                "amk_commit": valid_amk_commit(),
                "version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn amk_wrapper_put_api_key_auth_success() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, prefix) =
        create_user_with_api_key(&store, &app, "Alice", "cred-amk-1").await;

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/amk/wrapper")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "wrapped_amk": valid_wrapped_amk(),
                "nonce": valid_nonce(),
                "amk_commit": valid_amk_commit(),
                "version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["ok"], true);

    // Verify wrapper was stored
    let wrappers = store.amk_wrappers.lock().expect("lock");
    assert_eq!(wrappers.len(), 1);
    let (_, rec) = wrappers.iter().next().unwrap();
    assert_eq!(rec.key_prefix, prefix);
}

#[tokio::test]
async fn amk_wrapper_put_session_auth_with_prefix_success() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (session_token, _wire_key, prefix) =
        create_user_with_api_key(&store, &app, "Bob", "cred-amk-2").await;

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/amk/wrapper")
        .header("authorization", format!("Bearer {session_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "key_prefix": prefix,
                "wrapped_amk": valid_wrapped_amk(),
                "nonce": valid_nonce(),
                "amk_commit": valid_amk_commit(),
                "version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn amk_wrapper_put_session_auth_no_prefix_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let session_token = passkey_register_flow(&app, "Carol", "cred-amk-3").await;

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/amk/wrapper")
        .header("authorization", format!("Bearer {session_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "wrapped_amk": valid_wrapped_amk(),
                "nonce": valid_nonce(),
                "amk_commit": valid_amk_commit(),
                "version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn amk_wrapper_put_wrong_wrapped_amk_length_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, _prefix) =
        create_user_with_api_key(&store, &app, "Dan", "cred-amk-4").await;

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/amk/wrapper")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "wrapped_amk": URL_SAFE_NO_PAD.encode([0u8; 32]),  // 32 instead of 48
                "nonce": valid_nonce(),
                "amk_commit": valid_amk_commit(),
                "version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert!(body["error"].as_str().unwrap().contains("wrapped_amk"));
}

#[tokio::test]
async fn amk_wrapper_put_wrong_nonce_length_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, _prefix) =
        create_user_with_api_key(&store, &app, "Eve", "cred-amk-5").await;

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/amk/wrapper")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "wrapped_amk": valid_wrapped_amk(),
                "nonce": URL_SAFE_NO_PAD.encode([0u8; 8]),  // 8 instead of 12
                "amk_commit": valid_amk_commit(),
                "version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert!(body["error"].as_str().unwrap().contains("nonce"));
}

#[tokio::test]
async fn amk_wrapper_put_wrong_amk_commit_length_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, _prefix) =
        create_user_with_api_key(&store, &app, "Fay", "cred-amk-6").await;

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/amk/wrapper")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "wrapped_amk": valid_wrapped_amk(),
                "nonce": valid_nonce(),
                "amk_commit": URL_SAFE_NO_PAD.encode([0u8; 16]),  // 16 instead of 32
                "version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert!(body["error"].as_str().unwrap().contains("amk_commit"));
}

#[tokio::test]
async fn amk_wrapper_put_bad_version_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, _prefix) =
        create_user_with_api_key(&store, &app, "Gus", "cred-amk-7").await;

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/amk/wrapper")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "wrapped_amk": valid_wrapped_amk(),
                "nonce": valid_nonce(),
                "amk_commit": valid_amk_commit(),
                "version": 99
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ==========================================
// GET /api/v1/amk/wrapper
// ==========================================

#[tokio::test]
async fn amk_wrapper_get_unauthenticated_401() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, amk_config());

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/amk/wrapper")
        .body(Body::empty())
        .expect("request");

    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn amk_wrapper_get_not_found_404() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, _prefix) =
        create_user_with_api_key(&store, &app, "Hal", "cred-amk-8").await;

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/amk/wrapper")
        .header("x-api-key", &wire_key)
        .body(Body::empty())
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn amk_wrapper_put_then_get_roundtrip() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, _prefix) =
        create_user_with_api_key(&store, &app, "Ivy", "cred-amk-9").await;

    // PUT wrapper
    let put_req = Request::builder()
        .method("PUT")
        .uri("/api/v1/amk/wrapper")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "wrapped_amk": valid_wrapped_amk(),
                "nonce": valid_nonce(),
                "amk_commit": valid_amk_commit(),
                "version": 1
            })
            .to_string(),
        ))
        .expect("request");
    let put_resp = app.clone().oneshot(put_req).await.expect("response");
    assert_eq!(put_resp.status(), StatusCode::OK);

    // GET wrapper
    let get_req = Request::builder()
        .method("GET")
        .uri("/api/v1/amk/wrapper")
        .header("x-api-key", &wire_key)
        .body(Body::empty())
        .expect("request");
    let get_resp = app.clone().oneshot(get_req).await.expect("response");
    assert_eq!(get_resp.status(), StatusCode::OK);
    let body = response_json(get_resp).await;
    assert_eq!(body["wrapped_amk"].as_str().unwrap(), valid_wrapped_amk());
    assert_eq!(body["nonce"].as_str().unwrap(), valid_nonce());
    assert_eq!(body["version"].as_i64().unwrap(), 1);
    assert!(body["user_id"].as_str().is_some());
}

// ==========================================
// GET /api/v1/amk/wrappers
// ==========================================

#[tokio::test]
async fn amk_wrappers_list_unauthenticated_401() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, amk_config());

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/amk/wrappers")
        .body(Body::empty())
        .expect("request");

    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn amk_wrappers_list_api_key_only_401() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, _prefix) =
        create_user_with_api_key(&store, &app, "Jay", "cred-amk-10").await;

    // /amk/wrappers requires session auth, not API key
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/amk/wrappers")
        .header("x-api-key", &wire_key)
        .body(Body::empty())
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn amk_wrappers_list_session_auth_success() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (session_token, wire_key, prefix) =
        create_user_with_api_key(&store, &app, "Kay", "cred-amk-11").await;

    // First, upsert a wrapper
    let put_req = Request::builder()
        .method("PUT")
        .uri("/api/v1/amk/wrapper")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "wrapped_amk": valid_wrapped_amk(),
                "nonce": valid_nonce(),
                "amk_commit": valid_amk_commit(),
                "version": 1
            })
            .to_string(),
        ))
        .expect("request");
    let put_resp = app.clone().oneshot(put_req).await.expect("response");
    assert_eq!(put_resp.status(), StatusCode::OK);

    // List wrappers
    let list_req = Request::builder()
        .method("GET")
        .uri("/api/v1/amk/wrappers")
        .header("authorization", format!("Bearer {session_token}"))
        .body(Body::empty())
        .expect("request");
    let list_resp = app.clone().oneshot(list_req).await.expect("response");
    assert_eq!(list_resp.status(), StatusCode::OK);
    let body = response_json(list_resp).await;
    let wrappers = body["wrappers"].as_array().expect("wrappers array");
    assert_eq!(wrappers.len(), 1);
    assert_eq!(wrappers[0]["key_prefix"].as_str().unwrap(), prefix);
}

// ==========================================
// GET /api/v1/amk/exists
// ==========================================

#[tokio::test]
async fn amk_exists_unauthenticated_401() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, amk_config());

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/amk/exists")
        .body(Body::empty())
        .expect("request");

    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn amk_exists_no_wrappers_false() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, _prefix) =
        create_user_with_api_key(&store, &app, "Leo", "cred-amk-12").await;

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/amk/exists")
        .header("x-api-key", &wire_key)
        .body(Body::empty())
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["exists"], false);
}

#[tokio::test]
async fn amk_exists_has_wrapper_true() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, _prefix) =
        create_user_with_api_key(&store, &app, "Mia", "cred-amk-13").await;

    // Upsert a wrapper
    let put_req = Request::builder()
        .method("PUT")
        .uri("/api/v1/amk/wrapper")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "wrapped_amk": valid_wrapped_amk(),
                "nonce": valid_nonce(),
                "amk_commit": valid_amk_commit(),
                "version": 1
            })
            .to_string(),
        ))
        .expect("request");
    let put_resp = app.clone().oneshot(put_req).await.expect("response");
    assert_eq!(put_resp.status(), StatusCode::OK);

    // Check exists
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/amk/exists")
        .header("x-api-key", &wire_key)
        .body(Body::empty())
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["exists"], true);
}

// ==========================================
// POST /api/v1/amk/commit
// ==========================================

#[tokio::test]
async fn amk_commit_success() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let session_token = passkey_register_flow(&app, "Commit1", "cred-commit-1").await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/amk/commit")
        .header("authorization", format!("Bearer {session_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "amk_commit": valid_amk_commit() }).to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["ok"], true);
}

#[tokio::test]
async fn amk_commit_first_writer_wins() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let session_token = passkey_register_flow(&app, "Commit2", "cred-commit-2").await;

    // First commit
    let req1 = Request::builder()
        .method("POST")
        .uri("/api/v1/amk/commit")
        .header("authorization", format!("Bearer {session_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "amk_commit": valid_amk_commit() }).to_string(),
        ))
        .expect("request");
    let resp1 = app.clone().oneshot(req1).await.expect("response");
    assert_eq!(resp1.status(), StatusCode::OK);

    // Second commit with different hash => 409
    let different_commit = URL_SAFE_NO_PAD.encode([0xAAu8; 32]);
    let req2 = Request::builder()
        .method("POST")
        .uri("/api/v1/amk/commit")
        .header("authorization", format!("Bearer {session_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "amk_commit": different_commit }).to_string(),
        ))
        .expect("request");
    let resp2 = app.clone().oneshot(req2).await.expect("response");
    assert_eq!(resp2.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn amk_commit_idempotent() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let session_token = passkey_register_flow(&app, "Commit3", "cred-commit-3").await;

    for _ in 0..2 {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/amk/commit")
            .header("authorization", format!("Bearer {session_token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "amk_commit": valid_amk_commit() }).to_string(),
            ))
            .expect("request");
        let resp = app.clone().oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn amk_commit_unauthenticated_401() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, amk_config());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/amk/commit")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "amk_commit": valid_amk_commit() }).to_string(),
        ))
        .expect("request");

    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn amk_exists_committed_no_wrapper_true() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let session_token = passkey_register_flow(&app, "CommitOnly", "cred-commit-4").await;

    // Commit without any wrapper
    let commit_req = Request::builder()
        .method("POST")
        .uri("/api/v1/amk/commit")
        .header("authorization", format!("Bearer {session_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "amk_commit": valid_amk_commit() }).to_string(),
        ))
        .expect("request");
    let commit_resp = app.clone().oneshot(commit_req).await.expect("response");
    assert_eq!(commit_resp.status(), StatusCode::OK);

    // Check exists — should be true even without a wrapper
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/amk/exists")
        .header("authorization", format!("Bearer {session_token}"))
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["exists"], true);
}

// ==========================================
// PUT /api/v1/secrets/{id}/meta
// ==========================================

/// Insert a test secret owned by the given owner_key.
fn insert_test_secret(store: &Arc<MemStore>, id: &str, owner_key: &str) {
    let mut m = store.secrets.lock().expect("secrets mutex");
    m.insert(
        id.to_string(),
        SecretRecord {
            id: id.to_string(),
            owner_key: owner_key.to_string(),
            envelope: r#"{"ct":"test"}"#.into(),
            claim_hash: "dummy_claim_hash".to_string(),
            expires_at: Utc::now() + Duration::hours(24),
            created_at: Utc::now(),
        },
    );
}

fn owner_key_for_api_prefix(prefix: &str) -> String {
    format!("apikey:{prefix}")
}

#[tokio::test]
async fn secret_meta_put_unauthenticated_401() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, amk_config());

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/secrets/test-id/meta")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "enc_meta": {
                    "v": 1,
                    "note": {
                        "ct": valid_enc_meta_ct(),
                        "nonce": valid_enc_meta_nonce(),
                        "salt": valid_enc_meta_salt()
                    }
                },
                "meta_key_version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn secret_meta_put_not_owner_404() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, _prefix) =
        create_user_with_api_key(&store, &app, "Nina", "cred-amk-14").await;

    // Insert a secret owned by someone else
    insert_test_secret(&store, "other-secret", "other-owner");

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/secrets/other-secret/meta")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "enc_meta": {
                    "v": 1,
                    "note": {
                        "ct": valid_enc_meta_ct(),
                        "nonce": valid_enc_meta_nonce(),
                        "salt": valid_enc_meta_salt()
                    }
                },
                "meta_key_version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn secret_meta_put_invalid_version_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, prefix) =
        create_user_with_api_key(&store, &app, "Ova", "cred-amk-15").await;

    insert_test_secret(&store, "my-secret-v", &owner_key_for_api_prefix(&prefix));

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/secrets/my-secret-v/meta")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "enc_meta": {
                    "v": 99,
                    "note": {
                        "ct": valid_enc_meta_ct(),
                        "nonce": valid_enc_meta_nonce(),
                        "salt": valid_enc_meta_salt()
                    }
                },
                "meta_key_version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn secret_meta_put_invalid_nonce_length_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, prefix) =
        create_user_with_api_key(&store, &app, "Pat", "cred-amk-16").await;

    insert_test_secret(&store, "my-secret-n", &owner_key_for_api_prefix(&prefix));

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/secrets/my-secret-n/meta")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "enc_meta": {
                    "v": 1,
                    "note": {
                        "ct": valid_enc_meta_ct(),
                        "nonce": URL_SAFE_NO_PAD.encode([0u8; 8]),  // 8 instead of 12
                        "salt": valid_enc_meta_salt()
                    }
                },
                "meta_key_version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert!(body["error"].as_str().unwrap().contains("nonce"));
}

#[tokio::test]
async fn secret_meta_put_invalid_salt_length_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, prefix) =
        create_user_with_api_key(&store, &app, "Quin", "cred-amk-17").await;

    insert_test_secret(&store, "my-secret-s", &owner_key_for_api_prefix(&prefix));

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/secrets/my-secret-s/meta")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "enc_meta": {
                    "v": 1,
                    "note": {
                        "ct": valid_enc_meta_ct(),
                        "nonce": valid_enc_meta_nonce(),
                        "salt": URL_SAFE_NO_PAD.encode([0u8; 16])  // 16 instead of 32
                    }
                },
                "meta_key_version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert!(body["error"].as_str().unwrap().contains("salt"));
}

#[tokio::test]
async fn secret_meta_put_ct_exceeds_8kib_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, prefix) =
        create_user_with_api_key(&store, &app, "Rex", "cred-amk-18").await;

    insert_test_secret(&store, "my-secret-big", &owner_key_for_api_prefix(&prefix));

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/secrets/my-secret-big/meta")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "enc_meta": {
                    "v": 1,
                    "note": {
                        "ct": URL_SAFE_NO_PAD.encode(vec![0u8; 8193]),  // > 8192
                        "nonce": valid_enc_meta_nonce(),
                        "salt": valid_enc_meta_salt()
                    }
                },
                "meta_key_version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert!(body["error"].as_str().unwrap().contains("8 KiB"));
}

#[tokio::test]
async fn secret_meta_put_invalid_base64_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, prefix) =
        create_user_with_api_key(&store, &app, "Sam", "cred-amk-19").await;

    insert_test_secret(&store, "my-secret-b64", &owner_key_for_api_prefix(&prefix));

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/secrets/my-secret-b64/meta")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "enc_meta": {
                    "v": 1,
                    "note": {
                        "ct": "not!valid!base64!!!",
                        "nonce": valid_enc_meta_nonce(),
                        "salt": valid_enc_meta_salt()
                    }
                },
                "meta_key_version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn secret_meta_put_valid_update_200() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), amk_config());

    let (_session, wire_key, prefix) =
        create_user_with_api_key(&store, &app, "Tina", "cred-amk-20").await;

    insert_test_secret(&store, "my-secret-ok", &owner_key_for_api_prefix(&prefix));

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/secrets/my-secret-ok/meta")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "enc_meta": {
                    "v": 1,
                    "note": {
                        "ct": valid_enc_meta_ct(),
                        "nonce": valid_enc_meta_nonce(),
                        "salt": valid_enc_meta_salt()
                    }
                },
                "meta_key_version": 1
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["ok"], true);
}

// ==========================================
// require_encrypted_notes feature gate
// ==========================================

#[tokio::test]
async fn amk_endpoints_404_when_feature_disabled() {
    let store = Arc::new(MemStore::default());
    let mut cfg = test_config();
    cfg.encrypted_notes_enabled = false;
    let app = test_app_with_store(store.clone(), cfg);

    let (_session, wire_key, _prefix) =
        create_user_with_api_key(&store, &app, "Vic", "cred-amk-21").await;

    // PUT /amk/wrapper
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/amk/wrapper")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "wrapped_amk": valid_wrapped_amk(),
                "nonce": valid_nonce(),
                "amk_commit": valid_amk_commit(),
                "version": 1
            })
            .to_string(),
        ))
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PUT /amk/wrapper should 404 when disabled"
    );

    // GET /amk/wrapper
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/amk/wrapper")
        .header("x-api-key", &wire_key)
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "GET /amk/wrapper should 404 when disabled"
    );

    // GET /amk/wrappers
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/amk/wrappers")
        .header("x-api-key", &wire_key)
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "GET /amk/wrappers should 404 when disabled"
    );

    // POST /amk/commit
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/amk/commit")
        .header("authorization", format!("Bearer {_session}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "amk_commit": valid_amk_commit() }).to_string(),
        ))
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "POST /amk/commit should 404 when disabled"
    );

    // GET /amk/exists
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/amk/exists")
        .header("x-api-key", &wire_key)
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "GET /amk/exists should 404 when disabled"
    );

    // PUT /secrets/{id}/meta
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/secrets/test-id/meta")
        .header("x-api-key", &wire_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "enc_meta": {
                    "v": 1,
                    "note": {
                        "ct": valid_enc_meta_ct(),
                        "nonce": valid_enc_meta_nonce(),
                        "salt": valid_enc_meta_salt()
                    }
                },
                "meta_key_version": 1
            })
            .to_string(),
        ))
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PUT /secrets/{{id}}/meta should 404 when disabled"
    );
}

// ==========================================
// GET /api/v1/secrets/{id} (metadata lookup)
// ==========================================

#[tokio::test]
async fn get_secret_metadata_unauthenticated_401() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/secrets/some-id")
        .body(Body::empty())
        .expect("request");

    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_secret_metadata_not_owner_404() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());

    let (_session, wire_key, _prefix) =
        create_user_with_api_key(&store, &app, "Wes", "cred-amk-22").await;

    insert_test_secret(&store, "someone-elses-secret", "other-owner-key");

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/secrets/someone-elses-secret")
        .header("x-api-key", &wire_key)
        .body(Body::empty())
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_secret_metadata_success() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());

    let (_session, wire_key, prefix) =
        create_user_with_api_key(&store, &app, "Xia", "cred-amk-23").await;

    let owner_key = owner_key_for_api_prefix(&prefix);
    insert_test_secret(&store, "my-owned-secret", &owner_key);

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/secrets/my-owned-secret")
        .header("x-api-key", &wire_key)
        .body(Body::empty())
        .expect("request");

    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["id"].as_str().unwrap(), "my-owned-secret");
    assert!(body["share_url"]
        .as_str()
        .unwrap()
        .contains("my-owned-secret"));
    assert!(body["expires_at"].as_str().is_some());
    assert!(body["created_at"].as_str().is_some());
    assert!(body["ciphertext_size"].as_i64().is_some());
}
