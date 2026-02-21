mod helpers;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use helpers::{test_app_with_store, test_config, MemStore};
use serde_json::{json, Value};
use tower::ServiceExt;

async fn response_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    serde_json::from_slice(&bytes).expect("json")
}

/// Register a passkey and return a session token.
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

fn authed_get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

fn authed_post(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

fn authed_json(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

// ── List passkeys ───────────────────────────────────────────

#[tokio::test]
async fn list_passkeys_requires_auth() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/passkeys")
        .body(Body::empty())
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_passkeys_wrong_method_405() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-list-405").await;

    let req = authed_json("POST", "/api/v1/auth/passkeys", &token, json!({}));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn list_passkeys_returns_user_passkeys() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-list-1").await;

    let resp = app
        .clone()
        .oneshot(authed_get("/api/v1/auth/passkeys", &token))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    let passkeys = body["passkeys"].as_array().expect("passkeys array");
    assert_eq!(passkeys.len(), 1);
    assert!(passkeys[0]["id"].is_number());
    assert!(passkeys[0].get("created_at").is_some());
}

#[tokio::test]
async fn list_passkeys_excludes_other_users() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());

    let token_a = passkey_register_flow(&app, "Alice", "cred-iso-a").await;
    let _token_b = passkey_register_flow(&app, "Bob", "cred-iso-b").await;

    let resp = app
        .clone()
        .oneshot(authed_get("/api/v1/auth/passkeys", &token_a))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    let passkeys = body["passkeys"].as_array().expect("passkeys array");
    // Alice should only see her own passkey, not Bob's
    assert_eq!(passkeys.len(), 1);
}

// ── Add passkey (start/finish) ──────────────────────────────

#[tokio::test]
async fn passkey_add_start_requires_auth() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/add/start")
        .body(Body::empty())
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn passkey_add_start_wrong_method_405() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-add-405").await;

    let resp = app
        .clone()
        .oneshot(authed_get("/api/v1/auth/passkeys/add/start", &token))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn passkey_add_start_returns_challenge() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-add-start").await;

    let resp = app
        .clone()
        .oneshot(authed_post("/api/v1/auth/passkeys/add/start", &token))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert!(body["challenge_id"].is_string());
    assert!(body["challenge"].is_string());
    assert!(body["expires_at"].is_string());
}

#[tokio::test]
async fn passkey_add_finish_requires_auth() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/add/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": "x",
                "credential_id": "c",
                "public_key": "p"
            })
            .to_string(),
        ))
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn passkey_add_finish_wrong_method_405() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-add-fin-405").await;

    let resp = app
        .clone()
        .oneshot(authed_get("/api/v1/auth/passkeys/add/finish", &token))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn passkey_add_full_flow() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-add-flow").await;

    // Start: get a challenge
    let start_resp = app
        .clone()
        .oneshot(authed_post("/api/v1/auth/passkeys/add/start", &token))
        .await
        .expect("response");
    assert_eq!(start_resp.status(), StatusCode::OK);
    let start_body = response_json(start_resp).await;
    let challenge_id = start_body["challenge_id"]
        .as_str()
        .expect("challenge_id")
        .to_string();

    // Finish: register the new passkey
    let finish_resp = app
        .clone()
        .oneshot(authed_json(
            "POST",
            "/api/v1/auth/passkeys/add/finish",
            &token,
            json!({
                "challenge_id": challenge_id,
                "credential_id": "cred-add-flow-2",
                "public_key": "pk2"
            }),
        ))
        .await
        .expect("response");
    assert_eq!(finish_resp.status(), StatusCode::OK);
    let finish_body = response_json(finish_resp).await;
    assert_eq!(finish_body["ok"], true);
    assert!(finish_body["passkey"]["id"].is_number());
    assert!(finish_body["passkey"].get("created_at").is_some());

    // Verify: list now shows 2 passkeys
    let list_resp = app
        .clone()
        .oneshot(authed_get("/api/v1/auth/passkeys", &token))
        .await
        .expect("response");
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_body = response_json(list_resp).await;
    assert_eq!(list_body["passkeys"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn passkey_add_finish_rejects_empty_credential_id() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-add-empty").await;

    // Get a valid challenge first
    let start_resp = app
        .clone()
        .oneshot(authed_post("/api/v1/auth/passkeys/add/start", &token))
        .await
        .expect("response");
    let start_body = response_json(start_resp).await;
    let challenge_id = start_body["challenge_id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(authed_json(
            "POST",
            "/api/v1/auth/passkeys/add/finish",
            &token,
            json!({
                "challenge_id": challenge_id,
                "credential_id": "",
                "public_key": "pk"
            }),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn passkey_add_finish_rejects_invalid_challenge() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-add-bad-ch").await;

    let resp = app
        .clone()
        .oneshot(authed_json(
            "POST",
            "/api/v1/auth/passkeys/add/finish",
            &token,
            json!({
                "challenge_id": "nonexistent",
                "credential_id": "c",
                "public_key": "pk"
            }),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Rename passkey (PATCH) ──────────────────────────────────

#[tokio::test]
async fn rename_passkey_requires_auth() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());

    let req = Request::builder()
        .method("PATCH")
        .uri("/api/v1/auth/passkeys/1")
        .header("content-type", "application/json")
        .body(Body::from(json!({"label": "new"}).to_string()))
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rename_passkey_wrong_method_405() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-rename-405").await;

    let resp = app
        .clone()
        .oneshot(authed_get("/api/v1/auth/passkeys/1", &token))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn rename_passkey_success() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-rename-ok").await;

    // Get the passkey ID from list
    let list_resp = app
        .clone()
        .oneshot(authed_get("/api/v1/auth/passkeys", &token))
        .await
        .expect("response");
    let list_body = response_json(list_resp).await;
    let pk_id = list_body["passkeys"][0]["id"].as_i64().unwrap();

    // Rename it
    let resp = app
        .clone()
        .oneshot(authed_json(
            "PATCH",
            &format!("/api/v1/auth/passkeys/{pk_id}"),
            &token,
            json!({"label": "MacBook Pro"}),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["ok"], true);

    // Verify label persisted in store
    let passkeys = store.passkeys.lock().expect("lock");
    let pk = passkeys.values().find(|p| p.id == pk_id).expect("passkey");
    assert_eq!(pk.label, "MacBook Pro");
}

#[tokio::test]
async fn rename_passkey_trims_whitespace() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-rename-trim").await;

    let list_resp = app
        .clone()
        .oneshot(authed_get("/api/v1/auth/passkeys", &token))
        .await
        .expect("response");
    let list_body = response_json(list_resp).await;
    let pk_id = list_body["passkeys"][0]["id"].as_i64().unwrap();

    let resp = app
        .clone()
        .oneshot(authed_json(
            "PATCH",
            &format!("/api/v1/auth/passkeys/{pk_id}"),
            &token,
            json!({"label": "  padded  "}),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);

    let passkeys = store.passkeys.lock().expect("lock");
    let pk = passkeys.values().find(|p| p.id == pk_id).unwrap();
    assert_eq!(pk.label, "padded");
}

#[tokio::test]
async fn rename_passkey_too_long_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-rename-long").await;

    let list_resp = app
        .clone()
        .oneshot(authed_get("/api/v1/auth/passkeys", &token))
        .await
        .expect("response");
    let list_body = response_json(list_resp).await;
    let pk_id = list_body["passkeys"][0]["id"].as_i64().unwrap();

    let long_label = "x".repeat(101);
    let resp = app
        .clone()
        .oneshot(authed_json(
            "PATCH",
            &format!("/api/v1/auth/passkeys/{pk_id}"),
            &token,
            json!({"label": long_label}),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rename_passkey_not_found_404() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-rename-404").await;

    let resp = app
        .clone()
        .oneshot(authed_json(
            "PATCH",
            "/api/v1/auth/passkeys/99999",
            &token,
            json!({"label": "nope"}),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rename_passkey_cross_user_isolation() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());

    let _token_a = passkey_register_flow(&app, "Alice", "cred-xuser-a").await;
    let token_b = passkey_register_flow(&app, "Bob", "cred-xuser-b").await;

    // Get Alice's passkey ID
    let passkeys = store.passkeys.lock().expect("lock");
    let alice_pk_id = passkeys
        .values()
        .find(|p| p.credential_id == "cred-xuser-a")
        .expect("alice pk")
        .id;
    drop(passkeys);

    // Bob tries to rename Alice's passkey → 404
    let resp = app
        .clone()
        .oneshot(authed_json(
            "PATCH",
            &format!("/api/v1/auth/passkeys/{alice_pk_id}"),
            &token_b,
            json!({"label": "hacked"}),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Revoke passkey ──────────────────────────────────────────

#[tokio::test]
async fn revoke_passkey_requires_auth() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/1/revoke")
        .body(Body::empty())
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_passkey_wrong_method_405() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-revoke-405").await;

    let resp = app
        .clone()
        .oneshot(authed_get("/api/v1/auth/passkeys/1/revoke", &token))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn revoke_last_passkey_returns_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-revoke-last").await;

    // Get the single passkey ID
    let list_resp = app
        .clone()
        .oneshot(authed_get("/api/v1/auth/passkeys", &token))
        .await
        .expect("response");
    let list_body = response_json(list_resp).await;
    let pk_id = list_body["passkeys"][0]["id"].as_i64().unwrap();

    // Try to revoke the only passkey → 400
    let resp = app
        .clone()
        .oneshot(authed_post(
            &format!("/api/v1/auth/passkeys/{pk_id}/revoke"),
            &token,
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn revoke_passkey_success_with_multiple() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-revoke-ok").await;

    // Add a second passkey via the add flow
    let start_resp = app
        .clone()
        .oneshot(authed_post("/api/v1/auth/passkeys/add/start", &token))
        .await
        .expect("response");
    let start_body = response_json(start_resp).await;
    let challenge_id = start_body["challenge_id"].as_str().unwrap().to_string();

    let finish_resp = app
        .clone()
        .oneshot(authed_json(
            "POST",
            "/api/v1/auth/passkeys/add/finish",
            &token,
            json!({
                "challenge_id": challenge_id,
                "credential_id": "cred-revoke-ok-2",
                "public_key": "pk2"
            }),
        ))
        .await
        .expect("response");
    assert_eq!(finish_resp.status(), StatusCode::OK);

    // Get the first passkey's ID
    let list_resp = app
        .clone()
        .oneshot(authed_get("/api/v1/auth/passkeys", &token))
        .await
        .expect("response");
    let list_body = response_json(list_resp).await;
    let passkeys = list_body["passkeys"].as_array().unwrap();
    assert_eq!(passkeys.len(), 2);
    let first_pk_id = passkeys[0]["id"].as_i64().unwrap();

    // Revoke the first passkey → 200
    let resp = app
        .clone()
        .oneshot(authed_post(
            &format!("/api/v1/auth/passkeys/{first_pk_id}/revoke"),
            &token,
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["ok"], true);

    // Verify only one passkey remains in list
    let list_resp2 = app
        .clone()
        .oneshot(authed_get("/api/v1/auth/passkeys", &token))
        .await
        .expect("response");
    let list_body2 = response_json(list_resp2).await;
    assert_eq!(list_body2["passkeys"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn revoke_passkey_cross_user_isolation() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());

    let _token_a = passkey_register_flow(&app, "Alice", "cred-rev-xuser-a").await;
    let token_b = passkey_register_flow(&app, "Bob", "cred-rev-xuser-b").await;

    // Get Alice's passkey ID
    let passkeys = store.passkeys.lock().expect("lock");
    let alice_pk_id = passkeys
        .values()
        .find(|p| p.credential_id == "cred-rev-xuser-a")
        .expect("alice pk")
        .id;
    drop(passkeys);

    // Bob tries to revoke Alice's passkey → 400 (looks like "last passkey"
    // because the store doesn't find it for Bob's user_id)
    let resp = app
        .clone()
        .oneshot(authed_post(
            &format!("/api/v1/auth/passkeys/{alice_pk_id}/revoke"),
            &token_b,
        ))
        .await
        .expect("response");
    // Bob only has 1 passkey, so revoke returns false → 400 "cannot revoke last active"
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Update display name (PATCH /api/v1/auth/account) ────────

#[tokio::test]
async fn update_display_name_requires_auth() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());

    let req = Request::builder()
        .method("PATCH")
        .uri("/api/v1/auth/account")
        .header("content-type", "application/json")
        .body(Body::from(json!({"display_name": "New Name"}).to_string()))
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn update_display_name_get_405() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-dn-405").await;

    let resp = app
        .clone()
        .oneshot(authed_get("/api/v1/auth/account", &token))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn update_display_name_success() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-dn-ok").await;

    let resp = app
        .clone()
        .oneshot(authed_json(
            "PATCH",
            "/api/v1/auth/account",
            &token,
            json!({"display_name": "New Alice"}),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["display_name"], "New Alice");

    // Verify in store
    let users = store.users.lock().expect("lock");
    let user = users.values().next().expect("user");
    assert_eq!(user.display_name, "New Alice");
}

#[tokio::test]
async fn update_display_name_trims_whitespace() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-dn-trim").await;

    let resp = app
        .clone()
        .oneshot(authed_json(
            "PATCH",
            "/api/v1/auth/account",
            &token,
            json!({"display_name": "  Trimmed  "}),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["display_name"], "Trimmed");
}

#[tokio::test]
async fn update_display_name_empty_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-dn-empty").await;

    let resp = app
        .clone()
        .oneshot(authed_json(
            "PATCH",
            "/api/v1/auth/account",
            &token,
            json!({"display_name": ""}),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_display_name_whitespace_only_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-dn-ws").await;

    let resp = app
        .clone()
        .oneshot(authed_json(
            "PATCH",
            "/api/v1/auth/account",
            &token,
            json!({"display_name": "   "}),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_display_name_too_long_400() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-dn-long").await;

    let long_name = "x".repeat(101);
    let resp = app
        .clone()
        .oneshot(authed_json(
            "PATCH",
            "/api/v1/auth/account",
            &token,
            json!({"display_name": long_name}),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_display_name_exactly_100_chars_ok() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let token = passkey_register_flow(&app, "Alice", "cred-dn-100").await;

    let name_100 = "x".repeat(100);
    let resp = app
        .clone()
        .oneshot(authed_json(
            "PATCH",
            "/api/v1/auth/account",
            &token,
            json!({"display_name": name_100}),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
}
