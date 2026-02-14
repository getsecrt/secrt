mod helpers;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine;
use chrono::{Duration, Utc};
use helpers::{create_api_key, test_app_with_store, test_config, with_remote, MemStore};
use secrt_server::storage::UserId;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn response_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    serde_json::from_slice(&bytes).expect("json")
}

async fn passkey_register_finish_response(
    app: &axum::Router,
    display_name: &str,
    credential_id: &str,
) -> Value {
    let start_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/register/start")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "display_name": display_name,
            })
            .to_string(),
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
            json!({
                "challenge_id": challenge_id,
                "credential_id": credential_id,
                "public_key": "pk-test",
            })
            .to_string(),
        ))
        .expect("request");
    let finish_resp = app.clone().oneshot(finish_req).await.expect("response");
    assert_eq!(finish_resp.status(), StatusCode::OK);
    response_json(finish_resp).await
}

async fn passkey_register_flow(
    app: &axum::Router,
    display_name: &str,
    credential_id: &str,
) -> String {
    let finish_json = passkey_register_finish_response(app, display_name, credential_id).await;
    assert!(finish_json.get("user_id").is_none());
    finish_json["session_token"]
        .as_str()
        .expect("session_token")
        .to_string()
}

async fn passkey_login_finish_response(app: &axum::Router, credential_id: &str) -> Value {
    let start_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/login/start")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "credential_id": credential_id,
            })
            .to_string(),
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
        .uri("/api/v1/auth/passkeys/login/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": challenge_id,
                "credential_id": credential_id,
            })
            .to_string(),
        ))
        .expect("request");
    let finish_resp = app.clone().oneshot(finish_req).await.expect("response");
    assert_eq!(finish_resp.status(), StatusCode::OK);
    response_json(finish_resp).await
}

async fn passkey_login_flow(app: &axum::Router, credential_id: &str) -> String {
    let finish_json = passkey_login_finish_response(app, credential_id).await;
    assert!(finish_json.get("user_id").is_none());
    finish_json["session_token"]
        .as_str()
        .expect("session_token")
        .to_string()
}

async fn passkey_login_start_only(app: &axum::Router, credential_id: &str) -> String {
    let start_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/login/start")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "credential_id": credential_id,
            })
            .to_string(),
        ))
        .expect("request");
    let start_resp = app.clone().oneshot(start_req).await.expect("response");
    assert_eq!(start_resp.status(), StatusCode::OK);
    let start_json = response_json(start_resp).await;
    start_json["challenge_id"]
        .as_str()
        .expect("challenge_id")
        .to_string()
}

async fn register_apikey(
    app: &axum::Router,
    session_token: &str,
    auth_token: &str,
) -> axum::response::Response {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/apikeys/register")
        .header("authorization", format!("Bearer {session_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "auth_token": auth_token,
                "scopes": ""
            })
            .to_string(),
        ))
        .expect("request");
    app.clone()
        .oneshot(with_remote(req, [198, 51, 100, 10], 12345))
        .await
        .expect("response")
}

fn session_sid(token: &str) -> &str {
    token
        .trim_start_matches("uss_")
        .split('.')
        .next()
        .expect("sid")
}

fn user_id_for_session(store: &Arc<MemStore>, token: &str) -> UserId {
    let sessions = store.sessions.lock().expect("sessions mutex");
    sessions
        .get(session_sid(token))
        .expect("session record")
        .user_id
}

#[tokio::test]
async fn passkey_register_login_and_session_happy_path() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let session_token = passkey_register_flow(&app, "Alice", "cred-a").await;
    assert!(session_token.starts_with("uss_"));
    let register_user_id = user_id_for_session(&store, &session_token);

    let login_token = passkey_login_flow(&app, "cred-a").await;
    assert!(login_token.starts_with("uss_"));
    let login_user_id = user_id_for_session(&store, &login_token);
    assert_eq!(login_user_id, register_user_id);

    let session_req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/session")
        .header("authorization", format!("Bearer {login_token}"))
        .body(Body::empty())
        .expect("request");
    let session_resp = app.clone().oneshot(session_req).await.expect("response");
    assert_eq!(session_resp.status(), StatusCode::OK);
    let body = response_json(session_resp).await;
    assert_eq!(body["authenticated"].as_bool(), Some(true));
    assert!(body.get("user_id").is_none());
}

#[tokio::test]
async fn passkey_finish_responses_return_public_session_fields_only() {
    let app = test_app_with_store(Arc::new(MemStore::default()), test_config());
    let register_finish = passkey_register_finish_response(&app, "Alice", "cred-redact").await;
    assert!(register_finish["session_token"].as_str().is_some());
    assert_eq!(register_finish["display_name"].as_str(), Some("Alice"));
    assert!(register_finish["expires_at"].as_str().is_some());
    assert!(register_finish.get("user_id").is_none());

    let login_finish = passkey_login_finish_response(&app, "cred-redact").await;
    assert!(login_finish["session_token"].as_str().is_some());
    assert_eq!(login_finish["display_name"].as_str(), Some("Alice"));
    assert!(login_finish["expires_at"].as_str().is_some());
    assert!(login_finish.get("user_id").is_none());
}

#[tokio::test]
async fn session_expiry_and_logout_invalidate_session() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let session_token = passkey_register_flow(&app, "Bob", "cred-b").await;

    let logout_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header("authorization", format!("Bearer {session_token}"))
        .body(Body::empty())
        .expect("request");
    let logout_resp = app.clone().oneshot(logout_req).await.expect("response");
    assert_eq!(logout_resp.status(), StatusCode::OK);

    let session_req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/session")
        .header("authorization", format!("Bearer {session_token}"))
        .body(Body::empty())
        .expect("request");
    let session_resp = app.clone().oneshot(session_req).await.expect("response");
    let session_body = response_json(session_resp).await;
    assert_eq!(session_body["authenticated"].as_bool(), Some(false));

    let fresh_token = passkey_register_flow(&app, "Bobby", "cred-b2").await;
    let sid = fresh_token
        .trim_start_matches("uss_")
        .split('.')
        .next()
        .expect("sid")
        .to_string();
    {
        let mut sessions = store.sessions.lock().expect("sessions mutex");
        let rec = sessions.get_mut(&sid).expect("session");
        rec.expires_at = Utc::now() - Duration::seconds(1);
    }

    let expired_req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/session")
        .header("authorization", format!("Bearer {fresh_token}"))
        .body(Body::empty())
        .expect("request");
    let expired_resp = app.clone().oneshot(expired_req).await.expect("response");
    let expired_body = response_json(expired_resp).await;
    assert_eq!(expired_body["authenticated"].as_bool(), Some(false));
}

#[tokio::test]
async fn register_apikey_success_requires_valid_session() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let session_token = passkey_register_flow(&app, "Carol", "cred-c").await;
    let user_id = user_id_for_session(&store, &session_token);
    let auth_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);

    let resp = register_apikey(&app, &session_token, &auth_token).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = response_json(resp).await;
    assert!(body["prefix"].as_str().unwrap_or_default().len() >= 6);

    let keys = store.keys.lock().expect("keys mutex");
    let key = keys.values().next().expect("stored key");
    assert_eq!(key.user_id, Some(user_id));
}

#[tokio::test]
async fn register_apikey_rejects_missing_session_and_bad_auth_token() {
    let app = test_app_with_store(Arc::new(MemStore::default()), test_config());

    let missing_session_req = Request::builder()
        .method("POST")
        .uri("/api/v1/apikeys/register")
        .header("content-type", "application/json")
        .body(Body::from(json!({"auth_token":"abc"}).to_string()))
        .expect("request");
    let missing_session_resp = app
        .clone()
        .oneshot(with_remote(missing_session_req, [198, 51, 100, 11], 1111))
        .await
        .expect("response");
    assert_eq!(missing_session_resp.status(), StatusCode::UNAUTHORIZED);

    let session_token = passkey_register_flow(&app, "Dana", "cred-d").await;
    let bad_req = Request::builder()
        .method("POST")
        .uri("/api/v1/apikeys/register")
        .header("authorization", format!("Bearer {session_token}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({"auth_token":"bad"}).to_string()))
        .expect("request");
    let bad_resp = app
        .clone()
        .oneshot(with_remote(bad_req, [198, 51, 100, 11], 1111))
        .await
        .expect("response");
    assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_apikey_account_hourly_cap_blocks_sixth() {
    let mut cfg = test_config();
    cfg.apikey_register_rate = 1000.0;
    cfg.apikey_register_burst = 1000;
    cfg.apikey_register_account_max_per_hour = 5;
    cfg.apikey_register_account_max_per_day = 100;
    cfg.apikey_register_ip_max_per_hour = 100;
    cfg.apikey_register_ip_max_per_day = 100;
    let app = test_app_with_store(Arc::new(MemStore::default()), cfg);
    let session_token = passkey_register_flow(&app, "Eve", "cred-e").await;

    for i in 0..5u8 {
        let tok = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([i; 32]);
        let resp = register_apikey(&app, &session_token, &tok).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
    let sixth = register_apikey(
        &app,
        &session_token,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([99u8; 32]),
    )
    .await;
    assert_eq!(sixth.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn register_apikey_account_daily_cap_blocks_twenty_first() {
    let mut cfg = test_config();
    cfg.apikey_register_rate = 1000.0;
    cfg.apikey_register_burst = 1000;
    cfg.apikey_register_account_max_per_hour = 100;
    cfg.apikey_register_account_max_per_day = 20;
    cfg.apikey_register_ip_max_per_hour = 100;
    cfg.apikey_register_ip_max_per_day = 100;
    let app = test_app_with_store(Arc::new(MemStore::default()), cfg);
    let session_token = passkey_register_flow(&app, "Frank", "cred-f").await;

    for i in 0..20u8 {
        let tok = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([i; 32]);
        let resp = register_apikey(&app, &session_token, &tok).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
    let twenty_first = register_apikey(
        &app,
        &session_token,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([200u8; 32]),
    )
    .await;
    assert_eq!(twenty_first.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn register_apikey_ip_hourly_and_daily_caps_are_enforced() {
    let mut cfg_hour = test_config();
    cfg_hour.apikey_register_rate = 1000.0;
    cfg_hour.apikey_register_burst = 1000;
    cfg_hour.apikey_register_account_max_per_hour = 100;
    cfg_hour.apikey_register_account_max_per_day = 100;
    cfg_hour.apikey_register_ip_max_per_hour = 5;
    cfg_hour.apikey_register_ip_max_per_day = 100;
    let app_hour = test_app_with_store(Arc::new(MemStore::default()), cfg_hour);
    let session_hour = passkey_register_flow(&app_hour, "Grace", "cred-g").await;

    for i in 0..5u8 {
        let tok = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([i; 32]);
        let resp = register_apikey(&app_hour, &session_hour, &tok).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
    let sixth = register_apikey(
        &app_hour,
        &session_hour,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([55u8; 32]),
    )
    .await;
    assert_eq!(sixth.status(), StatusCode::TOO_MANY_REQUESTS);

    let mut cfg_day = test_config();
    cfg_day.apikey_register_rate = 1000.0;
    cfg_day.apikey_register_burst = 1000;
    cfg_day.apikey_register_account_max_per_hour = 100;
    cfg_day.apikey_register_account_max_per_day = 100;
    cfg_day.apikey_register_ip_max_per_hour = 100;
    cfg_day.apikey_register_ip_max_per_day = 20;
    let app_day = test_app_with_store(Arc::new(MemStore::default()), cfg_day);
    let session_day = passkey_register_flow(&app_day, "Heidi", "cred-h").await;

    for i in 0..20u8 {
        let tok = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([i; 32]);
        let resp = register_apikey(&app_day, &session_day, &tok).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
    let twenty_first = register_apikey(
        &app_day,
        &session_day,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([201u8; 32]),
    )
    .await;
    assert_eq!(twenty_first.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn auth_session_rejects_tampered_token_secret() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let session_token = passkey_register_flow(&app, "Ivan", "cred-i").await;
    let mut parts = session_token.trim_start_matches("uss_").split('.');
    let sid = parts.next().expect("sid");
    let tampered = format!("uss_{sid}.tampered");

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/session")
        .header("authorization", format!("Bearer {tampered}"))
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    let body = response_json(resp).await;
    assert_eq!(body["authenticated"].as_bool(), Some(false));
}

#[tokio::test]
async fn logout_rejects_tampered_token_secret_and_preserves_session() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let session_token = passkey_register_flow(&app, "Ivy", "cred-ivy").await;

    let mut parts = session_token.trim_start_matches("uss_").split('.');
    let sid = parts.next().expect("sid");
    let tampered = format!("uss_{sid}.tampered");

    let logout_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header("authorization", format!("Bearer {tampered}"))
        .body(Body::empty())
        .expect("request");
    let logout_resp = app.clone().oneshot(logout_req).await.expect("response");
    assert_eq!(logout_resp.status(), StatusCode::UNAUTHORIZED);

    let session_req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/session")
        .header("authorization", format!("Bearer {session_token}"))
        .body(Body::empty())
        .expect("request");
    let session_resp = app.clone().oneshot(session_req).await.expect("response");
    let body = response_json(session_resp).await;
    assert_eq!(body["authenticated"].as_bool(), Some(true));
    assert!(body.get("user_id").is_none());
}

#[tokio::test]
async fn passkey_login_start_rejects_revoked_passkey() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let _ = passkey_register_flow(&app, "Judy", "cred-j").await;
    {
        let mut passkeys = store.passkeys.lock().expect("passkeys mutex");
        let p = passkeys.get_mut("cred-j").expect("passkey");
        p.revoked_at = Some(Utc::now());
    }

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/login/start")
        .header("content-type", "application/json")
        .body(Body::from(json!({"credential_id":"cred-j"}).to_string()))
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn passkey_login_finish_uses_challenge_id_bearer_semantics_in_v1() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());
    let _ = passkey_register_flow(&app, "Kara", "cred-kara").await;

    // v1 semantics are challenge-id bearer based: unknown challenge_id fails even
    // when credential_id is valid.
    let missing_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/login/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": "missing",
                "credential_id": "cred-kara"
            })
            .to_string(),
        ))
        .expect("request");
    let missing_resp = app.clone().oneshot(missing_req).await.expect("response");
    assert_eq!(missing_resp.status(), StatusCode::BAD_REQUEST);

    let challenge_id = passkey_login_start_only(&app, "cred-kara").await;
    let ok_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/login/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": challenge_id,
                "credential_id": "cred-kara"
            })
            .to_string(),
        ))
        .expect("request");
    let ok_resp = app.clone().oneshot(ok_req).await.expect("response");
    assert_eq!(ok_resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn passkey_finish_paths_cover_mismatch_revoked_and_bad_challenge_json() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let _ = passkey_register_flow(&app, "Kim", "cred-k").await;

    let mismatch_challenge = passkey_login_start_only(&app, "cred-k").await;
    let mismatch_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/login/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": mismatch_challenge,
                "credential_id": "cred-other"
            })
            .to_string(),
        ))
        .expect("request");
    let mismatch_resp = app.clone().oneshot(mismatch_req).await.expect("response");
    assert_eq!(mismatch_resp.status(), StatusCode::UNAUTHORIZED);

    let revoked_challenge = passkey_login_start_only(&app, "cred-k").await;
    {
        let mut passkeys = store.passkeys.lock().expect("passkeys mutex");
        let p = passkeys.get_mut("cred-k").expect("passkey");
        p.revoked_at = Some(Utc::now());
    }
    let revoked_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/login/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": revoked_challenge,
                "credential_id": "cred-k"
            })
            .to_string(),
        ))
        .expect("request");
    let revoked_resp = app.clone().oneshot(revoked_req).await.expect("response");
    assert_eq!(revoked_resp.status(), StatusCode::UNAUTHORIZED);

    {
        let mut challenges = store.challenges.lock().expect("challenges mutex");
        challenges.insert(
            "bad-json-login".into(),
            secrt_server::storage::ChallengeRecord {
                id: 999,
                challenge_id: "bad-json-login".into(),
                user_id: None,
                purpose: "passkey-login".into(),
                challenge_json: "{not-json".into(),
                expires_at: Utc::now() + Duration::minutes(10),
                created_at: Utc::now(),
            },
        );
    }
    let bad_json_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/login/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": "bad-json-login",
                "credential_id": "cred-k"
            })
            .to_string(),
        ))
        .expect("request");
    let bad_json_resp = app.clone().oneshot(bad_json_req).await.expect("response");
    assert_eq!(bad_json_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn passkey_register_finish_bad_challenge_json_and_session_pepper_error() {
    let store_bad_json = Arc::new(MemStore::default());
    let app_bad_json = test_app_with_store(store_bad_json.clone(), test_config());
    {
        let mut challenges = store_bad_json.challenges.lock().expect("challenges mutex");
        challenges.insert(
            "bad-json-register".into(),
            secrt_server::storage::ChallengeRecord {
                id: 1001,
                challenge_id: "bad-json-register".into(),
                user_id: None,
                purpose: "passkey-register".into(),
                challenge_json: "{not-json".into(),
                expires_at: Utc::now() + Duration::minutes(10),
                created_at: Utc::now(),
            },
        );
    }
    let bad_json_finish = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/register/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": "bad-json-register",
                "credential_id": "cred-rj",
                "public_key": "pk-rj"
            })
            .to_string(),
        ))
        .expect("request");
    let bad_json_resp = app_bad_json
        .clone()
        .oneshot(bad_json_finish)
        .await
        .expect("response");
    assert_eq!(bad_json_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let mut cfg = test_config();
    cfg.session_token_pepper = String::new();
    let app_bad_pepper = test_app_with_store(Arc::new(MemStore::default()), cfg);
    let start_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/register/start")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "display_name": "Liam",
            })
            .to_string(),
        ))
        .expect("request");
    let start_resp = app_bad_pepper
        .clone()
        .oneshot(start_req)
        .await
        .expect("response");
    assert_eq!(start_resp.status(), StatusCode::OK);
    let start_json = response_json(start_resp).await;
    let challenge_id = start_json["challenge_id"].as_str().expect("challenge id");

    let finish_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/passkeys/register/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": challenge_id,
                "credential_id": "cred-liam",
                "public_key": "pk-liam",
            })
            .to_string(),
        ))
        .expect("request");
    let finish_resp = app_bad_pepper
        .clone()
        .oneshot(finish_req)
        .await
        .expect("response");
    assert_eq!(finish_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn logout_unknown_sid_and_apikey_register_rate_limit_and_validation() {
    let app = test_app_with_store(Arc::new(MemStore::default()), test_config());
    let logout_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header("authorization", "Bearer uss_missing.secret")
        .body(Body::empty())
        .expect("request");
    let logout_resp = app.clone().oneshot(logout_req).await.expect("response");
    assert_eq!(logout_resp.status(), StatusCode::UNAUTHORIZED);

    let mut cfg_rate = test_config();
    cfg_rate.apikey_register_rate = 0.0;
    cfg_rate.apikey_register_burst = 0;
    let app_rate = test_app_with_store(Arc::new(MemStore::default()), cfg_rate);
    let session_token = passkey_register_flow(&app_rate, "Mia", "cred-mia").await;
    let auth_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32]);
    let limited = register_apikey(&app_rate, &session_token, &auth_token).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

    let app_validation = test_app_with_store(Arc::new(MemStore::default()), test_config());
    let session_token_validation = passkey_register_flow(&app_validation, "Nia", "cred-nia").await;
    let bad_ct_req = Request::builder()
        .method("POST")
        .uri("/api/v1/apikeys/register")
        .header(
            "authorization",
            format!("Bearer {session_token_validation}"),
        )
        .header("content-type", "text/plain")
        .body(Body::from("bad"))
        .expect("request");
    let bad_ct_resp = app_validation
        .clone()
        .oneshot(with_remote(bad_ct_req, [198, 51, 100, 42], 4242))
        .await
        .expect("response");
    assert_eq!(bad_ct_resp.status(), StatusCode::BAD_REQUEST);

    let mut cfg_pepper = test_config();
    cfg_pepper.api_key_pepper = String::new();
    let app_bad_pepper = test_app_with_store(Arc::new(MemStore::default()), cfg_pepper);
    let session_token_bad_pepper =
        passkey_register_flow(&app_bad_pepper, "Omar", "cred-omar").await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/apikeys/register")
        .header(
            "authorization",
            format!("Bearer {session_token_bad_pepper}"),
        )
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "auth_token": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([3u8; 32]),
            })
            .to_string(),
        ))
        .expect("request");
    let resp = app_bad_pepper
        .clone()
        .oneshot(with_remote(req, [198, 51, 100, 43], 4343))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn authed_routes_accept_ak2_and_reject_legacy_sk() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let (api_key, _) = create_api_key(&store, "pepper").await;

    let info_ok = Request::builder()
        .method("GET")
        .uri("/api/v1/info")
        .header("x-api-key", api_key.clone())
        .body(Body::empty())
        .expect("request");
    let info_ok_resp = app.clone().oneshot(info_ok).await.expect("response");
    let info_ok_json = response_json(info_ok_resp).await;
    assert_eq!(info_ok_json["authenticated"].as_bool(), Some(true));

    let info_legacy = Request::builder()
        .method("GET")
        .uri("/api/v1/info")
        .header("x-api-key", "sk_legacy.old")
        .body(Body::empty())
        .expect("request");
    let info_legacy_resp = app.clone().oneshot(info_legacy).await.expect("response");
    let info_legacy_json = response_json(info_legacy_resp).await;
    assert_eq!(info_legacy_json["authenticated"].as_bool(), Some(false));

    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");
    let create_legacy = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets")
        .header("x-api-key", "sk_legacy.old")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "envelope": {"ct":"x"},
                "claim_hash": claim_hash
            })
            .to_string(),
        ))
        .expect("request");
    let create_legacy_resp = app.clone().oneshot(create_legacy).await.expect("response");
    assert_eq!(create_legacy_resp.status(), StatusCode::UNAUTHORIZED);
}
