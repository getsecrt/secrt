mod helpers;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine;
use helpers::{
    create_api_key, test_app_with_store, test_config, test_state_and_app, with_proxy_ip,
    with_remote, MemStore,
};
use serde_json::Value;
use tower::ServiceExt;

async fn response_body_text(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    String::from_utf8(bytes.to_vec()).expect("utf8 body")
}

async fn create_public(
    app: &axum::Router,
    claim_hash: &str,
    envelope: &str,
) -> axum::response::Response {
    let body = serde_json::json!({
        "envelope": serde_json::from_str::<Value>(envelope).expect("envelope json"),
        "claim_hash": claim_hash,
    })
    .to_string();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("request");

    app.clone()
        .oneshot(with_proxy_ip(req, [127, 0, 0, 1], "203.0.113.44"))
        .await
        .expect("response")
}

#[tokio::test]
async fn public_create_and_claim_flow() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());

    let claim_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim_token).expect("claim hash");

    let create_resp = create_public(&app, &claim_hash, "{\"ct\":\"hello\"}").await;
    assert_eq!(create_resp.status(), StatusCode::CREATED);

    let create_body: Value =
        serde_json::from_str(&response_body_text(create_resp).await).expect("json");
    let id = create_body["id"].as_str().expect("id");

    let claim_body = serde_json::json!({ "claim": claim_token }).to_string();
    let claim_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/secrets/{id}/claim"))
        .header("content-type", "application/json")
        .body(Body::from(claim_body.clone()))
        .expect("request");

    let claim_resp = app
        .clone()
        .oneshot(with_remote(claim_req, [203, 0, 113, 10], 5555))
        .await
        .expect("response");
    assert_eq!(claim_resp.status(), StatusCode::OK);

    let claim_req2 = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/secrets/{id}/claim"))
        .header("content-type", "application/json")
        .body(Body::from(claim_body))
        .expect("request");

    let second_resp = app
        .clone()
        .oneshot(with_remote(claim_req2, [203, 0, 113, 10], 5555))
        .await
        .expect("response");
    assert_eq!(second_resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn wrong_claim_then_right_claim() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());

    let good_claim_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([8u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&good_claim_token).expect("claim hash");

    let create_resp = create_public(&app, &claim_hash, "{\"ct\":\"mine\"}").await;
    let create_body: Value =
        serde_json::from_str(&response_body_text(create_resp).await).expect("json");
    let id = create_body["id"].as_str().expect("id");

    let wrong_claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]);
    let wrong_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/secrets/{id}/claim"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "claim": wrong_claim }).to_string(),
        ))
        .expect("request");
    let wrong_resp = app
        .clone()
        .oneshot(with_remote(wrong_req, [203, 0, 113, 55], 4444))
        .await
        .expect("response");
    assert_eq!(wrong_resp.status(), StatusCode::NOT_FOUND);

    let right_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/secrets/{id}/claim"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "claim": good_claim_token }).to_string(),
        ))
        .expect("request");
    let right_resp = app
        .clone()
        .oneshot(with_remote(right_req, [203, 0, 113, 55], 4444))
        .await
        .expect("response");
    assert_eq!(right_resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn authed_create_requires_api_key() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());

    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");
    let payload = serde_json::json!({
        "envelope": {"ct":"x"},
        "claim_hash": claim_hash,
    })
    .to_string();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets")
        .header("content-type", "application/json")
        .body(Body::from(payload.clone()))
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let (api_key, _) = create_api_key(&store, "pepper").await;

    let req2 = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets")
        .header("content-type", "application/json")
        .header("x-api-key", api_key)
        .body(Body::from(payload))
        .expect("request");
    let resp2 = app.clone().oneshot(req2).await.expect("response");
    assert_eq!(resp2.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn info_endpoint_authenticated_and_cache_header() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/info")
        .body(Body::empty())
        .expect("request");
    let resp = app
        .clone()
        .oneshot(with_remote(req, [198, 51, 100, 2], 1234))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("public, max-age=300")
    );

    let body: Value = serde_json::from_str(&response_body_text(resp).await).expect("json");
    assert_eq!(body["authenticated"], Value::Bool(false));

    let (api_key, _) = create_api_key(&store, "pepper").await;
    let req2 = Request::builder()
        .method("GET")
        .uri("/api/v1/info")
        .header("x-api-key", api_key)
        .body(Body::empty())
        .expect("request");
    let resp2 = app
        .clone()
        .oneshot(with_remote(req2, [198, 51, 100, 2], 1234))
        .await
        .expect("response");
    assert_eq!(
        resp2
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("private, no-store"),
        "authenticated /info must not be publicly cacheable"
    );
    assert_eq!(
        resp2
            .headers()
            .get("vary")
            .and_then(|v| v.to_str().ok()),
        Some("Authorization, X-API-Key"),
        "authenticated /info must include Vary header"
    );
    let body2: Value = serde_json::from_str(&response_body_text(resp2).await).expect("json");
    assert_eq!(body2["authenticated"], Value::Bool(true));
}

#[tokio::test]
async fn create_validation_and_content_type_errors() {
    let app = test_app_with_store(Arc::new(MemStore::default()), test_config());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "text/plain")
        .body(Body::from("{}"))
        .expect("request");
    let resp = app
        .clone()
        .oneshot(with_remote(req, [203, 0, 113, 10], 4444))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from("{"))
        .expect("request");
    let resp = app
        .clone()
        .oneshot(with_remote(req, [203, 0, 113, 10], 4444))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"envelope": [], "claim_hash": "abc"}).to_string(),
        ))
        .expect("request");
    let resp = app
        .clone()
        .oneshot(with_remote(req, [203, 0, 113, 10], 4444))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_accepts_json_content_type_with_charset() {
    let app = test_app_with_store(Arc::new(MemStore::default()), test_config());
    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json; charset=utf-8")
        .body(Body::from(
            serde_json::json!({
                "envelope": {"ct":"charset"},
                "claim_hash": claim_hash
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app
        .clone()
        .oneshot(with_remote(req, [203, 0, 113, 12], 4444))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn claim_validation_and_not_found_masking() {
    let app = test_app_with_store(Arc::new(MemStore::default()), test_config());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets/missing/claim")
        .header("content-type", "application/json")
        .body(Body::from("{\"claim\":\"not*b64\"}"))
        .expect("request");
    let resp = app
        .clone()
        .oneshot(with_remote(req, [203, 0, 113, 10], 5555))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets/missing/claim")
        .header("content-type", "application/json")
        .body(Body::from("{\"claim\":\"   \"}"))
        .expect("request");
    let resp = app
        .clone()
        .oneshot(with_remote(req, [203, 0, 113, 10], 5555))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn burn_flow_and_owner_scope() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());

    let (api_key, prefix) = create_api_key(&store, "pepper").await;
    let (other_key, _) = create_api_key(&store, "pepper").await;

    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([3u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");

    let create_payload = serde_json::json!({
        "envelope": {"ct":"burn"},
        "claim_hash": claim_hash,
    })
    .to_string();

    let create_req = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets")
        .header("content-type", "application/json")
        .header("x-api-key", api_key.clone())
        .body(Body::from(create_payload))
        .expect("request");
    let create_resp = app.clone().oneshot(create_req).await.expect("response");
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let create_json: Value =
        serde_json::from_str(&response_body_text(create_resp).await).expect("json");
    let id = create_json["id"].as_str().expect("id").to_string();

    let burn_req_wrong = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/secrets/{id}/burn"))
        .header("x-api-key", other_key)
        .body(Body::empty())
        .expect("request");
    let burn_wrong = app.clone().oneshot(burn_req_wrong).await.expect("response");
    assert_eq!(burn_wrong.status(), StatusCode::NOT_FOUND);

    let burn_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/secrets/{id}/burn"))
        .header("x-api-key", api_key)
        .body(Body::empty())
        .expect("request");
    let burn_resp = app.clone().oneshot(burn_req).await.expect("response");
    assert_eq!(burn_resp.status(), StatusCode::OK);

    // Ensure secret really gone.
    let claim_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/secrets/{id}/claim"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"claim": claim}).to_string()))
        .expect("request");
    let claim_resp = app
        .clone()
        .oneshot(with_remote(claim_req, [198, 51, 100, 4], 4444))
        .await
        .expect("response");
    assert_eq!(claim_resp.status(), StatusCode::NOT_FOUND);

    assert!(prefix.len() >= 8);
}

#[tokio::test]
async fn method_not_allowed_and_headers() {
    let app = test_app_with_store(Arc::new(MemStore::default()), test_config());

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/public/secrets")
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    // Security headers and request-id should be present on all responses.
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        resp.headers()
            .get("referrer-policy")
            .and_then(|v| v.to_str().ok()),
        Some("no-referrer")
    );
    assert_eq!(
        resp.headers()
            .get("x-frame-options")
            .and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert!(resp.headers().get("x-request-id").is_some());
}

#[tokio::test]
async fn page_and_robots_routes() {
    let app = test_app_with_store(Arc::new(MemStore::default()), test_config());

    let idx = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");
    assert_eq!(idx.status(), StatusCode::OK);

    let robots = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/robots.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");
    assert_eq!(robots.status(), StatusCode::OK);

    let secret = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/s/example-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");
    assert_eq!(secret.status(), StatusCode::OK);
    assert_eq!(
        secret
            .headers()
            .get("x-robots-tag")
            .and_then(|v| v.to_str().ok()),
        Some("noindex")
    );
}

#[tokio::test]
async fn incoming_request_id_is_echoed() {
    let app = test_app_with_store(Arc::new(MemStore::default()), test_config());
    let req = Request::builder()
        .method("GET")
        .uri("/healthz")
        .header("x-request-id", "req-123")
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(
        resp.headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok()),
        Some("req-123")
    );
}

#[tokio::test]
async fn healthz_route_returns_ok_payload() {
    let app = test_app_with_store(Arc::new(MemStore::default()), test_config());
    let req = Request::builder()
        .method("GET")
        .uri("/healthz")
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = serde_json::from_str(&response_body_text(resp).await).expect("json");
    assert_eq!(body["ok"], Value::Bool(true));
    assert!(body["time"].as_str().is_some());
}

#[tokio::test]
async fn privacy_check_triggers_on_first_proxied_request() {
    let (state, app) = test_state_and_app(Arc::new(MemStore::default()), test_config());
    assert!(!state
        .privacy_checked
        .load(std::sync::atomic::Ordering::Relaxed));

    let req = Request::builder()
        .method("GET")
        .uri("/healthz")
        .header("x-forwarded-for", "203.0.113.9")
        .body(Body::empty())
        .expect("request");
    let _ = app
        .clone()
        .oneshot(with_remote(req, [127, 0, 0, 1], 9999))
        .await
        .expect("response");

    assert!(state
        .privacy_checked
        .load(std::sync::atomic::Ordering::Relaxed));
}

#[tokio::test]
async fn concurrent_claim_only_one_succeeds() {
    let app = test_app_with_store(Arc::new(MemStore::default()), test_config());

    let claim_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([41u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim_token).expect("claim hash");
    let create_resp = create_public(&app, &claim_hash, "{\"ct\":\"racy\"}").await;
    let create_body: Value =
        serde_json::from_str(&response_body_text(create_resp).await).expect("json");
    let id = create_body["id"].as_str().expect("id").to_string();

    let mut tasks = Vec::new();
    for i in 0..8 {
        let app = app.clone();
        let id = id.clone();
        let claim_token = claim_token.clone();
        tasks.push(tokio::spawn(async move {
            let req = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/secrets/{id}/claim"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "claim": claim_token }).to_string(),
                ))
                .expect("request");
            app.oneshot(with_remote(req, [198, 51, 100, 80 + i], 3333))
                .await
                .expect("response")
                .status()
        }));
    }

    let mut ok = 0;
    let mut not_found = 0;
    for task in tasks {
        match task.await.expect("join") {
            StatusCode::OK => ok += 1,
            StatusCode::NOT_FOUND => not_found += 1,
            other => panic!("unexpected status {other}"),
        }
    }

    assert_eq!(ok, 1);
    assert_eq!(not_found, 7);
}

#[tokio::test]
async fn concurrent_create_generates_unique_ids() {
    let mut cfg = test_config();
    cfg.public_create_rate = 1_000_000.0;
    cfg.public_create_burst = 1_000_000;
    cfg.public_max_secrets = 10_000;
    cfg.public_max_total_bytes = 128 * 1024 * 1024;
    let app = test_app_with_store(Arc::new(MemStore::default()), cfg);

    let mut tasks = Vec::new();
    for i in 0..24usize {
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([i as u8; 32]);
            let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");
            let req = Request::builder()
                .method("POST")
                .uri("/api/v1/public/secrets")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "envelope": {"ct": format!("blob-{i}")},
                        "claim_hash": claim_hash,
                    })
                    .to_string(),
                ))
                .expect("request");
            app.oneshot(with_remote(req, [203, 0, 113, 80], 9999))
                .await
                .expect("response")
        }));
    }

    let mut ids = std::collections::HashSet::new();
    for task in tasks {
        let resp = task.await.expect("join");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body: Value = serde_json::from_str(&response_body_text(resp).await).expect("json");
        let id = body["id"].as_str().expect("id").to_string();
        assert!(ids.insert(id), "duplicate id generated");
    }
}

#[tokio::test]
async fn binary_payload_envelope_roundtrip() {
    let app = test_app_with_store(Arc::new(MemStore::default()), test_config());
    let claim_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([91u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim_token).expect("claim hash");
    let envelope = serde_json::json!({
        "v": 1,
        "mime": "image/png",
        "name": "pixel.png",
        "note": "contains null-byte and binary-safe text",
        "blob_b64u": "AAECAwQFBgcICQoLDA0ODw",
        "meta": {
            "fields": ["a", "b", "c"],
            "checksum": "deadbeef"
        }
    })
    .to_string();

    let create_resp = create_public(&app, &claim_hash, &envelope).await;
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let create_json: Value =
        serde_json::from_str(&response_body_text(create_resp).await).expect("json");
    let id = create_json["id"].as_str().expect("id").to_string();

    let claim_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/secrets/{id}/claim"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "claim": claim_token }).to_string(),
        ))
        .expect("request");
    let claim_resp = app
        .clone()
        .oneshot(with_remote(claim_req, [203, 0, 113, 81], 9999))
        .await
        .expect("response");
    assert_eq!(claim_resp.status(), StatusCode::OK);

    let claim_json: Value =
        serde_json::from_str(&response_body_text(claim_resp).await).expect("json");
    assert_eq!(
        claim_json["envelope"],
        serde_json::from_str::<Value>(&envelope).unwrap()
    );
}
