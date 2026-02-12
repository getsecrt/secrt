mod helpers;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine;
use helpers::{create_api_key, test_app_with_store, test_config, with_proxy_ip, MemStore};
use serde_json::Value;
use tower::ServiceExt;

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn public_secret_count_quota_exceeded() {
    let mut cfg = test_config();
    cfg.public_max_secrets = 2;
    cfg.public_create_rate = 1_000_000.0;
    cfg.public_create_burst = 1_000_000;

    let app = test_app_with_store(Arc::new(MemStore::default()), cfg);

    for _ in 0..2 {
        let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([6u8; 32]);
        let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/public/secrets")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "envelope": {"ct":"quota"},
                    "claim_hash": claim_hash,
                })
                .to_string(),
            ))
            .expect("request");

        let resp = app
            .clone()
            .oneshot(with_proxy_ip(req, [127, 0, 0, 1], "10.0.0.1"))
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "envelope": {"ct":"quota"},
                "claim_hash": claim_hash,
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app
        .clone()
        .oneshot(with_proxy_ip(req, [127, 0, 0, 1], "10.0.0.1"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    let body = body_json(resp).await;
    assert!(body["error"]
        .as_str()
        .expect("error")
        .contains("secret limit exceeded"));
}

#[tokio::test]
async fn public_total_bytes_quota_exceeded() {
    let mut cfg = test_config();
    cfg.public_max_total_bytes = 90;
    cfg.public_create_rate = 1_000_000.0;
    cfg.public_create_burst = 1_000_000;

    let app = test_app_with_store(Arc::new(MemStore::default()), cfg);

    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([8u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "envelope": {"ct":"small"},
                "claim_hash": claim_hash,
            })
            .to_string(),
        ))
        .expect("request");
    let first = app
        .clone()
        .oneshot(with_proxy_ip(req, [127, 0, 0, 1], "10.0.0.2"))
        .await
        .expect("response");
    assert_eq!(first.status(), StatusCode::CREATED);

    let claim2 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]);
    let claim_hash2 = secrt_core::hash_claim_token(&claim2).expect("claim hash");
    let big_ct = "x".repeat(120);
    let req2 = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "envelope": {"ct": big_ct},
                "claim_hash": claim_hash2,
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app
        .clone()
        .oneshot(with_proxy_ip(req2, [127, 0, 0, 1], "10.0.0.2"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn authed_quota_higher_than_public() {
    let mut cfg = test_config();
    cfg.public_max_secrets = 1;
    cfg.authed_max_secrets = 5;

    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), cfg);
    let (api_key, _) = create_api_key(&store, "pepper").await;

    for _ in 0..3 {
        let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([11u8; 32]);
        let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/secrets")
            .header("content-type", "application/json")
            .header("x-api-key", api_key.clone())
            .body(Body::from(
                serde_json::json!({
                    "envelope": {"ct":"authed"},
                    "claim_hash": claim_hash,
                })
                .to_string(),
            ))
            .expect("request");

        let resp = app.clone().oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
}

#[tokio::test]
async fn public_rate_limit_burst() {
    let cfg = test_config();
    let app = test_app_with_store(Arc::new(MemStore::default()), cfg);

    for i in 0..6 {
        let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([i as u8 + 20; 32]);
        let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/public/secrets")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "envelope": {"ct":"rate"},
                    "claim_hash": claim_hash,
                })
                .to_string(),
            ))
            .expect("request");
        let resp = app
            .clone()
            .oneshot(with_proxy_ip(req, [127, 0, 0, 1], "203.0.113.10"))
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::CREATED, "req {i}");
    }

    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([99u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "envelope": {"ct":"rate"},
                "claim_hash": claim_hash,
            })
            .to_string(),
        ))
        .expect("request");
    let resp = app
        .clone()
        .oneshot(with_proxy_ip(req, [127, 0, 0, 1], "203.0.113.10"))
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        resp.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("10")
    );
}

#[tokio::test]
async fn claim_rate_limit_after_burst() {
    let app = test_app_with_store(Arc::new(MemStore::default()), test_config());
    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([44u8; 16]);

    for i in 0..10 {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/secrets/missing/claim")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "claim": claim }).to_string(),
            ))
            .expect("request");
        let resp = app
            .clone()
            .oneshot(with_proxy_ip(req, [127, 0, 0, 1], "203.0.113.99"))
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "req {i}");
    }

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets/missing/claim")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "claim": claim }).to_string(),
        ))
        .expect("request");
    let resp = app
        .clone()
        .oneshot(with_proxy_ip(req, [127, 0, 0, 1], "203.0.113.99"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn quota_resets_after_claim() {
    let mut cfg = test_config();
    cfg.public_max_secrets = 1;
    cfg.public_create_rate = 1_000_000.0;
    cfg.public_create_burst = 1_000_000;

    let app = test_app_with_store(Arc::new(MemStore::default()), cfg);
    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([120u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");

    let create_req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "envelope": {"ct":"first"},
                "claim_hash": claim_hash,
            })
            .to_string(),
        ))
        .expect("request");
    let create_resp = app
        .clone()
        .oneshot(with_proxy_ip(create_req, [127, 0, 0, 1], "10.0.0.9"))
        .await
        .expect("response");
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let body = body_json(create_resp).await;
    let id = body["id"].as_str().expect("id");

    let second_create = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "envelope": {"ct":"blocked"},
                "claim_hash": claim_hash,
            })
            .to_string(),
        ))
        .expect("request");
    let blocked = app
        .clone()
        .oneshot(with_proxy_ip(second_create, [127, 0, 0, 1], "10.0.0.9"))
        .await
        .expect("response");
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);

    let claim_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/secrets/{id}/claim"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "claim": claim }).to_string(),
        ))
        .expect("request");
    let claim_resp = app
        .clone()
        .oneshot(with_proxy_ip(claim_req, [127, 0, 0, 1], "10.0.0.10"))
        .await
        .expect("response");
    assert_eq!(claim_resp.status(), StatusCode::OK);

    let third_create = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "envelope": {"ct":"after-claim"},
                "claim_hash": claim_hash,
            })
            .to_string(),
        ))
        .expect("request");
    let allowed = app
        .clone()
        .oneshot(with_proxy_ip(third_create, [127, 0, 0, 1], "10.0.0.9"))
        .await
        .expect("response");
    assert_eq!(allowed.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn quota_zero_limits_mean_unlimited() {
    let mut cfg = test_config();
    cfg.public_max_secrets = 0;
    cfg.public_max_total_bytes = 0;
    cfg.public_create_rate = 1_000_000.0;
    cfg.public_create_burst = 1_000_000;

    let app = test_app_with_store(Arc::new(MemStore::default()), cfg);
    for i in 0..20 {
        let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([i as u8 + 150; 32]);
        let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/public/secrets")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "envelope": {"ct": format!("free-{i}")},
                    "claim_hash": claim_hash,
                })
                .to_string(),
            ))
            .expect("request");
        let resp = app
            .clone()
            .oneshot(with_proxy_ip(req, [127, 0, 0, 1], "10.0.1.1"))
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::CREATED, "iteration {i}");
    }
}

#[tokio::test]
async fn public_envelope_near_max_size_allowed() {
    let mut cfg = test_config();
    cfg.public_max_envelope_bytes = 220;
    cfg.public_create_rate = 1_000_000.0;
    cfg.public_create_burst = 1_000_000;

    let app = test_app_with_store(Arc::new(MemStore::default()), cfg);
    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([200u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");
    let ct = "x".repeat(170);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "envelope": {"ct": ct},
                "claim_hash": claim_hash
            })
            .to_string(),
        ))
        .expect("request");

    let resp = app
        .clone()
        .oneshot(with_proxy_ip(req, [127, 0, 0, 1], "10.0.2.1"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::CREATED);
}
