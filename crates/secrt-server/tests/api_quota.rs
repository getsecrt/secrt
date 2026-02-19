mod helpers;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine;
use chrono::{DateTime, Utc};
use helpers::{create_api_key, test_app_with_store, test_config, with_proxy_ip, MemStore};
use secrt_server::http::{build_router, AppState};
use secrt_server::storage::{
    AmkStore, ApiKeysStore, AuthStore, SecretQuotaLimits, SecretRecord, SecretSummary,
    SecretsStore, StorageError, StorageUsage,
};
use serde_json::Value;
use tokio::sync::Barrier;
use tower::ServiceExt;

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    serde_json::from_slice(&bytes).expect("json")
}

struct QuotaRaceStore {
    secrets: Mutex<HashMap<String, SecretRecord>>,
    usage_barrier: Barrier,
}

impl QuotaRaceStore {
    fn new(expected_concurrent_checks: usize) -> Self {
        assert!(expected_concurrent_checks > 0);
        Self {
            secrets: Mutex::new(HashMap::new()),
            usage_barrier: Barrier::new(expected_concurrent_checks),
        }
    }
}

#[async_trait]
impl SecretsStore for QuotaRaceStore {
    async fn create(&self, secret: SecretRecord) -> Result<(), StorageError> {
        let mut m = self.secrets.lock().expect("secrets mutex poisoned");
        if m.contains_key(&secret.id) {
            return Err(StorageError::DuplicateId);
        }
        m.insert(secret.id.clone(), secret);
        Ok(())
    }

    async fn create_with_quota(
        &self,
        secret: SecretRecord,
        limits: SecretQuotaLimits,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        // Keep requests aligned so contention is deterministic.
        self.usage_barrier.wait().await;

        let mut m = self.secrets.lock().expect("secrets mutex poisoned");
        if limits.max_secrets > 0 || limits.max_total_bytes > 0 {
            let mut usage = StorageUsage {
                secret_count: 0,
                total_bytes: 0,
            };
            for s in m.values() {
                if s.owner_key == secret.owner_key && s.expires_at > now {
                    usage.secret_count += 1;
                    usage.total_bytes += s.envelope.len() as i64;
                }
            }

            if limits.max_secrets > 0 && usage.secret_count >= limits.max_secrets {
                return Err(StorageError::QuotaExceeded("secret_count".into()));
            }

            if limits.max_total_bytes > 0
                && usage.total_bytes + secret.envelope.len() as i64 > limits.max_total_bytes
            {
                return Err(StorageError::QuotaExceeded("total_bytes".into()));
            }
        }

        if m.contains_key(&secret.id) {
            return Err(StorageError::DuplicateId);
        }
        m.insert(secret.id.clone(), secret);
        Ok(())
    }

    async fn claim_and_delete(
        &self,
        id: &str,
        claim_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<SecretRecord, StorageError> {
        let mut m = self.secrets.lock().expect("secrets mutex poisoned");
        let Some(s) = m.get(id).cloned() else {
            return Err(StorageError::NotFound);
        };

        if s.claim_hash != claim_hash {
            return Err(StorageError::NotFound);
        }

        if s.expires_at <= now {
            m.remove(id);
            return Err(StorageError::NotFound);
        }

        m.remove(id).ok_or(StorageError::NotFound)
    }

    async fn burn(&self, id: &str, owner_key: &str) -> Result<bool, StorageError> {
        let mut m = self.secrets.lock().expect("secrets mutex poisoned");
        let Some(s) = m.get(id) else {
            return Ok(false);
        };
        if s.owner_key != owner_key {
            return Ok(false);
        }
        m.remove(id);
        Ok(true)
    }

    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<i64, StorageError> {
        let mut m = self.secrets.lock().expect("secrets mutex poisoned");
        let before = m.len();
        m.retain(|_, s| s.expires_at > now);
        Ok((before - m.len()) as i64)
    }

    async fn get_usage(&self, owner_key: &str) -> Result<StorageUsage, StorageError> {
        let usage = {
            let m = self.secrets.lock().expect("secrets mutex poisoned");
            let mut usage = StorageUsage {
                secret_count: 0,
                total_bytes: 0,
            };

            for s in m.values() {
                if s.owner_key == owner_key {
                    usage.secret_count += 1;
                    usage.total_bytes += s.envelope.len() as i64;
                }
            }

            usage
        };
        Ok(usage)
    }

    async fn list_by_owner_keys(
        &self,
        _owner_keys: &[String],
        _now: DateTime<Utc>,
        _limit: i64,
        _offset: i64,
    ) -> Result<Vec<SecretSummary>, StorageError> {
        Ok(vec![])
    }

    async fn count_by_owner_keys(
        &self,
        _owner_keys: &[String],
        _now: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        Ok(0)
    }

    async fn burn_all_by_owner_keys(&self, _owner_keys: &[String]) -> Result<i64, StorageError> {
        Ok(0)
    }

    async fn checksum_by_owner_keys(
        &self,
        _owner_keys: &[String],
        _now: DateTime<Utc>,
    ) -> Result<(i64, String), StorageError> {
        Ok((0, String::new()))
    }
}

fn test_app_with_custom_secrets(
    secrets: Arc<dyn SecretsStore>,
    aux_store: Arc<MemStore>,
    cfg: secrt_server::config::Config,
) -> axum::Router {
    let api_keys: Arc<dyn ApiKeysStore> = aux_store.clone();
    let auth_store: Arc<dyn AuthStore> = aux_store.clone();
    let amk_store: Arc<dyn AmkStore> = aux_store;
    let state = Arc::new(AppState::new(cfg, secrets, api_keys, auth_store, amk_store));
    build_router(state)
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
async fn public_secret_count_quota_is_atomic_under_concurrency() {
    let mut cfg = test_config();
    cfg.public_max_secrets = 1;
    cfg.public_create_rate = 1_000_000.0;
    cfg.public_create_burst = 1_000_000;

    let concurrent_reqs = 8usize;
    let secrets: Arc<dyn SecretsStore> = Arc::new(QuotaRaceStore::new(concurrent_reqs));
    let app = test_app_with_custom_secrets(secrets, Arc::new(MemStore::default()), cfg);

    let mut set = tokio::task::JoinSet::new();
    for i in 0..concurrent_reqs {
        let app = app.clone();
        set.spawn(async move {
            let claim =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([30u8 + i as u8; 32]);
            let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");
            let req = Request::builder()
                .method("POST")
                .uri("/api/v1/public/secrets")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "envelope": {"ct":"quota-race"},
                        "claim_hash": claim_hash,
                    })
                    .to_string(),
                ))
                .expect("request");

            app.oneshot(with_proxy_ip(req, [127, 0, 0, 1], "203.0.113.55"))
                .await
                .expect("response")
                .status()
        });
    }

    let mut created = 0usize;
    let mut limited = 0usize;
    while let Some(result) = set.join_next().await {
        let status = result.expect("join");
        match status {
            StatusCode::CREATED => created += 1,
            StatusCode::TOO_MANY_REQUESTS => limited += 1,
            other => panic!("unexpected status: {other}"),
        }
    }

    assert_eq!(
        created, 1,
        "quota checks must be atomic with insert under concurrency"
    );
    assert_eq!(limited, concurrent_reqs - 1);
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
