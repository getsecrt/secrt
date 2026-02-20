use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine;
use chrono::{DateTime, Utc};
use secrt_server::config::Config;
use secrt_server::domain::auth::hash_api_key_auth_token;
use secrt_server::http::{build_router, AppState};
use secrt_server::storage::{
    AmkStore, AmkUpsertResult, AmkWrapperRecord, ApiKeyRecord, ApiKeyRegistrationLimits,
    ApiKeysStore, AuthStore, ChallengeRecord, PasskeyRecord, SecretRecord, SecretSummary,
    SecretsStore, SessionRecord, StorageError, StorageUsage, UserId, UserRecord,
};
use tower::ServiceExt;
use uuid::Uuid;

fn cfg() -> Config {
    Config {
        env: "test".into(),
        listen_addr: "127.0.0.1:0".into(),
        public_base_url: "https://example.com".into(),
        log_level: "error".into(),

        database_url: String::new(),
        db_host: "127.0.0.1".into(),
        db_port: 5432,
        db_name: "secrt".into(),
        db_user: "secrt".into(),
        db_password: String::new(),
        db_sslmode: "disable".into(),
        db_sslrootcert: String::new(),

        api_key_pepper: "pepper".into(),
        session_token_pepper: "session-pepper".into(),

        public_max_envelope_bytes: 64,
        authed_max_envelope_bytes: 128,
        public_max_secrets: 10,
        public_max_total_bytes: 1024,
        authed_max_secrets: 1000,
        authed_max_total_bytes: 2048,

        public_create_rate: 1000.0,
        public_create_burst: 1000,
        claim_rate: 1000.0,
        claim_burst: 1000,
        authed_create_rate: 1000.0,
        authed_create_burst: 1000,
        apikey_register_rate: 1000.0,
        apikey_register_burst: 1000,
        apikey_register_account_max_per_hour: 5,
        apikey_register_account_max_per_day: 20,
        apikey_register_ip_max_per_hour: 5,
        apikey_register_ip_max_per_day: 20,
        encrypted_notes_enabled: false,
    }
}

struct ErrStore {
    fail_usage: bool,
    fail_create: bool,
    duplicate_create: bool,
    duplicate_then_ok: AtomicUsize,
    fail_claim: bool,
    claim_invalid_envelope: bool,
    fail_burn: bool,
    key: Option<ApiKeyRecord>,
}

impl Default for ErrStore {
    fn default() -> Self {
        Self {
            fail_usage: false,
            fail_create: false,
            duplicate_create: false,
            duplicate_then_ok: AtomicUsize::new(0),
            fail_claim: false,
            claim_invalid_envelope: false,
            fail_burn: false,
            key: None,
        }
    }
}

#[async_trait]
impl SecretsStore for ErrStore {
    async fn create(&self, _secret: SecretRecord) -> Result<(), StorageError> {
        if self.duplicate_then_ok.load(Ordering::SeqCst) > 0 {
            let prior = self.duplicate_then_ok.fetch_sub(1, Ordering::SeqCst);
            if prior > 0 {
                return Err(StorageError::DuplicateId);
            }
        }
        if self.duplicate_create {
            return Err(StorageError::DuplicateId);
        }
        if self.fail_create {
            Err(StorageError::Other("boom".into()))
        } else {
            Ok(())
        }
    }

    async fn claim_and_delete(
        &self,
        _id: &str,
        _claim_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<SecretRecord, StorageError> {
        if self.claim_invalid_envelope {
            return Ok(SecretRecord {
                id: "id".into(),
                claim_hash: "hash".into(),
                envelope: "{".into(),
                expires_at: Utc::now(),
                created_at: Utc::now(),
                owner_key: "owner".into(),
            });
        }
        if self.fail_claim {
            Err(StorageError::Other("boom".into()))
        } else {
            Err(StorageError::NotFound)
        }
    }

    async fn burn(&self, _id: &str, _owner_key: &str) -> Result<bool, StorageError> {
        if self.fail_burn {
            Err(StorageError::Other("boom".into()))
        } else {
            Ok(false)
        }
    }

    async fn delete_expired(&self, _now: DateTime<Utc>) -> Result<i64, StorageError> {
        Ok(0)
    }

    async fn get_usage(&self, _owner_key: &str) -> Result<StorageUsage, StorageError> {
        if self.fail_usage {
            Err(StorageError::Other("boom".into()))
        } else {
            Ok(StorageUsage {
                secret_count: 0,
                total_bytes: 0,
            })
        }
    }

    async fn list_by_owner_keys(
        &self,
        _owner_keys: &[String],
        _now: DateTime<Utc>,
        _limit: i64,
        _offset: i64,
    ) -> Result<Vec<SecretSummary>, StorageError> {
        Err(StorageError::Other("error".into()))
    }
    async fn count_by_owner_keys(
        &self,
        _owner_keys: &[String],
        _now: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        Err(StorageError::Other("error".into()))
    }
    async fn burn_all_by_owner_keys(&self, _owner_keys: &[String]) -> Result<i64, StorageError> {
        Err(StorageError::Other("error".into()))
    }
    async fn checksum_by_owner_keys(
        &self,
        _owner_keys: &[String],
        _now: DateTime<Utc>,
    ) -> Result<(i64, String), StorageError> {
        Err(StorageError::Other("error".into()))
    }
    async fn get_summary_by_id(
        &self,
        _id: &str,
        _owner_keys: &[String],
        _now: DateTime<Utc>,
    ) -> Result<Option<SecretSummary>, StorageError> {
        Ok(None)
    }
}

#[async_trait]
impl ApiKeysStore for ErrStore {
    async fn get_by_prefix(&self, prefix: &str) -> Result<ApiKeyRecord, StorageError> {
        let Some(key) = &self.key else {
            return Err(StorageError::NotFound);
        };
        if key.prefix == prefix {
            Ok(key.clone())
        } else {
            Err(StorageError::NotFound)
        }
    }

    async fn insert(&self, _key: ApiKeyRecord) -> Result<(), StorageError> {
        Ok(())
    }

    async fn revoke_by_prefix(&self, _prefix: &str) -> Result<bool, StorageError> {
        Ok(false)
    }

    async fn list_by_user_id(&self, _user_id: UserId) -> Result<Vec<ApiKeyRecord>, StorageError> {
        Err(StorageError::Other("error".into()))
    }
    async fn revoke_all_by_user_id(&self, _user_id: UserId) -> Result<i64, StorageError> {
        Err(StorageError::Other("error".into()))
    }
}

#[async_trait]
impl AuthStore for ErrStore {
    async fn create_user(&self, _display_name: &str) -> Result<UserRecord, StorageError> {
        Err(StorageError::Other("unsupported".into()))
    }

    async fn get_user_by_id(&self, _user_id: UserId) -> Result<UserRecord, StorageError> {
        Err(StorageError::NotFound)
    }

    async fn insert_passkey(
        &self,
        _user_id: UserId,
        _credential_id: &str,
        _public_key: &str,
        _sign_count: i64,
    ) -> Result<PasskeyRecord, StorageError> {
        Err(StorageError::Other("unsupported".into()))
    }

    async fn get_passkey_by_credential_id(
        &self,
        _credential_id: &str,
    ) -> Result<PasskeyRecord, StorageError> {
        Err(StorageError::NotFound)
    }

    async fn update_passkey_sign_count(
        &self,
        _credential_id: &str,
        _sign_count: i64,
    ) -> Result<(), StorageError> {
        Err(StorageError::NotFound)
    }

    async fn insert_session(
        &self,
        _sid: &str,
        _user_id: UserId,
        _token_hash: &str,
        _expires_at: DateTime<Utc>,
    ) -> Result<SessionRecord, StorageError> {
        Err(StorageError::Other("unsupported".into()))
    }

    async fn get_session_by_sid(&self, _sid: &str) -> Result<SessionRecord, StorageError> {
        Err(StorageError::NotFound)
    }

    async fn revoke_session_by_sid(&self, _sid: &str) -> Result<bool, StorageError> {
        Ok(false)
    }

    async fn insert_challenge(
        &self,
        _challenge_id: &str,
        _user_id: Option<UserId>,
        _purpose: &str,
        _challenge_json: &str,
        _expires_at: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        Err(StorageError::Other("unsupported".into()))
    }

    async fn consume_challenge(
        &self,
        _challenge_id: &str,
        _purpose: &str,
        _now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        Err(StorageError::NotFound)
    }

    async fn get_challenge(
        &self,
        _challenge_id: &str,
        _purpose: &str,
        _now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        Err(StorageError::NotFound)
    }

    async fn update_challenge_json(
        &self,
        _challenge_id: &str,
        _purpose: &str,
        _challenge_json: &str,
        _now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        Err(StorageError::NotFound)
    }

    async fn find_device_challenge_by_user_code(
        &self,
        _user_code: &str,
        _now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        Err(StorageError::NotFound)
    }

    async fn count_apikey_registrations_by_user_since(
        &self,
        _user_id: UserId,
        _since: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        Ok(0)
    }

    async fn count_apikey_registrations_by_ip_since(
        &self,
        _ip_hash: &str,
        _since: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        Ok(0)
    }

    async fn register_api_key(
        &self,
        _key: ApiKeyRecord,
        _ip_hash: &str,
        _now: DateTime<Utc>,
        _limits: ApiKeyRegistrationLimits,
    ) -> Result<(), StorageError> {
        Err(StorageError::Other("unsupported".into()))
    }

    async fn insert_apikey_registration_event(
        &self,
        _user_id: UserId,
        _ip_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        Ok(())
    }

    async fn delete_user(&self, _user_id: UserId) -> Result<bool, StorageError> {
        Err(StorageError::Other("error".into()))
    }

    async fn touch_user_last_active(
        &self,
        _user_id: UserId,
        _now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        Err(StorageError::Other("error".into()))
    }
}

#[async_trait]
impl AmkStore for ErrStore {
    async fn upsert_wrapper(
        &self,
        _w: AmkWrapperRecord,
        _amk_commit: &[u8],
    ) -> Result<AmkUpsertResult, StorageError> {
        Err(StorageError::Other("error".into()))
    }
    async fn get_wrapper(
        &self,
        _user_id: Uuid,
        _key_prefix: &str,
    ) -> Result<Option<AmkWrapperRecord>, StorageError> {
        Ok(None)
    }
    async fn list_wrappers(&self, _user_id: Uuid) -> Result<Vec<AmkWrapperRecord>, StorageError> {
        Ok(vec![])
    }
    async fn delete_wrapper(
        &self,
        _user_id: Uuid,
        _key_prefix: &str,
    ) -> Result<bool, StorageError> {
        Ok(false)
    }
    async fn has_any_wrapper(&self, _user_id: Uuid) -> Result<bool, StorageError> {
        Ok(false)
    }
    async fn get_amk_commit(&self, _user_id: Uuid) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }
    async fn commit_amk(
        &self,
        _user_id: Uuid,
        _amk_commit: &[u8],
    ) -> Result<AmkUpsertResult, StorageError> {
        Err(StorageError::Other("error".into()))
    }
    async fn update_enc_meta(
        &self,
        _secret_id: &str,
        _owner_keys: &[String],
        _enc_meta: &secrt_core::api::EncMetaV1,
        _meta_key_version: i16,
    ) -> Result<(), StorageError> {
        Err(StorageError::NotFound)
    }
}

fn app_with_store(store: Arc<ErrStore>) -> axum::Router {
    let secrets: Arc<dyn SecretsStore> = store.clone();
    let api_keys: Arc<dyn ApiKeysStore> = store.clone();
    let auth_store: Arc<dyn AuthStore> = store.clone();
    let amk_store: Arc<dyn AmkStore> = store;
    let state = Arc::new(AppState::new(
        cfg(),
        secrets,
        api_keys,
        auth_store,
        amk_store,
    ));
    build_router(state)
}

async fn body_text(resp: axum::response::Response) -> String {
    String::from_utf8(
        to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn create_usage_error_is_500() {
    let app = app_with_store(Arc::new(ErrStore {
        fail_usage: true,
        ..Default::default()
    }));

    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([5u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"envelope":{"ct":"x"},"claim_hash":claim_hash}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn create_store_error_is_500() {
    let app = app_with_store(Arc::new(ErrStore {
        fail_create: true,
        ..Default::default()
    }));

    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([6u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"envelope":{"ct":"x"},"claim_hash":claim_hash}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn create_duplicate_id_exhaustion_is_500() {
    let app = app_with_store(Arc::new(ErrStore {
        duplicate_create: true,
        ..Default::default()
    }));

    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([60u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"envelope":{"ct":"x"},"claim_hash":claim_hash}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn create_duplicate_id_retries_then_succeeds() {
    let app = app_with_store(Arc::new(ErrStore {
        duplicate_then_ok: AtomicUsize::new(2),
        ..Default::default()
    }));

    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([61u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"envelope":{"ct":"x"},"claim_hash":claim_hash}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn claim_store_error_is_500() {
    let app = app_with_store(Arc::new(ErrStore {
        fail_claim: true,
        ..Default::default()
    }));

    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets/id/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"claim": claim}).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn burn_store_error_is_500() {
    let auth = [1u8; 32];
    let auth_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(auth);
    let hash = hash_api_key_auth_token("pepper", "abcdef", &auth).expect("hash");
    let app = app_with_store(Arc::new(ErrStore {
        fail_burn: true,
        key: Some(ApiKeyRecord {
            id: 1,
            prefix: "abcdef".into(),
            auth_hash: hash,
            scopes: String::new(),
            user_id: None,
            created_at: Utc::now(),
            revoked_at: None,
        }),
        ..Default::default()
    }));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets/id/burn")
        .header("x-api-key", format!("ak2_abcdef.{auth_b64}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn create_envelope_too_large_and_invalid_claim_hash() {
    let app = app_with_store(Arc::new(ErrStore::default()));

    let huge = "x".repeat(500);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"envelope":{"ct":huge},"claim_hash":"bad"}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = body_text(resp).await;
    assert!(body.contains("envelope exceeds maximum size") || body.contains("invalid claim_hash"));
}

#[tokio::test]
async fn info_with_invalid_api_key_returns_authenticated_false() {
    let app = app_with_store(Arc::new(ErrStore::default()));

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/info")
        .header("x-api-key", "ak2_invalid.invalid")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let txt = body_text(resp).await;
    assert!(txt.contains("\"authenticated\":false"));
}

#[tokio::test]
async fn claim_bad_content_type_is_400() {
    let app = app_with_store(Arc::new(ErrStore::default()));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets/id/claim")
        .header("content-type", "text/plain")
        .body(Body::from("{}"))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_invalid_ttl_and_claim_hash() {
    let app = app_with_store(Arc::new(ErrStore::default()));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "envelope": {"ct":"x"},
                "claim_hash": "bad",
                "ttl_seconds": -1,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let txt = body_text(resp).await;
    assert!(txt.contains("invalid claim_hash") || txt.contains("invalid ttl_seconds"));
}

#[tokio::test]
async fn create_invalid_ttl_with_valid_claim_hash() {
    let app = app_with_store(Arc::new(ErrStore::default()));
    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([34u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/public/secrets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "envelope": {"ct":"x"},
                "claim_hash": claim_hash,
                "ttl_seconds": 0,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let txt = body_text(resp).await;
    assert!(txt.contains("invalid ttl_seconds"));
}

#[tokio::test]
async fn method_not_allowed_on_burn_and_info() {
    let app = app_with_store(Arc::new(ErrStore::default()));

    let burn_req = Request::builder()
        .method("GET")
        .uri("/api/v1/secrets/id/burn")
        .body(Body::empty())
        .unwrap();
    let burn_resp = app.clone().oneshot(burn_req).await.unwrap();
    assert_eq!(burn_resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    let info_req = Request::builder()
        .method("POST")
        .uri("/api/v1/info")
        .body(Body::empty())
        .unwrap();
    let info_resp = app.clone().oneshot(info_req).await.unwrap();
    assert_eq!(info_resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn method_not_allowed_on_authed_create_and_claim() {
    let app = app_with_store(Arc::new(ErrStore::default()));

    // GET /api/v1/secrets is now valid (list secrets) — returns 401 without auth
    let authed_req = Request::builder()
        .method("GET")
        .uri("/api/v1/secrets")
        .body(Body::empty())
        .unwrap();
    let authed_resp = app.clone().oneshot(authed_req).await.unwrap();
    assert_eq!(authed_resp.status(), StatusCode::UNAUTHORIZED);

    // PUT /api/v1/secrets is not a valid method
    let put_req = Request::builder()
        .method("PUT")
        .uri("/api/v1/secrets")
        .body(Body::empty())
        .unwrap();
    let put_resp = app.clone().oneshot(put_req).await.unwrap();
    assert_eq!(put_resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    let claim_req = Request::builder()
        .method("GET")
        .uri("/api/v1/secrets/id/claim")
        .body(Body::empty())
        .unwrap();
    let claim_resp = app.clone().oneshot(claim_req).await.unwrap();
    assert_eq!(claim_resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn burn_requires_api_key() {
    let app = app_with_store(Arc::new(ErrStore::default()));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets/id/burn")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn claim_invalid_json_envelope_from_store_is_500() {
    let app = app_with_store(Arc::new(ErrStore {
        claim_invalid_envelope: true,
        ..Default::default()
    }));

    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([12u8; 32]);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets/id/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"claim": claim}).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn info_rate_limited_path() {
    let mut c = cfg();
    c.claim_rate = 0.0;
    c.claim_burst = 1;
    let store = Arc::new(ErrStore::default());
    let secrets: Arc<dyn SecretsStore> = store.clone();
    let api_keys: Arc<dyn ApiKeysStore> = store.clone();
    let auth_store: Arc<dyn AuthStore> = store.clone();
    let amk_store: Arc<dyn AmkStore> = store;
    let state = Arc::new(AppState::new(c, secrets, api_keys, auth_store, amk_store));
    let app = build_router(state);

    let req1 = Request::builder()
        .method("GET")
        .uri("/api/v1/info")
        .body(Body::empty())
        .unwrap();
    let _ = app.clone().oneshot(req1).await.unwrap();

    let req2 = Request::builder()
        .method("GET")
        .uri("/api/v1/info")
        .body(Body::empty())
        .unwrap();
    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn authed_create_rate_limited_path() {
    let mut c = cfg();
    c.authed_create_rate = 0.0;
    c.authed_create_burst = 1;
    let auth = [2u8; 32];
    let auth_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(auth);
    let hash = hash_api_key_auth_token("pepper", "abcdef", &auth).expect("hash");
    let store = Arc::new(ErrStore {
        key: Some(ApiKeyRecord {
            id: 1,
            prefix: "abcdef".into(),
            auth_hash: hash,
            scopes: String::new(),
            user_id: None,
            created_at: Utc::now(),
            revoked_at: None,
        }),
        ..Default::default()
    });
    let secrets: Arc<dyn SecretsStore> = store.clone();
    let api_keys: Arc<dyn ApiKeysStore> = store.clone();
    let auth_store: Arc<dyn AuthStore> = store.clone();
    let amk_store: Arc<dyn AmkStore> = store;
    let state = Arc::new(AppState::new(c, secrets, api_keys, auth_store, amk_store));
    let app = build_router(state);

    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([31u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).unwrap();
    let payload = serde_json::json!({
        "envelope": {"ct":"x"},
        "claim_hash": claim_hash
    })
    .to_string();

    let req1 = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets")
        .header("x-api-key", format!("ak2_abcdef.{auth_b64}"))
        .header("content-type", "application/json")
        .body(Body::from(payload.clone()))
        .unwrap();
    let _ = app.clone().oneshot(req1).await.unwrap();

    let req2 = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets")
        .header("x-api-key", format!("ak2_abcdef.{auth_b64}"))
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap();
    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn authed_create_with_non_bearer_authorization_is_401() {
    let app = app_with_store(Arc::new(ErrStore::default()));
    let claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([33u8; 32]);
    let claim_hash = secrt_core::hash_claim_token(&claim).unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/secrets")
        .header("content-type", "application/json")
        .header("authorization", "Basic abc123")
        .body(Body::from(
            serde_json::json!({
                "envelope": {"ct":"x"},
                "claim_hash": claim_hash
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
