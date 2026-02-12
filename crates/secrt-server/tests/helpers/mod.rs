#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Request};
use chrono::{DateTime, Utc};
use secrt_server::config::Config;
use secrt_server::domain::auth::{generate_api_key, hash_api_key_secret};
use secrt_server::http::{build_router, AppState};
use secrt_server::storage::{
    ApiKeyRecord, ApiKeysStore, SecretRecord, SecretsStore, StorageError, StorageUsage,
};

#[derive(Default)]
pub struct MemStore {
    pub secrets: Mutex<HashMap<String, SecretRecord>>,
    pub keys: Mutex<HashMap<String, ApiKeyRecord>>,
}

#[async_trait]
impl SecretsStore for MemStore {
    async fn create(&self, secret: SecretRecord) -> Result<(), StorageError> {
        let mut m = self.secrets.lock().expect("secrets mutex poisoned");
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

        Ok(usage)
    }
}

#[async_trait]
impl ApiKeysStore for MemStore {
    async fn get_by_prefix(&self, prefix: &str) -> Result<ApiKeyRecord, StorageError> {
        self.keys
            .lock()
            .expect("keys mutex poisoned")
            .get(prefix)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn insert(&self, key: ApiKeyRecord) -> Result<(), StorageError> {
        self.keys
            .lock()
            .expect("keys mutex poisoned")
            .insert(key.prefix.clone(), key);
        Ok(())
    }

    async fn revoke_by_prefix(&self, prefix: &str) -> Result<bool, StorageError> {
        let mut m = self.keys.lock().expect("keys mutex poisoned");
        let Some(k) = m.get_mut(prefix) else {
            return Ok(false);
        };
        if k.revoked_at.is_some() {
            return Ok(false);
        }
        k.revoked_at = Some(Utc::now());
        Ok(true)
    }
}

pub fn test_config() -> Config {
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

        public_max_envelope_bytes: 256 * 1024,
        authed_max_envelope_bytes: 1024 * 1024,
        public_max_secrets: 10,
        public_max_total_bytes: 2 * 1024 * 1024,
        authed_max_secrets: 1000,
        authed_max_total_bytes: 20 * 1024 * 1024,

        public_create_rate: 0.5,
        public_create_burst: 6,
        claim_rate: 1.0,
        claim_burst: 10,
        authed_create_rate: 2.0,
        authed_create_burst: 20,
    }
}

pub fn test_app_with_store(store: Arc<MemStore>, cfg: Config) -> axum::Router {
    let secrets: Arc<dyn SecretsStore> = store.clone();
    let api_keys: Arc<dyn ApiKeysStore> = store;
    let state = Arc::new(AppState::new(cfg, secrets, api_keys));
    build_router(state)
}

pub fn test_state_and_app(store: Arc<MemStore>, cfg: Config) -> (Arc<AppState>, axum::Router) {
    let secrets: Arc<dyn SecretsStore> = store.clone();
    let api_keys: Arc<dyn ApiKeysStore> = store;
    let state = Arc::new(AppState::new(cfg, secrets, api_keys));
    let app = build_router(state.clone());
    (state, app)
}

pub async fn create_api_key(store: &Arc<MemStore>, pepper: &str) -> (String, String) {
    let (api_key, prefix, hash) = generate_api_key(pepper).expect("generate api key");
    store
        .insert(ApiKeyRecord {
            id: 1,
            prefix: prefix.clone(),
            hash,
            scopes: String::new(),
            created_at: Utc::now(),
            revoked_at: None,
        })
        .await
        .expect("insert key");
    (api_key, prefix)
}

pub async fn insert_api_key_with_secret(
    store: &Arc<MemStore>,
    pepper: &str,
    prefix: &str,
    secret: &str,
) -> String {
    let hash = hash_api_key_secret(pepper, prefix, secret).expect("hash key");
    let key = format!("sk_{prefix}.{secret}");
    store
        .insert(ApiKeyRecord {
            id: 1,
            prefix: prefix.to_string(),
            hash,
            scopes: String::new(),
            created_at: Utc::now(),
            revoked_at: None,
        })
        .await
        .expect("insert key");
    key
}

pub fn with_remote(
    mut req: Request<axum::body::Body>,
    ip: [u8; 4],
    port: u16,
) -> Request<axum::body::Body> {
    req.extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((ip, port))));
    req
}

pub fn with_proxy_ip(
    mut req: Request<axum::body::Body>,
    proxy_ip: [u8; 4],
    client_ip: &str,
) -> Request<axum::body::Body> {
    req.extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((proxy_ip, 1234))));
    req.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_str(client_ip).expect("valid xff"),
    );
    req
}
