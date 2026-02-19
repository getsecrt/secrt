#![allow(dead_code)]

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Request};
use base64::Engine;
use chrono::{DateTime, Utc};
use secrt_core::{derive_auth_token, format_wire_api_key};
use secrt_server::config::Config;
use secrt_server::domain::auth::{generate_api_key_prefix, hash_api_key_auth_token};
use secrt_server::http::{build_router, AppState};
use secrt_server::storage::{
    AmkStore, AmkUpsertResult, AmkWrapperRecord, ApiKeyRecord, ApiKeyRegistrationLimits,
    ApiKeysStore, AuthStore, ChallengeRecord, PasskeyRecord, SecretQuotaLimits, SecretRecord,
    SecretSummary, SecretsStore, SessionRecord, StorageError, StorageUsage, UserId, UserRecord,
};
use uuid::Uuid;

#[derive(Default)]
pub struct MemStore {
    pub secrets: Mutex<HashMap<String, SecretRecord>>,
    pub keys: Mutex<HashMap<String, ApiKeyRecord>>,
    pub users: Mutex<HashMap<UserId, UserRecord>>,
    pub passkeys: Mutex<HashMap<String, PasskeyRecord>>,
    pub sessions: Mutex<HashMap<String, SessionRecord>>,
    pub challenges: Mutex<HashMap<String, ChallengeRecord>>,
    pub apikey_regs: Mutex<Vec<(UserId, String, DateTime<Utc>)>>,
    pub amk_wrappers: Mutex<HashMap<String, AmkWrapperRecord>>,
    pub ids: Mutex<i64>,
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

    async fn create_with_quota(
        &self,
        secret: SecretRecord,
        limits: SecretQuotaLimits,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
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

    async fn list_by_owner_keys(
        &self,
        owner_keys: &[String],
        now: DateTime<Utc>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SecretSummary>, StorageError> {
        let m = self.secrets.lock().expect("secrets mutex poisoned");
        let mut matching: Vec<_> = m
            .values()
            .filter(|s| owner_keys.contains(&s.owner_key) && s.expires_at > now)
            .collect();
        matching.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(matching
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .map(|s| {
                let passphrase_protected = serde_json::from_str::<serde_json::Value>(&s.envelope)
                    .ok()
                    .and_then(|v| v.get("kdf")?.get("name")?.as_str().map(|n| n != "none"))
                    .unwrap_or(false);
                SecretSummary {
                    id: s.id.clone(),
                    expires_at: s.expires_at,
                    created_at: s.created_at,
                    ciphertext_size: s.envelope.len() as i64,
                    passphrase_protected,
                    enc_meta: None,
                }
            })
            .collect())
    }

    async fn count_by_owner_keys(
        &self,
        owner_keys: &[String],
        now: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        let m = self.secrets.lock().expect("secrets mutex poisoned");
        Ok(m.values()
            .filter(|s| owner_keys.contains(&s.owner_key) && s.expires_at > now)
            .count() as i64)
    }

    async fn burn_all_by_owner_keys(&self, owner_keys: &[String]) -> Result<i64, StorageError> {
        let mut m = self.secrets.lock().expect("secrets mutex poisoned");
        let before = m.len();
        m.retain(|_, s| !owner_keys.contains(&s.owner_key));
        Ok((before - m.len()) as i64)
    }

    async fn checksum_by_owner_keys(
        &self,
        owner_keys: &[String],
        now: DateTime<Utc>,
    ) -> Result<(i64, String), StorageError> {
        let m = self.secrets.lock().expect("secrets mutex poisoned");
        let mut ids: Vec<&str> = m
            .values()
            .filter(|s| owner_keys.contains(&s.owner_key) && s.expires_at > now)
            .map(|s| s.id.as_str())
            .collect();
        ids.sort();
        let count = ids.len() as i64;
        if ids.is_empty() {
            return Ok((0, String::new()));
        }
        let joined = ids.join(",");
        let mut hasher = DefaultHasher::new();
        joined.hash(&mut hasher);
        let checksum = format!("{:016x}", hasher.finish());
        Ok((count, checksum))
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

    async fn list_by_user_id(&self, user_id: UserId) -> Result<Vec<ApiKeyRecord>, StorageError> {
        let m = self.keys.lock().expect("keys mutex poisoned");
        let mut result: Vec<_> = m
            .values()
            .filter(|k| k.user_id == Some(user_id))
            .cloned()
            .collect();
        result.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(result)
    }

    async fn revoke_all_by_user_id(&self, user_id: UserId) -> Result<i64, StorageError> {
        let mut m = self.keys.lock().expect("keys mutex poisoned");
        let mut count = 0i64;
        for k in m.values_mut() {
            if k.user_id == Some(user_id) && k.revoked_at.is_none() {
                k.revoked_at = Some(Utc::now());
                count += 1;
            }
        }
        Ok(count)
    }
}

#[async_trait]
impl AuthStore for MemStore {
    async fn create_user(&self, display_name: &str) -> Result<UserRecord, StorageError> {
        let u = UserRecord {
            id: Uuid::now_v7(),
            display_name: display_name.to_string(),
            created_at: Utc::now(),
        };
        self.users
            .lock()
            .expect("users mutex poisoned")
            .insert(u.id, u.clone());
        Ok(u)
    }

    async fn get_user_by_id(&self, user_id: UserId) -> Result<UserRecord, StorageError> {
        self.users
            .lock()
            .expect("users mutex poisoned")
            .get(&user_id)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn insert_passkey(
        &self,
        user_id: UserId,
        credential_id: &str,
        public_key: &str,
        sign_count: i64,
    ) -> Result<PasskeyRecord, StorageError> {
        let mut ids = self.ids.lock().expect("ids mutex poisoned");
        *ids += 1;
        let p = PasskeyRecord {
            id: *ids,
            user_id,
            credential_id: credential_id.to_string(),
            public_key: public_key.to_string(),
            sign_count,
            created_at: Utc::now(),
            revoked_at: None,
        };
        self.passkeys
            .lock()
            .expect("passkeys mutex poisoned")
            .insert(credential_id.to_string(), p.clone());
        Ok(p)
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<PasskeyRecord, StorageError> {
        self.passkeys
            .lock()
            .expect("passkeys mutex poisoned")
            .get(credential_id)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn update_passkey_sign_count(
        &self,
        credential_id: &str,
        sign_count: i64,
    ) -> Result<(), StorageError> {
        let mut m = self.passkeys.lock().expect("passkeys mutex poisoned");
        let Some(p) = m.get_mut(credential_id) else {
            return Err(StorageError::NotFound);
        };
        p.sign_count = sign_count;
        Ok(())
    }

    async fn insert_session(
        &self,
        sid: &str,
        user_id: UserId,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<SessionRecord, StorageError> {
        let mut ids = self.ids.lock().expect("ids mutex poisoned");
        *ids += 1;
        let s = SessionRecord {
            id: *ids,
            sid: sid.to_string(),
            user_id,
            token_hash: token_hash.to_string(),
            expires_at,
            created_at: Utc::now(),
            revoked_at: None,
        };
        self.sessions
            .lock()
            .expect("sessions mutex poisoned")
            .insert(sid.to_string(), s.clone());
        Ok(s)
    }

    async fn get_session_by_sid(&self, sid: &str) -> Result<SessionRecord, StorageError> {
        self.sessions
            .lock()
            .expect("sessions mutex poisoned")
            .get(sid)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn revoke_session_by_sid(&self, sid: &str) -> Result<bool, StorageError> {
        let mut m = self.sessions.lock().expect("sessions mutex poisoned");
        let Some(s) = m.get_mut(sid) else {
            return Ok(false);
        };
        if s.revoked_at.is_some() {
            return Ok(false);
        }
        s.revoked_at = Some(Utc::now());
        Ok(true)
    }

    async fn insert_challenge(
        &self,
        challenge_id: &str,
        user_id: Option<UserId>,
        purpose: &str,
        challenge_json: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        let mut ids = self.ids.lock().expect("ids mutex poisoned");
        *ids += 1;
        let c = ChallengeRecord {
            id: *ids,
            challenge_id: challenge_id.to_string(),
            user_id,
            purpose: purpose.to_string(),
            challenge_json: challenge_json.to_string(),
            expires_at,
            created_at: Utc::now(),
        };
        self.challenges
            .lock()
            .expect("challenges mutex poisoned")
            .insert(challenge_id.to_string(), c.clone());
        Ok(c)
    }

    async fn consume_challenge(
        &self,
        challenge_id: &str,
        purpose: &str,
        now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        let mut m = self.challenges.lock().expect("challenges mutex poisoned");
        let Some(c) = m.remove(challenge_id) else {
            return Err(StorageError::NotFound);
        };
        if c.purpose != purpose || c.expires_at <= now {
            return Err(StorageError::NotFound);
        }
        Ok(c)
    }

    async fn get_challenge(
        &self,
        challenge_id: &str,
        purpose: &str,
        now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        self.challenges
            .lock()
            .expect("challenges mutex poisoned")
            .get(challenge_id)
            .filter(|r| r.purpose == purpose && r.expires_at > now)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn update_challenge_json(
        &self,
        challenge_id: &str,
        purpose: &str,
        challenge_json: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let mut m = self.challenges.lock().expect("challenges mutex poisoned");
        let rec = m
            .get_mut(challenge_id)
            .filter(|r| r.purpose == purpose && r.expires_at > now)
            .ok_or(StorageError::NotFound)?;
        rec.challenge_json = challenge_json.to_string();
        Ok(())
    }

    async fn find_device_challenge_by_user_code(
        &self,
        user_code: &str,
        now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        let m = self.challenges.lock().expect("challenges mutex poisoned");
        for rec in m.values() {
            if rec.purpose != "device-auth" || rec.expires_at <= now {
                continue;
            }
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&rec.challenge_json) {
                if json.get("user_code").and_then(|v| v.as_str()) == Some(user_code) {
                    return Ok(rec.clone());
                }
            }
        }
        Err(StorageError::NotFound)
    }

    async fn count_apikey_registrations_by_user_since(
        &self,
        user_id: UserId,
        since: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        let regs = self.apikey_regs.lock().expect("apikey_regs mutex poisoned");
        Ok(regs
            .iter()
            .filter(|(uid, _, t)| *uid == user_id && *t > since)
            .count() as i64)
    }

    async fn count_apikey_registrations_by_ip_since(
        &self,
        ip_hash: &str,
        since: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        let regs = self.apikey_regs.lock().expect("apikey_regs mutex poisoned");
        Ok(regs
            .iter()
            .filter(|(_, ip, t)| ip == ip_hash && *t > since)
            .count() as i64)
    }

    async fn register_api_key(
        &self,
        key: ApiKeyRecord,
        ip_hash: &str,
        now: DateTime<Utc>,
        limits: ApiKeyRegistrationLimits,
    ) -> Result<(), StorageError> {
        let user_id = key
            .user_id
            .ok_or_else(|| StorageError::Other("api key registration requires user_id".into()))?;

        let since_hour = now - chrono::Duration::hours(1);
        let since_day = now - chrono::Duration::hours(24);
        let mut regs = self.apikey_regs.lock().expect("apikey_regs mutex poisoned");

        let account_hour = regs
            .iter()
            .filter(|(uid, _, t)| *uid == user_id && *t > since_hour)
            .count() as i64;
        if limits.account_hour > 0 && account_hour >= limits.account_hour {
            return Err(StorageError::QuotaExceeded("account/hour".into()));
        }

        let account_day = regs
            .iter()
            .filter(|(uid, _, t)| *uid == user_id && *t > since_day)
            .count() as i64;
        if limits.account_day > 0 && account_day >= limits.account_day {
            return Err(StorageError::QuotaExceeded("account/day".into()));
        }

        let ip_hour = regs
            .iter()
            .filter(|(_, ip, t)| ip == ip_hash && *t > since_hour)
            .count() as i64;
        if limits.ip_hour > 0 && ip_hour >= limits.ip_hour {
            return Err(StorageError::QuotaExceeded("ip/hour".into()));
        }

        let ip_day = regs
            .iter()
            .filter(|(_, ip, t)| ip == ip_hash && *t > since_day)
            .count() as i64;
        if limits.ip_day > 0 && ip_day >= limits.ip_day {
            return Err(StorageError::QuotaExceeded("ip/day".into()));
        }

        let mut keys = self.keys.lock().expect("keys mutex poisoned");
        if keys.contains_key(&key.prefix) {
            return Err(StorageError::DuplicateId);
        }
        keys.insert(key.prefix.clone(), key);

        regs.push((user_id, ip_hash.to_string(), now));
        Ok(())
    }

    async fn insert_apikey_registration_event(
        &self,
        user_id: UserId,
        ip_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        self.apikey_regs
            .lock()
            .expect("apikey_regs mutex poisoned")
            .push((user_id, ip_hash.to_string(), now));
        Ok(())
    }

    async fn delete_user(&self, user_id: UserId) -> Result<bool, StorageError> {
        let removed = self
            .users
            .lock()
            .expect("users mutex poisoned")
            .remove(&user_id)
            .is_some();
        if removed {
            self.sessions
                .lock()
                .expect("sessions mutex poisoned")
                .retain(|_, s| s.user_id != user_id);
        }
        Ok(removed)
    }
}

#[async_trait]
impl AmkStore for MemStore {
    async fn upsert_wrapper(
        &self,
        w: AmkWrapperRecord,
        _amk_commit: &[u8],
    ) -> Result<AmkUpsertResult, StorageError> {
        let key = format!("{}:{}", w.user_id, w.key_prefix);
        self.amk_wrappers
            .lock()
            .expect("amk_wrappers mutex poisoned")
            .insert(key, w);
        Ok(AmkUpsertResult::Ok)
    }

    async fn get_wrapper(
        &self,
        user_id: Uuid,
        key_prefix: &str,
    ) -> Result<Option<AmkWrapperRecord>, StorageError> {
        let key = format!("{user_id}:{key_prefix}");
        Ok(self
            .amk_wrappers
            .lock()
            .expect("amk_wrappers mutex poisoned")
            .get(&key)
            .cloned())
    }

    async fn list_wrappers(&self, user_id: Uuid) -> Result<Vec<AmkWrapperRecord>, StorageError> {
        let m = self
            .amk_wrappers
            .lock()
            .expect("amk_wrappers mutex poisoned");
        Ok(m.values()
            .filter(|w| w.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn delete_wrapper(&self, user_id: Uuid, key_prefix: &str) -> Result<bool, StorageError> {
        let key = format!("{user_id}:{key_prefix}");
        Ok(self
            .amk_wrappers
            .lock()
            .expect("amk_wrappers mutex poisoned")
            .remove(&key)
            .is_some())
    }

    async fn has_any_wrapper(&self, user_id: Uuid) -> Result<bool, StorageError> {
        let m = self
            .amk_wrappers
            .lock()
            .expect("amk_wrappers mutex poisoned");
        Ok(m.values().any(|w| w.user_id == user_id))
    }

    async fn get_amk_commit(&self, _user_id: Uuid) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }

    async fn update_enc_meta(
        &self,
        secret_id: &str,
        owner_keys: &[String],
        _enc_meta: &secrt_core::api::EncMetaV1,
        _meta_key_version: i16,
    ) -> Result<(), StorageError> {
        let m = self.secrets.lock().expect("secrets mutex poisoned");
        let Some(s) = m.get(secret_id) else {
            return Err(StorageError::NotFound);
        };
        if !owner_keys.contains(&s.owner_key) {
            return Err(StorageError::NotFound);
        }
        Ok(())
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
        session_token_pepper: "session-pepper".into(),

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
        apikey_register_rate: 0.5,
        apikey_register_burst: 6,
        apikey_register_account_max_per_hour: 5,
        apikey_register_account_max_per_day: 20,
        apikey_register_ip_max_per_hour: 5,
        apikey_register_ip_max_per_day: 20,
        encrypted_notes_enabled: false,
    }
}

pub fn test_app_with_store(store: Arc<MemStore>, cfg: Config) -> axum::Router {
    let secrets: Arc<dyn SecretsStore> = store.clone();
    let api_keys: Arc<dyn ApiKeysStore> = store.clone();
    let auth_store: Arc<dyn AuthStore> = store.clone();
    let amk_store: Arc<dyn AmkStore> = store;
    let state = Arc::new(AppState::new(cfg, secrets, api_keys, auth_store, amk_store));
    build_router(state)
}

pub fn test_state_and_app(store: Arc<MemStore>, cfg: Config) -> (Arc<AppState>, axum::Router) {
    let secrets: Arc<dyn SecretsStore> = store.clone();
    let api_keys: Arc<dyn ApiKeysStore> = store.clone();
    let auth_store: Arc<dyn AuthStore> = store.clone();
    let amk_store: Arc<dyn AmkStore> = store;
    let state = Arc::new(AppState::new(cfg, secrets, api_keys, auth_store, amk_store));
    let app = build_router(state.clone());
    (state, app)
}

pub async fn create_api_key(store: &Arc<MemStore>, pepper: &str) -> (String, String) {
    let prefix = generate_api_key_prefix().expect("generate api key prefix");
    let root = [42u8; 32];
    let auth = derive_auth_token(&root).expect("derive auth token");
    let api_key = format_wire_api_key(&prefix, &auth).expect("format wire api key");
    let auth_hash = hash_api_key_auth_token(pepper, &prefix, &auth).expect("hash auth token");
    store
        .insert(ApiKeyRecord {
            id: 1,
            prefix: prefix.clone(),
            auth_hash,
            scopes: String::new(),
            user_id: None,
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
    auth_b64: &str,
) -> String {
    let auth = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(auth_b64)
        .expect("decode auth");
    let hash = hash_api_key_auth_token(pepper, prefix, &auth).expect("hash key");
    let key = format!("ak2_{prefix}.{auth_b64}");
    store
        .insert(ApiKeyRecord {
            id: 1,
            prefix: prefix.to_string(),
            auth_hash: hash,
            scopes: String::new(),
            user_id: None,
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
