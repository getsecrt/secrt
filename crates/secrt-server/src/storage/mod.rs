use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use secrt_core::api::EncMetaV1;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub mod migrations;
pub mod postgres;

pub type UserId = Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretSummary {
    pub id: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub ciphertext_size: i64,
    pub passphrase_protected: bool,
    pub enc_meta: Option<EncMetaV1>,
}

#[derive(Clone, Debug)]
pub struct AmkWrapperRecord {
    pub user_id: Uuid,
    pub key_prefix: String,
    pub wrapped_amk: Vec<u8>,
    pub nonce: Vec<u8>,
    pub version: i16,
    pub created_at: DateTime<Utc>,
}

/// Result of an atomic commit-then-upsert-wrapper operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AmkUpsertResult {
    /// Wrapper upserted successfully (commit matched or was first).
    Ok,
    /// A different AMK already committed for this user.
    CommitMismatch,
}

#[derive(Clone, Debug)]
pub struct SecretRecord {
    pub id: String,
    pub claim_hash: String,
    pub envelope: Box<str>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub owner_key: String,
}

#[derive(Clone, Debug)]
pub struct StorageUsage {
    pub secret_count: i64,
    pub total_bytes: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct SecretQuotaLimits {
    pub max_secrets: i64,
    pub max_total_bytes: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    pub id: i64,
    pub prefix: String,
    pub auth_hash: String,
    pub scopes: String,
    pub user_id: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserRecord {
    pub id: UserId,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub last_active_at: NaiveDate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyRecord {
    pub id: i64,
    pub user_id: UserId,
    pub credential_id: String,
    pub public_key: String,
    pub sign_count: i64,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionRecord {
    pub id: i64,
    pub sid: String,
    pub user_id: UserId,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeRecord {
    pub id: i64,
    pub challenge_id: String,
    pub user_id: Option<UserId>,
    pub purpose: String,
    pub challenge_json: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug)]
pub struct ApiKeyRegistrationLimits {
    pub account_hour: i64,
    pub account_day: i64,
    pub ip_hour: i64,
    pub ip_day: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("not found")]
    NotFound,
    #[error("duplicate id")]
    DuplicateId,
    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),
    #[error("storage error: {0}")]
    Other(String),
}

impl From<tokio_postgres::Error> for StorageError {
    fn from(value: tokio_postgres::Error) -> Self {
        StorageError::Other(format_error_chain(&value))
    }
}

impl From<deadpool_postgres::PoolError> for StorageError {
    fn from(value: deadpool_postgres::PoolError) -> Self {
        StorageError::Other(format_error_chain(&value))
    }
}

impl From<deadpool_postgres::CreatePoolError> for StorageError {
    fn from(value: deadpool_postgres::CreatePoolError) -> Self {
        StorageError::Other(format_error_chain(&value))
    }
}

/// Format an error with its full source chain so root causes aren't swallowed.
fn format_error_chain(err: &dyn std::error::Error) -> String {
    let mut msg = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        msg.push_str(": ");
        msg.push_str(&cause.to_string());
        source = cause.source();
    }
    msg
}

#[async_trait]
pub trait SecretsStore: Send + Sync {
    async fn create(&self, secret: SecretRecord) -> Result<(), StorageError>;
    async fn create_with_quota(
        &self,
        secret: SecretRecord,
        limits: SecretQuotaLimits,
        _now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        if limits.max_secrets > 0 || limits.max_total_bytes > 0 {
            let usage = self.get_usage(&secret.owner_key).await?;

            if limits.max_secrets > 0 && usage.secret_count >= limits.max_secrets {
                return Err(StorageError::QuotaExceeded("secret_count".into()));
            }

            if limits.max_total_bytes > 0
                && usage.total_bytes + secret.envelope.len() as i64 > limits.max_total_bytes
            {
                return Err(StorageError::QuotaExceeded("total_bytes".into()));
            }
        }

        self.create(secret).await
    }
    async fn claim_and_delete(
        &self,
        id: &str,
        claim_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<SecretRecord, StorageError>;
    async fn burn(&self, id: &str, owner_key: &str) -> Result<bool, StorageError>;
    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<i64, StorageError>;
    async fn get_usage(&self, owner_key: &str) -> Result<StorageUsage, StorageError>;
    async fn list_by_owner_keys(
        &self,
        owner_keys: &[String],
        now: DateTime<Utc>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SecretSummary>, StorageError>;
    async fn count_by_owner_keys(
        &self,
        owner_keys: &[String],
        now: DateTime<Utc>,
    ) -> Result<i64, StorageError>;
    async fn burn_all_by_owner_keys(&self, owner_keys: &[String]) -> Result<i64, StorageError>;
    async fn checksum_by_owner_keys(
        &self,
        owner_keys: &[String],
        now: DateTime<Utc>,
    ) -> Result<(i64, String), StorageError>;
    async fn get_summary_by_id(
        &self,
        id: &str,
        owner_keys: &[String],
        now: DateTime<Utc>,
    ) -> Result<Option<SecretSummary>, StorageError>;
}

#[async_trait]
pub trait ApiKeysStore: Send + Sync {
    async fn get_by_prefix(&self, prefix: &str) -> Result<ApiKeyRecord, StorageError>;
    async fn insert(&self, key: ApiKeyRecord) -> Result<(), StorageError>;
    async fn revoke_by_prefix(&self, prefix: &str) -> Result<bool, StorageError>;
    async fn list_by_user_id(&self, user_id: UserId) -> Result<Vec<ApiKeyRecord>, StorageError>;
    async fn revoke_all_by_user_id(&self, user_id: UserId) -> Result<i64, StorageError>;
}

#[async_trait]
pub trait AuthStore: Send + Sync {
    async fn create_user(&self, display_name: &str) -> Result<UserRecord, StorageError>;
    async fn get_user_by_id(&self, user_id: UserId) -> Result<UserRecord, StorageError>;

    async fn insert_passkey(
        &self,
        user_id: UserId,
        credential_id: &str,
        public_key: &str,
        sign_count: i64,
    ) -> Result<PasskeyRecord, StorageError>;
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<PasskeyRecord, StorageError>;
    async fn update_passkey_sign_count(
        &self,
        credential_id: &str,
        sign_count: i64,
    ) -> Result<(), StorageError>;

    async fn insert_session(
        &self,
        sid: &str,
        user_id: UserId,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<SessionRecord, StorageError>;
    async fn get_session_by_sid(&self, sid: &str) -> Result<SessionRecord, StorageError>;
    async fn revoke_session_by_sid(&self, sid: &str) -> Result<bool, StorageError>;

    async fn insert_challenge(
        &self,
        challenge_id: &str,
        user_id: Option<UserId>,
        purpose: &str,
        challenge_json: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError>;
    async fn consume_challenge(
        &self,
        challenge_id: &str,
        purpose: &str,
        now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError>;

    async fn count_apikey_registrations_by_user_since(
        &self,
        user_id: UserId,
        since: DateTime<Utc>,
    ) -> Result<i64, StorageError>;
    async fn count_apikey_registrations_by_ip_since(
        &self,
        ip_hash: &str,
        since: DateTime<Utc>,
    ) -> Result<i64, StorageError>;
    async fn register_api_key(
        &self,
        key: ApiKeyRecord,
        ip_hash: &str,
        now: DateTime<Utc>,
        limits: ApiKeyRegistrationLimits,
    ) -> Result<(), StorageError>;
    async fn insert_apikey_registration_event(
        &self,
        user_id: UserId,
        ip_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError>;
    async fn delete_user(&self, user_id: UserId) -> Result<bool, StorageError>;

    /// Bump the user's last_active_at to the month-start of `now`.
    /// Skips the write when the stored value already matches.
    async fn touch_user_last_active(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError>;

    /// Read a challenge without consuming it (for device-auth polling).
    async fn get_challenge(
        &self,
        challenge_id: &str,
        purpose: &str,
        now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError>;

    /// Update the challenge_json field in-place (for marking device-auth approved).
    async fn update_challenge_json(
        &self,
        challenge_id: &str,
        purpose: &str,
        challenge_json: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError>;

    /// Find a challenge by its user_code and purpose (for approve endpoints).
    async fn find_challenge_by_user_code(
        &self,
        user_code: &str,
        purpose: &str,
        now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError>;

    async fn update_display_name(
        &self,
        user_id: UserId,
        display_name: &str,
    ) -> Result<(), StorageError>;

    async fn list_passkeys_by_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<PasskeyRecord>, StorageError>;

    /// Soft-revoke a passkey. Returns false if it was the last active passkey.
    async fn revoke_passkey(&self, id: i64, user_id: UserId) -> Result<bool, StorageError>;

    async fn update_passkey_label(
        &self,
        id: i64,
        user_id: UserId,
        label: &str,
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait AmkStore: Send + Sync {
    /// Atomically: ensure amk_accounts row exists (INSERT ON CONFLICT DO NOTHING),
    /// verify submitted commit matches stored commit, then upsert wrapper.
    async fn upsert_wrapper(
        &self,
        w: AmkWrapperRecord,
        amk_commit: &[u8],
    ) -> Result<AmkUpsertResult, StorageError>;

    async fn get_wrapper(
        &self,
        user_id: Uuid,
        key_prefix: &str,
    ) -> Result<Option<AmkWrapperRecord>, StorageError>;

    async fn list_wrappers(&self, user_id: Uuid) -> Result<Vec<AmkWrapperRecord>, StorageError>;

    async fn delete_wrapper(&self, user_id: Uuid, key_prefix: &str) -> Result<bool, StorageError>;

    async fn has_any_wrapper(&self, user_id: Uuid) -> Result<bool, StorageError>;

    async fn get_amk_commit(&self, user_id: Uuid) -> Result<Option<Vec<u8>>, StorageError>;

    /// Commit an AMK hash for a user (first-writer-wins, no wrapper needed).
    async fn commit_amk(
        &self,
        user_id: Uuid,
        amk_commit: &[u8],
    ) -> Result<AmkUpsertResult, StorageError>;

    /// Update enc_meta on an existing secret owned by one of the given owner_keys.
    async fn update_enc_meta(
        &self,
        secret_id: &str,
        owner_keys: &[String],
        enc_meta: &EncMetaV1,
        meta_key_version: i16,
    ) -> Result<(), StorageError>;
}

#[async_trait]
impl<T> SecretsStore for Arc<T>
where
    T: SecretsStore + ?Sized,
{
    async fn create(&self, secret: SecretRecord) -> Result<(), StorageError> {
        (**self).create(secret).await
    }

    async fn create_with_quota(
        &self,
        secret: SecretRecord,
        limits: SecretQuotaLimits,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        (**self).create_with_quota(secret, limits, now).await
    }

    async fn claim_and_delete(
        &self,
        id: &str,
        claim_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<SecretRecord, StorageError> {
        (**self).claim_and_delete(id, claim_hash, now).await
    }

    async fn burn(&self, id: &str, owner_key: &str) -> Result<bool, StorageError> {
        (**self).burn(id, owner_key).await
    }

    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<i64, StorageError> {
        (**self).delete_expired(now).await
    }

    async fn get_usage(&self, owner_key: &str) -> Result<StorageUsage, StorageError> {
        (**self).get_usage(owner_key).await
    }

    async fn list_by_owner_keys(
        &self,
        owner_keys: &[String],
        now: DateTime<Utc>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SecretSummary>, StorageError> {
        (**self)
            .list_by_owner_keys(owner_keys, now, limit, offset)
            .await
    }

    async fn count_by_owner_keys(
        &self,
        owner_keys: &[String],
        now: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        (**self).count_by_owner_keys(owner_keys, now).await
    }

    async fn burn_all_by_owner_keys(&self, owner_keys: &[String]) -> Result<i64, StorageError> {
        (**self).burn_all_by_owner_keys(owner_keys).await
    }

    async fn checksum_by_owner_keys(
        &self,
        owner_keys: &[String],
        now: DateTime<Utc>,
    ) -> Result<(i64, String), StorageError> {
        (**self).checksum_by_owner_keys(owner_keys, now).await
    }

    async fn get_summary_by_id(
        &self,
        id: &str,
        owner_keys: &[String],
        now: DateTime<Utc>,
    ) -> Result<Option<SecretSummary>, StorageError> {
        (**self).get_summary_by_id(id, owner_keys, now).await
    }
}

#[async_trait]
impl<T> ApiKeysStore for Arc<T>
where
    T: ApiKeysStore + ?Sized,
{
    async fn get_by_prefix(&self, prefix: &str) -> Result<ApiKeyRecord, StorageError> {
        (**self).get_by_prefix(prefix).await
    }

    async fn insert(&self, key: ApiKeyRecord) -> Result<(), StorageError> {
        (**self).insert(key).await
    }

    async fn revoke_by_prefix(&self, prefix: &str) -> Result<bool, StorageError> {
        (**self).revoke_by_prefix(prefix).await
    }

    async fn list_by_user_id(&self, user_id: UserId) -> Result<Vec<ApiKeyRecord>, StorageError> {
        (**self).list_by_user_id(user_id).await
    }

    async fn revoke_all_by_user_id(&self, user_id: UserId) -> Result<i64, StorageError> {
        (**self).revoke_all_by_user_id(user_id).await
    }
}

#[async_trait]
impl<T> AuthStore for Arc<T>
where
    T: AuthStore + ?Sized,
{
    async fn create_user(&self, display_name: &str) -> Result<UserRecord, StorageError> {
        (**self).create_user(display_name).await
    }

    async fn get_user_by_id(&self, user_id: UserId) -> Result<UserRecord, StorageError> {
        (**self).get_user_by_id(user_id).await
    }

    async fn insert_passkey(
        &self,
        user_id: UserId,
        credential_id: &str,
        public_key: &str,
        sign_count: i64,
    ) -> Result<PasskeyRecord, StorageError> {
        (**self)
            .insert_passkey(user_id, credential_id, public_key, sign_count)
            .await
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<PasskeyRecord, StorageError> {
        (**self).get_passkey_by_credential_id(credential_id).await
    }

    async fn update_passkey_sign_count(
        &self,
        credential_id: &str,
        sign_count: i64,
    ) -> Result<(), StorageError> {
        (**self)
            .update_passkey_sign_count(credential_id, sign_count)
            .await
    }

    async fn insert_session(
        &self,
        sid: &str,
        user_id: UserId,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<SessionRecord, StorageError> {
        (**self)
            .insert_session(sid, user_id, token_hash, expires_at)
            .await
    }

    async fn get_session_by_sid(&self, sid: &str) -> Result<SessionRecord, StorageError> {
        (**self).get_session_by_sid(sid).await
    }

    async fn revoke_session_by_sid(&self, sid: &str) -> Result<bool, StorageError> {
        (**self).revoke_session_by_sid(sid).await
    }

    async fn insert_challenge(
        &self,
        challenge_id: &str,
        user_id: Option<UserId>,
        purpose: &str,
        challenge_json: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        (**self)
            .insert_challenge(challenge_id, user_id, purpose, challenge_json, expires_at)
            .await
    }

    async fn consume_challenge(
        &self,
        challenge_id: &str,
        purpose: &str,
        now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        (**self).consume_challenge(challenge_id, purpose, now).await
    }

    async fn count_apikey_registrations_by_user_since(
        &self,
        user_id: UserId,
        since: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        (**self)
            .count_apikey_registrations_by_user_since(user_id, since)
            .await
    }

    async fn count_apikey_registrations_by_ip_since(
        &self,
        ip_hash: &str,
        since: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        (**self)
            .count_apikey_registrations_by_ip_since(ip_hash, since)
            .await
    }

    async fn register_api_key(
        &self,
        key: ApiKeyRecord,
        ip_hash: &str,
        now: DateTime<Utc>,
        limits: ApiKeyRegistrationLimits,
    ) -> Result<(), StorageError> {
        (**self).register_api_key(key, ip_hash, now, limits).await
    }

    async fn insert_apikey_registration_event(
        &self,
        user_id: UserId,
        ip_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        (**self)
            .insert_apikey_registration_event(user_id, ip_hash, now)
            .await
    }

    async fn delete_user(&self, user_id: UserId) -> Result<bool, StorageError> {
        (**self).delete_user(user_id).await
    }

    async fn touch_user_last_active(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        (**self).touch_user_last_active(user_id, now).await
    }

    async fn get_challenge(
        &self,
        challenge_id: &str,
        purpose: &str,
        now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        (**self).get_challenge(challenge_id, purpose, now).await
    }

    async fn update_challenge_json(
        &self,
        challenge_id: &str,
        purpose: &str,
        challenge_json: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        (**self)
            .update_challenge_json(challenge_id, purpose, challenge_json, now)
            .await
    }

    async fn find_challenge_by_user_code(
        &self,
        user_code: &str,
        purpose: &str,
        now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        (**self)
            .find_challenge_by_user_code(user_code, purpose, now)
            .await
    }

    async fn update_display_name(
        &self,
        user_id: UserId,
        display_name: &str,
    ) -> Result<(), StorageError> {
        (**self).update_display_name(user_id, display_name).await
    }

    async fn list_passkeys_by_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<PasskeyRecord>, StorageError> {
        (**self).list_passkeys_by_user(user_id).await
    }

    async fn revoke_passkey(&self, id: i64, user_id: UserId) -> Result<bool, StorageError> {
        (**self).revoke_passkey(id, user_id).await
    }

    async fn update_passkey_label(
        &self,
        id: i64,
        user_id: UserId,
        label: &str,
    ) -> Result<(), StorageError> {
        (**self).update_passkey_label(id, user_id, label).await
    }
}

#[async_trait]
impl<T> AmkStore for Arc<T>
where
    T: AmkStore + ?Sized,
{
    async fn upsert_wrapper(
        &self,
        w: AmkWrapperRecord,
        amk_commit: &[u8],
    ) -> Result<AmkUpsertResult, StorageError> {
        (**self).upsert_wrapper(w, amk_commit).await
    }

    async fn get_wrapper(
        &self,
        user_id: Uuid,
        key_prefix: &str,
    ) -> Result<Option<AmkWrapperRecord>, StorageError> {
        (**self).get_wrapper(user_id, key_prefix).await
    }

    async fn list_wrappers(&self, user_id: Uuid) -> Result<Vec<AmkWrapperRecord>, StorageError> {
        (**self).list_wrappers(user_id).await
    }

    async fn delete_wrapper(&self, user_id: Uuid, key_prefix: &str) -> Result<bool, StorageError> {
        (**self).delete_wrapper(user_id, key_prefix).await
    }

    async fn has_any_wrapper(&self, user_id: Uuid) -> Result<bool, StorageError> {
        (**self).has_any_wrapper(user_id).await
    }

    async fn get_amk_commit(&self, user_id: Uuid) -> Result<Option<Vec<u8>>, StorageError> {
        (**self).get_amk_commit(user_id).await
    }

    async fn commit_amk(
        &self,
        user_id: Uuid,
        amk_commit: &[u8],
    ) -> Result<AmkUpsertResult, StorageError> {
        (**self).commit_amk(user_id, amk_commit).await
    }

    async fn update_enc_meta(
        &self,
        secret_id: &str,
        owner_keys: &[String],
        enc_meta: &EncMetaV1,
        meta_key_version: i16,
    ) -> Result<(), StorageError> {
        (**self)
            .update_enc_meta(secret_id, owner_keys, enc_meta, meta_key_version)
            .await
    }
}

// ── Admin query result types ──────────────────────────────────────────

pub struct DashboardStats {
    pub active_secrets: i64,
    pub total_secret_bytes: i64,
    pub secrets_24h: i64,
    pub secrets_7d: i64,
    pub secrets_30d: i64,
    pub total_users: i64,
    pub users_active_30d: i64,
    pub users_active_90d: i64,
    pub active_api_keys: i64,
    pub revoked_api_keys: i64,
    pub active_sessions: i64,
}

pub struct SecretBreakdown {
    pub expiring_1h: i64,
    pub expiring_24h: i64,
    pub expiring_7d: i64,
    pub expiring_beyond_7d: i64,
    pub anonymous_count: i64,
    pub authenticated_count: i64,
    pub passphrase_protected: i64,
    pub not_passphrase_protected: i64,
    pub avg_ciphertext_bytes: i64,
    pub median_ciphertext_bytes: i64,
}

pub struct UserListEntry {
    pub id: UserId,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub last_active_at: NaiveDate,
    pub active_api_keys: i64,
    pub active_secrets: i64,
    pub passkey_count: i64,
}

pub struct UserDetail {
    pub user: UserRecord,
    pub api_keys: Vec<ApiKeyRecord>,
    pub secret_count: i64,
    pub total_secret_bytes: i64,
    pub passkey_count: i64,
    pub has_amk: bool,
}

pub struct ApiKeyListEntry {
    pub prefix: String,
    pub scopes: String,
    pub user_id: Option<UserId>,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub struct TopUser {
    pub id: UserId,
    pub display_name: String,
    pub value: i64,
}

#[async_trait]
pub trait AdminStore: Send + Sync {
    async fn dashboard_stats(&self, now: DateTime<Utc>) -> Result<DashboardStats, StorageError>;
    async fn secret_breakdown(&self, now: DateTime<Utc>) -> Result<SecretBreakdown, StorageError>;
    async fn list_users(
        &self,
        now: DateTime<Utc>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<UserListEntry>, StorageError>;
    async fn user_detail(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> Result<UserDetail, StorageError>;
    async fn list_all_api_keys(
        &self,
        user_id: Option<UserId>,
        limit: i64,
    ) -> Result<Vec<ApiKeyListEntry>, StorageError>;
    async fn top_users_by_secrets(
        &self,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<TopUser>, StorageError>;
    async fn top_users_by_bytes(
        &self,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<TopUser>, StorageError>;
    async fn top_users_by_keys(&self, limit: i64) -> Result<Vec<TopUser>, StorageError>;
}

#[async_trait]
impl<T> AdminStore for Arc<T>
where
    T: AdminStore + ?Sized,
{
    async fn dashboard_stats(&self, now: DateTime<Utc>) -> Result<DashboardStats, StorageError> {
        (**self).dashboard_stats(now).await
    }

    async fn secret_breakdown(&self, now: DateTime<Utc>) -> Result<SecretBreakdown, StorageError> {
        (**self).secret_breakdown(now).await
    }

    async fn list_users(
        &self,
        now: DateTime<Utc>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<UserListEntry>, StorageError> {
        (**self).list_users(now, limit, offset).await
    }

    async fn user_detail(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> Result<UserDetail, StorageError> {
        (**self).user_detail(user_id, now).await
    }

    async fn list_all_api_keys(
        &self,
        user_id: Option<UserId>,
        limit: i64,
    ) -> Result<Vec<ApiKeyListEntry>, StorageError> {
        (**self).list_all_api_keys(user_id, limit).await
    }

    async fn top_users_by_secrets(
        &self,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<TopUser>, StorageError> {
        (**self).top_users_by_secrets(now, limit).await
    }

    async fn top_users_by_bytes(
        &self,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<TopUser>, StorageError> {
        (**self).top_users_by_bytes(now, limit).await
    }

    async fn top_users_by_keys(&self, limit: i64) -> Result<Vec<TopUser>, StorageError> {
        (**self).top_users_by_keys(limit).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn storage_error_from_tokio_postgres_error() {
        let err =
            match tokio_postgres::connect("postgres://invalid:%zz", tokio_postgres::NoTls).await {
                Ok(_) => panic!("invalid url should fail"),
                Err(err) => err,
            };
        let converted: StorageError = err.into();
        assert!(matches!(converted, StorageError::Other(_)));
    }

    #[test]
    fn storage_error_from_deadpool_errors() {
        let pool_err: deadpool_postgres::PoolError = deadpool_postgres::PoolError::Closed;
        let converted_pool: StorageError = pool_err.into();
        assert!(matches!(converted_pool, StorageError::Other(_)));

        let create_err: deadpool_postgres::CreatePoolError =
            deadpool_postgres::CreatePoolError::Build(
                deadpool_postgres::BuildError::NoRuntimeSpecified,
            );
        let converted_create: StorageError = create_err.into();
        assert!(matches!(converted_create, StorageError::Other(_)));
    }
}
