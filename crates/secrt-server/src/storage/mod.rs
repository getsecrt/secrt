use async_trait::async_trait;
use chrono::{DateTime, Utc};
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyRecord {
    pub id: i64,
    pub user_id: UserId,
    pub credential_id: String,
    pub public_key: String,
    pub sign_count: i64,
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
