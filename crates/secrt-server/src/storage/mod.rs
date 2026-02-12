use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod migrations;
pub mod postgres;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    pub id: i64,
    pub prefix: String,
    pub hash: String,
    pub scopes: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("not found")]
    NotFound,
    #[error("duplicate id")]
    DuplicateId,
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
    async fn claim_and_delete(
        &self,
        id: &str,
        claim_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<SecretRecord, StorageError>;
    async fn burn(&self, id: &str, owner_key: &str) -> Result<bool, StorageError>;
    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<i64, StorageError>;
    async fn get_usage(&self, owner_key: &str) -> Result<StorageUsage, StorageError>;
}

#[async_trait]
pub trait ApiKeysStore: Send + Sync {
    async fn get_by_prefix(&self, prefix: &str) -> Result<ApiKeyRecord, StorageError>;
    async fn insert(&self, key: ApiKeyRecord) -> Result<(), StorageError>;
    async fn revoke_by_prefix(&self, prefix: &str) -> Result<bool, StorageError>;
}

#[async_trait]
impl<T> SecretsStore for Arc<T>
where
    T: SecretsStore + ?Sized,
{
    async fn create(&self, secret: SecretRecord) -> Result<(), StorageError> {
        (**self).create(secret).await
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
