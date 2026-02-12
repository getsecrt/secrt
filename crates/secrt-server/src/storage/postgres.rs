use async_trait::async_trait;
use chrono::{DateTime, Utc};
use deadpool_postgres::{Config as PgPoolConfig, ManagerConfig, Pool, RecyclingMethod, Runtime};
use tokio_postgres::error::SqlState;

use super::{ApiKeyRecord, ApiKeysStore, SecretRecord, SecretsStore, StorageError, StorageUsage};

#[derive(Clone)]
pub struct PgStore {
    pool: Pool,
}

impl PgStore {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    pub async fn from_database_url(database_url: &str) -> Result<Self, StorageError> {
        let mut pool_cfg = PgPoolConfig::new();
        pool_cfg.url = Some(database_url.to_string());
        pool_cfg.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });
        pool_cfg.pool = Some(deadpool_postgres::PoolConfig {
            max_size: 10,
            ..Default::default()
        });
        let pool = pool_cfg.create_pool(Some(Runtime::Tokio1), tokio_postgres::NoTls)?;

        // Verify connectivity on startup.
        let _ = pool.get().await?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl SecretsStore for PgStore {
    async fn create(&self, secret: SecretRecord) -> Result<(), StorageError> {
        let client = self.pool.get().await?;
        let envelope: serde_json::Value = serde_json::from_str(secret.envelope.as_ref())
            .map_err(|e| StorageError::Other(format!("decode envelope json: {e}")))?;

        let err = client
            .execute(
                "INSERT INTO secrets (id, claim_hash, envelope, expires_at, owner_key) \
                 VALUES ($1, $2, $3::jsonb, $4, $5)",
                &[
                    &secret.id,
                    &secret.claim_hash,
                    &envelope,
                    &secret.expires_at,
                    &secret.owner_key,
                ],
            )
            .await
            .err();

        if let Some(e) = err {
            if let Some(db) = e.as_db_error() {
                if db.code() == &SqlState::UNIQUE_VIOLATION {
                    return Err(StorageError::DuplicateId);
                }
            }
            return Err(e.into());
        }

        Ok(())
    }

    async fn claim_and_delete(
        &self,
        id: &str,
        claim_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<SecretRecord, StorageError> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "DELETE FROM secrets \
                 WHERE id=$1 AND claim_hash=$2 AND expires_at>$3 \
                 RETURNING envelope::text, expires_at, created_at, owner_key",
                &[&id, &claim_hash, &now],
            )
            .await?;

        let Some(row) = row else {
            return Err(StorageError::NotFound);
        };

        let envelope: String = row.try_get(0)?;
        let expires_at: DateTime<Utc> = row.try_get(1)?;
        let created_at: DateTime<Utc> = row.try_get(2)?;
        let owner_key: String = row.try_get(3)?;

        Ok(SecretRecord {
            id: id.to_string(),
            claim_hash: claim_hash.to_string(),
            envelope: envelope.into_boxed_str(),
            expires_at,
            created_at,
            owner_key,
        })
    }

    async fn burn(&self, id: &str, owner_key: &str) -> Result<bool, StorageError> {
        let client = self.pool.get().await?;

        let n = client
            .execute(
                "DELETE FROM secrets WHERE id=$1 AND owner_key=$2",
                &[&id, &owner_key],
            )
            .await?;

        Ok(n > 0)
    }

    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<i64, StorageError> {
        let client = self.pool.get().await?;
        let n = client
            .execute("DELETE FROM secrets WHERE expires_at <= $1", &[&now])
            .await?;
        Ok(n as i64)
    }

    async fn get_usage(&self, owner_key: &str) -> Result<StorageUsage, StorageError> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(envelope::text)), 0) \
                 FROM secrets WHERE owner_key = $1 AND expires_at > now()",
                &[&owner_key],
            )
            .await?;
        let secret_count: i64 = row.try_get(0)?;
        let total_bytes: i64 = row.try_get(1)?;
        Ok(StorageUsage {
            secret_count,
            total_bytes,
        })
    }
}

#[async_trait]
impl ApiKeysStore for PgStore {
    async fn get_by_prefix(&self, prefix: &str) -> Result<ApiKeyRecord, StorageError> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT id, key_prefix, key_hash, scopes, created_at, revoked_at \
                 FROM api_keys WHERE key_prefix=$1",
                &[&prefix],
            )
            .await?;

        let Some(row) = row else {
            return Err(StorageError::NotFound);
        };

        Ok(ApiKeyRecord {
            id: row.try_get(0)?,
            prefix: row.try_get(1)?,
            hash: row.try_get(2)?,
            scopes: row.try_get(3)?,
            created_at: row.try_get(4)?,
            revoked_at: row.try_get(5)?,
        })
    }

    async fn insert(&self, key: ApiKeyRecord) -> Result<(), StorageError> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO api_keys (key_prefix, key_hash, scopes, revoked_at) \
                 VALUES ($1, $2, $3, $4)",
                &[&key.prefix, &key.hash, &key.scopes, &key.revoked_at],
            )
            .await?;
        Ok(())
    }

    async fn revoke_by_prefix(&self, prefix: &str) -> Result<bool, StorageError> {
        let client = self.pool.get().await?;
        let n = client
            .execute(
                "UPDATE api_keys SET revoked_at = now() \
                 WHERE key_prefix=$1 AND revoked_at IS NULL",
                &[&prefix],
            )
            .await?;
        Ok(n > 0)
    }
}
