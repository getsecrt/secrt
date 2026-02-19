use async_trait::async_trait;
use chrono::{DateTime, Utc};
use deadpool_postgres::{
    Config as PgPoolConfig, Hook, HookError, Manager, ManagerConfig, Pool, RecyclingMethod, Runtime,
};
use tokio_postgres::error::SqlState;
use uuid::Uuid;

use super::{
    ApiKeyRecord, ApiKeyRegistrationLimits, ApiKeysStore, AuthStore, ChallengeRecord,
    PasskeyRecord, SecretQuotaLimits, SecretRecord, SecretSummary, SecretsStore, SessionRecord,
    StorageError, StorageUsage, UserId, UserRecord,
};

const POOL_MAX_SIZE: usize = 10;
const POOL_MAX_LIFETIME: std::time::Duration = std::time::Duration::from_secs(30 * 60);
const APIKEY_REGISTRATION_RETENTION_HOURS: i64 = 24;

const DELETE_EXPIRED_SECRETS_SQL: &str = "DELETE FROM secrets WHERE expires_at <= $1";
const DELETE_EXPIRED_CHALLENGES_SQL: &str =
    "DELETE FROM webauthn_challenges WHERE expires_at <= $1";
const DELETE_STALE_SESSIONS_SQL: &str =
    "DELETE FROM sessions WHERE expires_at <= $1 OR revoked_at IS NOT NULL";
const DELETE_OLD_REGISTRATIONS_SQL: &str =
    "DELETE FROM api_key_registrations WHERE created_at <= $1";

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
        Self::from_database_url_with_max_lifetime(database_url, POOL_MAX_LIFETIME).await
    }

    pub async fn from_database_url_with_max_lifetime(
        database_url: &str,
        max_lifetime: std::time::Duration,
    ) -> Result<Self, StorageError> {
        let mut pool_cfg = PgPoolConfig::new();
        pool_cfg.url = Some(database_url.to_string());
        pool_cfg.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });
        pool_cfg.pool = Some(deadpool_postgres::PoolConfig {
            max_size: POOL_MAX_SIZE,
            ..Default::default()
        });
        let pg_config = pool_cfg
            .get_pg_config()
            .map_err(|e| StorageError::Other(e.to_string()))?;
        let manager = Manager::from_config(
            pg_config,
            tokio_postgres::NoTls,
            pool_cfg.get_manager_config(),
        );
        let pool = Pool::builder(manager)
            .config(pool_cfg.get_pool_config())
            .runtime(Runtime::Tokio1)
            .post_recycle(Hook::sync_fn(move |_client, metrics| {
                if connection_exceeds_max_lifetime(metrics.age(), max_lifetime) {
                    return Err(HookError::message("connection max lifetime exceeded"));
                }
                Ok(())
            }))
            .build()
            .map_err(|e| StorageError::Other(e.to_string()))?;

        // Verify connectivity on startup.
        let _ = pool.get().await?;

        Ok(Self { pool })
    }
}

fn connection_exceeds_max_lifetime(
    age: std::time::Duration,
    max_lifetime: std::time::Duration,
) -> bool {
    age >= max_lifetime
}

fn map_write_error(err: tokio_postgres::Error) -> StorageError {
    if let Some(db) = err.as_db_error() {
        if db.code() == &SqlState::UNIQUE_VIOLATION {
            return StorageError::DuplicateId;
        }
    }
    err.into()
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

    async fn create_with_quota(
        &self,
        secret: SecretRecord,
        limits: SecretQuotaLimits,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;

        if limits.max_secrets > 0 || limits.max_total_bytes > 0 {
            tx.query_one(
                "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)",
                &[&secret.owner_key],
            )
            .await?;

            let row = tx
                .query_one(
                    "SELECT COUNT(*), COALESCE(SUM(LENGTH(envelope::text)), 0) \
                     FROM secrets WHERE owner_key = $1 AND expires_at > $2",
                    &[&secret.owner_key, &now],
                )
                .await?;

            let secret_count: i64 = row.try_get(0)?;
            let total_bytes: i64 = row.try_get(1)?;

            if limits.max_secrets > 0 && secret_count >= limits.max_secrets {
                return Err(StorageError::QuotaExceeded("secret_count".into()));
            }

            if limits.max_total_bytes > 0
                && total_bytes + secret.envelope.len() as i64 > limits.max_total_bytes
            {
                return Err(StorageError::QuotaExceeded("total_bytes".into()));
            }
        }

        let envelope: serde_json::Value = serde_json::from_str(secret.envelope.as_ref())
            .map_err(|e| StorageError::Other(format!("decode envelope json: {e}")))?;

        let err = tx
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
        if let Some(err) = err {
            return Err(map_write_error(err));
        }

        tx.commit().await?;
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
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let registration_cutoff =
            now - chrono::Duration::hours(APIKEY_REGISTRATION_RETENTION_HOURS);

        let deleted_secrets = tx.execute(DELETE_EXPIRED_SECRETS_SQL, &[&now]).await?;
        let deleted_challenges = tx.execute(DELETE_EXPIRED_CHALLENGES_SQL, &[&now]).await?;
        let deleted_sessions = tx.execute(DELETE_STALE_SESSIONS_SQL, &[&now]).await?;
        let deleted_registrations = tx
            .execute(DELETE_OLD_REGISTRATIONS_SQL, &[&registration_cutoff])
            .await?;

        tx.commit().await?;

        Ok(
            (deleted_secrets + deleted_challenges + deleted_sessions + deleted_registrations)
                as i64,
        )
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

    async fn list_by_owner_keys(
        &self,
        owner_keys: &[String],
        now: DateTime<Utc>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SecretSummary>, StorageError> {
        if owner_keys.is_empty() {
            return Ok(vec![]);
        }
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT id, expires_at, created_at, \
                        octet_length(envelope::text)::bigint AS ciphertext_size, \
                        COALESCE(envelope->'kdf'->>'name', 'none') <> 'none' AS passphrase_protected \
                 FROM secrets \
                 WHERE owner_key = ANY($1) AND expires_at > $2 \
                 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
                &[&owner_keys, &now, &limit, &offset],
            )
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(SecretSummary {
                id: row.try_get(0)?,
                expires_at: row.try_get(1)?,
                created_at: row.try_get(2)?,
                ciphertext_size: row.try_get(3)?,
                passphrase_protected: row.try_get(4)?,
            });
        }
        Ok(out)
    }

    async fn count_by_owner_keys(
        &self,
        owner_keys: &[String],
        now: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        if owner_keys.is_empty() {
            return Ok(0);
        }
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                "SELECT COUNT(*) FROM secrets \
                 WHERE owner_key = ANY($1) AND expires_at > $2",
                &[&owner_keys, &now],
            )
            .await?;
        Ok(row.try_get(0)?)
    }

    async fn burn_all_by_owner_keys(&self, owner_keys: &[String]) -> Result<i64, StorageError> {
        if owner_keys.is_empty() {
            return Ok(0);
        }
        let client = self.pool.get().await?;
        let n = client
            .execute(
                "DELETE FROM secrets WHERE owner_key = ANY($1)",
                &[&owner_keys],
            )
            .await?;
        Ok(n as i64)
    }

    async fn checksum_by_owner_keys(
        &self,
        owner_keys: &[String],
        now: DateTime<Utc>,
    ) -> Result<(i64, String), StorageError> {
        if owner_keys.is_empty() {
            return Ok((0, String::new()));
        }
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                "SELECT COUNT(*), \
                        COALESCE(md5(string_agg(id, ',' ORDER BY id)), '') \
                 FROM secrets \
                 WHERE owner_key = ANY($1) AND expires_at > $2",
                &[&owner_keys, &now],
            )
            .await?;
        let count: i64 = row.try_get(0)?;
        let checksum: String = row.try_get(1)?;
        Ok((count, checksum))
    }
}

#[cfg(test)]
mod tests {
    use super::connection_exceeds_max_lifetime;

    #[test]
    fn connection_max_lifetime_check() {
        let max = std::time::Duration::from_secs(1800);
        assert!(!connection_exceeds_max_lifetime(
            std::time::Duration::from_secs(1799),
            max
        ));
        assert!(connection_exceeds_max_lifetime(
            std::time::Duration::from_secs(1800),
            max
        ));
        assert!(connection_exceeds_max_lifetime(
            std::time::Duration::from_secs(1801),
            max
        ));
    }
}

#[async_trait]
impl ApiKeysStore for PgStore {
    async fn get_by_prefix(&self, prefix: &str) -> Result<ApiKeyRecord, StorageError> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT id, key_prefix, auth_hash, scopes, user_id, created_at, revoked_at \
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
            auth_hash: row.try_get(2)?,
            scopes: row.try_get(3)?,
            user_id: row.try_get(4)?,
            created_at: row.try_get(5)?,
            revoked_at: row.try_get(6)?,
        })
    }

    async fn insert(&self, key: ApiKeyRecord) -> Result<(), StorageError> {
        let client = self.pool.get().await?;
        let err = client
            .execute(
                "INSERT INTO api_keys (key_prefix, auth_hash, scopes, user_id, revoked_at) \
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &key.prefix,
                    &key.auth_hash,
                    &key.scopes,
                    &key.user_id,
                    &key.revoked_at,
                ],
            )
            .await
            .err();
        if let Some(err) = err {
            return Err(map_write_error(err));
        }
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

    async fn list_by_user_id(&self, user_id: UserId) -> Result<Vec<ApiKeyRecord>, StorageError> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT id, key_prefix, auth_hash, scopes, user_id, created_at, revoked_at \
                 FROM api_keys WHERE user_id=$1 ORDER BY created_at DESC",
                &[&user_id],
            )
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(ApiKeyRecord {
                id: row.try_get(0)?,
                prefix: row.try_get(1)?,
                auth_hash: row.try_get(2)?,
                scopes: row.try_get(3)?,
                user_id: row.try_get(4)?,
                created_at: row.try_get(5)?,
                revoked_at: row.try_get(6)?,
            });
        }
        Ok(out)
    }

    async fn revoke_all_by_user_id(&self, user_id: UserId) -> Result<i64, StorageError> {
        let client = self.pool.get().await?;
        let n = client
            .execute(
                "UPDATE api_keys SET revoked_at = now() \
                 WHERE user_id=$1 AND revoked_at IS NULL",
                &[&user_id],
            )
            .await?;
        Ok(n as i64)
    }
}

#[async_trait]
impl AuthStore for PgStore {
    async fn create_user(&self, display_name: &str) -> Result<UserRecord, StorageError> {
        let client = self.pool.get().await?;
        let user_id = Uuid::now_v7();
        let row = client
            .query_one(
                "INSERT INTO users (id, display_name) VALUES ($1, $2) \
                 RETURNING id, display_name, created_at",
                &[&user_id, &display_name],
            )
            .await?;
        Ok(UserRecord {
            id: row.try_get(0)?,
            display_name: row.try_get(1)?,
            created_at: row.try_get(2)?,
        })
    }

    async fn get_user_by_id(&self, user_id: UserId) -> Result<UserRecord, StorageError> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT id, display_name, created_at FROM users WHERE id=$1",
                &[&user_id],
            )
            .await?;
        let Some(row) = row else {
            return Err(StorageError::NotFound);
        };
        Ok(UserRecord {
            id: row.try_get(0)?,
            display_name: row.try_get(1)?,
            created_at: row.try_get(2)?,
        })
    }

    async fn insert_passkey(
        &self,
        user_id: UserId,
        credential_id: &str,
        public_key: &str,
        sign_count: i64,
    ) -> Result<PasskeyRecord, StorageError> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                "INSERT INTO passkeys (user_id, credential_id, public_key, sign_count) \
                 VALUES ($1, $2, $3, $4) \
                 RETURNING id, user_id, credential_id, public_key, sign_count, created_at, revoked_at",
                &[&user_id, &credential_id, &public_key, &sign_count],
            )
            .await?;
        Ok(PasskeyRecord {
            id: row.try_get(0)?,
            user_id: row.try_get(1)?,
            credential_id: row.try_get(2)?,
            public_key: row.try_get(3)?,
            sign_count: row.try_get(4)?,
            created_at: row.try_get(5)?,
            revoked_at: row.try_get(6)?,
        })
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<PasskeyRecord, StorageError> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT id, user_id, credential_id, public_key, sign_count, created_at, revoked_at \
                 FROM passkeys WHERE credential_id=$1",
                &[&credential_id],
            )
            .await?;
        let Some(row) = row else {
            return Err(StorageError::NotFound);
        };
        Ok(PasskeyRecord {
            id: row.try_get(0)?,
            user_id: row.try_get(1)?,
            credential_id: row.try_get(2)?,
            public_key: row.try_get(3)?,
            sign_count: row.try_get(4)?,
            created_at: row.try_get(5)?,
            revoked_at: row.try_get(6)?,
        })
    }

    async fn update_passkey_sign_count(
        &self,
        credential_id: &str,
        sign_count: i64,
    ) -> Result<(), StorageError> {
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE passkeys SET sign_count=$1 WHERE credential_id=$2",
                &[&sign_count, &credential_id],
            )
            .await?;
        Ok(())
    }

    async fn insert_session(
        &self,
        sid: &str,
        user_id: UserId,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<SessionRecord, StorageError> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                "INSERT INTO sessions (sid, user_id, token_hash, expires_at) \
                 VALUES ($1, $2, $3, $4) \
                 RETURNING id, sid, user_id, token_hash, expires_at, created_at, revoked_at",
                &[&sid, &user_id, &token_hash, &expires_at],
            )
            .await?;
        Ok(SessionRecord {
            id: row.try_get(0)?,
            sid: row.try_get(1)?,
            user_id: row.try_get(2)?,
            token_hash: row.try_get(3)?,
            expires_at: row.try_get(4)?,
            created_at: row.try_get(5)?,
            revoked_at: row.try_get(6)?,
        })
    }

    async fn get_session_by_sid(&self, sid: &str) -> Result<SessionRecord, StorageError> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT id, sid, user_id, token_hash, expires_at, created_at, revoked_at \
                 FROM sessions WHERE sid=$1",
                &[&sid],
            )
            .await?;
        let Some(row) = row else {
            return Err(StorageError::NotFound);
        };
        Ok(SessionRecord {
            id: row.try_get(0)?,
            sid: row.try_get(1)?,
            user_id: row.try_get(2)?,
            token_hash: row.try_get(3)?,
            expires_at: row.try_get(4)?,
            created_at: row.try_get(5)?,
            revoked_at: row.try_get(6)?,
        })
    }

    async fn revoke_session_by_sid(&self, sid: &str) -> Result<bool, StorageError> {
        let client = self.pool.get().await?;
        let n = client
            .execute(
                "UPDATE sessions SET revoked_at=now() WHERE sid=$1 AND revoked_at IS NULL",
                &[&sid],
            )
            .await?;
        Ok(n > 0)
    }

    async fn insert_challenge(
        &self,
        challenge_id: &str,
        user_id: Option<UserId>,
        purpose: &str,
        challenge_json: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                "INSERT INTO webauthn_challenges (challenge_id, user_id, purpose, challenge_json, expires_at) \
                 VALUES ($1, $2, $3, $4, $5) \
                 RETURNING id, challenge_id, user_id, purpose, challenge_json, expires_at, created_at",
                &[&challenge_id, &user_id, &purpose, &challenge_json, &expires_at],
            )
            .await?;
        Ok(ChallengeRecord {
            id: row.try_get(0)?,
            challenge_id: row.try_get(1)?,
            user_id: row.try_get(2)?,
            purpose: row.try_get(3)?,
            challenge_json: row.try_get(4)?,
            expires_at: row.try_get(5)?,
            created_at: row.try_get(6)?,
        })
    }

    async fn consume_challenge(
        &self,
        challenge_id: &str,
        purpose: &str,
        now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "DELETE FROM webauthn_challenges \
                 WHERE challenge_id=$1 AND purpose=$2 AND expires_at>$3 \
                 RETURNING id, challenge_id, user_id, purpose, challenge_json, expires_at, created_at",
                &[&challenge_id, &purpose, &now],
            )
            .await?;
        let Some(row) = row else {
            return Err(StorageError::NotFound);
        };
        Ok(ChallengeRecord {
            id: row.try_get(0)?,
            challenge_id: row.try_get(1)?,
            user_id: row.try_get(2)?,
            purpose: row.try_get(3)?,
            challenge_json: row.try_get(4)?,
            expires_at: row.try_get(5)?,
            created_at: row.try_get(6)?,
        })
    }

    async fn count_apikey_registrations_by_user_since(
        &self,
        user_id: UserId,
        since: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                "SELECT COUNT(*) FROM api_key_registrations WHERE user_id=$1 AND created_at>$2",
                &[&user_id, &since],
            )
            .await?;
        Ok(row.try_get(0)?)
    }

    async fn count_apikey_registrations_by_ip_since(
        &self,
        ip_hash: &str,
        since: DateTime<Utc>,
    ) -> Result<i64, StorageError> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                "SELECT COUNT(*) FROM api_key_registrations WHERE ip_hash=$1 AND created_at>$2",
                &[&ip_hash, &since],
            )
            .await?;
        Ok(row.try_get(0)?)
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

        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let since_hour = now - chrono::Duration::hours(1);
        let since_day = now - chrono::Duration::hours(24);

        let account_hour: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM api_key_registrations WHERE user_id=$1 AND created_at>$2",
                &[&user_id, &since_hour],
            )
            .await?
            .try_get(0)?;
        if limits.account_hour > 0 && account_hour >= limits.account_hour {
            return Err(StorageError::QuotaExceeded("account/hour".into()));
        }

        let account_day: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM api_key_registrations WHERE user_id=$1 AND created_at>$2",
                &[&user_id, &since_day],
            )
            .await?
            .try_get(0)?;
        if limits.account_day > 0 && account_day >= limits.account_day {
            return Err(StorageError::QuotaExceeded("account/day".into()));
        }

        let ip_hour: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM api_key_registrations WHERE ip_hash=$1 AND created_at>$2",
                &[&ip_hash, &since_hour],
            )
            .await?
            .try_get(0)?;
        if limits.ip_hour > 0 && ip_hour >= limits.ip_hour {
            return Err(StorageError::QuotaExceeded("ip/hour".into()));
        }

        let ip_day: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM api_key_registrations WHERE ip_hash=$1 AND created_at>$2",
                &[&ip_hash, &since_day],
            )
            .await?
            .try_get(0)?;
        if limits.ip_day > 0 && ip_day >= limits.ip_day {
            return Err(StorageError::QuotaExceeded("ip/day".into()));
        }

        let err = tx
            .execute(
                "INSERT INTO api_keys (key_prefix, auth_hash, scopes, user_id, revoked_at) \
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &key.prefix,
                    &key.auth_hash,
                    &key.scopes,
                    &key.user_id,
                    &key.revoked_at,
                ],
            )
            .await
            .err();
        if let Some(err) = err {
            return Err(map_write_error(err));
        }

        tx.execute(
            "INSERT INTO api_key_registrations (user_id, ip_hash, created_at) VALUES ($1, $2, $3)",
            &[&user_id, &ip_hash, &now],
        )
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn insert_apikey_registration_event(
        &self,
        user_id: UserId,
        ip_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO api_key_registrations (user_id, ip_hash, created_at) VALUES ($1, $2, $3)",
                &[&user_id, &ip_hash, &now],
            )
            .await?;
        Ok(())
    }

    async fn delete_user(&self, user_id: UserId) -> Result<bool, StorageError> {
        let client = self.pool.get().await?;
        let n = client
            .execute("DELETE FROM users WHERE id=$1", &[&user_id])
            .await?;
        Ok(n > 0)
    }

    async fn get_challenge(
        &self,
        challenge_id: &str,
        purpose: &str,
        now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT id, challenge_id, user_id, purpose, challenge_json, expires_at, created_at \
                 FROM webauthn_challenges \
                 WHERE challenge_id=$1 AND purpose=$2 AND expires_at>$3",
                &[&challenge_id, &purpose, &now],
            )
            .await?;
        let Some(row) = row else {
            return Err(StorageError::NotFound);
        };
        Ok(ChallengeRecord {
            id: row.try_get(0)?,
            challenge_id: row.try_get(1)?,
            user_id: row.try_get(2)?,
            purpose: row.try_get(3)?,
            challenge_json: row.try_get(4)?,
            expires_at: row.try_get(5)?,
            created_at: row.try_get(6)?,
        })
    }

    async fn update_challenge_json(
        &self,
        challenge_id: &str,
        purpose: &str,
        challenge_json: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let client = self.pool.get().await?;
        let n = client
            .execute(
                "UPDATE webauthn_challenges SET challenge_json=$1 \
                 WHERE challenge_id=$2 AND purpose=$3 AND expires_at>$4",
                &[&challenge_json, &challenge_id, &purpose, &now],
            )
            .await?;
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    async fn find_device_challenge_by_user_code(
        &self,
        user_code: &str,
        now: DateTime<Utc>,
    ) -> Result<ChallengeRecord, StorageError> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT id, challenge_id, user_id, purpose, challenge_json, expires_at, created_at \
                 FROM webauthn_challenges \
                 WHERE purpose='device-auth' AND expires_at>$1 \
                   AND challenge_json::jsonb->>'user_code'=$2",
                &[&now, &user_code],
            )
            .await?;
        let Some(row) = row else {
            return Err(StorageError::NotFound);
        };
        Ok(ChallengeRecord {
            id: row.try_get(0)?,
            challenge_id: row.try_get(1)?,
            user_id: row.try_get(2)?,
            purpose: row.try_get(3)?,
            challenge_json: row.try_get(4)?,
            expires_at: row.try_get(5)?,
            created_at: row.try_get(6)?,
        })
    }
}
