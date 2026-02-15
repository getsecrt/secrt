use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secrt_server::reaper::{
    run_expiry_reaper_once, start_expiry_reaper, EXPIRY_REAPER_DELETE_TIMEOUT,
};
use secrt_server::storage::{SecretRecord, SecretSummary, SecretsStore, StorageError, StorageUsage};

struct CountingStore {
    calls: AtomicUsize,
}

#[async_trait]
impl SecretsStore for CountingStore {
    async fn create(&self, _secret: SecretRecord) -> Result<(), StorageError> {
        Ok(())
    }

    async fn claim_and_delete(
        &self,
        _id: &str,
        _claim_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<SecretRecord, StorageError> {
        Err(StorageError::NotFound)
    }

    async fn burn(&self, _id: &str, _owner_key: &str) -> Result<bool, StorageError> {
        Ok(false)
    }

    async fn delete_expired(&self, _now: DateTime<Utc>) -> Result<i64, StorageError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }

    async fn get_usage(&self, _owner_key: &str) -> Result<StorageUsage, StorageError> {
        Ok(StorageUsage {
            secret_count: 0,
            total_bytes: 0,
        })
    }

    async fn list_by_owner_keys(&self, _owner_keys: &[String], _now: DateTime<Utc>, _limit: i64, _offset: i64) -> Result<Vec<SecretSummary>, StorageError> {
        Ok(vec![])
    }
    async fn count_by_owner_keys(&self, _owner_keys: &[String], _now: DateTime<Utc>) -> Result<i64, StorageError> {
        Ok(0)
    }
    async fn burn_all_by_owner_keys(&self, _owner_keys: &[String]) -> Result<i64, StorageError> {
        Ok(0)
    }
    async fn checksum_by_owner_keys(&self, _owner_keys: &[String], _now: DateTime<Utc>) -> Result<(i64, String), StorageError> {
        Ok((0, String::new()))
    }
}

struct ErrorStore;

#[async_trait]
impl SecretsStore for ErrorStore {
    async fn create(&self, _secret: SecretRecord) -> Result<(), StorageError> {
        Ok(())
    }

    async fn claim_and_delete(
        &self,
        _id: &str,
        _claim_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<SecretRecord, StorageError> {
        Err(StorageError::NotFound)
    }

    async fn burn(&self, _id: &str, _owner_key: &str) -> Result<bool, StorageError> {
        Ok(false)
    }

    async fn delete_expired(&self, _now: DateTime<Utc>) -> Result<i64, StorageError> {
        Err(StorageError::Other("boom".into()))
    }

    async fn get_usage(&self, _owner_key: &str) -> Result<StorageUsage, StorageError> {
        Ok(StorageUsage {
            secret_count: 0,
            total_bytes: 0,
        })
    }

    async fn list_by_owner_keys(&self, _owner_keys: &[String], _now: DateTime<Utc>, _limit: i64, _offset: i64) -> Result<Vec<SecretSummary>, StorageError> {
        Ok(vec![])
    }
    async fn count_by_owner_keys(&self, _owner_keys: &[String], _now: DateTime<Utc>) -> Result<i64, StorageError> {
        Ok(0)
    }
    async fn burn_all_by_owner_keys(&self, _owner_keys: &[String]) -> Result<i64, StorageError> {
        Ok(0)
    }
    async fn checksum_by_owner_keys(&self, _owner_keys: &[String], _now: DateTime<Utc>) -> Result<(i64, String), StorageError> {
        Ok((0, String::new()))
    }
}

struct DeletedStore;

#[async_trait]
impl SecretsStore for DeletedStore {
    async fn create(&self, _secret: SecretRecord) -> Result<(), StorageError> {
        Ok(())
    }

    async fn claim_and_delete(
        &self,
        _id: &str,
        _claim_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<SecretRecord, StorageError> {
        Err(StorageError::NotFound)
    }

    async fn burn(&self, _id: &str, _owner_key: &str) -> Result<bool, StorageError> {
        Ok(false)
    }

    async fn delete_expired(&self, _now: DateTime<Utc>) -> Result<i64, StorageError> {
        Ok(2)
    }

    async fn get_usage(&self, _owner_key: &str) -> Result<StorageUsage, StorageError> {
        Ok(StorageUsage {
            secret_count: 0,
            total_bytes: 0,
        })
    }

    async fn list_by_owner_keys(&self, _owner_keys: &[String], _now: DateTime<Utc>, _limit: i64, _offset: i64) -> Result<Vec<SecretSummary>, StorageError> {
        Ok(vec![])
    }
    async fn count_by_owner_keys(&self, _owner_keys: &[String], _now: DateTime<Utc>) -> Result<i64, StorageError> {
        Ok(0)
    }
    async fn burn_all_by_owner_keys(&self, _owner_keys: &[String]) -> Result<i64, StorageError> {
        Ok(0)
    }
    async fn checksum_by_owner_keys(&self, _owner_keys: &[String], _now: DateTime<Utc>) -> Result<(i64, String), StorageError> {
        Ok((0, String::new()))
    }
}

struct SlowStore;

#[async_trait]
impl SecretsStore for SlowStore {
    async fn create(&self, _secret: SecretRecord) -> Result<(), StorageError> {
        Ok(())
    }

    async fn claim_and_delete(
        &self,
        _id: &str,
        _claim_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<SecretRecord, StorageError> {
        Err(StorageError::NotFound)
    }

    async fn burn(&self, _id: &str, _owner_key: &str) -> Result<bool, StorageError> {
        Ok(false)
    }

    async fn delete_expired(&self, _now: DateTime<Utc>) -> Result<i64, StorageError> {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        Ok(0)
    }

    async fn get_usage(&self, _owner_key: &str) -> Result<StorageUsage, StorageError> {
        Ok(StorageUsage {
            secret_count: 0,
            total_bytes: 0,
        })
    }

    async fn list_by_owner_keys(&self, _owner_keys: &[String], _now: DateTime<Utc>, _limit: i64, _offset: i64) -> Result<Vec<SecretSummary>, StorageError> {
        Ok(vec![])
    }
    async fn count_by_owner_keys(&self, _owner_keys: &[String], _now: DateTime<Utc>) -> Result<i64, StorageError> {
        Ok(0)
    }
    async fn burn_all_by_owner_keys(&self, _owner_keys: &[String]) -> Result<i64, StorageError> {
        Ok(0)
    }
    async fn checksum_by_owner_keys(&self, _owner_keys: &[String], _now: DateTime<Utc>) -> Result<(i64, String), StorageError> {
        Ok((0, String::new()))
    }
}

#[tokio::test(start_paused = true)]
async fn reaper_runs_once_immediately_before_first_interval_tick() {
    let store = Arc::new(CountingStore {
        calls: AtomicUsize::new(0),
    });
    let stop = start_expiry_reaper(store.clone());

    tokio::task::yield_now().await;
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);

    tokio::time::advance(Duration::from_secs(5 * 60) + Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(store.calls.load(Ordering::SeqCst), 2);

    let _ = stop.send(());
    tokio::task::yield_now().await;
}

#[tokio::test]
async fn reaper_once_invokes_delete() {
    let store = Arc::new(CountingStore {
        calls: AtomicUsize::new(0),
    });
    run_expiry_reaper_once(store.clone()).await;
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reaper_once_logs_deleted_count_path() {
    run_expiry_reaper_once(Arc::new(DeletedStore)).await;
}

#[tokio::test]
async fn reaper_once_error_path() {
    run_expiry_reaper_once(Arc::new(ErrorStore)).await;
}

#[tokio::test(start_paused = true)]
async fn reaper_once_timeout_path() {
    let task = tokio::spawn(run_expiry_reaper_once(Arc::new(SlowStore)));
    tokio::time::advance(EXPIRY_REAPER_DELETE_TIMEOUT + Duration::from_millis(1)).await;
    task.await.expect("join");
}
