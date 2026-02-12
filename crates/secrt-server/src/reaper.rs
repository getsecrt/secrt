use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::oneshot;
use tracing::{error, info};

use crate::storage::SecretsStore;

pub const EXPIRY_REAPER_INTERVAL: Duration = Duration::from_secs(5 * 60);
pub const EXPIRY_REAPER_DELETE_TIMEOUT: Duration = Duration::from_secs(10);

pub fn start_expiry_reaper(store: Arc<dyn SecretsStore>) -> oneshot::Sender<()> {
    let (tx, mut rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        run_expiry_reaper_once(store.clone()).await;
        let mut ticker = tokio::time::interval(EXPIRY_REAPER_INTERVAL);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    run_expiry_reaper_once(store.clone()).await;
                }
                _ = &mut rx => {
                    break;
                }
            }
        }
    });

    tx
}

pub async fn run_expiry_reaper_once(store: Arc<dyn SecretsStore>) {
    let timeout = tokio::time::timeout(
        EXPIRY_REAPER_DELETE_TIMEOUT,
        store.delete_expired(Utc::now()),
    )
    .await;

    match timeout {
        Ok(Ok(deleted)) => {
            if deleted > 0 {
                info!(count = deleted, "expired secrets deleted");
            }
        }
        Ok(Err(err)) => {
            error!(err = %err, "expiry reaper delete failed");
        }
        Err(_) => {
            error!("expiry reaper timed out");
        }
    }
}
