use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info};

use crate::config::{Config, ConfigError};
use crate::http::{build_router, parse_socket_addr, AppState};
use crate::reaper::start_expiry_reaper;
use crate::storage::migrations::migrate;
use crate::storage::postgres::PgStore;
use crate::storage::{ApiKeysStore, SecretsStore, StorageError};

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    #[error("storage: {0}")]
    Storage(#[from] StorageError),
    #[error("listen addr parse: {0}")]
    ParseListenAddr(String),
    #[error("bind listener: {0}")]
    Bind(String),
    #[error("serve: {0}")]
    Serve(String),
}

pub async fn run_server() -> Result<(), RuntimeError> {
    run_server_with_shutdown(shutdown_signal()).await
}

pub async fn run_server_with_shutdown<F>(shutdown: F) -> Result<(), RuntimeError>
where
    F: Future<Output = ()> + Send + 'static,
{
    if std::env::var("ENV").unwrap_or_else(|_| "development".to_string()) != "production" {
        let _ = load_dotenv_if_present(".env");
    }

    let cfg = Config::load()?;
    init_logging(&cfg.log_level);

    let db_url = cfg.postgres_url()?;
    let pg_store = Arc::new(PgStore::from_database_url(&db_url).await?);
    migrate(pg_store.pool()).await?;

    let secrets: Arc<dyn SecretsStore> = pg_store.clone();
    let api_keys: Arc<dyn ApiKeysStore> = pg_store.clone();
    let state = Arc::new(AppState::new(cfg.clone(), secrets.clone(), api_keys));
    state.start_limiter_gc();

    let reaper_stop = start_expiry_reaper(secrets);

    let app = build_router(state.clone());

    let addr = parse_socket_addr(&cfg.listen_addr)
        .map_err(|e| RuntimeError::ParseListenAddr(format!("{} ({e})", cfg.listen_addr)))?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| RuntimeError::Bind(e.to_string()))?;

    info!(addr = %addr, "listening");

    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown);

    let result = server.await;

    let _ = reaper_stop.send(());
    state.stop_limiter_gc();

    if let Err(err) = result {
        error!(err = %err, "http server error");
        return Err(RuntimeError::Serve(err.to_string()));
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut stream) = signal(SignalKind::terminate()) {
            let _ = stream.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

pub fn load_dotenv_if_present(path: impl AsRef<Path>) -> std::io::Result<()> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(());
    }

    let contents = fs::read_to_string(path)?;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };

        if std::env::var_os(k).is_some() {
            continue;
        }

        std::env::set_var(k.trim(), v.trim());
    }

    Ok(())
}

pub fn init_logging(log_level: &str) {
    let level = match log_level.to_ascii_lowercase().as_str() {
        "debug" => "debug",
        "warn" | "warning" => "warn",
        "error" => "error",
        _ => "info",
    };

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(false)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        key: &'static str,
        old: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let old = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, old }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(old) = &self.old {
                std::env::set_var(self.key, old);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn dotenv_absent_is_ok() {
        let r = load_dotenv_if_present("/tmp/definitely-not-there-secrt-dotenv");
        assert!(r.is_ok());
    }

    #[test]
    fn parse_log_level_does_not_panic() {
        init_logging("info");
    }

    #[test]
    fn dotenv_parses_lines_and_preserves_existing_env() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let original_foo = std::env::var("FOO").ok();
        let original_existing = std::env::var("EXISTING").ok();
        std::env::set_var("FOO", "before_foo");
        std::env::set_var("EXISTING", "before_existing");
        let path = format!(
            "/tmp/secrt-dotenv-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        );
        std::fs::write(
            &path,
            "\n# comment\nFOO=bar\nMISSING_LINE\nEXISTING=from_file\n",
        )
        .expect("write dotenv");

        let old_foo = std::env::var("FOO").ok();
        let old_existing = std::env::var("EXISTING").ok();
        std::env::remove_var("FOO");
        std::env::set_var("EXISTING", "from_env");

        load_dotenv_if_present(&path).expect("load dotenv");
        assert_eq!(std::env::var("FOO").ok().as_deref(), Some("bar"));
        assert_eq!(std::env::var("EXISTING").ok().as_deref(), Some("from_env"));

        if let Some(v) = old_foo {
            std::env::set_var("FOO", v);
        } else {
            std::env::remove_var("FOO");
        }
        if let Some(v) = old_existing {
            std::env::set_var("EXISTING", v);
        } else {
            std::env::remove_var("EXISTING");
        }

        if let Some(v) = original_foo {
            std::env::set_var("FOO", v);
        } else {
            std::env::remove_var("FOO");
        }
        if let Some(v) = original_existing {
            std::env::set_var("EXISTING", v);
        } else {
            std::env::remove_var("EXISTING");
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn env_guard_restores_previous_value() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        std::env::set_var("SECRT_RUNTIME_GUARD", "before");
        {
            let _guard = EnvGuard::set("SECRT_RUNTIME_GUARD", "after");
            assert_eq!(
                std::env::var("SECRT_RUNTIME_GUARD").ok().as_deref(),
                Some("after")
            );
        }
        assert_eq!(
            std::env::var("SECRT_RUNTIME_GUARD").ok().as_deref(),
            Some("before")
        );
        std::env::remove_var("SECRT_RUNTIME_GUARD");
    }

    #[tokio::test]
    async fn run_server_invalid_listen_addr_errors() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = [
            EnvGuard::set("ENV", "development"),
            EnvGuard::set("LISTEN_ADDR", "not-an-addr"),
            EnvGuard::set("PUBLIC_BASE_URL", "https://example.com"),
            EnvGuard::set(
                "DATABASE_URL",
                "postgres://localhost/postgres?sslmode=disable",
            ),
        ];

        let err = run_server_with_shutdown(async {})
            .await
            .expect_err("expected error");
        assert!(matches!(err, RuntimeError::ParseListenAddr(_)));
    }

    #[tokio::test]
    async fn run_server_invalid_database_url_errors() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = [
            EnvGuard::set("ENV", "development"),
            EnvGuard::set("LISTEN_ADDR", "127.0.0.1:0"),
            EnvGuard::set("PUBLIC_BASE_URL", "https://example.com"),
            EnvGuard::set("DATABASE_URL", "postgres://invalid:%zz"),
        ];

        let err = run_server_with_shutdown(async {})
            .await
            .expect_err("expected error");
        assert!(matches!(err, RuntimeError::Storage(_)));
    }

    #[tokio::test]
    async fn run_server_with_immediate_shutdown_smoke() {
        let _lock = ENV_LOCK.lock().expect("env lock");

        let base_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/postgres?sslmode=disable".to_string());

        let schema = format!(
            "test_runtime_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        );

        // Create isolated schema for this runtime test.
        let (client, connection) = tokio_postgres::connect(&base_url, tokio_postgres::NoTls)
            .await
            .expect("connect postgres");
        let conn_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        client
            .batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS \"{schema}\""))
            .await
            .expect("create schema");
        drop(client);
        let _ = conn_task.await;

        let sep = if base_url.contains('?') { '&' } else { '?' };
        let db_url = format!("{base_url}{sep}options=-csearch_path%3D{schema}");

        let _env = [
            EnvGuard::set("ENV", "development"),
            EnvGuard::set("LISTEN_ADDR", "127.0.0.1:0"),
            EnvGuard::set("PUBLIC_BASE_URL", "https://example.com"),
            EnvGuard::set("DATABASE_URL", &db_url),
            EnvGuard::set("API_KEY_PEPPER", "pepper"),
        ];

        let result = run_server_with_shutdown(async {
            tokio::time::sleep(std::time::Duration::from_millis(40)).await
        })
        .await;
        assert!(result.is_ok(), "{result:?}");
    }
}
