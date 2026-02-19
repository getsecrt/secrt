use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::signal;
use tokio::sync::Notify;
use tokio_io_timeout::TimeoutStream;
use tower::Service;
use tower_http::timeout::TimeoutLayer;
use tracing::{error, info};

use crate::config::{Config, ConfigError};
use crate::http::{build_router, parse_socket_addr, AppState};
use crate::reaper::start_expiry_reaper;
use crate::storage::migrations::migrate;
use crate::storage::postgres::PgStore;
use crate::storage::{AmkStore, ApiKeysStore, SecretsStore, StorageError};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HttpTimeouts {
    read_header_timeout: Duration,
    request_timeout: Duration,
    write_timeout: Duration,
    idle_timeout: Duration,
    graceful_shutdown_timeout: Duration,
}

impl HttpTimeouts {
    const fn production() -> Self {
        Self {
            read_header_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
            write_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(60),
            graceful_shutdown_timeout: Duration::from_secs(10),
        }
    }
}

const PRODUCTION_HTTP_TIMEOUTS: HttpTimeouts = HttpTimeouts::production();

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

    // Validate listen address early, before expensive DB operations.
    let addr = parse_socket_addr(&cfg.listen_addr)
        .map_err(|e| RuntimeError::ParseListenAddr(format!("{} ({e})", cfg.listen_addr)))?;

    let db_url = cfg.postgres_url()?;
    let pg_store = Arc::new(PgStore::from_database_url(&db_url).await?);
    migrate(pg_store.pool()).await?;

    let secrets: Arc<dyn SecretsStore> = pg_store.clone();
    let api_keys: Arc<dyn ApiKeysStore> = pg_store.clone();
    let auth_store = pg_store.clone();
    let amk_store: Arc<dyn AmkStore> = pg_store.clone();
    let state = Arc::new(AppState::new(
        cfg.clone(),
        secrets.clone(),
        api_keys,
        auth_store,
        amk_store,
    ));
    state.start_limiter_gc();

    let reaper_stop = start_expiry_reaper(secrets);

    let timeouts = PRODUCTION_HTTP_TIMEOUTS;
    let app = build_router(state.clone()).layer(TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        timeouts.request_timeout,
    ));
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| RuntimeError::Bind(e.to_string()))?;

    info!(addr = %addr, "listening");

    let result = serve_with_timeouts(listener, app, shutdown, timeouts).await;

    let _ = reaper_stop.send(());
    state.stop_limiter_gc();

    if let Err(err) = result {
        error!(err = %err, "http server error");
        return Err(RuntimeError::Serve(err.to_string()));
    }

    Ok(())
}

async fn serve_with_timeouts<F>(
    listener: TcpListener,
    app: axum::Router,
    shutdown: F,
    timeouts: HttpTimeouts,
) -> Result<(), RuntimeError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    let mut conn_builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    conn_builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Some(timeouts.read_header_timeout));
    let graceful = GracefulShutdown::new();
    let shutdown_notify = Arc::new(Notify::new());
    let shutdown_trigger = shutdown_notify.clone();
    tokio::spawn(async move {
        shutdown.await;
        shutdown_trigger.notify_waiters();
    });

    loop {
        tokio::select! {
            _ = shutdown_notify.notified() => {
                break;
            }
            accept_result = listener.accept() => {
                let (stream, remote_addr) = match accept_result {
                    Ok(v) => v,
                    Err(err) => {
                        error!(err = %err, "accept failed");
                        continue;
                    }
                };
                let service = match make_service.call(remote_addr).await {
                    Ok(v) => v,
                    Err(_) => {
                        error!("make_service failed");
                        continue;
                    }
                };

                let io = TokioIo::new(Box::pin(configure_stream_timeouts(stream, timeouts)));
                let service = TowerToHyperService::new(service);
                let conn = conn_builder.serve_connection(io, service);
                let conn = graceful.watch(conn.into_owned());

                tokio::spawn(async move {
                    if let Err(err) = conn.await {
                        error!(err = %err, peer = %remote_addr, "connection error");
                    }
                });
            }
        }
    }

    drop(listener);

    match tokio::time::timeout(timeouts.graceful_shutdown_timeout, graceful.shutdown()).await {
        Ok(_) => Ok(()),
        Err(_) => Err(RuntimeError::Serve(format!(
            "graceful shutdown timed out after {}s",
            timeouts.graceful_shutdown_timeout.as_secs()
        ))),
    }
}

fn configure_stream_timeouts(
    stream: TcpStream,
    timeouts: HttpTimeouts,
) -> TimeoutStream<TcpStream> {
    let mut stream = TimeoutStream::new(stream);
    // Read timeout on the raw stream enforces keepalive-idle behavior.
    // Per-request read/write budget is enforced by the request timeout layer.
    stream.set_read_timeout(Some(timeouts.idle_timeout));
    stream.set_write_timeout(Some(timeouts.write_timeout));
    stream
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
    use axum::routing::{get, post};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

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
    fn http_timeout_constants_match_spec() {
        assert_eq!(
            PRODUCTION_HTTP_TIMEOUTS.read_header_timeout,
            std::time::Duration::from_secs(5)
        );
        assert_eq!(
            PRODUCTION_HTTP_TIMEOUTS.request_timeout,
            std::time::Duration::from_secs(15)
        );
        assert_eq!(
            PRODUCTION_HTTP_TIMEOUTS.write_timeout,
            std::time::Duration::from_secs(15)
        );
        assert_eq!(
            PRODUCTION_HTTP_TIMEOUTS.idle_timeout,
            std::time::Duration::from_secs(60)
        );
        assert_eq!(
            PRODUCTION_HTTP_TIMEOUTS.graceful_shutdown_timeout,
            std::time::Duration::from_secs(10)
        );
    }

    #[test]
    fn dotenv_parses_lines_and_preserves_existing_env() {
        let _lock = env_lock();
        let original_foo = std::env::var("FOO").ok();
        let original_existing = std::env::var("EXISTING").ok();
        std::env::set_var("FOO", "before_foo");
        std::env::set_var("EXISTING", "before_existing");
        let path = std::env::temp_dir()
            .join(format!(
                "secrt-dotenv-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("time")
                    .as_nanos()
            ))
            .to_string_lossy()
            .to_string();
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
        let _lock = env_lock();
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

    fn short_test_timeouts() -> HttpTimeouts {
        HttpTimeouts {
            read_header_timeout: std::time::Duration::from_millis(60),
            request_timeout: std::time::Duration::from_millis(120),
            write_timeout: std::time::Duration::from_millis(250),
            idle_timeout: std::time::Duration::from_millis(150),
            graceful_shutdown_timeout: std::time::Duration::from_millis(120),
        }
    }

    async fn spawn_timeout_test_server(
        app: axum::Router,
        timeouts: HttpTimeouts,
    ) -> (
        std::net::SocketAddr,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<(), RuntimeError>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener local addr");
        let app = app.layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeouts.request_timeout,
        ));
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            serve_with_timeouts(
                listener,
                app,
                async move {
                    let _ = shutdown_rx.await;
                },
                timeouts,
            )
            .await
        });
        (addr, shutdown_tx, handle)
    }

    fn assert_read_closed(result: std::io::Result<usize>) {
        match result {
            Ok(0) => {}
            Ok(n) => panic!("expected closed stream, read {n} bytes"),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::NotConnected
                ) => {}
            Err(err) => panic!("expected closed stream, got error: {err}"),
        }
    }

    #[tokio::test]
    async fn header_read_timeout_closes_slow_connections() {
        let timeouts = short_test_timeouts();
        let app = axum::Router::new().route("/", get(|| async { StatusCode::NO_CONTENT }));
        let (addr, shutdown_tx, handle) = spawn_timeout_test_server(app, timeouts).await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .expect("write partial request");

        tokio::time::sleep(timeouts.read_header_timeout + std::time::Duration::from_millis(40))
            .await;

        let mut buf = [0_u8; 64];
        let read_result =
            tokio::time::timeout(std::time::Duration::from_millis(500), stream.read(&mut buf))
                .await
                .expect("read wait timeout");
        assert_read_closed(read_result);

        let _ = shutdown_tx.send(());
        let result = handle.await.expect("join server task");
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn request_timeout_returns_408_for_stalled_body_reads() {
        let timeouts = HttpTimeouts {
            idle_timeout: std::time::Duration::from_secs(2),
            write_timeout: std::time::Duration::from_secs(2),
            ..short_test_timeouts()
        };
        let app = axum::Router::new().route(
            "/slow-body",
            post(|_body: String| async { StatusCode::NO_CONTENT }),
        );
        let (addr, shutdown_tx, handle) = spawn_timeout_test_server(app, timeouts).await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");

        stream
            .write_all(
                b"POST /slow-body HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\na",
            )
            .await
            .expect("write partial body request");

        tokio::time::sleep(timeouts.request_timeout + std::time::Duration::from_millis(40)).await;

        let mut buf = [0_u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut buf))
            .await
            .expect("read response timeout")
            .expect("read response");
        assert!(n > 0, "expected timeout response bytes");
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("408 Request Timeout") || response.contains(" 408 "),
            "expected 408 timeout response, got: {response}"
        );

        let _ = shutdown_tx.send(());
        let result = handle.await.expect("join server task");
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn idle_timeout_closes_keepalive_connection() {
        let timeouts = short_test_timeouts();
        let app = axum::Router::new().route("/", get(|| async { StatusCode::NO_CONTENT }));
        let (addr, shutdown_tx, handle) = spawn_timeout_test_server(app, timeouts).await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
        stream
            .write_all(request)
            .await
            .expect("write first request");

        let mut first_buf = [0_u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read(&mut first_buf),
        )
        .await
        .expect("read first response timeout")
        .expect("read first response");
        assert!(n > 0, "expected first response bytes");
        let first_response = String::from_utf8_lossy(&first_buf[..n]);
        assert!(
            first_response.contains("204 No Content"),
            "expected 204 response, got: {first_response}"
        );

        tokio::time::sleep(timeouts.idle_timeout + std::time::Duration::from_millis(40)).await;

        let second_write = stream.write_all(request).await;
        if let Err(err) = second_write {
            assert!(
                matches!(
                    err.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::NotConnected
                ),
                "expected closed write error, got: {err}"
            );
        } else {
            let mut buf = [0_u8; 64];
            let read_result =
                tokio::time::timeout(std::time::Duration::from_millis(500), stream.read(&mut buf))
                    .await
                    .expect("read after idle timeout");
            assert_read_closed(read_result);
        }

        let _ = shutdown_tx.send(());
        let result = handle.await.expect("join server task");
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn graceful_shutdown_times_out_when_inflight_request_hangs() {
        let timeouts = HttpTimeouts {
            read_header_timeout: std::time::Duration::from_millis(100),
            request_timeout: std::time::Duration::from_secs(5),
            write_timeout: std::time::Duration::from_secs(5),
            idle_timeout: std::time::Duration::from_secs(5),
            graceful_shutdown_timeout: std::time::Duration::from_millis(120),
        };
        let app = axum::Router::new().route(
            "/hold",
            get(|| async {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                StatusCode::NO_CONTENT
            }),
        );
        let (addr, shutdown_tx, handle) = spawn_timeout_test_server(app, timeouts).await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"GET /hold HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write hold request");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let _ = shutdown_tx.send(());
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("join timeout")
            .expect("join server task");
        match result {
            Err(RuntimeError::Serve(msg)) => {
                assert!(
                    msg.contains("graceful shutdown timed out"),
                    "unexpected graceful shutdown error: {msg}"
                );
            }
            other => panic!("expected graceful shutdown timeout error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_server_invalid_listen_addr_errors() {
        let _lock = env_lock();
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
        let _lock = env_lock();
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
        let _lock = env_lock();

        let base_url = match std::env::var("TEST_DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            }
        };

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
