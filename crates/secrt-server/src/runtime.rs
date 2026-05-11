use std::fs;
use std::future::Future;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
use tracing::{error, info, warn};

use crate::config::{Config, ConfigError, DEFAULT_PUBLIC_BASE_URL};
use crate::http::{build_router, parse_socket_addr, AppState};
use crate::reaper::start_expiry_reaper;
use crate::release_poller::{start_release_poller, PollerConfig, ReleaseFetcher, ReqwestFetcher};
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
    let is_production =
        std::env::var("ENV").unwrap_or_else(|_| "development".to_string()) == "production";
    let dotenv_outcome = if is_production {
        DotenvLoadOutcome::skipped(".env")
    } else {
        load_dotenv_if_present(".env")
            .unwrap_or_else(|err| DotenvLoadOutcome::error(".env", err.to_string()))
    };

    let cfg = Config::load()?;
    init_logging(&cfg.log_level);

    // One-line bootstrap log so a misconfigured PUBLIC_BASE_URL / LISTEN_ADDR
    // is visible at boot rather than only via the symptom (WebAuthn 401,
    // generic origin mismatch). Origin / RP-ID values are public per-RP
    // identifiers, not secrets.
    //
    // Strip URL fragment, query, and userinfo before logging:
    // `public_base_url` is operator-supplied and already URL-validated in
    // Config::load, so this is defense-in-depth against an operator typo
    // (trailing `#…`, accidental `?token=…`, `user:pass@host`) ending up
    // in shipped logs. If parsing fails — which shouldn't happen since
    // Config::load rejects invalid URLs — emit a sanitized placeholder
    // rather than risk logging an unredacted credential.
    let public_base_url_for_log = url::Url::parse(&cfg.public_base_url)
        .map(|mut u| {
            u.set_fragment(None);
            u.set_query(None);
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.to_string().trim_end_matches('/').to_string()
        })
        .unwrap_or_else(|_| "<invalid-public-base-url>".to_string());

    info!(
        event = "server_bootstrap",
        public_base_url = %public_base_url_for_log,
        listen_addr = %cfg.listen_addr,
        log_level = %cfg.log_level,
        env = %cfg.env,
        dotenv = %dotenv_outcome.summary(),
        cwd = %std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string()),
        "server bootstrap"
    );

    // Dev-mode hint: if .env wasn't found OR couldn't be read AND
    // PUBLIC_BASE_URL ended up at the default, the user is almost certainly
    // launching from a directory that doesn't contain a readable .env
    // (e.g. cargo run from inside `web/`, or .env with the wrong perms).
    // The symptom is `OriginMismatch` on every WebAuthn ceremony against a
    // Vite dev server on a different port. Tell them where to look.
    if !is_production
        && matches!(
            dotenv_outcome,
            DotenvLoadOutcome::NotFound(_) | DotenvLoadOutcome::Error { .. }
        )
        && cfg.public_base_url == DEFAULT_PUBLIC_BASE_URL
    {
        warn!(
            cwd = %std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unknown>".to_string()),
            dotenv_path = %dotenv_outcome.path_display(),
            "no .env found in current working directory; PUBLIC_BASE_URL is the default {default}. \
             If you're hitting this server through a Vite dev server on a different port, launch from the repo root \
             (or export PUBLIC_BASE_URL explicitly) — otherwise WebAuthn registration will fail with OriginMismatch.",
            default = DEFAULT_PUBLIC_BASE_URL,
        );
    }

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

    let release_poller_stop =
        match ReqwestFetcher::new(cfg.github_repo.clone(), cfg.github_token.clone()) {
            Ok(fetcher) => {
                let fetcher: Arc<dyn ReleaseFetcher> = Arc::new(fetcher);
                start_release_poller(
                    state.release_cache.clone(),
                    fetcher,
                    PollerConfig {
                        interval: Duration::from_secs(cfg.github_poll_interval_seconds),
                    },
                )
            }
            Err(err) => {
                error!(err = %err, "release poller: failed to build HTTP client; polling disabled");
                None
            }
        };

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
    if let Some(stop) = release_poller_stop {
        let _ = stop.send(());
    }
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

/// Outcome of a `load_dotenv_if_present` call. Carries the resolved path
/// (relative or absolute, as supplied) so the caller can include it in a
/// bootstrap log without re-deriving it.
#[derive(Debug, Clone)]
pub enum DotenvLoadOutcome {
    /// File found and parsed; some or all lines may have been skipped (the
    /// path is included; the count of applied lines is not — the file is
    /// for local dev, the truth is in the resolved Config).
    Loaded(PathBuf),
    /// No file at this path. Bootstrap fell back to process env + defaults.
    NotFound(PathBuf),
    /// Production mode — the loader was bypassed entirely. Process env is
    /// expected to come from systemd `EnvironmentFile=` or similar.
    Skipped(PathBuf),
    /// Found the file but failed to read it (permissions, IO error). The
    /// caller proceeds with process env + defaults but should surface the
    /// error.
    Error { path: PathBuf, message: String },
}

impl DotenvLoadOutcome {
    fn skipped(path: impl Into<PathBuf>) -> Self {
        Self::Skipped(path.into())
    }

    fn error(path: impl Into<PathBuf>, message: String) -> Self {
        Self::Error {
            path: path.into(),
            message,
        }
    }

    /// One-line tag suitable for a structured log field. Stable form so a
    /// future grep or alert can match on it.
    pub fn summary(&self) -> String {
        match self {
            Self::Loaded(p) => format!("loaded:{}", p.display()),
            Self::NotFound(p) => format!("not_found:{}", p.display()),
            Self::Skipped(p) => format!("skipped:{}", p.display()),
            Self::Error { path, message } => format!("error:{}:{}", path.display(), message),
        }
    }

    fn path_display(&self) -> String {
        match self {
            Self::Loaded(p) | Self::NotFound(p) | Self::Skipped(p) => p.display().to_string(),
            Self::Error { path, .. } => path.display().to_string(),
        }
    }
}

pub fn load_dotenv_if_present(path: impl AsRef<Path>) -> std::io::Result<DotenvLoadOutcome> {
    let path = path.as_ref().to_path_buf();
    if !path.exists() {
        return Ok(DotenvLoadOutcome::NotFound(path));
    }

    let contents = fs::read_to_string(&path)?;
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

    Ok(DotenvLoadOutcome::Loaded(path))
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

    // TTY → human-readable text with ANSI colors (WARN=yellow, ERROR=red).
    // Non-TTY (journald, log shippers, `| jq`, CI) → JSON. The shape is
    // load-bearing in production; only the local-dev rendering changes.
    let is_tty = std::io::stdout().is_terminal();

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);

    if is_tty {
        let _ = builder.with_ansi(true).try_init();
    } else {
        // JSON: keep the production shape — flat fields, no nested "span".
        let _ = builder.json().with_current_span(false).try_init();
    }
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
// `env_lock()` serializes tests that mutate process-global env vars; the
// guard must outlive the async test body because the contention is on the
// env (process state), not the mutex itself. Switching to an async-aware
// mutex would not solve the underlying serialization problem.
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

        fn clear(key: &'static str) -> Self {
            let old = std::env::var(key).ok();
            std::env::remove_var(key);
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
        let outcome = r.unwrap();
        assert!(matches!(outcome, DotenvLoadOutcome::NotFound(_)));
        let summary = outcome.summary();
        assert!(summary.starts_with("not_found:"), "got: {summary}");
    }

    #[test]
    fn dotenv_loaded_outcome_reports_path() {
        let _lock = env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dotenv-outcome");
        std::fs::write(&path, "DOTENV_OUTCOME_PROBE=hello\n").expect("write dotenv");
        let _guard = EnvGuard::clear("DOTENV_OUTCOME_PROBE");

        let outcome = load_dotenv_if_present(&path).expect("load dotenv");
        match outcome {
            DotenvLoadOutcome::Loaded(p) => assert_eq!(p, path),
            other => panic!("expected Loaded, got {other:?}"),
        }
    }

    #[test]
    fn dotenv_summary_is_stable_per_variant() {
        // Summary tags are intentionally stable so a future grep / alert can
        // match on them. Pin the prefixes.
        assert!(DotenvLoadOutcome::Loaded(PathBuf::from("/x"))
            .summary()
            .starts_with("loaded:"));
        assert!(DotenvLoadOutcome::NotFound(PathBuf::from("/x"))
            .summary()
            .starts_with("not_found:"));
        assert!(DotenvLoadOutcome::Skipped(PathBuf::from("/x"))
            .summary()
            .starts_with("skipped:"));
        assert!(DotenvLoadOutcome::Error {
            path: PathBuf::from("/x"),
            message: "perm".to_string(),
        }
        .summary()
        .starts_with("error:"));
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
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir
            .path()
            .join("secrt-dotenv")
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

        // pid + nanos so two parallel nextest processes can't collide on schema name.
        let schema = format!(
            "test_runtime_{}_{}",
            std::process::id(),
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
