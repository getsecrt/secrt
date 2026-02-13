use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn server_exits_non_zero_on_invalid_database_url() {
    let bin = env!("CARGO_BIN_EXE_secrt-server");
    let out = Command::new(bin)
        .env("ENV", "development")
        .env("LISTEN_ADDR", "127.0.0.1:0")
        .env("PUBLIC_BASE_URL", "https://example.com")
        .env("DATABASE_URL", "postgres://invalid:%zz")
        .output()
        .expect("run server binary");

    assert!(!out.status.success());
}

#[cfg(unix)]
fn test_database_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(unix)]
fn schema_url(base: &str, schema: &str) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}options=-csearch_path%3D{schema}")
}

#[cfg(unix)]
async fn create_schema(base_url: &str, schema: &str) {
    let (client, connection) = tokio_postgres::connect(base_url, tokio_postgres::NoTls)
        .await
        .expect("connect postgres");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS \"{schema}\""))
        .await
        .expect("create schema");
}

#[cfg(unix)]
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

#[cfg(unix)]
#[tokio::test]
async fn server_starts_and_stops_gracefully_with_sigterm() {
    let Some(base) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let schema = format!(
        "test_server_bin_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    );
    create_schema(&base, &schema).await;
    let db_url = schema_url(&base, &schema);
    let port = free_port();
    let listen_addr = format!("127.0.0.1:{port}");

    let bin = env!("CARGO_BIN_EXE_secrt-server");
    let mut child = Command::new(bin)
        .env("ENV", "development")
        .env("LISTEN_ADDR", &listen_addr)
        .env("PUBLIC_BASE_URL", "https://example.com")
        .env("DATABASE_URL", &db_url)
        .env("API_KEY_PEPPER", "pepper")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");

    let addr = format!("127.0.0.1:{port}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if std::net::TcpStream::connect(&addr).is_ok() {
            break;
        }
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!("server exited early with status {status}");
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("server did not start in time");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let kill_status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("send sigterm");
    assert!(kill_status.success());

    let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            assert!(status.success(), "server should exit cleanly: {status}");
            break;
        }
        if std::time::Instant::now() > wait_deadline {
            let _ = child.kill();
            panic!("server did not stop in time");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn server_sigterm_honors_shutdown_deadline_with_stalled_request_body() {
    let Some(base) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let schema = format!(
        "test_server_shutdown_deadline_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    );
    create_schema(&base, &schema).await;
    let db_url = schema_url(&base, &schema);
    let port = free_port();
    let listen_addr = format!("127.0.0.1:{port}");

    let bin = env!("CARGO_BIN_EXE_secrt-server");
    let mut child = Command::new(bin)
        .env("ENV", "development")
        .env("LISTEN_ADDR", &listen_addr)
        .env("PUBLIC_BASE_URL", "https://example.com")
        .env("DATABASE_URL", &db_url)
        .env("API_KEY_PEPPER", "pepper")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");

    let addr = format!("127.0.0.1:{port}");
    let startup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if std::net::TcpStream::connect(&addr).is_ok() {
            break;
        }
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!("server exited early with status {status}");
        }
        if std::time::Instant::now() > startup_deadline {
            let _ = child.kill();
            panic!("server did not start in time");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // Hold an in-flight request body open; shutdown should still complete by the forced deadline.
    let mut stalled = std::net::TcpStream::connect(&addr).expect("connect stalled request");
    stalled
        .write_all(
            b"POST /api/v1/public/secrets HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2048\r\n\r\n{\"ttl_seconds\":3600,\"claim_hash\":\"m6Fi32zi7U2fMTM9gMNBk1nKEs8o2PjEbdF9oUj0HoQ\",\"envelope\":\"",
        )
        .expect("write partial request body");
    stalled.flush().expect("flush partial request");

    std::thread::sleep(std::time::Duration::from_millis(100));

    let kill_status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("send sigterm");
    assert!(kill_status.success());

    let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            assert!(
                status.success(),
                "server should exit cleanly even with stalled body: {status}"
            );
            break;
        }
        if std::time::Instant::now() > wait_deadline {
            let _ = child.kill();
            panic!("server did not stop within shutdown deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
