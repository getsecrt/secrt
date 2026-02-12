use std::process::Command;

fn test_database_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn schema_url(base: &str, schema: &str) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}options=-csearch_path%3D{schema}")
}

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

#[tokio::test]
async fn admin_create_and_revoke_api_key() {
    let Some(base) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let schema = format!(
        "test_admin_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    );
    create_schema(&base, &schema).await;
    let db_url = schema_url(&base, &schema);

    let bin = env!("CARGO_BIN_EXE_secrt-admin");

    let create = Command::new(bin)
        .arg("apikey")
        .arg("create")
        .env("ENV", "development")
        .env("DATABASE_URL", &db_url)
        .env("PUBLIC_BASE_URL", "https://example.com")
        .env("API_KEY_PEPPER", "pepper")
        .output()
        .expect("run create command");

    assert!(
        create.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&create.stderr)
    );
    let api_key = String::from_utf8(create.stdout).expect("utf8 stdout");
    let api_key = api_key.trim();
    assert!(api_key.starts_with("sk_"));

    let prefix = api_key
        .trim_start_matches("sk_")
        .split('.')
        .next()
        .expect("prefix");

    let revoke = Command::new(bin)
        .arg("apikey")
        .arg("revoke")
        .arg(prefix)
        .env("ENV", "development")
        .env("DATABASE_URL", &db_url)
        .env("PUBLIC_BASE_URL", "https://example.com")
        .output()
        .expect("run revoke command");

    assert!(
        revoke.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&revoke.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&revoke.stdout).trim(), "revoked");

    let revoke2 = Command::new(bin)
        .arg("apikey")
        .arg("revoke")
        .arg(prefix)
        .env("ENV", "development")
        .env("DATABASE_URL", &db_url)
        .env("PUBLIC_BASE_URL", "https://example.com")
        .output()
        .expect("run second revoke command");
    assert!(!revoke2.status.success());
}

#[test]
fn admin_usage_on_bad_args() {
    let bin = env!("CARGO_BIN_EXE_secrt-admin");
    let out = Command::new(bin).output().expect("run command");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn admin_usage_on_missing_apikey_action() {
    let bin = env!("CARGO_BIN_EXE_secrt-admin");
    let out = Command::new(bin)
        .arg("apikey")
        .output()
        .expect("run command");
    assert_eq!(out.status.code(), Some(2));
}

#[tokio::test]
async fn admin_create_requires_pepper() {
    let Some(base) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let schema = format!(
        "test_admin_nopepper_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    );
    create_schema(&base, &schema).await;
    let db_url = schema_url(&base, &schema);

    let bin = env!("CARGO_BIN_EXE_secrt-admin");
    let out = Command::new(bin)
        .arg("apikey")
        .arg("create")
        .env("ENV", "development")
        .env("DATABASE_URL", &db_url)
        .env("PUBLIC_BASE_URL", "https://example.com")
        .env_remove("API_KEY_PEPPER")
        .output()
        .expect("run create command");

    assert!(!out.status.success());
}

#[test]
fn admin_unknown_subcommands_exit_2() {
    let bin = env!("CARGO_BIN_EXE_secrt-admin");
    let out = Command::new(bin)
        .arg("apikey")
        .arg("unknown")
        .output()
        .expect("run command");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn admin_revoke_missing_prefix_exits_2() {
    let bin = env!("CARGO_BIN_EXE_secrt-admin");
    let out = Command::new(bin)
        .arg("apikey")
        .arg("revoke")
        .output()
        .expect("run command");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn admin_bad_database_url_exits_non_zero() {
    let bin = env!("CARGO_BIN_EXE_secrt-admin");
    let out = Command::new(bin)
        .arg("apikey")
        .arg("create")
        .env("ENV", "development")
        .env("DATABASE_URL", "postgres://invalid:%zz")
        .env("PUBLIC_BASE_URL", "https://example.com")
        .env("API_KEY_PEPPER", "pepper")
        .output()
        .expect("run command");
    assert!(!out.status.success());
}

#[test]
fn admin_config_error_exits_non_zero() {
    let bin = env!("CARGO_BIN_EXE_secrt-admin");
    let out = Command::new(bin)
        .arg("apikey")
        .arg("create")
        .env("ENV", "development")
        .env("PUBLIC_BASE_URL", "://bad-url")
        .env("DATABASE_URL", "postgres://localhost/test")
        .env("API_KEY_PEPPER", "pepper")
        .output()
        .expect("run command");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("config error"));
}

#[test]
fn admin_db_url_error_exits_non_zero() {
    let bin = env!("CARGO_BIN_EXE_secrt-admin");
    let out = Command::new(bin)
        .arg("apikey")
        .arg("create")
        .env("ENV", "development")
        .env("PUBLIC_BASE_URL", "https://example.com")
        .env_remove("DATABASE_URL")
        .env("DB_HOST", "")
        .env("DB_NAME", "")
        .env("DB_USER", "")
        .env("DB_SSLMODE", "")
        .env("API_KEY_PEPPER", "pepper")
        .output()
        .expect("run command");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("db url error"));
}
