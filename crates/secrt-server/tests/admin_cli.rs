use std::process::Command;

use chrono::{Datelike, Duration, Utc};
use secrt_server::storage::migrations::migrate;
use secrt_server::storage::postgres::PgStore;
use uuid::Uuid;

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

fn unique_schema(prefix: &str) -> String {
    format!(
        "{}_{}_{}",
        prefix,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos(),
        std::process::id()
    )
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

async fn migrate_schema(base_url: &str, schema: &str) {
    let url = schema_url(base_url, schema);
    let store = PgStore::from_database_url(&url)
        .await
        .expect("connect schema database");
    migrate(store.pool()).await.expect("apply migrations");
}

async fn insert_api_key(base_url: &str, schema: &str, prefix: &str) {
    let url = schema_url(base_url, schema);
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect postgres");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .execute(
            "INSERT INTO api_keys (key_prefix, auth_hash, scopes) VALUES ($1, $2, $3)",
            &[&prefix, &"a".repeat(64), &""],
        )
        .await
        .expect("insert api key");
}

fn admin_cmd() -> Command {
    let bin = env!("CARGO_BIN_EXE_secrt-admin");
    let mut cmd = Command::new(bin);
    cmd.env("ENV", "development")
        .env("PUBLIC_BASE_URL", "https://example.com");
    cmd
}

fn admin_cmd_with_db(db_url: &str) -> Command {
    let mut cmd = admin_cmd();
    cmd.env("DATABASE_URL", db_url);
    cmd
}

// ── Arg parsing unit tests (no DB needed) ────────────────────────────

#[test]
fn admin_usage_on_bad_args() {
    let out = admin_cmd().output().expect("run command");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn admin_usage_on_missing_apikey_action() {
    let out = admin_cmd().arg("apikey").output().expect("run command");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn admin_unknown_subcommands_exit_2() {
    let out = admin_cmd()
        .arg("apikey")
        .arg("unknown")
        .output()
        .expect("run command");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn admin_revoke_missing_prefix_exits_2() {
    let out = admin_cmd()
        .arg("apikey")
        .arg("revoke")
        .output()
        .expect("run command");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn admin_stats_parses() {
    // stats needs DB, but will fail at config/connect, not at parse
    let out = admin_cmd()
        .arg("stats")
        .env_remove("DATABASE_URL")
        .env("DB_HOST", "")
        .env("DB_NAME", "")
        .env("DB_USER", "")
        .env("DB_SSLMODE", "")
        .output()
        .expect("run command");
    // Should fail with db url error, not usage exit code 2
    assert_ne!(out.status.code(), Some(2));
}

#[test]
fn admin_secrets_stats_parses() {
    let out = admin_cmd()
        .arg("secrets")
        .arg("stats")
        .env_remove("DATABASE_URL")
        .env("DB_HOST", "")
        .env("DB_NAME", "")
        .env("DB_USER", "")
        .env("DB_SSLMODE", "")
        .output()
        .expect("run command");
    assert_ne!(out.status.code(), Some(2));
}

#[test]
fn admin_users_list_parses() {
    let out = admin_cmd()
        .arg("users")
        .arg("list")
        .env_remove("DATABASE_URL")
        .env("DB_HOST", "")
        .env("DB_NAME", "")
        .env("DB_USER", "")
        .env("DB_SSLMODE", "")
        .output()
        .expect("run command");
    assert_ne!(out.status.code(), Some(2));
}

#[test]
fn admin_users_show_parses() {
    let out = admin_cmd()
        .arg("users")
        .arg("show")
        .arg("00000000-0000-0000-0000-000000000000")
        .env_remove("DATABASE_URL")
        .env("DB_HOST", "")
        .env("DB_NAME", "")
        .env("DB_USER", "")
        .env("DB_SSLMODE", "")
        .output()
        .expect("run command");
    assert_ne!(out.status.code(), Some(2));
}

#[test]
fn admin_users_show_missing_id_exits_2() {
    let out = admin_cmd()
        .arg("users")
        .arg("show")
        .output()
        .expect("run command");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn admin_apikeys_list_parses() {
    let out = admin_cmd()
        .arg("apikeys")
        .arg("list")
        .env_remove("DATABASE_URL")
        .env("DB_HOST", "")
        .env("DB_NAME", "")
        .env("DB_USER", "")
        .env("DB_SSLMODE", "")
        .output()
        .expect("run command");
    assert_ne!(out.status.code(), Some(2));
}

#[test]
fn admin_apikeys_backward_compat() {
    // Both "apikey" and "apikeys" should parse "list"
    let out = admin_cmd()
        .arg("apikey")
        .arg("list")
        .env_remove("DATABASE_URL")
        .env("DB_HOST", "")
        .env("DB_NAME", "")
        .env("DB_USER", "")
        .env("DB_SSLMODE", "")
        .output()
        .expect("run command");
    assert_ne!(out.status.code(), Some(2));
}

#[test]
fn admin_top_users_parses() {
    let out = admin_cmd()
        .arg("top-users")
        .env_remove("DATABASE_URL")
        .env("DB_HOST", "")
        .env("DB_NAME", "")
        .env("DB_USER", "")
        .env("DB_SSLMODE", "")
        .output()
        .expect("run command");
    assert_ne!(out.status.code(), Some(2));
}

#[test]
fn admin_top_users_by_bytes_parses() {
    let out = admin_cmd()
        .arg("top-users")
        .arg("--by")
        .arg("bytes")
        .env_remove("DATABASE_URL")
        .env("DB_HOST", "")
        .env("DB_NAME", "")
        .env("DB_USER", "")
        .env("DB_SSLMODE", "")
        .output()
        .expect("run command");
    assert_ne!(out.status.code(), Some(2));
}

#[test]
fn admin_secrets_without_stats_exits_2() {
    let out = admin_cmd().arg("secrets").output().expect("run command");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn admin_users_without_subcommand_exits_2() {
    let out = admin_cmd().arg("users").output().expect("run command");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn admin_bad_database_url_exits_non_zero() {
    let out = admin_cmd()
        .arg("apikey")
        .arg("revoke")
        .arg("prefix")
        .env("DATABASE_URL", "postgres://invalid:%zz")
        .output()
        .expect("run command");
    assert!(!out.status.success());
}

#[test]
fn admin_config_error_exits_non_zero() {
    let out = admin_cmd()
        .arg("apikey")
        .arg("revoke")
        .arg("prefix")
        .env("PUBLIC_BASE_URL", "://bad-url")
        .env("DATABASE_URL", "postgres://localhost/test")
        .output()
        .expect("run command");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("config error"));
}

#[test]
fn admin_db_url_error_exits_non_zero() {
    let out = admin_cmd()
        .arg("apikey")
        .arg("revoke")
        .arg("prefix")
        .env_remove("DATABASE_URL")
        .env("DB_HOST", "")
        .env("DB_NAME", "")
        .env("DB_USER", "")
        .env("DB_SSLMODE", "")
        .output()
        .expect("run command");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("db url error"));
}

// ── Integration tests (require TEST_DATABASE_URL) ────────────────────

#[tokio::test]
async fn admin_revoke_api_key() {
    let Some(base) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let schema = unique_schema("test_admin_revoke");
    create_schema(&base, &schema).await;
    migrate_schema(&base, &schema).await;
    let db_url = schema_url(&base, &schema);
    let prefix = "adminkey";
    insert_api_key(&base, &schema, prefix).await;

    let revoke = admin_cmd_with_db(&db_url)
        .arg("apikey")
        .arg("revoke")
        .arg(prefix)
        .output()
        .expect("run revoke command");

    assert!(
        revoke.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&revoke.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&revoke.stdout).trim(), "revoked");

    let revoke2 = admin_cmd_with_db(&db_url)
        .arg("apikey")
        .arg("revoke")
        .arg(prefix)
        .output()
        .expect("run second revoke command");
    assert!(!revoke2.status.success());
}

#[tokio::test]
async fn admin_create_subcommand_is_removed() {
    let Some(base) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let schema = unique_schema("test_admin_nopepper");
    create_schema(&base, &schema).await;
    let db_url = schema_url(&base, &schema);

    let out = admin_cmd_with_db(&db_url)
        .arg("apikey")
        .arg("create")
        .output()
        .expect("run create command");

    assert_eq!(out.status.code(), Some(2));
}

#[tokio::test]
async fn admin_stats_empty_db() {
    let Some(base) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let schema = unique_schema("test_admin_stats_empty");
    create_schema(&base, &schema).await;
    migrate_schema(&base, &schema).await;
    let db_url = schema_url(&base, &schema);

    let out = admin_cmd_with_db(&db_url)
        .arg("stats")
        .output()
        .expect("run stats");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("Active:"),
        "stdout should contain stats: {stdout}"
    );
}

#[tokio::test]
async fn admin_stats_with_seeded_data() {
    let Some(base) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let schema = unique_schema("test_admin_stats_data");
    create_schema(&base, &schema).await;
    migrate_schema(&base, &schema).await;
    let db_url = schema_url(&base, &schema);

    // Seed data
    let url = schema_url(&base, &schema);
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let user_id = Uuid::now_v7();
    let now = Utc::now();
    let month_start = now.date_naive().with_day(1).unwrap();
    client
        .execute(
            "INSERT INTO users (id, display_name, last_active_at) VALUES ($1, $2, $3)",
            &[&user_id, &"Test User", &month_start],
        )
        .await
        .expect("insert user");

    client
        .execute(
            "INSERT INTO api_keys (key_prefix, auth_hash, scopes, user_id) VALUES ($1, $2, $3, $4)",
            &[&"statskey1", &"a".repeat(64), &"", &user_id],
        )
        .await
        .expect("insert key");

    let expires = now + Duration::hours(1);
    let envelope = serde_json::json!({"ciphertext": "abc"});
    client
        .execute(
            "INSERT INTO secrets (id, claim_hash, envelope, expires_at, owner_key) VALUES ($1, $2, $3::jsonb, $4, $5)",
            &[&"stats-secret-1", &"claimhash1", &envelope, &expires, &format!("user:{user_id}")],
        )
        .await
        .expect("insert secret");

    let out = admin_cmd_with_db(&db_url)
        .arg("stats")
        .output()
        .expect("run stats");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Should show non-zero counts somewhere
    assert!(stdout.contains("secrt dashboard"), "stdout: {stdout}");
}

#[tokio::test]
async fn admin_secret_stats_empty_db() {
    let Some(base) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let schema = unique_schema("test_admin_secstats");
    create_schema(&base, &schema).await;
    migrate_schema(&base, &schema).await;
    let db_url = schema_url(&base, &schema);

    let out = admin_cmd_with_db(&db_url)
        .arg("secrets")
        .arg("stats")
        .output()
        .expect("run secrets stats");

    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("secret breakdown"), "stdout: {stdout}");
}

#[tokio::test]
async fn admin_users_list_with_data() {
    let Some(base) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let schema = unique_schema("test_admin_users_list");
    create_schema(&base, &schema).await;
    migrate_schema(&base, &schema).await;
    let db_url = schema_url(&base, &schema);

    let url = schema_url(&base, &schema);
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let user_id = Uuid::now_v7();
    let month_start = Utc::now().date_naive().with_day(1).unwrap();
    client
        .execute(
            "INSERT INTO users (id, display_name, last_active_at) VALUES ($1, $2, $3)",
            &[&user_id, &"Alice Admin", &month_start],
        )
        .await
        .expect("insert user");

    let out = admin_cmd_with_db(&db_url)
        .arg("users")
        .arg("list")
        .output()
        .expect("run users list");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("Alice Admin"), "stdout: {stdout}");
}

#[tokio::test]
async fn admin_users_show_detail() {
    let Some(base) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let schema = unique_schema("test_admin_users_show");
    create_schema(&base, &schema).await;
    migrate_schema(&base, &schema).await;
    let db_url = schema_url(&base, &schema);

    let url = schema_url(&base, &schema);
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let user_id = Uuid::now_v7();
    let month_start = Utc::now().date_naive().with_day(1).unwrap();
    client
        .execute(
            "INSERT INTO users (id, display_name, last_active_at) VALUES ($1, $2, $3)",
            &[&user_id, &"Bob Show", &month_start],
        )
        .await
        .expect("insert user");

    client
        .execute(
            "INSERT INTO api_keys (key_prefix, auth_hash, scopes, user_id) VALUES ($1, $2, $3, $4)",
            &[&"bobkey01", &"a".repeat(64), &"", &user_id],
        )
        .await
        .expect("insert key");

    let out = admin_cmd_with_db(&db_url)
        .arg("users")
        .arg("show")
        .arg(&user_id.to_string())
        .output()
        .expect("run users show");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("Bob Show"), "stdout: {stdout}");
    assert!(stdout.contains("bobkey01"), "stdout: {stdout}");
}

#[tokio::test]
async fn admin_users_show_invalid_uuid() {
    let Some(base) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let schema = unique_schema("test_admin_show_bad");
    create_schema(&base, &schema).await;
    migrate_schema(&base, &schema).await;
    let db_url = schema_url(&base, &schema);

    let out = admin_cmd_with_db(&db_url)
        .arg("users")
        .arg("show")
        .arg("not-a-uuid")
        .output()
        .expect("run users show");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid user ID"), "stderr: {stderr}");
}

#[tokio::test]
async fn admin_apikeys_list_all() {
    let Some(base) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let schema = unique_schema("test_admin_keylist");
    create_schema(&base, &schema).await;
    migrate_schema(&base, &schema).await;
    let db_url = schema_url(&base, &schema);

    insert_api_key(&base, &schema, "listkey01").await;

    let out = admin_cmd_with_db(&db_url)
        .arg("apikeys")
        .arg("list")
        .output()
        .expect("run apikeys list");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("listkey01"), "stdout: {stdout}");
}

#[tokio::test]
async fn admin_top_users_ranking() {
    let Some(base) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let schema = unique_schema("test_admin_topusers");
    create_schema(&base, &schema).await;
    migrate_schema(&base, &schema).await;
    let db_url = schema_url(&base, &schema);

    let url = schema_url(&base, &schema);
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let now = Utc::now();
    let month_start = now.date_naive().with_day(1).unwrap();

    // User A: 3 secrets
    let user_a = Uuid::now_v7();
    client
        .execute(
            "INSERT INTO users (id, display_name, last_active_at) VALUES ($1, $2, $3)",
            &[&user_a, &"Power User", &month_start],
        )
        .await
        .expect("insert user A");

    let expires = now + Duration::hours(1);
    let envelope = serde_json::json!({"ciphertext": "abc"});
    for i in 0..3 {
        client
            .execute(
                "INSERT INTO secrets (id, claim_hash, envelope, expires_at, owner_key) VALUES ($1, $2, $3::jsonb, $4, $5)",
                &[
                    &format!("top-a-{i}"),
                    &format!("claim-a-{i}"),
                    &envelope,
                    &expires,
                    &format!("user:{user_a}"),
                ],
            )
            .await
            .expect("insert secret for user A");
    }

    // User B: 1 secret
    let user_b = Uuid::now_v7();
    client
        .execute(
            "INSERT INTO users (id, display_name, last_active_at) VALUES ($1, $2, $3)",
            &[&user_b, &"Light User", &month_start],
        )
        .await
        .expect("insert user B");

    client
        .execute(
            "INSERT INTO secrets (id, claim_hash, envelope, expires_at, owner_key) VALUES ($1, $2, $3::jsonb, $4, $5)",
            &[&"top-b-0", &"claim-b-0", &envelope, &expires, &format!("user:{user_b}")],
        )
        .await
        .expect("insert secret for user B");

    let out = admin_cmd_with_db(&db_url)
        .arg("top-users")
        .arg("--by")
        .arg("secrets")
        .arg("--limit")
        .arg("5")
        .output()
        .expect("run top-users");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Power User (3 secrets) should appear before Light User (1 secret)
    let pos_power = stdout.find("Power User");
    let pos_light = stdout.find("Light User");
    assert!(pos_power.is_some(), "Power User missing: {stdout}");
    assert!(pos_light.is_some(), "Light User missing: {stdout}");
    assert!(
        pos_power.unwrap() < pos_light.unwrap(),
        "Power User should rank before Light User: {stdout}"
    );
}
