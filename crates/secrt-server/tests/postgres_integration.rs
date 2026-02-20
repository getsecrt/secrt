use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};

use chrono::{Datelike, Duration, NaiveDate, Utc};
use secrt_server::storage::migrations::migrate;
use secrt_server::storage::postgres::PgStore;
use secrt_server::storage::{
    ApiKeyRecord, ApiKeyRegistrationLimits, ApiKeysStore, AuthStore, SecretRecord, SecretsStore,
    StorageError, UserRecord,
};
use uuid::Uuid;

fn test_database_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn test_schema_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let ctr = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("test_{}_{}", nanos, ctr)
}

fn with_search_path(url: &str, schema: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}options=-csearch_path%3D{schema}")
}

async fn create_schema(base_url: &str, schema: &str) {
    let base = PgStore::from_database_url(base_url)
        .await
        .expect("connect base database");
    let client = base.pool().get().await.expect("get client");
    client
        .batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS \"{schema}\""))
        .await
        .expect("create schema");
}

async fn assert_column_udt_name(store: &PgStore, table: &str, column: &str, expected: &str) {
    let client = store.pool().get().await.expect("get client");
    let row = client
        .query_one(
            "SELECT udt_name
             FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = $1
               AND column_name = $2",
            &[&table, &column],
        )
        .await
        .expect("query information_schema.columns");
    let actual: String = row.get(0);
    assert_eq!(
        actual, expected,
        "expected {table}.{column} to use {expected}, got {actual}"
    );
}

#[tokio::test]
async fn postgres_secret_lifecycle_and_api_keys() {
    let Some(base_url) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };

    let schema = test_schema_name();
    create_schema(&base_url, &schema).await;

    let db_url = with_search_path(&base_url, &schema);
    let store = PgStore::from_database_url(&db_url)
        .await
        .expect("connect schema database");
    let _store_from_pool = PgStore::new(store.pool().clone());

    let applied = migrate(store.pool()).await.expect("migrate first");
    assert!(!applied.is_empty());
    let applied2 = migrate(store.pool()).await.expect("migrate second");
    assert!(applied2.is_empty());

    let now = Utc::now();
    let sec = SecretRecord {
        id: "id1".into(),
        claim_hash: "claimhash1".into(),
        envelope: "{\"ciphertext\":\"abc\"}".to_string().into_boxed_str(),
        expires_at: now + Duration::hours(1),
        created_at: now,
        owner_key: "apikey:test-prefix".into(),
    };

    store.create(sec.clone()).await.expect("create secret");

    let bad_json = SecretRecord {
        id: "badjson".into(),
        claim_hash: "claimhash_bad".into(),
        envelope: "{".into(),
        expires_at: now + Duration::hours(1),
        created_at: now,
        owner_key: "apikey:test-prefix".into(),
    };
    let bad = store
        .create(bad_json)
        .await
        .expect_err("invalid envelope json should fail");
    assert!(matches!(bad, StorageError::Other(_)));

    let dup = store
        .create(sec.clone())
        .await
        .expect_err("duplicate id should fail");
    assert!(matches!(dup, StorageError::DuplicateId));

    let wrong = store
        .claim_and_delete("id1", "wrong", now)
        .await
        .expect_err("wrong claim should fail");
    assert!(matches!(wrong, StorageError::NotFound));

    let claimed = store
        .claim_and_delete("id1", "claimhash1", now)
        .await
        .expect("claim and delete");
    assert_eq!(claimed.id, "id1");

    let missing = store
        .claim_and_delete("id1", "claimhash1", now)
        .await
        .expect_err("already deleted");
    assert!(matches!(missing, StorageError::NotFound));

    // Burn owner-scoped behavior.
    let sec2 = SecretRecord {
        id: "id2".into(),
        claim_hash: "claimhash2".into(),
        envelope: "{\"ciphertext\":\"def\"}".to_string().into_boxed_str(),
        expires_at: now + Duration::hours(1),
        created_at: now,
        owner_key: "apikey:owner-a".into(),
    };
    store.create(sec2).await.expect("create secret 2");

    let wrong_owner = store
        .burn("id2", "apikey:owner-b")
        .await
        .expect("burn wrong owner");
    assert!(!wrong_owner);

    let right_owner = store
        .burn("id2", "apikey:owner-a")
        .await
        .expect("burn right owner");
    assert!(right_owner);

    // Delete expired.
    let expired = SecretRecord {
        id: "id3".into(),
        claim_hash: "claimhash3".into(),
        envelope: "{\"ciphertext\":\"ghi\"}".to_string().into_boxed_str(),
        expires_at: now - Duration::seconds(1),
        created_at: now,
        owner_key: "apikey:owner-c".into(),
    };
    store.create(expired).await.expect("create expired secret");
    let deleted = store.delete_expired(now).await.expect("delete expired");
    assert_eq!(deleted, 1);

    // Usage.
    let usage = store.get_usage("apikey:owner-a").await.expect("get usage");
    assert_eq!(usage.secret_count, 0);

    // Quota usage calculations: excludes expired and separates owners.
    let usage_owner_a_1 = SecretRecord {
        id: "u1".into(),
        claim_hash: "u1".into(),
        envelope: "{\"ct\":\"12345\"}".to_string().into_boxed_str(),
        expires_at: now + Duration::hours(1),
        created_at: now,
        owner_key: "apikey:usage-a".into(),
    };
    let usage_owner_a_2 = SecretRecord {
        id: "u2".into(),
        claim_hash: "u2".into(),
        envelope: "{\"ct\":\"67890\"}".to_string().into_boxed_str(),
        expires_at: now + Duration::hours(1),
        created_at: now,
        owner_key: "apikey:usage-a".into(),
    };
    let usage_owner_a_expired = SecretRecord {
        id: "u3".into(),
        claim_hash: "u3".into(),
        envelope: "{\"ct\":\"expired\"}".to_string().into_boxed_str(),
        expires_at: now - Duration::seconds(1),
        created_at: now,
        owner_key: "apikey:usage-a".into(),
    };
    let usage_owner_b = SecretRecord {
        id: "u4".into(),
        claim_hash: "u4".into(),
        envelope: "{\"ct\":\"owner-b\"}".to_string().into_boxed_str(),
        expires_at: now + Duration::hours(1),
        created_at: now,
        owner_key: "apikey:usage-b".into(),
    };
    store.create(usage_owner_a_1).await.expect("usage a1");
    store.create(usage_owner_a_2).await.expect("usage a2");
    store
        .create(usage_owner_a_expired)
        .await
        .expect("usage a expired");
    store.create(usage_owner_b).await.expect("usage b");

    let usage_missing = store
        .get_usage("apikey:no-such-owner")
        .await
        .expect("usage missing owner");
    assert_eq!(usage_missing.secret_count, 0);
    assert_eq!(usage_missing.total_bytes, 0);

    let usage_a = store
        .get_usage("apikey:usage-a")
        .await
        .expect("usage owner a");
    assert_eq!(usage_a.secret_count, 2);
    assert!(usage_a.total_bytes > 0);

    let usage_b = store
        .get_usage("apikey:usage-b")
        .await
        .expect("usage owner b");
    assert_eq!(usage_b.secret_count, 1);
    assert!(usage_b.total_bytes > 0);

    // API key lifecycle.
    let key = ApiKeyRecord {
        id: 0,
        prefix: "pfx1".into(),
        auth_hash: "a".repeat(64),
        scopes: "secrets:write".into(),
        user_id: None,
        created_at: now,
        revoked_at: None,
    };
    store.insert(key).await.expect("insert key");

    let fetched = store.get_by_prefix("pfx1").await.expect("get key");
    assert_eq!(fetched.prefix, "pfx1");
    assert_eq!(fetched.scopes, "secrets:write");
    assert!(fetched.revoked_at.is_none());

    let revoked = store.revoke_by_prefix("pfx1").await.expect("revoke key");
    assert!(revoked);

    let fetched2 = store.get_by_prefix("pfx1").await.expect("get revoked key");
    assert!(fetched2.revoked_at.is_some());

    let missing = store
        .get_by_prefix("missing")
        .await
        .expect_err("missing key should fail");
    assert!(matches!(missing, StorageError::NotFound));

    let revoke_missing = store
        .revoke_by_prefix("missing")
        .await
        .expect("revoke missing");
    assert!(!revoke_missing);

    let revoke_again = store.revoke_by_prefix("pfx1").await.expect("revoke again");
    assert!(!revoke_again);
}

#[tokio::test]
async fn postgres_invalid_url_errors() {
    let err = match PgStore::from_database_url("postgres://invalid:%zz").await {
        Ok(_) => panic!("invalid url should fail"),
        Err(err) => err,
    };
    assert!(matches!(err, StorageError::Other(_)));
}

#[tokio::test]
async fn postgres_pool_recycles_connection_when_age_exceeds_max_lifetime() {
    let Some(base_url) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };

    let schema = test_schema_name();
    create_schema(&base_url, &schema).await;

    let db_url = with_search_path(&base_url, &schema);
    let store = PgStore::from_database_url_with_max_lifetime(&db_url, StdDuration::from_millis(1))
        .await
        .expect("connect schema database");
    migrate(store.pool()).await.expect("migrate");

    let first_pid = {
        let client = store.pool().get().await.expect("get first client");
        let row = client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .expect("query first backend pid");
        row.get::<_, i32>(0)
    };

    let mut observed_new_pid = false;
    for _ in 0..5 {
        tokio::time::sleep(StdDuration::from_millis(20)).await;
        let next_pid = {
            let client = store.pool().get().await.expect("get next client");
            let row = client
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .expect("query next backend pid");
            row.get::<_, i32>(0)
        };
        if next_pid != first_pid {
            observed_new_pid = true;
            break;
        }
    }

    assert!(
        observed_new_pid,
        "expected pool to recycle aged connection and allocate a new backend pid"
    );
}

#[tokio::test]
async fn postgres_delete_expired_cleans_stale_auth_and_quota_rows() {
    let Some(base_url) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };

    let schema = test_schema_name();
    create_schema(&base_url, &schema).await;

    let db_url = with_search_path(&base_url, &schema);
    let store = PgStore::from_database_url(&db_url)
        .await
        .expect("connect schema database");
    migrate(store.pool()).await.expect("migrate");

    let now = Utc::now();
    let user = store
        .create_user("Cleanup User")
        .await
        .expect("create user");

    store
        .create(SecretRecord {
            id: "cleanup-secret-expired".into(),
            claim_hash: "cleanup-claim-expired".into(),
            envelope: "{\"ciphertext\":\"x\"}".to_string().into_boxed_str(),
            expires_at: now - Duration::minutes(1),
            created_at: now,
            owner_key: "apikey:cleanup".into(),
        })
        .await
        .expect("insert expired secret");

    store
        .insert_session(
            "cleanup-session-expired",
            user.id,
            "tokenhash-cleanup-expired",
            now - Duration::minutes(1),
        )
        .await
        .expect("insert expired session");
    store
        .insert_session(
            "cleanup-session-revoked",
            user.id,
            "tokenhash-cleanup-revoked",
            now + Duration::hours(1),
        )
        .await
        .expect("insert revoked session");
    store
        .revoke_session_by_sid("cleanup-session-revoked")
        .await
        .expect("revoke session");
    store
        .insert_session(
            "cleanup-session-active",
            user.id,
            "tokenhash-cleanup-active",
            now + Duration::hours(1),
        )
        .await
        .expect("insert active session");

    store
        .insert_challenge(
            "cleanup-challenge-expired",
            Some(user.id),
            "login",
            "{\"challenge\":\"expired\"}",
            now - Duration::minutes(1),
        )
        .await
        .expect("insert expired challenge");
    store
        .insert_challenge(
            "cleanup-challenge-active",
            Some(user.id),
            "login",
            "{\"challenge\":\"active\"}",
            now + Duration::minutes(10),
        )
        .await
        .expect("insert active challenge");

    store
        .insert_apikey_registration_event(user.id, "cleanup-ip", now - Duration::hours(25))
        .await
        .expect("insert stale registration");
    store
        .insert_apikey_registration_event(user.id, "cleanup-ip", now - Duration::minutes(30))
        .await
        .expect("insert fresh registration");

    let deleted = store.delete_expired(now).await.expect("delete expired");
    assert_eq!(deleted, 5);

    assert!(matches!(
        store.get_session_by_sid("cleanup-session-expired").await,
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        store.get_session_by_sid("cleanup-session-revoked").await,
        Err(StorageError::NotFound)
    ));
    assert!(store
        .get_session_by_sid("cleanup-session-active")
        .await
        .is_ok());

    assert!(matches!(
        store
            .consume_challenge("cleanup-challenge-expired", "login", now)
            .await,
        Err(StorageError::NotFound)
    ));
    assert!(store
        .consume_challenge("cleanup-challenge-active", "login", now)
        .await
        .is_ok());

    let since = now - Duration::hours(48);
    assert_eq!(
        store
            .count_apikey_registrations_by_user_since(user.id, since)
            .await
            .expect("count user registrations"),
        1
    );
    assert_eq!(
        store
            .count_apikey_registrations_by_ip_since("cleanup-ip", since)
            .await
            .expect("count ip registrations"),
        1
    );
}

#[tokio::test]
async fn postgres_auth_store_and_apikey_registration_paths() {
    let Some(base_url) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };

    let schema = test_schema_name();
    create_schema(&base_url, &schema).await;

    let db_url = with_search_path(&base_url, &schema);
    let store = PgStore::from_database_url(&db_url)
        .await
        .expect("connect schema database");
    migrate(store.pool()).await.expect("migrate");

    let now = Utc::now();

    let user = store.create_user("User Auth").await.expect("create user");
    assert_eq!(user.display_name, "User Auth");
    assert_eq!(user.id.get_version_num(), 7);

    let fetched_user = store.get_user_by_id(user.id).await.expect("get user");
    assert_eq!(fetched_user.display_name, "User Auth");
    let missing_user = store
        .get_user_by_id(Uuid::now_v7())
        .await
        .expect_err("missing user");
    assert!(matches!(missing_user, StorageError::NotFound));

    let passkey = store
        .insert_passkey(user.id, "cred-auth-1", "pk-auth-1", 1)
        .await
        .expect("insert passkey");
    assert_eq!(passkey.sign_count, 1);
    let fetched_passkey = store
        .get_passkey_by_credential_id("cred-auth-1")
        .await
        .expect("get passkey");
    assert_eq!(fetched_passkey.public_key, "pk-auth-1");

    store
        .update_passkey_sign_count("cred-auth-1", 7)
        .await
        .expect("update sign_count");
    let updated_passkey = store
        .get_passkey_by_credential_id("cred-auth-1")
        .await
        .expect("get updated passkey");
    assert_eq!(updated_passkey.sign_count, 7);
    let missing_passkey = store
        .get_passkey_by_credential_id("cred-missing")
        .await
        .expect_err("missing passkey");
    assert!(matches!(missing_passkey, StorageError::NotFound));

    let expires_at = now + Duration::hours(1);
    let session = store
        .insert_session("sid-auth-1", user.id, "tokenhash-auth-1", expires_at)
        .await
        .expect("insert session");
    assert_eq!(session.sid, "sid-auth-1");
    let fetched_session = store
        .get_session_by_sid("sid-auth-1")
        .await
        .expect("get session");
    assert_eq!(fetched_session.token_hash, "tokenhash-auth-1");
    assert!(store
        .revoke_session_by_sid("sid-auth-1")
        .await
        .expect("revoke session"));
    assert!(!store
        .revoke_session_by_sid("sid-auth-1")
        .await
        .expect("revoke session again"));
    let missing_session = store
        .get_session_by_sid("sid-missing")
        .await
        .expect_err("missing session");
    assert!(matches!(missing_session, StorageError::NotFound));

    let challenge_exp = now + Duration::minutes(5);
    store
        .insert_challenge(
            "challenge-auth-1",
            Some(user.id),
            "register",
            "{\"challenge\":\"ok\"}",
            challenge_exp,
        )
        .await
        .expect("insert challenge");

    let wrong_purpose = store
        .consume_challenge("challenge-auth-1", "login", now)
        .await
        .expect_err("wrong purpose");
    assert!(matches!(wrong_purpose, StorageError::NotFound));

    let consumed = store
        .consume_challenge("challenge-auth-1", "register", now)
        .await
        .expect("consume challenge");
    assert_eq!(consumed.challenge_id, "challenge-auth-1");

    let consumed_again = store
        .consume_challenge("challenge-auth-1", "register", now)
        .await
        .expect_err("challenge already consumed");
    assert!(matches!(consumed_again, StorageError::NotFound));

    let since = now - Duration::hours(1);
    assert_eq!(
        store
            .count_apikey_registrations_by_user_since(user.id, since)
            .await
            .expect("count user before"),
        0
    );
    assert_eq!(
        store
            .count_apikey_registrations_by_ip_since("ip-auth-1", since)
            .await
            .expect("count ip before"),
        0
    );

    store
        .insert_apikey_registration_event(user.id, "ip-auth-1", now)
        .await
        .expect("insert registration event");

    assert_eq!(
        store
            .count_apikey_registrations_by_user_since(user.id, since)
            .await
            .expect("count user after event"),
        1
    );
    assert_eq!(
        store
            .count_apikey_registrations_by_ip_since("ip-auth-1", since)
            .await
            .expect("count ip after event"),
        1
    );

    let open_limits = ApiKeyRegistrationLimits {
        account_hour: 10,
        account_day: 10,
        ip_hour: 10,
        ip_day: 10,
    };
    let no_user_key = ApiKeyRecord {
        id: 0,
        prefix: "no-user-key".into(),
        auth_hash: "b".repeat(64),
        scopes: "".into(),
        user_id: None,
        created_at: now,
        revoked_at: None,
    };
    let no_user_err = store
        .register_api_key(
            no_user_key,
            "ip-auth-2",
            now + Duration::seconds(1),
            open_limits,
        )
        .await
        .expect_err("register without user_id");
    assert!(matches!(no_user_err, StorageError::Other(_)));

    let reg_key = ApiKeyRecord {
        id: 0,
        prefix: "reg-auth-ok".into(),
        auth_hash: "c".repeat(64),
        scopes: "".into(),
        user_id: Some(user.id),
        created_at: now,
        revoked_at: None,
    };
    store
        .register_api_key(
            reg_key.clone(),
            "ip-auth-2",
            now + Duration::seconds(2),
            open_limits,
        )
        .await
        .expect("register api key");

    let fetched_reg = store
        .get_by_prefix("reg-auth-ok")
        .await
        .expect("fetch registered key");
    assert_eq!(fetched_reg.user_id, Some(user.id));
    assert_eq!(
        store
            .count_apikey_registrations_by_user_since(user.id, since)
            .await
            .expect("count user after register"),
        2
    );
    assert_eq!(
        store
            .count_apikey_registrations_by_ip_since("ip-auth-2", since)
            .await
            .expect("count ip after register"),
        1
    );

    let duplicate_err = store
        .register_api_key(
            reg_key,
            "ip-auth-3",
            now + Duration::seconds(3),
            open_limits,
        )
        .await
        .expect_err("duplicate key");
    assert!(matches!(duplicate_err, StorageError::DuplicateId));

    let account_hour_err = store
        .register_api_key(
            ApiKeyRecord {
                id: 0,
                prefix: "quota-account-hour".into(),
                auth_hash: "d".repeat(64),
                scopes: "".into(),
                user_id: Some(user.id),
                created_at: now,
                revoked_at: None,
            },
            "ip-auth-4",
            now + Duration::seconds(4),
            ApiKeyRegistrationLimits {
                account_hour: 2,
                account_day: 0,
                ip_hour: 0,
                ip_day: 0,
            },
        )
        .await
        .expect_err("account/hour quota");
    assert!(matches!(
        account_hour_err,
        StorageError::QuotaExceeded(ref key) if key == "account/hour"
    ));

    let account_day_err = store
        .register_api_key(
            ApiKeyRecord {
                id: 0,
                prefix: "quota-account-day".into(),
                auth_hash: "e".repeat(64),
                scopes: "".into(),
                user_id: Some(user.id),
                created_at: now,
                revoked_at: None,
            },
            "ip-auth-5",
            now + Duration::seconds(5),
            ApiKeyRegistrationLimits {
                account_hour: 0,
                account_day: 2,
                ip_hour: 0,
                ip_day: 0,
            },
        )
        .await
        .expect_err("account/day quota");
    assert!(matches!(
        account_day_err,
        StorageError::QuotaExceeded(ref key) if key == "account/day"
    ));

    let ip_hour_err = store
        .register_api_key(
            ApiKeyRecord {
                id: 0,
                prefix: "quota-ip-hour".into(),
                auth_hash: "f".repeat(64),
                scopes: "".into(),
                user_id: Some(user.id),
                created_at: now,
                revoked_at: None,
            },
            "ip-auth-1",
            now + Duration::seconds(6),
            ApiKeyRegistrationLimits {
                account_hour: 0,
                account_day: 0,
                ip_hour: 1,
                ip_day: 0,
            },
        )
        .await
        .expect_err("ip/hour quota");
    assert!(matches!(
        ip_hour_err,
        StorageError::QuotaExceeded(ref key) if key == "ip/hour"
    ));

    let ip_day_err = store
        .register_api_key(
            ApiKeyRecord {
                id: 0,
                prefix: "quota-ip-day".into(),
                auth_hash: "g".repeat(64),
                scopes: "".into(),
                user_id: Some(user.id),
                created_at: now,
                revoked_at: None,
            },
            "ip-auth-1",
            now + Duration::seconds(7),
            ApiKeyRegistrationLimits {
                account_hour: 0,
                account_day: 0,
                ip_hour: 0,
                ip_day: 1,
            },
        )
        .await
        .expect_err("ip/day quota");
    assert!(matches!(
        ip_day_err,
        StorageError::QuotaExceeded(ref key) if key == "ip/day"
    ));
}

#[tokio::test]
async fn postgres_auth_schema_user_columns_use_uuid() {
    let Some(base_url) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };

    let schema = test_schema_name();
    create_schema(&base_url, &schema).await;

    let db_url = with_search_path(&base_url, &schema);
    let store = PgStore::from_database_url(&db_url)
        .await
        .expect("connect schema database");
    migrate(store.pool()).await.expect("migrate");

    assert_column_udt_name(&store, "users", "id", "uuid").await;
    assert_column_udt_name(&store, "passkeys", "user_id", "uuid").await;
    assert_column_udt_name(&store, "sessions", "user_id", "uuid").await;
    assert_column_udt_name(&store, "webauthn_challenges", "user_id", "uuid").await;
    assert_column_udt_name(&store, "api_keys", "user_id", "uuid").await;
    assert_column_udt_name(&store, "api_key_registrations", "user_id", "uuid").await;
}

/// Helper: read a user directly from the DB so we can inspect `last_active_at`.
async fn get_user(store: &PgStore, user: &UserRecord) -> UserRecord {
    store.get_user_by_id(user.id).await.expect("get user")
}

/// Helper: assert a NaiveDate is the first of its month.
fn assert_month_start(date: NaiveDate, msg: &str) {
    assert_eq!(
        date.day(),
        1,
        "{msg}: expected day=1, got day={}",
        date.day()
    );
}

#[tokio::test]
async fn postgres_last_active_at_schema_is_date_type() {
    let Some(base_url) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };

    let schema = test_schema_name();
    create_schema(&base_url, &schema).await;

    let db_url = with_search_path(&base_url, &schema);
    let store = PgStore::from_database_url(&db_url)
        .await
        .expect("connect schema database");
    migrate(store.pool()).await.expect("migrate");

    // The column must be DATE, not TIMESTAMPTZ — this is a privacy guarantee.
    assert_column_udt_name(&store, "users", "last_active_at", "date").await;
}

#[tokio::test]
async fn postgres_create_user_sets_last_active_at_to_month_start() {
    let Some(base_url) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };

    let schema = test_schema_name();
    create_schema(&base_url, &schema).await;

    let db_url = with_search_path(&base_url, &schema);
    let store = PgStore::from_database_url(&db_url)
        .await
        .expect("connect schema database");
    migrate(store.pool()).await.expect("migrate");

    let user = store.create_user("New User").await.expect("create user");

    // last_active_at must be set and must be the first of the current month.
    assert_month_start(user.last_active_at, "create_user");

    let today = Utc::now().date_naive();
    let expected_month_start = today.with_day(1).unwrap();
    assert_eq!(user.last_active_at, expected_month_start);
}

#[tokio::test]
async fn postgres_touch_user_last_active_updates_to_month_start() {
    let Some(base_url) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };

    let schema = test_schema_name();
    create_schema(&base_url, &schema).await;

    let db_url = with_search_path(&base_url, &schema);
    let store = PgStore::from_database_url(&db_url)
        .await
        .expect("connect schema database");
    migrate(store.pool()).await.expect("migrate");

    let user = store.create_user("Touch User").await.expect("create user");

    // Force last_active_at to 6 months ago so we can verify the bump.
    let six_months_ago = NaiveDate::from_ymd_opt(2025, 6, 1).unwrap();
    let client = store.pool().get().await.expect("get client");
    client
        .execute(
            "UPDATE users SET last_active_at = $1 WHERE id = $2",
            &[&six_months_ago, &user.id],
        )
        .await
        .expect("backdate last_active_at");

    let before = get_user(&store, &user).await;
    assert_eq!(before.last_active_at, six_months_ago);

    // Touch should bump to current month start.
    let now = Utc::now();
    store
        .touch_user_last_active(user.id, now)
        .await
        .expect("touch user");

    let after = get_user(&store, &user).await;
    let expected = now.date_naive().with_day(1).unwrap();
    assert_eq!(after.last_active_at, expected);
    assert_month_start(after.last_active_at, "after touch");
}

#[tokio::test]
async fn postgres_touch_user_last_active_is_idempotent_within_month() {
    let Some(base_url) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };

    let schema = test_schema_name();
    create_schema(&base_url, &schema).await;

    let db_url = with_search_path(&base_url, &schema);
    let store = PgStore::from_database_url(&db_url)
        .await
        .expect("connect schema database");
    migrate(store.pool()).await.expect("migrate");

    let user = store.create_user("Idempotent").await.expect("create user");
    let now = Utc::now();
    let expected = now.date_naive().with_day(1).unwrap();

    // Touch twice in the same month — value should not change.
    store
        .touch_user_last_active(user.id, now)
        .await
        .expect("first touch");
    let after_first = get_user(&store, &user).await;
    assert_eq!(after_first.last_active_at, expected);

    store
        .touch_user_last_active(user.id, now)
        .await
        .expect("second touch");
    let after_second = get_user(&store, &user).await;
    assert_eq!(after_second.last_active_at, expected);
}

#[tokio::test]
async fn postgres_touch_user_last_active_never_stores_sub_month_precision() {
    let Some(base_url) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };

    let schema = test_schema_name();
    create_schema(&base_url, &schema).await;

    let db_url = with_search_path(&base_url, &schema);
    let store = PgStore::from_database_url(&db_url)
        .await
        .expect("connect schema database");
    migrate(store.pool()).await.expect("migrate");

    let user = store.create_user("Precision").await.expect("create user");

    // Call touch with various timestamps throughout a month — the stored date
    // must always be the 1st.
    let test_dates = [
        "2025-03-01T00:00:00Z",
        "2025-03-15T12:30:45Z",
        "2025-03-31T23:59:59Z",
        "2025-07-04T08:00:00Z",
        "2025-12-25T18:30:00Z",
    ];

    for ts_str in &test_dates {
        let ts: chrono::DateTime<Utc> = ts_str.parse().expect("parse timestamp");

        // Reset to an old date first so the touch actually writes.
        let old = NaiveDate::from_ymd_opt(2020, 1, 1).unwrap();
        let client = store.pool().get().await.expect("get client");
        client
            .execute(
                "UPDATE users SET last_active_at = $1 WHERE id = $2",
                &[&old, &user.id],
            )
            .await
            .expect("reset last_active_at");

        store
            .touch_user_last_active(user.id, ts)
            .await
            .expect("touch");
        let u = get_user(&store, &user).await;
        assert_month_start(u.last_active_at, &format!("touch with {ts_str}"));
        assert_eq!(
            u.last_active_at,
            ts.date_naive().with_day(1).unwrap(),
            "expected month-start for {ts_str}"
        );
    }
}

#[tokio::test]
async fn postgres_touch_user_last_active_does_not_go_backwards() {
    let Some(base_url) = test_database_url() else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };

    let schema = test_schema_name();
    create_schema(&base_url, &schema).await;

    let db_url = with_search_path(&base_url, &schema);
    let store = PgStore::from_database_url(&db_url)
        .await
        .expect("connect schema database");
    migrate(store.pool()).await.expect("migrate");

    let user = store.create_user("NoBackwards").await.expect("create user");

    // Set to a future month.
    let future_month = NaiveDate::from_ymd_opt(2030, 1, 1).unwrap();
    let client = store.pool().get().await.expect("get client");
    client
        .execute(
            "UPDATE users SET last_active_at = $1 WHERE id = $2",
            &[&future_month, &user.id],
        )
        .await
        .expect("set future date");

    // Touch with current time — should NOT go backwards.
    let now = Utc::now();
    store
        .touch_user_last_active(user.id, now)
        .await
        .expect("touch");

    let u = get_user(&store, &user).await;
    assert_eq!(
        u.last_active_at, future_month,
        "touch should never move last_active_at backwards"
    );
}
