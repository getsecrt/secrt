use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{Duration, Utc};
use secrt_server::storage::migrations::migrate;
use secrt_server::storage::postgres::PgStore;
use secrt_server::storage::{
    ApiKeyRecord, ApiKeyRegistrationLimits, ApiKeysStore, AuthStore, SecretRecord, SecretsStore,
    StorageError,
};

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

    let user = store
        .create_user("user-auth", "User Auth")
        .await
        .expect("create user");
    assert_eq!(user.handle, "user-auth");

    let fetched_user = store.get_user_by_id(user.id).await.expect("get user");
    assert_eq!(fetched_user.display_name, "User Auth");
    let missing_user = store
        .get_user_by_id(user.id + 999_999)
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
