use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{Duration, Utc};
use secrt_server::storage::migrations::migrate;
use secrt_server::storage::postgres::PgStore;
use secrt_server::storage::{ApiKeyRecord, ApiKeysStore, SecretRecord, SecretsStore, StorageError};

fn test_database_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn test_schema_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    format!("test_{}", nanos)
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
