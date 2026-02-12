use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use secrt_server::domain::auth::{
    generate_api_key, hash_api_key_secret, parse_api_key, secure_equals_hex, Authenticator,
};
use secrt_server::storage::{ApiKeyRecord, ApiKeysStore, StorageError};

#[derive(Default)]
struct KeyStore {
    key: Option<ApiKeyRecord>,
    fail: bool,
}

#[async_trait]
impl ApiKeysStore for KeyStore {
    async fn get_by_prefix(&self, prefix: &str) -> Result<ApiKeyRecord, StorageError> {
        if self.fail {
            return Err(StorageError::Other("db down".into()));
        }
        let Some(k) = self.key.clone() else {
            return Err(StorageError::NotFound);
        };
        if k.prefix == prefix {
            Ok(k)
        } else {
            Err(StorageError::NotFound)
        }
    }

    async fn insert(&self, _key: ApiKeyRecord) -> Result<(), StorageError> {
        Ok(())
    }

    async fn revoke_by_prefix(&self, _prefix: &str) -> Result<bool, StorageError> {
        Ok(false)
    }
}

#[tokio::test]
async fn authenticate_success_and_failure() {
    let pepper = "pepper";
    let prefix = "abcdef";
    let secret = "supersecret";
    let hash = hash_api_key_secret(pepper, prefix, secret).expect("hash");

    let store = Arc::new(KeyStore {
        key: Some(ApiKeyRecord {
            id: 1,
            prefix: prefix.to_string(),
            hash,
            scopes: String::new(),
            created_at: Utc::now(),
            revoked_at: None,
        }),
        fail: false,
    });

    let auth = Authenticator::new(pepper.to_string(), store);
    let ok = auth
        .authenticate(&format!("sk_{prefix}.{secret}"))
        .await
        .expect("auth success");
    assert_eq!(ok.prefix, prefix);

    let bad = auth.authenticate("sk_abcdef.wrong").await;
    assert!(bad.is_err());
}

#[tokio::test]
async fn authenticate_rejects_revoked_key() {
    let pepper = "pepper";
    let prefix = "abcdef";
    let secret = "supersecret";
    let hash = hash_api_key_secret(pepper, prefix, secret).expect("hash");

    let store = Arc::new(KeyStore {
        key: Some(ApiKeyRecord {
            id: 1,
            prefix: prefix.to_string(),
            hash,
            scopes: String::new(),
            created_at: Utc::now(),
            revoked_at: Some(Utc::now()),
        }),
        fail: false,
    });

    let auth = Authenticator::new(pepper.to_string(), store);
    let res = auth.authenticate(&format!("sk_{prefix}.{secret}")).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn authenticate_maps_storage_errors() {
    let pepper = "pepper";
    let store = Arc::new(KeyStore {
        key: None,
        fail: true,
    });
    let auth = Authenticator::new(pepper.to_string(), store);
    let err = auth
        .authenticate("sk_abcdef.supersecret")
        .await
        .expect_err("expected storage error");
    assert!(matches!(
        err,
        secrt_server::domain::auth::AuthError::Storage(_)
    ));
}

#[test]
fn parse_and_hash_helpers() {
    let parsed = parse_api_key("sk_abcdef.secret").expect("parse");
    assert_eq!(parsed.prefix, "abcdef");
    assert!(parse_api_key("invalid").is_err());

    let h1 = hash_api_key_secret("pepper", "p", "s").expect("hash");
    let h2 = hash_api_key_secret("pepper", "p", "s").expect("hash");
    assert!(secure_equals_hex(&h1, &h2));
    assert!(!secure_equals_hex(&h1, "deadbeef"));
    assert!(!secure_equals_hex("not-hex", &h2));
    assert!(!secure_equals_hex(&h1, "not-hex"));

    let (api_key, prefix, hash) = generate_api_key("pepper").expect("generate");
    assert!(api_key.starts_with("sk_"));
    assert!(!prefix.is_empty());
    assert_eq!(hash.len(), 64);
}
