use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use secrt_server::domain::auth::{
    generate_api_key_prefix, hash_api_key_auth_token, parse_api_key, secure_equals_hex,
    Authenticator,
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
    let auth = [7u8; 32];
    let auth_b64 = URL_SAFE_NO_PAD.encode(auth);
    let hash = hash_api_key_auth_token(pepper, prefix, &auth).expect("hash");

    let store = Arc::new(KeyStore {
        key: Some(ApiKeyRecord {
            id: 1,
            prefix: prefix.to_string(),
            auth_hash: hash,
            scopes: String::new(),
            user_id: None,
            created_at: Utc::now(),
            revoked_at: None,
        }),
        fail: false,
    });

    let auth = Authenticator::new(pepper.to_string(), store);
    let ok = auth
        .authenticate(&format!("ak2_{prefix}.{auth_b64}"))
        .await
        .expect("auth success");
    assert_eq!(ok.prefix, prefix);

    let bad = auth.authenticate("ak2_abcdef.wrong").await;
    assert!(bad.is_err());
}

#[tokio::test]
async fn authenticate_rejects_revoked_key() {
    let pepper = "pepper";
    let prefix = "abcdef";
    let auth = [3u8; 32];
    let auth_b64 = URL_SAFE_NO_PAD.encode(auth);
    let hash = hash_api_key_auth_token(pepper, prefix, &auth).expect("hash");

    let store = Arc::new(KeyStore {
        key: Some(ApiKeyRecord {
            id: 1,
            prefix: prefix.to_string(),
            auth_hash: hash,
            scopes: String::new(),
            user_id: None,
            created_at: Utc::now(),
            revoked_at: Some(Utc::now()),
        }),
        fail: false,
    });

    let auth = Authenticator::new(pepper.to_string(), store);
    let res = auth.authenticate(&format!("ak2_{prefix}.{auth_b64}")).await;
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
        .authenticate(&format!("ak2_abcdef.{}", URL_SAFE_NO_PAD.encode([9u8; 32])))
        .await
        .expect_err("expected storage error");
    assert!(matches!(
        err,
        secrt_server::domain::auth::AuthError::Storage(_)
    ));
}

#[test]
fn parse_and_hash_helpers() {
    let parsed =
        parse_api_key(&format!("ak2_abcdef.{}", URL_SAFE_NO_PAD.encode([4u8; 32]))).expect("parse");
    assert_eq!(parsed.prefix, "abcdef");
    assert!(parse_api_key("invalid").is_err());

    let h1 = hash_api_key_auth_token("pepper", "abcdef", &[1u8; 32]).expect("hash");
    let h2 = hash_api_key_auth_token("pepper", "abcdef", &[1u8; 32]).expect("hash");
    assert!(secure_equals_hex(&h1, &h2));
    assert!(!secure_equals_hex(&h1, "deadbeef"));
    assert!(!secure_equals_hex("not-hex", &h2));
    assert!(!secure_equals_hex(&h1, "not-hex"));

    let prefix = generate_api_key_prefix().expect("generate");
    assert!(!prefix.is_empty());
    let hash = hash_api_key_auth_token("pepper", &prefix, &[2u8; 32]).expect("hash");
    assert!(!prefix.is_empty());
    assert_eq!(hash.len(), 64);
}
