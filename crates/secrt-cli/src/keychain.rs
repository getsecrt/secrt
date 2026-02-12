//! OS keychain integration (behind the `keychain` feature flag).
//!
//! Provides get/set wrappers around the `keyring` crate for storing
//! api_key and passphrase in the OS credential store.

#[cfg(feature = "keychain")]
use keyring::Entry;

#[cfg(feature = "keychain")]
const SERVICE: &str = "secrt";

/// Retrieve a secret from the OS keychain. Returns None if not found
/// or if the keychain is unavailable.
#[cfg(feature = "keychain")]
pub fn get_secret(key: &str) -> Option<String> {
    let entry = Entry::new(SERVICE, key).ok()?;
    entry.get_password().ok()
}

/// Store a secret in the OS keychain.
#[cfg(feature = "keychain")]
pub fn set_secret(key: &str, value: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE, key).map_err(|e| format!("keychain entry error: {}", e))?;
    entry
        .set_password(value)
        .map_err(|e| format!("keychain set error: {}", e))
}

/// Delete a secret from the OS keychain.
#[cfg(feature = "keychain")]
pub fn delete_secret(key: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE, key).map_err(|e| format!("keychain entry error: {}", e))?;
    entry
        .delete_credential()
        .map_err(|e| format!("keychain delete error: {}", e))
}

/// Retrieve a list of secrets from the OS keychain.
/// The value may be a JSON array `["p1","p2"]` or a plain string.
/// Returns an empty vec if the key is not found.
#[cfg(feature = "keychain")]
pub fn get_secret_list(key: &str) -> Vec<String> {
    let raw = match get_secret(key) {
        Some(s) if !s.is_empty() => s,
        _ => return Vec::new(),
    };
    // Try JSON array first, fall back to single-entry
    serde_json::from_str::<Vec<String>>(&raw).unwrap_or_else(|_| vec![raw])
}

// Stubs when keychain feature is not enabled
#[cfg(not(feature = "keychain"))]
pub fn get_secret(_key: &str) -> Option<String> {
    None
}

#[cfg(not(feature = "keychain"))]
pub fn get_secret_list(_key: &str) -> Vec<String> {
    Vec::new()
}

#[cfg(not(feature = "keychain"))]
pub fn set_secret(_key: &str, _value: &str) -> Result<(), String> {
    Err("keychain feature not enabled; rebuild with --features keychain".into())
}

#[cfg(not(feature = "keychain"))]
pub fn delete_secret(_key: &str) -> Result<(), String> {
    Err("keychain feature not enabled; rebuild with --features keychain".into())
}
