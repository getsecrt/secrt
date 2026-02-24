use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use secrt_core::{
    CompressionPolicy, EnvelopeError, OpenParams, PayloadMeta, PayloadType, SealParams,
};
use serde::Serialize;
#[cfg(debug_assertions)]
use tauri::Manager;

fn system_rng(buf: &mut [u8]) -> Result<(), EnvelopeError> {
    SystemRandom::new()
        .fill(buf)
        .map_err(|_| EnvelopeError::RngError("SystemRandom failed".into()))
}

#[derive(Serialize)]
pub struct SealResponse {
    pub envelope: serde_json::Value,
    pub url_key: String,
    pub claim_hash: String,
}

#[derive(Serialize)]
pub struct OpenResponse {
    pub content: String,
    pub payload_type: String,
    pub filename: Option<String>,
    pub mime: Option<String>,
}

fn parse_metadata(
    payload_type: &str,
    filename: Option<String>,
    mime: Option<String>,
) -> PayloadMeta {
    match payload_type {
        "file" => PayloadMeta::file(
            filename.unwrap_or_default(),
            mime.unwrap_or_else(|| "application/octet-stream".into()),
        ),
        "binary" => PayloadMeta::binary(),
        _ => PayloadMeta::text(),
    }
}

pub fn seal_secret_inner(
    content_b64: &str,
    payload_type: &str,
    filename: Option<String>,
    mime: Option<String>,
    passphrase: Option<String>,
    rand_bytes: &dyn Fn(&mut [u8]) -> Result<(), EnvelopeError>,
) -> Result<SealResponse, String> {
    let content = URL_SAFE_NO_PAD
        .decode(content_b64)
        .map_err(|e| e.to_string())?;

    let metadata = parse_metadata(payload_type, filename, mime);

    let result = secrt_core::seal(SealParams {
        content,
        metadata,
        passphrase: passphrase.unwrap_or_default(),
        rand_bytes,
        compression_policy: CompressionPolicy::default(),
    })
    .map_err(|e| e.to_string())?;

    Ok(SealResponse {
        envelope: result.envelope,
        url_key: URL_SAFE_NO_PAD.encode(&result.url_key),
        claim_hash: result.claim_hash,
    })
}

pub fn open_secret_inner(
    envelope: serde_json::Value,
    url_key_b64: &str,
    passphrase: Option<String>,
) -> Result<OpenResponse, String> {
    let url_key = URL_SAFE_NO_PAD
        .decode(url_key_b64)
        .map_err(|e| e.to_string())?;

    let result = secrt_core::open(OpenParams {
        envelope,
        url_key,
        passphrase: passphrase.unwrap_or_default(),
    })
    .map_err(|e| e.to_string())?;

    let payload_type = match result.metadata.payload_type {
        PayloadType::Text => "text",
        PayloadType::File => "file",
        PayloadType::Binary => "binary",
    };

    Ok(OpenResponse {
        content: URL_SAFE_NO_PAD.encode(&result.content),
        payload_type: payload_type.into(),
        filename: result.metadata.filename,
        mime: result.metadata.mime,
    })
}

/// Copy text to the OS clipboard with "exclude from history" flags.
/// On macOS: sets org.nspasteboard.ConcealedType
/// On Windows: sets ExcludeClipboardContentFromMonitorProcessing + CanIncludeInClipboardHistory=0
/// On Linux: sets x-kde-passwordManagerHint
pub fn copy_sensitive_inner(text: &str) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;

    #[cfg(target_os = "macos")]
    {
        use arboard::SetExtApple;
        clipboard
            .set()
            .exclude_from_history()
            .text(text)
            .map_err(|e| e.to_string())?;
    }

    #[cfg(target_os = "windows")]
    {
        use arboard::SetExtWindows;
        clipboard
            .set()
            .exclude_from_monitoring()
            .exclude_from_history()
            .exclude_from_cloud()
            .text(text)
            .map_err(|e| e.to_string())?;
    }

    #[cfg(target_os = "linux")]
    {
        use arboard::SetExtLinux;
        clipboard
            .set()
            .exclude_from_history()
            .text(text)
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}

pub fn derive_claim_token_inner(url_key_b64: &str) -> Result<String, String> {
    let url_key = URL_SAFE_NO_PAD
        .decode(url_key_b64)
        .map_err(|e| e.to_string())?;
    let token = secrt_core::derive_claim_token(&url_key).map_err(|e| e.to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(&token))
}

#[tauri::command]
fn seal_secret(
    content_b64: String,
    payload_type: String,
    filename: Option<String>,
    mime: Option<String>,
    passphrase: Option<String>,
) -> Result<SealResponse, String> {
    seal_secret_inner(
        &content_b64,
        &payload_type,
        filename,
        mime,
        passphrase,
        &system_rng,
    )
}

#[tauri::command]
fn open_secret(
    envelope: serde_json::Value,
    url_key_b64: String,
    passphrase: Option<String>,
) -> Result<OpenResponse, String> {
    open_secret_inner(envelope, &url_key_b64, passphrase)
}

#[tauri::command]
fn derive_claim_token(url_key_b64: String) -> Result<String, String> {
    derive_claim_token_inner(&url_key_b64)
}

#[tauri::command]
fn copy_sensitive(text: String) -> Result<(), String> {
    copy_sensitive_inner(&text)
}

// --- Credential store (OS keychain with file-based fallback) ---
//
// macOS Tahoe 26 has a regression where SecItemAdd succeeds but
// SecItemCopyMatching returns errSecItemNotFound for the same item.
// We try the OS keychain first; if a set+verify round-trip fails,
// we fall back to a JSON file in the app data directory.

const KEYRING_SERVICE: &str = "ca.secrt.app";
const ALLOWED_KEY_PREFIXES: &[&str] = &["session_token", "session_profile", "amk:"];
const FALLBACK_FILENAME: &str = "credentials.json";

/// Lazily-initialized flag: if the OS keychain fails a round-trip,
/// all subsequent operations use the file fallback for the rest of
/// the process lifetime.
static KEYCHAIN_BROKEN: Mutex<Option<bool>> = Mutex::new(None);

fn validate_keyring_key(key: &str) -> Result<(), String> {
    if ALLOWED_KEY_PREFIXES
        .iter()
        .any(|p| key == *p || key.starts_with(p))
    {
        Ok(())
    } else {
        Err(format!("disallowed keyring key: {key}"))
    }
}

/// Return the path to the fallback credentials file.
/// Uses the standard app data directory: ~/Library/Application Support/ca.secrt.app/
fn fallback_path() -> Result<PathBuf, String> {
    let dir = dirs::data_dir()
        .ok_or("cannot determine app data directory")?
        .join(KEYRING_SERVICE);
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| format!("create data dir: {e}"))?;
    }
    Ok(dir.join(FALLBACK_FILENAME))
}

fn fallback_read() -> Result<HashMap<String, String>, String> {
    let path = fallback_path()?;
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let data = fs::read_to_string(&path).map_err(|e| format!("read credentials: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("parse credentials: {e}"))
}

fn fallback_write(map: &HashMap<String, String>) -> Result<(), String> {
    let path = fallback_path()?;
    let data = serde_json::to_string_pretty(map).map_err(|e| format!("serialize: {e}"))?;
    fs::write(&path, data).map_err(|e| format!("write credentials: {e}"))
}

/// Check whether the OS keychain works by doing a set+get round-trip.
/// Caches the result for the process lifetime.
fn is_keychain_broken() -> bool {
    let mut guard = KEYCHAIN_BROKEN.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(broken) = *guard {
        return broken;
    }
    let broken = probe_keychain();
    *guard = Some(broken);
    if broken {
        eprintln!("[keyring] OS keychain probe failed — using file-based fallback");
    } else {
        eprintln!("[keyring] OS keychain probe succeeded");
    }
    broken
}

fn probe_keychain() -> bool {
    let probe_key = "__secrt_probe__";
    let probe_val = "probe";
    let set_ok = keyring::Entry::new(KEYRING_SERVICE, probe_key)
        .and_then(|e| e.set_password(probe_val))
        .is_ok();
    if !set_ok {
        return true;
    }
    let get_ok = keyring::Entry::new(KEYRING_SERVICE, probe_key)
        .and_then(|e| e.get_password())
        .is_ok();
    // Cleanup
    let _ = keyring::Entry::new(KEYRING_SERVICE, probe_key).and_then(|e| e.delete_credential());
    !get_ok
}

#[tauri::command]
fn keyring_set(key: String, value: String) -> Result<(), String> {
    validate_keyring_key(&key)?;
    if is_keychain_broken() {
        let mut map = fallback_read()?;
        map.insert(key, value);
        return fallback_write(&map);
    }
    let entry = keyring::Entry::new(KEYRING_SERVICE, &key).map_err(|e| e.to_string())?;
    entry.set_password(&value).map_err(|e| e.to_string())
}

#[tauri::command]
fn keyring_get(key: String) -> Result<Option<String>, String> {
    validate_keyring_key(&key)?;
    if is_keychain_broken() {
        let map = fallback_read()?;
        return Ok(map.get(&key).cloned());
    }
    let entry = keyring::Entry::new(KEYRING_SERVICE, &key).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
fn keyring_delete(key: String) -> Result<(), String> {
    validate_keyring_key(&key)?;
    if is_keychain_broken() {
        let mut map = fallback_read()?;
        map.remove(&key);
        return fallback_write(&map);
    }
    let entry = keyring::Entry::new(KEYRING_SERVICE, &key).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_sensitive_sets_text() {
        copy_sensitive_inner("hello-sensitive").expect("copy_sensitive_inner should succeed");
        let mut clipboard = arboard::Clipboard::new().expect("open clipboard");
        assert_eq!(
            clipboard.get_text().expect("read clipboard"),
            "hello-sensitive"
        );
    }

    #[test]
    fn copy_sensitive_empty_string() {
        // Should not panic on empty input
        copy_sensitive_inner("").expect("copy_sensitive_inner should succeed for empty string");
    }

    #[test]
    fn keyring_probe_detects_broken_keychain() {
        // This test documents the current macOS Tahoe behavior.
        // If the keychain works, probe returns false; if broken, true.
        // Either way the app should function via the fallback.
        let broken = probe_keychain();
        eprintln!("keychain broken: {broken}");
    }

    #[test]
    fn fallback_roundtrip() {
        let mut map = HashMap::new();
        map.insert("amk:test-user".into(), "test-value-123".into());
        fallback_write(&map).expect("write");
        let read = fallback_read().expect("read");
        assert_eq!(read.get("amk:test-user").unwrap(), "test-value-123");
        // Cleanup
        let _ = fs::remove_file(fallback_path().unwrap());
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            seal_secret,
            open_secret,
            derive_claim_token,
            copy_sensitive,
            keyring_set,
            keyring_get,
            keyring_delete,
        ])
        .setup(|app| {
            #[cfg(debug_assertions)]
            {
                let windows = app.webview_windows();
                for window in windows.values() {
                    window.open_devtools();
                }
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
