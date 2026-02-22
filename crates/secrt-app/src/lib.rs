use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use secrt_core::{
    CompressionPolicy, EnvelopeError, OpenParams, PayloadMeta, PayloadType, SealParams,
};
use serde::Serialize;

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            seal_secret,
            open_secret,
            derive_claim_token,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
