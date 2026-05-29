//! Shared account-key (AMK) lifecycle helpers used by `pair`, `sync`, and
//! `auth login`. Centralizing this here keeps the three commands from
//! drifting on wrapping AAD, error vocabulary, or persistence semantics.
//!
//! The internal name remains `AMK` (account master key) for code identifiers
//! because it matches every existing call site in `secrt-core` and the
//! storage layer. User-facing text in this crate says "account key".

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::agreement;

use crate::cli::ParsedArgs;
use crate::client::SecretApi;

/// Outcome of attempting to load the local account key for the configured
/// API key. `pair` uses this to pick Send vs Receive mode strictly; other
/// callers can collapse the non-`Present` variants to a generic error via
/// [`resolve_amk`].
#[derive(Debug)]
pub enum AccountKeyState {
    /// Wrapper present and unwrapped successfully.
    Present(Vec<u8>),
    /// No wrapper for this caller (server returned 404 / `None`).
    Missing,
    /// No API key configured at all.
    NoApiKey,
    /// API key configured but rejected by the server (401) or unparseable
    /// locally.
    InvalidApiKey(String),
    /// Wrapper present but malformed or undecryptable (corrupted local
    /// root key, schema drift, etc).
    CorruptWrapper(String),
    /// Transport failure talking to the server.
    NetworkError(String),
}

/// Backwards-compatible wrapper: collapses every non-`Present` state to
/// `Err(String)` for callers that don't care about distinguishing them.
/// Behaviorally identical to the original `resolve_amk` in `send.rs`.
pub fn resolve_amk(pa: &ParsedArgs, client: &(dyn SecretApi + '_)) -> Result<Vec<u8>, String> {
    match resolve_account_key_state(pa, client) {
        AccountKeyState::Present(bytes) => Ok(bytes),
        AccountKeyState::Missing => Err(
            "no account key found; create one via web settings or `secrt auth login`".to_string(),
        ),
        AccountKeyState::NoApiKey => {
            Err("no API key configured (run `secrt auth login` first)".to_string())
        }
        AccountKeyState::InvalidApiKey(msg) => Err(msg),
        AccountKeyState::CorruptWrapper(msg) => Err(msg),
        AccountKeyState::NetworkError(msg) => Err(msg),
    }
}

/// Typed account-key resolution. Returns a distinct variant per failure
/// mode so `secrt pair` can decide whether to flip into Receive mode
/// (`Missing` only) or surface a specific error to the user.
pub fn resolve_account_key_state(
    pa: &ParsedArgs,
    client: &(dyn SecretApi + '_),
) -> AccountKeyState {
    use secrt_core::amk::{build_wrap_aad, derive_amk_wrap_key, unwrap_amk, WrappedAmk};

    if pa.api_key.trim().is_empty() {
        return AccountKeyState::NoApiKey;
    }

    let local_key = match secrt_core::parse_local_api_key(&pa.api_key) {
        Ok(k) => k,
        Err(e) => {
            return AccountKeyState::InvalidApiKey(format!("cannot parse API key: {e}"));
        }
    };

    let wrapper_resp = match client.get_amk_wrapper() {
        Ok(Some(w)) => w,
        Ok(None) => return AccountKeyState::Missing,
        Err(e) => {
            // Classify by substring on the error text. The current
            // `SecretApi` returns `String` for every server error, so
            // we have no typed status code here — best-effort matching.
            // Order matters: check the specific "not linked" message
            // (400) before the generic 401 path so an unlinked key
            // surfaces a re-link hint rather than a wrong-key hint.
            let lc = e.to_lowercase();
            if lc.contains("not linked") {
                return AccountKeyState::InvalidApiKey(e);
            }
            if lc.contains("unauthorized") || lc.contains("401") {
                return AccountKeyState::InvalidApiKey(e);
            }
            return AccountKeyState::NetworkError(e);
        }
    };

    let wrap_key = match derive_amk_wrap_key(&local_key.root_key) {
        Ok(k) => k,
        Err(e) => {
            return AccountKeyState::CorruptWrapper(format!("derive wrap key: {e}"));
        }
    };

    let ct = match URL_SAFE_NO_PAD.decode(&wrapper_resp.wrapped_amk) {
        Ok(b) => b,
        Err(e) => {
            return AccountKeyState::CorruptWrapper(format!("decode wrapped_amk: {e}"));
        }
    };
    let nonce = match URL_SAFE_NO_PAD.decode(&wrapper_resp.nonce) {
        Ok(b) => b,
        Err(e) => return AccountKeyState::CorruptWrapper(format!("decode nonce: {e}")),
    };

    let user_id_bytes = match uuid::Uuid::parse_str(&wrapper_resp.user_id) {
        Ok(u) => u.into_bytes(),
        Err(e) => {
            return AccountKeyState::CorruptWrapper(format!(
                "server returned invalid user_id UUID: {e}"
            ));
        }
    };
    let aad = build_wrap_aad(
        &user_id_bytes,
        &local_key.prefix,
        wrapper_resp.version as u16,
    );

    let wrapped = WrappedAmk {
        ct,
        nonce,
        version: wrapper_resp.version as u16,
    };

    match unwrap_amk(&wrapped, &wrap_key, &aad) {
        Ok(bytes) => AccountKeyState::Present(bytes),
        Err(e) => AccountKeyState::CorruptWrapper(format!("unwrap AMK: {e}")),
    }
}

/// Wrap a raw 32-byte account key with the caller's API key and upload
/// the wrapper to the server. Accepts an injected RNG so tests can be
/// deterministic. Caller is responsible for ensuring `api_key` is a
/// linked, valid key (any non-`Present` state from
/// [`resolve_account_key_state`] is grounds to refuse).
pub fn import_amk(
    amk_bytes: &[u8],
    api_key: &str,
    user_id: &str,
    client: &dyn SecretApi,
    rand_bytes: &dyn Fn(&mut [u8]) -> Result<(), secrt_core::types::EnvelopeError>,
) -> Result<(), String> {
    use secrt_core::amk;

    if amk_bytes.len() != amk::AMK_LEN {
        return Err(format!(
            "invalid account key length: expected {}, got {}",
            amk::AMK_LEN,
            amk_bytes.len()
        ));
    }

    let local_key = secrt_core::parse_local_api_key(api_key)
        .map_err(|e| format!("cannot parse API key: {}", e))?;

    let wrap_key = amk::derive_amk_wrap_key(&local_key.root_key)
        .map_err(|e| format!("derive wrap key: {}", e))?;

    let user_id_bytes = uuid::Uuid::parse_str(user_id)
        .map_err(|e| format!("server returned invalid user_id UUID: {}", e))?
        .into_bytes();

    let aad = amk::build_wrap_aad(&user_id_bytes, &local_key.prefix, 1);
    let wrapped = amk::wrap_amk(amk_bytes, &wrap_key, &aad, rand_bytes)
        .map_err(|e| format!("wrap account key: {}", e))?;

    let commit = amk::compute_amk_commit(amk_bytes);

    client.upsert_amk_wrapper(
        &local_key.prefix,
        &URL_SAFE_NO_PAD.encode(&wrapped.ct),
        &URL_SAFE_NO_PAD.encode(&wrapped.nonce),
        &URL_SAFE_NO_PAD.encode(commit),
        1,
    )
}

/// Decrypt an account-key transfer blob received via the pair flow or the
/// device-login flow, then persist it for this device via [`import_amk`].
///
/// `own_private` is consumed (`ring::agreement::EphemeralPrivateKey` is
/// move-only). `transfer_pubkey_b64` and `transfer_ct_b64` / `nonce_b64`
/// are URL-safe-base64 strings exactly as carried over the wire. The
/// AAD constant `"secrt-amk-transfer-v1"` matches `web/src/features/pair/`
/// and `secrt-core::amk::AMK_TRANSFER_AAD`.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_and_persist_transfer(
    transfer_pubkey_b64: &str,
    transfer_ct_b64: &str,
    transfer_nonce_b64: &str,
    own_private: agreement::EphemeralPrivateKey,
    api_key: &str,
    user_id: &str,
    client: &dyn SecretApi,
    rand_bytes: &dyn Fn(&mut [u8]) -> Result<(), secrt_core::types::EnvelopeError>,
) -> Result<Vec<u8>, String> {
    use secrt_core::amk;

    let peer_bytes = URL_SAFE_NO_PAD
        .decode(transfer_pubkey_b64)
        .map_err(|e| format!("decode peer public key: {}", e))?;
    let peer_pk = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &peer_bytes);

    let shared_secret: Vec<u8> = agreement::agree_ephemeral(own_private, &peer_pk, |s| s.to_vec())
        .map_err(|_| "ECDH agreement failed".to_string())?;

    let transfer_key = amk::derive_transfer_key(&shared_secret)
        .map_err(|e| format!("derive transfer key: {}", e))?;

    let ct = URL_SAFE_NO_PAD
        .decode(transfer_ct_b64)
        .map_err(|e| format!("decode ciphertext: {}", e))?;
    let nonce = URL_SAFE_NO_PAD
        .decode(transfer_nonce_b64)
        .map_err(|e| format!("decode nonce: {}", e))?;

    let amk_bytes = amk::aes256gcm_decrypt(&transfer_key, &nonce, amk::AMK_TRANSFER_AAD, &ct)
        .map_err(|e| format!("decrypt account key: {}", e))?;

    if amk_bytes.len() != amk::AMK_LEN {
        return Err(format!(
            "invalid account key length: expected {}, got {}",
            amk::AMK_LEN,
            amk_bytes.len()
        ));
    }

    import_amk(&amk_bytes, api_key, user_id, client, rand_bytes)?;
    Ok(amk_bytes)
}
