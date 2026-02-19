//! Account Master Key (AMK) crypto operations.
//!
//! - AMK wrap/unwrap: per-API-key encryption of the AMK
//! - Note encrypt/decrypt: per-secret note encryption bound to secret_id
//! - AMK commitment: blinded hash for race prevention
//! - ECDH helpers: transfer key derivation and SAS computation

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::hkdf;

use crate::apikey::{derive_from_root, ApiKeyError};
use crate::types::EnvelopeError;

// ── Constants ────────────────────────────────────────────────────────

pub const AMK_LEN: usize = 32;
pub const WRAP_KEY_LEN: usize = 32;
pub const NOTE_KEY_LEN: usize = 32;
pub const GCM_NONCE_LEN: usize = 12;
pub const GCM_TAG_LEN: usize = 16;
pub const NOTE_SALT_LEN: usize = 32;
pub const SAS_LEN: usize = 3;

pub const HKDF_INFO_AMK_WRAP: &str = "secrt-amk-wrap-v1";
pub const HKDF_INFO_NOTE: &str = "secrt-note-v1";
pub const HKDF_INFO_AMK_TRANSFER: &str = "secrt-amk-transfer-v1";
pub const HKDF_INFO_SAS: &str = "secrt-amk-sas-v1";
pub const AMK_COMMIT_DOMAIN_TAG: &[u8] = b"secrt-amk-commit-v1";

// ── Types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WrappedAmk {
    pub ct: Vec<u8>,
    pub nonce: Vec<u8>,
    pub version: u16,
}

#[derive(Debug, Clone)]
pub struct EncryptedNote {
    pub ct: Vec<u8>,
    pub nonce: Vec<u8>,
    pub salt: Vec<u8>,
    pub version: u16,
}

// ── AMK Commitment ──────────────────────────────────────────────────

/// Compute `SHA-256("secrt-amk-commit-v1" || amk)` — a blinded hash the server
/// can use to verify all wrappers belong to the same AMK without seeing it.
pub fn compute_amk_commit(amk: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(AMK_COMMIT_DOMAIN_TAG.len() + amk.len());
    input.extend_from_slice(AMK_COMMIT_DOMAIN_TAG);
    input.extend_from_slice(amk);
    let d = digest(&SHA256, &input);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

// ── Key Derivation ──────────────────────────────────────────────────

/// Derive the AMK wrap key from an API key's root_key.
/// Uses the same HKDF(root_key, root_salt, info, 32) pattern as `derive_auth_token`.
pub fn derive_amk_wrap_key(root_key: &[u8]) -> Result<Vec<u8>, ApiKeyError> {
    derive_from_root(root_key, HKDF_INFO_AMK_WRAP, WRAP_KEY_LEN)
}

/// Build domain-tagged AAD for AMK wrapping.
/// AAD = "secrt-amk-wrap-v1" || user_id || key_prefix || version (BE u16)
pub fn build_wrap_aad(user_id: &str, key_prefix: &str, version: u16) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(HKDF_INFO_AMK_WRAP.len() + user_id.len() + key_prefix.len() + 2);
    aad.extend_from_slice(HKDF_INFO_AMK_WRAP.as_bytes());
    aad.extend_from_slice(user_id.as_bytes());
    aad.extend_from_slice(key_prefix.as_bytes());
    aad.extend_from_slice(&version.to_be_bytes());
    aad
}

// ── AES-256-GCM Helpers ─────────────────────────────────────────────

pub fn aes256gcm_encrypt(
    key: &[u8],
    nonce_bytes: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| EnvelopeError::InvalidEnvelope("AES key creation failed".into()))?;
    let less_safe = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| EnvelopeError::InvalidEnvelope("invalid nonce".into()))?;
    let mut in_out = plaintext.to_vec();
    less_safe
        .seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| EnvelopeError::InvalidEnvelope("encryption failed".into()))?;
    Ok(in_out)
}

pub fn aes256gcm_decrypt(
    key: &[u8],
    nonce_bytes: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| EnvelopeError::InvalidEnvelope("AES key creation failed".into()))?;
    let less_safe = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| EnvelopeError::InvalidEnvelope("invalid nonce".into()))?;
    let mut in_out = ciphertext.to_vec();
    let plaintext = less_safe
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| EnvelopeError::DecryptionFailed)?;
    Ok(plaintext.to_vec())
}

// ── AMK Wrap / Unwrap ───────────────────────────────────────────────

/// Wrap (encrypt) an AMK with the derived wrap key. Generates a random nonce.
pub fn wrap_amk(
    amk: &[u8],
    wrap_key: &[u8],
    aad: &[u8],
    rand_bytes: &dyn Fn(&mut [u8]) -> Result<(), EnvelopeError>,
) -> Result<WrappedAmk, EnvelopeError> {
    if amk.len() != AMK_LEN {
        return Err(EnvelopeError::InvalidEnvelope(
            "AMK must be 32 bytes".into(),
        ));
    }
    let mut nonce = vec![0u8; GCM_NONCE_LEN];
    rand_bytes(&mut nonce)?;
    let ct = aes256gcm_encrypt(wrap_key, &nonce, aad, amk)?;
    Ok(WrappedAmk {
        ct,
        nonce,
        version: 1,
    })
}

/// Unwrap (decrypt) a wrapped AMK blob back to the raw 32-byte AMK.
pub fn unwrap_amk(
    wrapped: &WrappedAmk,
    wrap_key: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let amk = aes256gcm_decrypt(wrap_key, &wrapped.nonce, aad, &wrapped.ct)?;
    if amk.len() != AMK_LEN {
        return Err(EnvelopeError::InvalidEnvelope(
            "unwrapped AMK is not 32 bytes".into(),
        ));
    }
    Ok(amk)
}

// ── Note Encrypt / Decrypt ──────────────────────────────────────────

/// Build AAD for note encryption: `"secrt-note-v1" || secret_id`.
/// This binds each note to a specific secret, preventing cross-secret replay.
fn build_note_aad(secret_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HKDF_INFO_NOTE.len() + secret_id.len());
    aad.extend_from_slice(HKDF_INFO_NOTE.as_bytes());
    aad.extend_from_slice(secret_id.as_bytes());
    aad
}

/// Derive a per-note encryption key: `HKDF(AMK, salt, "secrt-note-v1", 32)`.
fn derive_note_key(amk: &[u8], salt: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let hkdf_salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = hkdf_salt.extract(amk);
    let info = [HKDF_INFO_NOTE.as_bytes()];
    let okm = prk
        .expand(&info, HkdfLen(NOTE_KEY_LEN))
        .map_err(|_| EnvelopeError::InvalidEnvelope("HKDF expand failed".into()))?;
    let mut out = vec![0u8; NOTE_KEY_LEN];
    okm.fill(&mut out)
        .map_err(|_| EnvelopeError::InvalidEnvelope("HKDF fill failed".into()))?;
    Ok(out)
}

/// Encrypt a note for a specific secret. Generates random salt and nonce.
pub fn encrypt_note(
    amk: &[u8],
    secret_id: &str,
    plaintext: &[u8],
    rand_bytes: &dyn Fn(&mut [u8]) -> Result<(), EnvelopeError>,
) -> Result<EncryptedNote, EnvelopeError> {
    if amk.len() != AMK_LEN {
        return Err(EnvelopeError::InvalidEnvelope(
            "AMK must be 32 bytes".into(),
        ));
    }
    let mut salt = vec![0u8; NOTE_SALT_LEN];
    rand_bytes(&mut salt)?;
    let mut nonce = vec![0u8; GCM_NONCE_LEN];
    rand_bytes(&mut nonce)?;

    let note_key = derive_note_key(amk, &salt)?;
    let aad = build_note_aad(secret_id);
    let ct = aes256gcm_encrypt(&note_key, &nonce, &aad, plaintext)?;

    Ok(EncryptedNote {
        ct,
        nonce,
        salt,
        version: 1,
    })
}

/// Decrypt a note for a specific secret. Verifies AAD binding to secret_id.
pub fn decrypt_note(
    amk: &[u8],
    secret_id: &str,
    encrypted: &EncryptedNote,
) -> Result<Vec<u8>, EnvelopeError> {
    if amk.len() != AMK_LEN {
        return Err(EnvelopeError::InvalidEnvelope(
            "AMK must be 32 bytes".into(),
        ));
    }
    let note_key = derive_note_key(amk, &encrypted.salt)?;
    let aad = build_note_aad(secret_id);
    aes256gcm_decrypt(&note_key, &encrypted.nonce, &aad, &encrypted.ct)
}

// ── ECDH Transfer Key ───────────────────────────────────────────────

/// Derive a symmetric transfer key from an ECDH shared secret.
/// `transfer_key = HKDF(shared_secret, empty_salt, "secrt-amk-transfer-v1", 32)`
pub fn derive_transfer_key(shared_secret: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(shared_secret);
    let info = [HKDF_INFO_AMK_TRANSFER.as_bytes()];
    let okm = prk
        .expand(&info, HkdfLen(32))
        .map_err(|_| EnvelopeError::InvalidEnvelope("HKDF expand failed".into()))?;
    let mut out = vec![0u8; 32];
    okm.fill(&mut out)
        .map_err(|_| EnvelopeError::InvalidEnvelope("HKDF fill failed".into()))?;
    Ok(out)
}

// ── SAS (Short Authentication String) ───────────────────────────────

/// Compute a 6-digit SAS code from ECDH shared secret and both public keys.
/// The public keys are sorted deterministically so both sides get the same code.
///
/// ```text
/// sas_input = HKDF-SHA256(
///     ikm  = shared_secret,
///     salt = min(pk_a, pk_b) || max(pk_a, pk_b),
///     info = "secrt-amk-sas-v1",
///     len  = 3
/// )
/// sas_code = (sas_input[0] << 16 | sas_input[1] << 8 | sas_input[2]) % 1_000_000
/// ```
pub fn compute_sas(shared_secret: &[u8], pk_a: &[u8], pk_b: &[u8]) -> Result<u32, EnvelopeError> {
    let (min_pk, max_pk) = if pk_a <= pk_b {
        (pk_a, pk_b)
    } else {
        (pk_b, pk_a)
    };
    let mut salt_bytes = Vec::with_capacity(min_pk.len() + max_pk.len());
    salt_bytes.extend_from_slice(min_pk);
    salt_bytes.extend_from_slice(max_pk);

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt_bytes);
    let prk = salt.extract(shared_secret);
    let info = [HKDF_INFO_SAS.as_bytes()];
    let okm = prk
        .expand(&info, HkdfLen(SAS_LEN))
        .map_err(|_| EnvelopeError::InvalidEnvelope("HKDF expand failed".into()))?;
    let mut out = [0u8; SAS_LEN];
    okm.fill(&mut out)
        .map_err(|_| EnvelopeError::InvalidEnvelope("HKDF fill failed".into()))?;

    let code = ((out[0] as u32) << 16 | (out[1] as u32) << 8 | (out[2] as u32)) % 1_000_000;
    Ok(code)
}

// ── Internal ────────────────────────────────────────────────────────

struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn real_rand(buf: &mut [u8]) -> Result<(), EnvelopeError> {
        use ring::rand::{SecureRandom, SystemRandom};
        SystemRandom::new()
            .fill(buf)
            .map_err(|_| EnvelopeError::RngError("SystemRandom failed".into()))
    }

    fn fixed_rand(value: u8) -> impl Fn(&mut [u8]) -> Result<(), EnvelopeError> {
        move |buf: &mut [u8]| {
            buf.fill(value);
            Ok(())
        }
    }

    // ── compute_amk_commit ──────────────────────────────────────────

    #[test]
    fn commit_is_deterministic() {
        let amk = [0xAA; AMK_LEN];
        let c1 = compute_amk_commit(&amk);
        let c2 = compute_amk_commit(&amk);
        assert_eq!(c1, c2);
    }

    #[test]
    fn commit_differs_for_different_amk() {
        let c1 = compute_amk_commit(&[0xAA; AMK_LEN]);
        let c2 = compute_amk_commit(&[0xBB; AMK_LEN]);
        assert_ne!(c1, c2);
    }

    // ── derive_amk_wrap_key ─────────────────────────────────────────

    #[test]
    fn wrap_key_derivation_is_deterministic() {
        let root = [7u8; 32];
        let k1 = derive_amk_wrap_key(&root).unwrap();
        let k2 = derive_amk_wrap_key(&root).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), WRAP_KEY_LEN);
    }

    #[test]
    fn wrap_key_differs_from_auth_token() {
        let root = [7u8; 32];
        let wrap = derive_amk_wrap_key(&root).unwrap();
        let auth = crate::apikey::derive_auth_token(&root).unwrap();
        assert_ne!(wrap, auth);
    }

    #[test]
    fn wrap_key_rejects_short_root() {
        assert!(derive_amk_wrap_key(&[0u8; 16]).is_err());
    }

    // ── build_wrap_aad ──────────────────────────────────────────────

    #[test]
    fn wrap_aad_is_deterministic() {
        let a1 = build_wrap_aad("user-1", "prefix1", 1);
        let a2 = build_wrap_aad("user-1", "prefix1", 1);
        assert_eq!(a1, a2);
    }

    #[test]
    fn wrap_aad_differs_by_user() {
        let a1 = build_wrap_aad("user-1", "prefix1", 1);
        let a2 = build_wrap_aad("user-2", "prefix1", 1);
        assert_ne!(a1, a2);
    }

    #[test]
    fn wrap_aad_differs_by_prefix() {
        let a1 = build_wrap_aad("user-1", "prefix1", 1);
        let a2 = build_wrap_aad("user-1", "prefix2", 1);
        assert_ne!(a1, a2);
    }

    #[test]
    fn wrap_aad_differs_by_version() {
        let a1 = build_wrap_aad("user-1", "prefix1", 1);
        let a2 = build_wrap_aad("user-1", "prefix1", 2);
        assert_ne!(a1, a2);
    }

    // ── AES-256-GCM round-trip ──────────────────────────────────────

    #[test]
    fn aes_gcm_round_trip() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let aad = b"test-aad";
        let plaintext = b"hello world";

        let ct = aes256gcm_encrypt(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + GCM_TAG_LEN);

        let pt = aes256gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn aes_gcm_wrong_key_fails() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let ct = aes256gcm_encrypt(&key, &nonce, b"", b"data").unwrap();

        let bad_key = [9u8; 32];
        assert!(aes256gcm_decrypt(&bad_key, &nonce, b"", &ct).is_err());
    }

    #[test]
    fn aes_gcm_wrong_aad_fails() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let ct = aes256gcm_encrypt(&key, &nonce, b"aad1", b"data").unwrap();
        assert!(aes256gcm_decrypt(&key, &nonce, b"aad2", &ct).is_err());
    }

    #[test]
    fn aes_gcm_bad_key_length() {
        assert!(aes256gcm_encrypt(&[0u8; 16], &[0u8; 12], b"", b"x").is_err());
    }

    #[test]
    fn aes_gcm_bad_nonce_length() {
        assert!(aes256gcm_encrypt(&[0u8; 32], &[0u8; 8], b"", b"x").is_err());
    }

    // ── AMK wrap/unwrap round-trip ──────────────────────────────────

    #[test]
    fn wrap_unwrap_round_trip() {
        let amk = [0xAA; AMK_LEN];
        let wrap_key = [0xBB; WRAP_KEY_LEN];
        let aad = build_wrap_aad("user-1", "prefix1", 1);

        let wrapped = wrap_amk(&amk, &wrap_key, &aad, &real_rand).unwrap();
        assert_eq!(wrapped.ct.len(), AMK_LEN + GCM_TAG_LEN);
        assert_eq!(wrapped.nonce.len(), GCM_NONCE_LEN);
        assert_eq!(wrapped.version, 1);

        let unwrapped = unwrap_amk(&wrapped, &wrap_key, &aad).unwrap();
        assert_eq!(unwrapped, amk);
    }

    #[test]
    fn unwrap_wrong_key_fails() {
        let amk = [0xAA; AMK_LEN];
        let wrap_key = [0xBB; WRAP_KEY_LEN];
        let bad_key = [0xCC; WRAP_KEY_LEN];
        let aad = build_wrap_aad("user-1", "prefix1", 1);

        let wrapped = wrap_amk(&amk, &wrap_key, &aad, &real_rand).unwrap();
        assert!(unwrap_amk(&wrapped, &bad_key, &aad).is_err());
    }

    #[test]
    fn unwrap_wrong_aad_fails() {
        let amk = [0xAA; AMK_LEN];
        let wrap_key = [0xBB; WRAP_KEY_LEN];
        let aad1 = build_wrap_aad("user-1", "prefix1", 1);
        let aad2 = build_wrap_aad("user-2", "prefix1", 1);

        let wrapped = wrap_amk(&amk, &wrap_key, &aad1, &real_rand).unwrap();
        assert!(unwrap_amk(&wrapped, &wrap_key, &aad2).is_err());
    }

    #[test]
    fn wrap_rejects_short_amk() {
        let aad = build_wrap_aad("user-1", "prefix1", 1);
        assert!(wrap_amk(&[0u8; 16], &[0u8; 32], &aad, &real_rand).is_err());
    }

    #[test]
    fn wrap_with_full_key_derivation() {
        let root_key = [42u8; 32];
        let amk = [0xDD; AMK_LEN];
        let wrap_key = derive_amk_wrap_key(&root_key).unwrap();
        let aad = build_wrap_aad("user-abc", "abcdef", 1);

        let wrapped = wrap_amk(&amk, &wrap_key, &aad, &real_rand).unwrap();
        let unwrapped = unwrap_amk(&wrapped, &wrap_key, &aad).unwrap();
        assert_eq!(unwrapped, amk);
    }

    // ── Note encrypt/decrypt round-trip ─────────────────────────────

    #[test]
    fn note_round_trip() {
        let amk = [0xEE; AMK_LEN];
        let secret_id = "secret-abc-123";
        let plaintext = b"AWS prod key for Bob";

        let encrypted = encrypt_note(&amk, secret_id, plaintext, &real_rand).unwrap();
        assert_eq!(encrypted.salt.len(), NOTE_SALT_LEN);
        assert_eq!(encrypted.nonce.len(), GCM_NONCE_LEN);
        assert_eq!(encrypted.version, 1);

        let decrypted = decrypt_note(&amk, secret_id, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn note_wrong_amk_fails() {
        let amk = [0xEE; AMK_LEN];
        let bad_amk = [0xFF; AMK_LEN];
        let encrypted = encrypt_note(&amk, "sid", b"secret note", &real_rand).unwrap();
        assert!(decrypt_note(&bad_amk, "sid", &encrypted).is_err());
    }

    #[test]
    fn note_wrong_secret_id_fails() {
        let amk = [0xEE; AMK_LEN];
        let encrypted = encrypt_note(&amk, "secret-1", b"note text", &real_rand).unwrap();
        assert!(decrypt_note(&amk, "secret-2", &encrypted).is_err());
    }

    #[test]
    fn note_rejects_short_amk() {
        assert!(encrypt_note(&[0u8; 16], "sid", b"x", &real_rand).is_err());
        let enc = EncryptedNote {
            ct: vec![0; 32],
            nonce: vec![0; 12],
            salt: vec![0; 32],
            version: 1,
        };
        assert!(decrypt_note(&[0u8; 16], "sid", &enc).is_err());
    }

    #[test]
    fn note_empty_plaintext_round_trips() {
        let amk = [0xEE; AMK_LEN];
        let encrypted = encrypt_note(&amk, "sid", b"", &real_rand).unwrap();
        let decrypted = decrypt_note(&amk, "sid", &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    // ── Transfer key derivation ─────────────────────────────────────

    #[test]
    fn transfer_key_is_deterministic() {
        let shared = [0x42; 32];
        let k1 = derive_transfer_key(&shared).unwrap();
        let k2 = derive_transfer_key(&shared).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn transfer_key_differs_for_different_shared_secret() {
        let k1 = derive_transfer_key(&[0x42; 32]).unwrap();
        let k2 = derive_transfer_key(&[0x43; 32]).unwrap();
        assert_ne!(k1, k2);
    }

    // ── SAS computation ─────────────────────────────────────────────

    #[test]
    fn sas_is_deterministic() {
        let shared = [0x42; 32];
        let pk_a = [1u8; 65];
        let pk_b = [2u8; 65];

        let s1 = compute_sas(&shared, &pk_a, &pk_b).unwrap();
        let s2 = compute_sas(&shared, &pk_a, &pk_b).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn sas_is_commutative() {
        let shared = [0x42; 32];
        let pk_a = [1u8; 65];
        let pk_b = [2u8; 65];

        let s1 = compute_sas(&shared, &pk_a, &pk_b).unwrap();
        let s2 = compute_sas(&shared, &pk_b, &pk_a).unwrap();
        assert_eq!(
            s1, s2,
            "SAS must be the same regardless of public key order"
        );
    }

    #[test]
    fn sas_is_six_digits() {
        let shared = [0x42; 32];
        let pk_a = [1u8; 65];
        let pk_b = [2u8; 65];

        let code = compute_sas(&shared, &pk_a, &pk_b).unwrap();
        assert!(code < 1_000_000, "SAS must be less than 1,000,000");
    }

    #[test]
    fn sas_differs_for_different_shared_secret() {
        let pk_a = [1u8; 65];
        let pk_b = [2u8; 65];

        let s1 = compute_sas(&[0x42; 32], &pk_a, &pk_b).unwrap();
        let s2 = compute_sas(&[0x43; 32], &pk_a, &pk_b).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn sas_differs_for_different_public_keys() {
        let shared = [0x42; 32];
        let pk_a = [1u8; 65];
        let pk_b = [2u8; 65];
        let pk_c = [3u8; 65];

        let s1 = compute_sas(&shared, &pk_a, &pk_b).unwrap();
        let s2 = compute_sas(&shared, &pk_a, &pk_c).unwrap();
        assert_ne!(s1, s2);
    }

    // ── Deterministic vector test (fixed randomness) ────────────────

    #[test]
    fn wrap_unwrap_deterministic() {
        let amk = [0x11; AMK_LEN];
        let wrap_key = [0x22; WRAP_KEY_LEN];
        let aad = build_wrap_aad("user-test", "abcdef", 1);

        let wrapped = wrap_amk(&amk, &wrap_key, &aad, &fixed_rand(0x33)).unwrap();
        // Nonce should be all 0x33
        assert!(wrapped.nonce.iter().all(|&b| b == 0x33));

        // Same inputs produce same output
        let wrapped2 = wrap_amk(&amk, &wrap_key, &aad, &fixed_rand(0x33)).unwrap();
        assert_eq!(wrapped.ct, wrapped2.ct);
        assert_eq!(wrapped.nonce, wrapped2.nonce);

        let unwrapped = unwrap_amk(&wrapped, &wrap_key, &aad).unwrap();
        assert_eq!(unwrapped, amk);
    }

    #[test]
    fn note_encrypt_decrypt_deterministic() {
        let amk = [0x11; AMK_LEN];
        let secret_id = "test-secret-id";
        let plaintext = b"deterministic test note";

        // Use a counter-based RNG: first call gets 0xAA (salt), second gets 0xBB (nonce)
        let call = std::cell::Cell::new(0u8);
        let counter_rand = |buf: &mut [u8]| -> Result<(), EnvelopeError> {
            let val = call.get();
            call.set(val.wrapping_add(1));
            buf.fill(0xAA + val);
            Ok(())
        };

        let encrypted = encrypt_note(&amk, secret_id, plaintext, &counter_rand).unwrap();
        assert!(encrypted.salt.iter().all(|&b| b == 0xAA)); // first call
        assert!(encrypted.nonce.iter().all(|&b| b == 0xAB)); // second call

        let decrypted = decrypt_note(&amk, secret_id, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
