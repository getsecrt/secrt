use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::hkdf;

use crate::payload::{decode_payload, encode_payload};
use crate::types::*;

pub fn b64_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, EnvelopeError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| EnvelopeError::InvalidEnvelope(format!("base64 decode: {}", e)))
}

/// HKDF-SHA-256 key derivation.
fn derive_hkdf(
    ikm: &[u8],
    salt: &[u8],
    info: &str,
    length: usize,
) -> Result<Vec<u8>, EnvelopeError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt.extract(ikm);
    let info_slice = &[info.as_bytes()];
    let okm = prk
        .expand(info_slice, HkdfLen(length))
        .map_err(|_| EnvelopeError::InvalidEnvelope("HKDF expand failed".into()))?;
    let mut out = vec![0u8; length];
    okm.fill(&mut out)
        .map_err(|_| EnvelopeError::InvalidEnvelope("HKDF fill failed".into()))?;
    Ok(out)
}

/// ring requires a type implementing KeyType for HKDF output length.
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derive claim token from url_key alone.
/// claim_token = HKDF-SHA-256(url_key, claim_salt, "secrt:v1:claim:sealed-payload", 32)
pub fn derive_claim_token(url_key: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if url_key.len() != URL_KEY_LEN {
        return Err(EnvelopeError::InvalidUrlKey);
    }
    let claim_salt = digest(&SHA256, CLAIM_SALT_LABEL.as_bytes());
    derive_hkdf(url_key, claim_salt.as_ref(), HKDF_INFO_CLAIM, HKDF_LEN)
}

/// Compute claim_hash = base64url(SHA-256(claim_token)).
pub fn compute_claim_hash(claim_token: &[u8]) -> String {
    let hash = digest(&SHA256, claim_token);
    b64_encode(hash.as_ref())
}

fn validate_argon2id_params(
    version: u32,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    length: u32,
) -> Result<(), EnvelopeError> {
    if version != ARGON2_VERSION {
        return Err(EnvelopeError::InvalidEnvelope(format!(
            "kdf.version must be {}",
            ARGON2_VERSION
        )));
    }
    if !(ARGON2_M_COST_MIN..=ARGON2_M_COST_MAX).contains(&m_cost) {
        return Err(EnvelopeError::InvalidEnvelope(format!(
            "kdf.m_cost must be in range {}..={}",
            ARGON2_M_COST_MIN, ARGON2_M_COST_MAX
        )));
    }
    if !(ARGON2_T_COST_MIN..=ARGON2_T_COST_MAX).contains(&t_cost) {
        return Err(EnvelopeError::InvalidEnvelope(format!(
            "kdf.t_cost must be in range {}..={}",
            ARGON2_T_COST_MIN, ARGON2_T_COST_MAX
        )));
    }
    if !(ARGON2_P_COST_MIN..=ARGON2_P_COST_MAX).contains(&p_cost) {
        return Err(EnvelopeError::InvalidEnvelope(format!(
            "kdf.p_cost must be in range {}..={}",
            ARGON2_P_COST_MIN, ARGON2_P_COST_MAX
        )));
    }
    if (m_cost as u64) * (t_cost as u64) > ARGON2_M_COST_T_COST_PRODUCT_MAX {
        return Err(EnvelopeError::InvalidEnvelope(format!(
            "kdf.m_cost * kdf.t_cost must be <= {}",
            ARGON2_M_COST_T_COST_PRODUCT_MAX
        )));
    }
    if length != PASS_KEY_LEN as u32 {
        return Err(EnvelopeError::InvalidEnvelope(format!(
            "kdf.length must be {}",
            PASS_KEY_LEN
        )));
    }
    Ok(())
}

fn derive_argon2id(
    passphrase: &str,
    salt: &[u8],
    version: u32,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    length: usize,
) -> Result<Vec<u8>, EnvelopeError> {
    validate_argon2id_params(version, m_cost, t_cost, p_cost, length as u32)?;

    let params = Params::new(m_cost, t_cost, p_cost, Some(length)).map_err(|e| {
        EnvelopeError::InvalidEnvelope(format!("kdf parameters are invalid: {}", e))
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = vec![0u8; length];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| {
            EnvelopeError::InvalidEnvelope(format!("argon2id derivation failed: {}", e))
        })?;
    Ok(out)
}

fn ensure_kdf_none_has_no_extra_fields(raw: &serde_json::Value) -> Result<(), EnvelopeError> {
    let obj = raw
        .as_object()
        .ok_or_else(|| EnvelopeError::InvalidEnvelope("invalid kdf".into()))?;
    for forbidden in [
        "version",
        "salt",
        "m_cost",
        "t_cost",
        "p_cost",
        "length",
        "iterations",
    ] {
        if obj.contains_key(forbidden) {
            return Err(EnvelopeError::InvalidEnvelope(format!(
                "kdf.name=none must not include {}",
                forbidden
            )));
        }
    }
    Ok(())
}

/// Create an encrypted envelope from content bytes and metadata.
pub fn seal(p: SealParams<'_>) -> Result<SealResult, EnvelopeError> {
    if p.content.is_empty() {
        return Err(EnvelopeError::EmptyPlaintext);
    }

    // 1. Generate url_key
    let mut url_key = vec![0u8; URL_KEY_LEN];
    (p.rand_bytes)(&mut url_key)?;

    // 2. Build KDF + compute IKM
    let (ikm, kdf_json): (Vec<u8>, serde_json::Value) = if p.passphrase.is_empty() {
        let kdf = KdfNone {
            name: "none".into(),
        };
        (url_key.clone(), serde_json::to_value(kdf).unwrap())
    } else {
        let mut kdf_salt = vec![0u8; KDF_SALT_LEN];
        (p.rand_bytes)(&mut kdf_salt)?;
        let pass_key = derive_argon2id(
            &p.passphrase,
            &kdf_salt,
            ARGON2_VERSION,
            ARGON2_M_COST_DEFAULT,
            ARGON2_T_COST_DEFAULT,
            ARGON2_P_COST_DEFAULT,
            PASS_KEY_LEN,
        )?;

        // IKM = SHA-256(url_key || pass_key)
        let mut hasher_input = Vec::with_capacity(url_key.len() + pass_key.len());
        hasher_input.extend_from_slice(&url_key);
        hasher_input.extend_from_slice(&pass_key);
        let ikm_hash = digest(&SHA256, &hasher_input);
        let ikm = ikm_hash.as_ref().to_vec();

        let kdf = KdfArgon2id {
            name: "argon2id".into(),
            version: ARGON2_VERSION,
            salt: b64_encode(&kdf_salt),
            m_cost: ARGON2_M_COST_DEFAULT,
            t_cost: ARGON2_T_COST_DEFAULT,
            p_cost: ARGON2_P_COST_DEFAULT,
            length: PASS_KEY_LEN as u32,
        };
        (ikm, serde_json::to_value(kdf).unwrap())
    };

    // 3. Generate HKDF salt
    let mut hkdf_salt = vec![0u8; HKDF_SALT_LEN];
    (p.rand_bytes)(&mut hkdf_salt)?;

    // 4. Derive enc_key
    let enc_key = derive_hkdf(&ikm, &hkdf_salt, HKDF_INFO_ENC, HKDF_LEN)?;

    // 5. Derive claim_token (from url_key alone)
    let claim_token = derive_claim_token(&url_key)?;

    // 6. Generate nonce
    let mut nonce_bytes = vec![0u8; GCM_NONCE_LEN];
    (p.rand_bytes)(&mut nonce_bytes)?;

    // 7. Build encrypted payload frame
    let (payload_bytes, _codec) = encode_payload(&p.content, &p.metadata, p.compression_policy)?;

    // 8. Encrypt (AES-256-GCM)
    let unbound_key = UnboundKey::new(&AES_256_GCM, &enc_key)
        .map_err(|_| EnvelopeError::InvalidEnvelope("AES key creation failed".into()))?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| EnvelopeError::InvalidEnvelope("invalid nonce".into()))?;

    let mut in_out = payload_bytes;
    key.seal_in_place_append_tag(nonce, Aad::from(AAD), &mut in_out)
        .map_err(|_| EnvelopeError::InvalidEnvelope("encryption failed".into()))?;
    let ciphertext = in_out;

    // 9. Build envelope
    let env = Envelope {
        v: 1,
        suite: SUITE.into(),
        enc: EncBlock {
            alg: "A256GCM".into(),
            nonce: b64_encode(&nonce_bytes),
            ciphertext: b64_encode(&ciphertext),
        },
        kdf: kdf_json,
        hkdf: HkdfBlock {
            hash: "SHA-256".into(),
            salt: b64_encode(&hkdf_salt),
            enc_info: HKDF_INFO_ENC.into(),
            claim_info: HKDF_INFO_CLAIM.into(),
            length: HKDF_LEN as u32,
        },
    };

    let env_json = serde_json::to_value(&env)
        .map_err(|e| EnvelopeError::InvalidEnvelope(format!("marshal envelope: {}", e)))?;

    Ok(SealResult {
        envelope: env_json,
        url_key,
        claim_token: claim_token.clone(),
        claim_hash: compute_claim_hash(&claim_token),
    })
}

/// Check if an envelope requires a passphrase by inspecting the KDF name.
pub fn requires_passphrase(envelope: &serde_json::Value) -> bool {
    envelope
        .get("kdf")
        .and_then(|kdf| kdf.get("name"))
        .and_then(|n| n.as_str())
        .is_some_and(|name| name != "none")
}

/// Decrypt an envelope and decode the sealed payload frame.
pub fn open(p: OpenParams) -> Result<OpenResult, EnvelopeError> {
    if p.url_key.len() != URL_KEY_LEN {
        return Err(EnvelopeError::InvalidUrlKey);
    }

    if let Some(obj) = p.envelope.as_object() {
        for key in ["hint", "filename", "mime", "type"] {
            if obj.contains_key(key) {
                return Err(EnvelopeError::InvalidEnvelope(format!(
                    "plaintext metadata field '{}' is not allowed in envelope",
                    key
                )));
            }
        }
    }

    // Parse envelope
    let env: Envelope = serde_json::from_value(p.envelope)
        .map_err(|e| EnvelopeError::InvalidEnvelope(e.to_string()))?;

    validate_envelope(&env)?;

    // Parse KDF
    let kdf = parse_kdf(&env.kdf)?;

    // Compute IKM
    let ikm = if kdf.name == "none" {
        p.url_key.clone()
    } else {
        let pass_key = derive_argon2id(
            &p.passphrase,
            &kdf.salt,
            kdf.version,
            kdf.m_cost,
            kdf.t_cost,
            kdf.p_cost,
            PASS_KEY_LEN,
        )?;
        let mut hasher_input = Vec::with_capacity(p.url_key.len() + pass_key.len());
        hasher_input.extend_from_slice(&p.url_key);
        hasher_input.extend_from_slice(&pass_key);
        let ikm_hash = digest(&SHA256, &hasher_input);
        ikm_hash.as_ref().to_vec()
    };

    // Derive enc_key
    let hkdf_salt = b64_decode(&env.hkdf.salt)?;
    let enc_key = derive_hkdf(&ikm, &hkdf_salt, HKDF_INFO_ENC, HKDF_LEN)?;

    // Decode nonce and ciphertext
    let nonce_bytes = b64_decode(&env.enc.nonce)?;
    let mut ciphertext = b64_decode(&env.enc.ciphertext)?;

    // Decrypt
    let unbound_key = UnboundKey::new(&AES_256_GCM, &enc_key)
        .map_err(|_| EnvelopeError::InvalidEnvelope("AES key creation failed".into()))?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| EnvelopeError::InvalidEnvelope("invalid nonce".into()))?;

    let plaintext = key
        .open_in_place(nonce, Aad::from(AAD), &mut ciphertext)
        .map_err(|_| EnvelopeError::DecryptionFailed)?;

    decode_payload(plaintext, MAX_DECOMPRESSED_BYTES_DEFAULT)
}

fn validate_envelope(env: &Envelope) -> Result<(), EnvelopeError> {
    if env.v != 1 {
        return Err(EnvelopeError::InvalidEnvelope(format!(
            "unsupported version {}",
            env.v
        )));
    }
    if env.suite != SUITE {
        return Err(EnvelopeError::InvalidEnvelope(format!(
            "unsupported suite {:?}",
            env.suite
        )));
    }
    if env.enc.alg != "A256GCM" {
        return Err(EnvelopeError::InvalidEnvelope(format!(
            "unsupported enc.alg {:?}",
            env.enc.alg
        )));
    }

    let nonce = b64_decode(&env.enc.nonce)?;
    if nonce.len() != GCM_NONCE_LEN {
        return Err(EnvelopeError::InvalidEnvelope(format!(
            "nonce must be {} bytes",
            GCM_NONCE_LEN
        )));
    }

    let ct = b64_decode(&env.enc.ciphertext)?;
    if ct.len() < 16 {
        return Err(EnvelopeError::InvalidEnvelope(
            "ciphertext too short (need at least GCM tag)".into(),
        ));
    }

    if env.hkdf.hash != "SHA-256" {
        return Err(EnvelopeError::InvalidEnvelope(format!(
            "unsupported hkdf.hash {:?}",
            env.hkdf.hash
        )));
    }
    let hkdf_salt = b64_decode(&env.hkdf.salt)?;
    if hkdf_salt.len() != HKDF_SALT_LEN {
        return Err(EnvelopeError::InvalidEnvelope(format!(
            "hkdf.salt must be {} bytes",
            HKDF_SALT_LEN
        )));
    }
    if env.hkdf.enc_info != HKDF_INFO_ENC {
        return Err(EnvelopeError::InvalidEnvelope(
            "invalid hkdf.enc_info".into(),
        ));
    }
    if env.hkdf.claim_info != HKDF_INFO_CLAIM {
        return Err(EnvelopeError::InvalidEnvelope(
            "invalid hkdf.claim_info".into(),
        ));
    }
    if env.hkdf.length != HKDF_LEN as u32 {
        return Err(EnvelopeError::InvalidEnvelope(format!(
            "hkdf.length must be {}",
            HKDF_LEN
        )));
    }

    Ok(())
}

fn parse_kdf(raw: &serde_json::Value) -> Result<KdfParsed, EnvelopeError> {
    let name = raw
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| EnvelopeError::InvalidEnvelope("invalid kdf".into()))?;

    match name {
        "none" => {
            ensure_kdf_none_has_no_extra_fields(raw)?;
            Ok(KdfParsed {
                name: "none".into(),
                version: 0,
                salt: Vec::new(),
                m_cost: 0,
                t_cost: 0,
                p_cost: 0,
            })
        }
        "argon2id" => {
            let k: KdfArgon2id = serde_json::from_value(raw.clone())
                .map_err(|_| EnvelopeError::InvalidEnvelope("invalid kdf".into()))?;
            let salt = b64_decode(&k.salt)?;
            if salt.len() < KDF_SALT_LEN {
                return Err(EnvelopeError::InvalidEnvelope(format!(
                    "kdf.salt must be at least {} bytes",
                    KDF_SALT_LEN
                )));
            }
            validate_argon2id_params(k.version, k.m_cost, k.t_cost, k.p_cost, k.length)?;
            Ok(KdfParsed {
                name: "argon2id".into(),
                version: k.version,
                salt,
                m_cost: k.m_cost,
                t_cost: k.t_cost,
                p_cost: k.p_cost,
            })
        }
        _ => Err(EnvelopeError::InvalidEnvelope(format!(
            "unsupported kdf.name {:?}",
            name
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real_rand(buf: &mut [u8]) -> Result<(), EnvelopeError> {
        use ring::rand::{SecureRandom, SystemRandom};
        SystemRandom::new()
            .fill(buf)
            .map_err(|_| EnvelopeError::RngError("SystemRandom failed".into()))
    }

    /// Helper: seal a valid envelope with no passphrase
    fn seal_valid() -> (SealResult, Vec<u8>) {
        let plaintext = b"test data".to_vec();
        let result = seal(SealParams {
            content: plaintext.clone(),
            passphrase: String::new(),
            rand_bytes: &real_rand,
            metadata: PayloadMeta::text(),
            compression_policy: CompressionPolicy::default(),
        })
        .unwrap();
        (result, plaintext)
    }

    /// Helper: modify a JSON field in a sealed envelope
    fn mutate_envelope(
        env: &serde_json::Value,
        path: &[&str],
        value: serde_json::Value,
    ) -> serde_json::Value {
        let mut e = env.clone();
        let mut target = &mut e;
        for &key in &path[..path.len() - 1] {
            target = target.get_mut(key).unwrap();
        }
        target[path[path.len() - 1]] = value;
        e
    }

    #[test]
    fn seal_empty_plaintext() {
        let err = seal(SealParams {
            content: Vec::new(),
            passphrase: String::new(),
            rand_bytes: &real_rand,
            metadata: PayloadMeta::text(),
            compression_policy: CompressionPolicy::default(),
        });
        assert!(matches!(err, Err(EnvelopeError::EmptyPlaintext)));
    }

    #[test]
    fn seal_rng_failure_url_key() {
        let fail_rand = |_buf: &mut [u8]| -> Result<(), EnvelopeError> {
            Err(EnvelopeError::RngError("fail".into()))
        };
        let err = seal(SealParams {
            content: b"x".to_vec(),
            passphrase: String::new(),
            rand_bytes: &fail_rand,
            metadata: PayloadMeta::text(),
            compression_policy: CompressionPolicy::default(),
        });
        assert!(matches!(err, Err(EnvelopeError::RngError(_))));
    }

    #[test]
    fn seal_rng_failure_kdf_salt() {
        let call = std::cell::Cell::new(0);
        let fail_on_second = |buf: &mut [u8]| -> Result<(), EnvelopeError> {
            let n = call.get();
            call.set(n + 1);
            if n == 1 {
                return Err(EnvelopeError::RngError("fail kdf salt".into()));
            }
            real_rand(buf)
        };
        let err = seal(SealParams {
            content: b"x".to_vec(),
            passphrase: "pass".into(),
            rand_bytes: &fail_on_second,
            metadata: PayloadMeta::text(),
            compression_policy: CompressionPolicy::default(),
        });
        assert!(matches!(err, Err(EnvelopeError::RngError(_))));
    }

    #[test]
    fn seal_rng_failure_hkdf_salt() {
        // Without passphrase: url_key(call 0), hkdf_salt(call 1)
        let call = std::cell::Cell::new(0);
        let fail_on_second = |buf: &mut [u8]| -> Result<(), EnvelopeError> {
            let n = call.get();
            call.set(n + 1);
            if n == 1 {
                return Err(EnvelopeError::RngError("fail hkdf salt".into()));
            }
            real_rand(buf)
        };
        let err = seal(SealParams {
            content: b"x".to_vec(),
            passphrase: String::new(),
            rand_bytes: &fail_on_second,
            metadata: PayloadMeta::text(),
            compression_policy: CompressionPolicy::default(),
        });
        assert!(matches!(err, Err(EnvelopeError::RngError(_))));
    }

    #[test]
    fn seal_rng_failure_nonce() {
        // Without passphrase: url_key(0), hkdf_salt(1), nonce(2)
        let call = std::cell::Cell::new(0);
        let fail_on_third = |buf: &mut [u8]| -> Result<(), EnvelopeError> {
            let n = call.get();
            call.set(n + 1);
            if n == 2 {
                return Err(EnvelopeError::RngError("fail nonce".into()));
            }
            real_rand(buf)
        };
        let err = seal(SealParams {
            content: b"x".to_vec(),
            passphrase: String::new(),
            rand_bytes: &fail_on_third,
            metadata: PayloadMeta::text(),
            compression_policy: CompressionPolicy::default(),
        });
        assert!(matches!(err, Err(EnvelopeError::RngError(_))));
    }

    #[test]
    fn seal_passphrase_uses_argon2id_defaults() {
        let result = seal(SealParams {
            content: b"secret".to_vec(),
            passphrase: "passphrase".into(),
            rand_bytes: &real_rand,
            metadata: PayloadMeta::text(),
            compression_policy: CompressionPolicy::default(),
        })
        .expect("seal should succeed with passphrase");
        assert_eq!(result.envelope["kdf"]["name"].as_str(), Some("argon2id"));
        assert_eq!(
            result.envelope["kdf"]["version"].as_u64(),
            Some(ARGON2_VERSION as u64)
        );
        assert_eq!(
            result.envelope["kdf"]["m_cost"].as_u64(),
            Some(ARGON2_M_COST_DEFAULT as u64)
        );
        assert_eq!(
            result.envelope["kdf"]["t_cost"].as_u64(),
            Some(ARGON2_T_COST_DEFAULT as u64)
        );
        assert_eq!(
            result.envelope["kdf"]["p_cost"].as_u64(),
            Some(ARGON2_P_COST_DEFAULT as u64)
        );
    }

    #[test]
    fn open_wrong_url_key_length() {
        let (result, _) = seal_valid();
        let err = open(OpenParams {
            envelope: result.envelope,
            url_key: vec![0u8; 16],
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidUrlKey)));
    }

    #[test]
    fn open_bad_json() {
        let err = open(OpenParams {
            envelope: serde_json::json!("not an object"),
            url_key: vec![0u8; 32],
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_wrong_version() {
        let (result, _) = seal_valid();
        let env = mutate_envelope(&result.envelope, &["v"], serde_json::json!(2));
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_wrong_suite() {
        let (result, _) = seal_valid();
        let env = mutate_envelope(&result.envelope, &["suite"], serde_json::json!("v2-bad"));
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_wrong_enc_alg() {
        let (result, _) = seal_valid();
        let env = mutate_envelope(
            &result.envelope,
            &["enc", "alg"],
            serde_json::json!("ChaCha20"),
        );
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_bad_nonce_length() {
        let (result, _) = seal_valid();
        // A 16-byte nonce instead of 12
        let bad_nonce = b64_encode(&[0u8; 16]);
        let env = mutate_envelope(
            &result.envelope,
            &["enc", "nonce"],
            serde_json::json!(bad_nonce),
        );
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_ciphertext_too_short() {
        let (result, _) = seal_valid();
        let short_ct = b64_encode(&[0u8; 8]);
        let env = mutate_envelope(
            &result.envelope,
            &["enc", "ciphertext"],
            serde_json::json!(short_ct),
        );
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_wrong_hkdf_hash() {
        let (result, _) = seal_valid();
        let env = mutate_envelope(
            &result.envelope,
            &["hkdf", "hash"],
            serde_json::json!("SHA-512"),
        );
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_wrong_hkdf_salt_length() {
        let (result, _) = seal_valid();
        let bad_salt = b64_encode(&[0u8; 16]);
        let env = mutate_envelope(
            &result.envelope,
            &["hkdf", "salt"],
            serde_json::json!(bad_salt),
        );
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_wrong_hkdf_enc_info() {
        let (result, _) = seal_valid();
        let env = mutate_envelope(
            &result.envelope,
            &["hkdf", "enc_info"],
            serde_json::json!("wrong"),
        );
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_wrong_hkdf_claim_info() {
        let (result, _) = seal_valid();
        let env = mutate_envelope(
            &result.envelope,
            &["hkdf", "claim_info"],
            serde_json::json!("wrong"),
        );
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_wrong_hkdf_length() {
        let (result, _) = seal_valid();
        let env = mutate_envelope(&result.envelope, &["hkdf", "length"], serde_json::json!(64));
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_kdf_missing_name() {
        let (result, _) = seal_valid();
        let env = mutate_envelope(&result.envelope, &["kdf"], serde_json::json!({}));
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_kdf_unknown_name() {
        let (result, _) = seal_valid();
        let env = mutate_envelope(
            &result.envelope,
            &["kdf"],
            serde_json::json!({"name": "argon2"}),
        );
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_kdf_none_rejects_extra_salt_field() {
        let (result, _) = seal_valid();
        let env = mutate_envelope(
            &result.envelope,
            &["kdf"],
            serde_json::json!({
                "name": "none",
                "salt": "AAAA"
            }),
        );
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_kdf_none_rejects_extra_iterations_field() {
        let (result, _) = seal_valid();
        let env = mutate_envelope(
            &result.envelope,
            &["kdf"],
            serde_json::json!({
                "name": "none",
                "iterations": 600000
            }),
        );
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_kdf_argon2id_short_salt() {
        let (result, _) = seal_valid();
        let short_salt = b64_encode(&[0u8; 8]);
        let env = mutate_envelope(
            &result.envelope,
            &["kdf"],
            serde_json::json!({
                "name": "argon2id",
                "version": ARGON2_VERSION,
                "salt": short_salt,
                "m_cost": ARGON2_M_COST_DEFAULT,
                "t_cost": ARGON2_T_COST_DEFAULT,
                "p_cost": ARGON2_P_COST_DEFAULT,
                "length": 32
            }),
        );
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: "test".into(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_kdf_argon2id_wrong_version() {
        let (result, _) = seal_valid();
        let salt = b64_encode(&[0u8; 16]);
        let env = mutate_envelope(
            &result.envelope,
            &["kdf"],
            serde_json::json!({
                "name": "argon2id",
                "version": 16,
                "salt": salt,
                "m_cost": ARGON2_M_COST_DEFAULT,
                "t_cost": ARGON2_T_COST_DEFAULT,
                "p_cost": ARGON2_P_COST_DEFAULT,
                "length": 32
            }),
        );
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: "test".into(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_kdf_argon2id_out_of_range_costs() {
        let (result, _) = seal_valid();
        let salt = b64_encode(&[0u8; 16]);
        for kdf in [
            serde_json::json!({
                "name": "argon2id",
                "version": ARGON2_VERSION,
                "salt": salt,
                "m_cost": ARGON2_M_COST_MIN - 1,
                "t_cost": ARGON2_T_COST_DEFAULT,
                "p_cost": ARGON2_P_COST_DEFAULT,
                "length": 32
            }),
            serde_json::json!({
                "name": "argon2id",
                "version": ARGON2_VERSION,
                "salt": salt,
                "m_cost": ARGON2_M_COST_MAX + 1,
                "t_cost": ARGON2_T_COST_DEFAULT,
                "p_cost": ARGON2_P_COST_DEFAULT,
                "length": 32
            }),
            serde_json::json!({
                "name": "argon2id",
                "version": ARGON2_VERSION,
                "salt": salt,
                "m_cost": ARGON2_M_COST_DEFAULT,
                "t_cost": ARGON2_T_COST_MIN - 1,
                "p_cost": ARGON2_P_COST_DEFAULT,
                "length": 32
            }),
            serde_json::json!({
                "name": "argon2id",
                "version": ARGON2_VERSION,
                "salt": salt,
                "m_cost": ARGON2_M_COST_DEFAULT,
                "t_cost": ARGON2_T_COST_MAX + 1,
                "p_cost": ARGON2_P_COST_DEFAULT,
                "length": 32
            }),
            serde_json::json!({
                "name": "argon2id",
                "version": ARGON2_VERSION,
                "salt": salt,
                "m_cost": ARGON2_M_COST_DEFAULT,
                "t_cost": ARGON2_T_COST_DEFAULT,
                "p_cost": ARGON2_P_COST_MIN - 1,
                "length": 32
            }),
            serde_json::json!({
                "name": "argon2id",
                "version": ARGON2_VERSION,
                "salt": salt,
                "m_cost": ARGON2_M_COST_DEFAULT,
                "t_cost": ARGON2_T_COST_DEFAULT,
                "p_cost": ARGON2_P_COST_MAX + 1,
                "length": 32
            }),
            serde_json::json!({
                "name": "argon2id",
                "version": ARGON2_VERSION,
                "salt": salt,
                "m_cost": ARGON2_M_COST_MAX,
                "t_cost": ARGON2_T_COST_MAX,
                "p_cost": ARGON2_P_COST_DEFAULT,
                "length": 32
            }),
            serde_json::json!({
                "name": "argon2id",
                "version": ARGON2_VERSION,
                "salt": salt,
                "m_cost": ARGON2_M_COST_DEFAULT,
                "t_cost": ARGON2_T_COST_DEFAULT,
                "p_cost": ARGON2_P_COST_DEFAULT,
                "length": 64
            }),
        ] {
            let env = mutate_envelope(&result.envelope, &["kdf"], kdf);
            let err = open(OpenParams {
                envelope: env,
                url_key: result.url_key.clone(),
                passphrase: "test".into(),
            });
            assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
        }
    }

    #[test]
    fn derive_claim_token_wrong_length() {
        let err = derive_claim_token(&[0u8; 16]);
        assert!(matches!(err, Err(EnvelopeError::InvalidUrlKey)));
    }

    #[test]
    fn b64_decode_invalid() {
        let err = b64_decode("!!!invalid!!!");
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_decryption_fails_with_wrong_key() {
        let (result, _) = seal_valid();
        let mut bad_key = result.url_key.clone();
        bad_key[0] ^= 0xFF;
        let err = open(OpenParams {
            envelope: result.envelope,
            url_key: bad_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::DecryptionFailed)));
    }

    #[test]
    fn sealed_envelope_has_no_plaintext_metadata() {
        let result = seal(SealParams {
            content: b"with hint".to_vec(),
            metadata: PayloadMeta::file("credentials.txt".into(), "text/plain".into()),
            passphrase: String::new(),
            rand_bytes: &real_rand,
            compression_policy: CompressionPolicy::default(),
        })
        .unwrap();
        assert!(result.envelope.get("hint").is_none());
        assert!(result.envelope.get("filename").is_none());
        assert!(result.envelope.get("mime").is_none());
        assert!(result.envelope.get("type").is_none());
    }

    #[test]
    fn open_rejects_plaintext_hint_field() {
        let result = seal(SealParams {
            content: b"with hint".to_vec(),
            metadata: PayloadMeta::text(),
            passphrase: String::new(),
            rand_bytes: &real_rand,
            compression_policy: CompressionPolicy::default(),
        })
        .unwrap();
        let env = mutate_envelope(
            &result.envelope,
            &["hint"],
            serde_json::json!({"type":"file","filename":"x.txt"}),
        );
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: String::new(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn open_returns_metadata_and_content() {
        let meta = PayloadMeta::file("credentials.txt".into(), "text/plain".into());
        let result = seal(SealParams {
            content: b"payload body".to_vec(),
            metadata: meta.clone(),
            passphrase: String::new(),
            rand_bytes: &real_rand,
            compression_policy: CompressionPolicy::default(),
        })
        .unwrap();
        let opened = open(OpenParams {
            envelope: result.envelope,
            url_key: result.url_key,
            passphrase: String::new(),
        })
        .unwrap();
        assert_eq!(opened.content, b"payload body");
        assert_eq!(opened.metadata, meta);
    }

    #[test]
    fn error_display_coverage() {
        // Exercise Display impl for all error variants
        let _ = format!("{}", EnvelopeError::EmptyPlaintext);
        let _ = format!("{}", EnvelopeError::InvalidEnvelope("x".into()));
        let _ = format!("{}", EnvelopeError::DecryptionFailed);
        let _ = format!("{}", EnvelopeError::InvalidFrame("x".into()));
        let _ = format!("{}", EnvelopeError::UnsupportedCodec(9));
        let _ = format!(
            "{}",
            EnvelopeError::DecompressedTooLarge {
                max: 1,
                requested: 2
            }
        );
        let _ = format!("{}", EnvelopeError::FrameLengthMismatch("x".into()));
        let _ = format!("{}", EnvelopeError::CompressionFailed("x".into()));
        let _ = format!("{}", EnvelopeError::DecompressionFailed("x".into()));
        let _ = format!("{}", EnvelopeError::InvalidFragment("x".into()));
        let _ = format!("{}", EnvelopeError::InvalidUrlKey);
        let _ = format!("{}", EnvelopeError::InvalidTtl("x".into()));
        let _ = format!("{}", EnvelopeError::RngError("x".into()));
    }

    #[test]
    fn requires_passphrase_none() {
        let env = serde_json::json!({"kdf": {"name": "none"}});
        assert!(!requires_passphrase(&env));
    }

    #[test]
    fn requires_passphrase_argon2id() {
        let env = serde_json::json!({"kdf": {"name": "argon2id"}});
        assert!(requires_passphrase(&env));
    }

    #[test]
    fn requires_passphrase_missing_kdf() {
        let env = serde_json::json!({});
        assert!(!requires_passphrase(&env));
    }

    #[test]
    fn requires_passphrase_sealed_envelope() {
        // Test with a real sealed envelope (no passphrase)
        let (result, _) = seal_valid();
        assert!(!requires_passphrase(&result.envelope));
    }

    #[test]
    fn open_kdf_argon2id_missing_fields() {
        // Argon2id with name only (missing required fields)
        let (result, _) = seal_valid();
        let env = mutate_envelope(
            &result.envelope,
            &["kdf"],
            serde_json::json!({"name": "argon2id"}),
        );
        let err = open(OpenParams {
            envelope: env,
            url_key: result.url_key,
            passphrase: "test".into(),
        });
        assert!(matches!(err, Err(EnvelopeError::InvalidEnvelope(_))));
    }

    #[test]
    fn requires_passphrase_sealed_with_passphrase() {
        // Test with a real sealed envelope (with passphrase)
        let result = seal(SealParams {
            content: b"secret".to_vec(),
            passphrase: "test".to_string(),
            rand_bytes: &real_rand,
            metadata: PayloadMeta::text(),
            compression_policy: CompressionPolicy::default(),
        })
        .unwrap();
        assert!(requires_passphrase(&result.envelope));
    }
}
