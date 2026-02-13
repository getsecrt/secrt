use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::hkdf;
use ring::pbkdf2;

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

        let iterations = if p.iterations == 0 {
            DEFAULT_PBKDF2_ITERATIONS
        } else {
            p.iterations
        };

        let mut pass_key = vec![0u8; PASS_KEY_LEN];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(iterations).unwrap(),
            &kdf_salt,
            p.passphrase.as_bytes(),
            &mut pass_key,
        );

        // IKM = SHA-256(url_key || pass_key)
        let mut hasher_input = Vec::with_capacity(url_key.len() + pass_key.len());
        hasher_input.extend_from_slice(&url_key);
        hasher_input.extend_from_slice(&pass_key);
        let ikm_hash = digest(&SHA256, &hasher_input);
        let ikm = ikm_hash.as_ref().to_vec();

        let kdf = KdfPbkdf2 {
            name: "PBKDF2-SHA256".into(),
            salt: b64_encode(&kdf_salt),
            iterations,
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
        let mut pass_key = vec![0u8; PASS_KEY_LEN];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(kdf.iterations).unwrap(),
            &kdf.salt,
            p.passphrase.as_bytes(),
            &mut pass_key,
        );
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
        "none" => Ok(KdfParsed {
            name: "none".into(),
            salt: Vec::new(),
            iterations: 0,
        }),
        "PBKDF2-SHA256" => {
            let k: KdfPbkdf2 = serde_json::from_value(raw.clone())
                .map_err(|_| EnvelopeError::InvalidEnvelope("invalid kdf".into()))?;
            let salt = b64_decode(&k.salt)?;
            if salt.len() < KDF_SALT_LEN {
                return Err(EnvelopeError::InvalidEnvelope(format!(
                    "kdf.salt must be at least {} bytes",
                    KDF_SALT_LEN
                )));
            }
            if k.iterations < MIN_PBKDF2_ITERATIONS {
                return Err(EnvelopeError::InvalidEnvelope(format!(
                    "kdf.iterations must be >= {}",
                    MIN_PBKDF2_ITERATIONS
                )));
            }
            if k.length != PASS_KEY_LEN as u32 {
                return Err(EnvelopeError::InvalidEnvelope(format!(
                    "kdf.length must be {}",
                    PASS_KEY_LEN
                )));
            }
            Ok(KdfParsed {
                name: "PBKDF2-SHA256".into(),
                salt,
                iterations: k.iterations,
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
            iterations: 0,
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
            iterations: 0,
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
            iterations: 0,
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
            iterations: 300_000,
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
            iterations: 0,
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
            iterations: 0,
        });
        assert!(matches!(err, Err(EnvelopeError::RngError(_))));
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
    fn open_kdf_pbkdf2_short_salt() {
        let (result, _) = seal_valid();
        let short_salt = b64_encode(&[0u8; 8]);
        let env = mutate_envelope(
            &result.envelope,
            &["kdf"],
            serde_json::json!({
                "name": "PBKDF2-SHA256",
                "salt": short_salt,
                "iterations": 600000,
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
    fn open_kdf_pbkdf2_low_iterations() {
        let (result, _) = seal_valid();
        let salt = b64_encode(&[0u8; 16]);
        let env = mutate_envelope(
            &result.envelope,
            &["kdf"],
            serde_json::json!({
                "name": "PBKDF2-SHA256",
                "salt": salt,
                "iterations": 100,
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
    fn open_kdf_pbkdf2_wrong_length() {
        let (result, _) = seal_valid();
        let salt = b64_encode(&[0u8; 16]);
        let env = mutate_envelope(
            &result.envelope,
            &["kdf"],
            serde_json::json!({
                "name": "PBKDF2-SHA256",
                "salt": salt,
                "iterations": 600000,
                "length": 64
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
            iterations: 0,
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
            iterations: 0,
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
            iterations: 0,
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
    fn requires_passphrase_pbkdf2() {
        let env = serde_json::json!({"kdf": {"name": "PBKDF2-SHA256"}});
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
    fn open_kdf_pbkdf2_missing_fields() {
        // PBKDF2-SHA256 with name only (missing salt, iterations, length)
        let (result, _) = seal_valid();
        let env = mutate_envelope(
            &result.envelope,
            &["kdf"],
            serde_json::json!({"name": "PBKDF2-SHA256"}),
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
            iterations: 300_000,
        })
        .unwrap();
        assert!(requires_passphrase(&result.envelope));
    }
}
