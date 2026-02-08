use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::hkdf;
use ring::pbkdf2;

use crate::envelope::types::*;

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
/// claim_token = HKDF-SHA-256(url_key, empty_salt, "secret:v1:claim", 32)
pub fn derive_claim_token(url_key: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if url_key.len() != URL_KEY_LEN {
        return Err(EnvelopeError::InvalidUrlKey);
    }
    // Go's HKDF with nil salt uses an all-zero salt of hash length (32 bytes for SHA-256)
    let empty_salt = [0u8; 32];
    derive_hkdf(url_key, &empty_salt, HKDF_INFO_CLAIM, HKDF_LEN)
}

/// Compute claim_hash = base64url(SHA-256(claim_token)).
pub fn compute_claim_hash(claim_token: &[u8]) -> String {
    let hash = digest(&SHA256, claim_token);
    b64_encode(hash.as_ref())
}

/// Create an encrypted envelope from plaintext.
pub fn seal(p: SealParams<'_>) -> Result<SealResult, EnvelopeError> {
    if p.plaintext.is_empty() {
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

    // 7. Encrypt (AES-256-GCM)
    let unbound_key = UnboundKey::new(&AES_256_GCM, &enc_key)
        .map_err(|_| EnvelopeError::InvalidEnvelope("AES key creation failed".into()))?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| EnvelopeError::InvalidEnvelope("invalid nonce".into()))?;

    let mut in_out = p.plaintext.clone();
    key.seal_in_place_append_tag(nonce, Aad::from(AAD), &mut in_out)
        .map_err(|_| EnvelopeError::InvalidEnvelope("encryption failed".into()))?;
    let ciphertext = in_out;

    // 8. Build envelope
    let hint = p.hint.filter(|h| !h.is_empty());

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
        hint,
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

/// Decrypt an envelope, returning plaintext.
pub fn open(p: OpenParams) -> Result<Vec<u8>, EnvelopeError> {
    if p.url_key.len() != URL_KEY_LEN {
        return Err(EnvelopeError::InvalidUrlKey);
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

    Ok(plaintext.to_vec())
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
