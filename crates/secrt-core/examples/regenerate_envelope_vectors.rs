use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::digest::{digest, SHA256};
use ring::hkdf;
use secrt_core::{
    seal, CompressionPolicy, EnvelopeError, PayloadMeta, SealParams, ARGON2_VERSION, HKDF_INFO_ENC,
    HKDF_LEN, PASS_KEY_LEN,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cell::Cell;
use std::fs;

#[derive(Serialize, Deserialize)]
struct VectorFile {
    #[serde(rename = "_description")]
    description: String,
    #[serde(rename = "_spec")]
    spec: String,
    aad: String,
    hkdf_info_enc: String,
    hkdf_info_claim: String,
    claim_salt_label: String,
    vectors: Vec<Vector>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Vector {
    description: String,
    url_key: String,
    plaintext: String,
    #[serde(default)]
    plaintext_utf8: Option<String>,
    passphrase: Option<String>,
    metadata: PayloadMeta,
    codec: String,
    ikm: String,
    enc_key: String,
    claim_token: String,
    claim_hash: String,
    envelope: Value,
}

struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn b64_decode(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(URL_SAFE_NO_PAD.decode(s)?)
}

fn b64_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn derive_hkdf(
    ikm: &[u8],
    salt: &[u8],
    info: &str,
    length: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt.extract(ikm);
    let info_slice = &[info.as_bytes()];
    let okm = prk
        .expand(info_slice, HkdfLen(length))
        .map_err(|_| "hkdf expand failed")?;
    let mut out = vec![0u8; length];
    okm.fill(&mut out).map_err(|_| "hkdf fill failed")?;
    Ok(out)
}

fn derive_argon2id(
    passphrase: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    length: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(length))
        .map_err(|e| format!("invalid argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; length];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| format!("argon2 derivation failed: {}", e))?;
    Ok(out)
}

fn derive_ikm(
    url_key: &[u8],
    passphrase: Option<&str>,
    envelope: &Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(passphrase) = passphrase {
        let kdf = envelope
            .get("kdf")
            .and_then(Value::as_object)
            .ok_or("missing kdf block")?;
        let version = kdf
            .get("version")
            .and_then(Value::as_u64)
            .ok_or("missing kdf.version")? as u32;
        if version != ARGON2_VERSION {
            return Err(format!("unexpected argon2 version {}", version).into());
        }
        let m_cost = kdf
            .get("m_cost")
            .and_then(Value::as_u64)
            .ok_or("missing kdf.m_cost")? as u32;
        let t_cost = kdf
            .get("t_cost")
            .and_then(Value::as_u64)
            .ok_or("missing kdf.t_cost")? as u32;
        let p_cost = kdf
            .get("p_cost")
            .and_then(Value::as_u64)
            .ok_or("missing kdf.p_cost")? as u32;
        let salt = b64_decode(
            kdf.get("salt")
                .and_then(Value::as_str)
                .ok_or("missing kdf.salt")?,
        )?;

        let pass_key = derive_argon2id(passphrase, &salt, m_cost, t_cost, p_cost, PASS_KEY_LEN)?;
        let mut ikm_input = Vec::with_capacity(url_key.len() + pass_key.len());
        ikm_input.extend_from_slice(url_key);
        ikm_input.extend_from_slice(&pass_key);
        Ok(digest(&SHA256, &ikm_input).as_ref().to_vec())
    } else {
        Ok(url_key.to_vec())
    }
}

fn deterministic_rng<'a>(bytes: &'a [u8]) -> impl Fn(&mut [u8]) -> Result<(), EnvelopeError> + 'a {
    let cursor = Cell::new(0usize);
    move |buf: &mut [u8]| {
        let start = cursor.get();
        let end = start.saturating_add(buf.len());
        if end > bytes.len() {
            return Err(EnvelopeError::RngError(
                "deterministic rng exhausted".to_string(),
            ));
        }
        buf.copy_from_slice(&bytes[start..end]);
        cursor.set(end);
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input_path = "spec/v1/envelope.vectors.json";
    let output_path = "spec/v1/envelope.vectors.json";
    let raw = fs::read_to_string(input_path)?;
    let source: VectorFile = serde_json::from_str(&raw)?;

    let mut vectors_out = Vec::with_capacity(source.vectors.len());
    for vector in source.vectors {
        let url_key = b64_decode(&vector.url_key)?;
        let plaintext = b64_decode(&vector.plaintext)?;
        let passphrase = vector.passphrase.clone().unwrap_or_default();

        let mut rng_stream = Vec::new();
        rng_stream.extend_from_slice(&url_key);

        if !passphrase.is_empty() {
            let kdf_salt = vector
                .envelope
                .get("kdf")
                .and_then(|k| k.get("salt"))
                .and_then(Value::as_str)
                .ok_or("missing vector kdf.salt")?;
            rng_stream.extend_from_slice(&b64_decode(kdf_salt)?);
        }

        let hkdf_salt = vector
            .envelope
            .get("hkdf")
            .and_then(|h| h.get("salt"))
            .and_then(Value::as_str)
            .ok_or("missing vector hkdf.salt")?;
        rng_stream.extend_from_slice(&b64_decode(hkdf_salt)?);

        let nonce = vector
            .envelope
            .get("enc")
            .and_then(|e| e.get("nonce"))
            .and_then(Value::as_str)
            .ok_or("missing vector enc.nonce")?;
        rng_stream.extend_from_slice(&b64_decode(nonce)?);

        let rand_bytes = deterministic_rng(&rng_stream);
        let sealed = seal(SealParams {
            content: plaintext,
            metadata: vector.metadata.clone(),
            passphrase: passphrase.clone(),
            rand_bytes: &rand_bytes,
            compression_policy: CompressionPolicy::default(),
        })?;

        let ikm = derive_ikm(
            &url_key,
            if passphrase.is_empty() {
                None
            } else {
                Some(passphrase.as_str())
            },
            &sealed.envelope,
        )?;
        let hkdf_salt = sealed
            .envelope
            .get("hkdf")
            .and_then(|h| h.get("salt"))
            .and_then(Value::as_str)
            .ok_or("missing sealed hkdf.salt")?;
        let enc_key = derive_hkdf(&ikm, &b64_decode(hkdf_salt)?, HKDF_INFO_ENC, HKDF_LEN)?;

        vectors_out.push(Vector {
            description: vector.description,
            url_key: vector.url_key,
            plaintext: vector.plaintext,
            plaintext_utf8: vector.plaintext_utf8,
            passphrase: vector.passphrase,
            metadata: vector.metadata,
            codec: vector.codec,
            ikm: b64_encode(&ikm),
            enc_key: b64_encode(&enc_key),
            claim_token: b64_encode(&sealed.claim_token),
            claim_hash: sealed.claim_hash,
            envelope: sealed.envelope,
        });
    }

    let output = VectorFile {
        description: source.description,
        spec: source.spec,
        aad: source.aad,
        hkdf_info_enc: source.hkdf_info_enc,
        hkdf_info_claim: source.hkdf_info_claim,
        claim_salt_label: source.claim_salt_label,
        vectors: vectors_out,
    };

    let json = serde_json::to_string_pretty(&output)?;
    fs::write(output_path, format!("{}\n", json))?;
    println!("updated {}", output_path);

    let fixture_path = "crates/secrt-cli/tests/fixtures/envelope.vectors.json";
    fs::write(fixture_path, format!("{}\n", json))?;
    println!("updated {}", fixture_path);

    Ok(())
}
