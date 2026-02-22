use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use secrt_app::{derive_claim_token_inner, open_secret_inner, seal_secret_inner};
use secrt_core::EnvelopeError;
use serde::Deserialize;

#[allow(dead_code)]
#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct VectorMetadata {
    #[serde(rename = "type")]
    payload_type: String,
    filename: Option<String>,
    mime: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct Vector {
    description: String,
    url_key: String,
    plaintext: String,
    #[serde(default)]
    plaintext_utf8: Option<String>,
    passphrase: Option<String>,
    metadata: VectorMetadata,
    #[serde(default)]
    codec: Option<String>,
    ikm: String,
    enc_key: String,
    claim_token: String,
    claim_hash: String,
    envelope: serde_json::Value,
}

fn load_vectors() -> VectorFile {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/v1/envelope.vectors.json"
    );
    let data = std::fs::read_to_string(path).expect("failed to read envelope.vectors.json");
    serde_json::from_str(&data).expect("failed to parse envelope.vectors.json")
}

fn b64_decode(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("b64 decode")
}

/// Test open_secret_inner decrypts all 5 vectors correctly.
///
/// Verifies: base64url decode of url_key, secrt_core::open(), base64url encode
/// of plaintext, and correct payload_type/filename/mime mapping.
#[test]
fn test_open_all_vectors() {
    let vf = load_vectors();
    for v in &vf.vectors {
        let result = open_secret_inner(v.envelope.clone(), &v.url_key, v.passphrase.clone())
            .unwrap_or_else(|e| panic!("open failed for {:?}: {}", v.description, e));

        assert_eq!(
            result.content, v.plaintext,
            "plaintext mismatch for {:?}",
            v.description
        );
        assert_eq!(
            result.payload_type, v.metadata.payload_type,
            "payload_type mismatch for {:?}",
            v.description
        );
        assert_eq!(
            result.filename, v.metadata.filename,
            "filename mismatch for {:?}",
            v.description
        );
        assert_eq!(
            result.mime, v.metadata.mime,
            "mime mismatch for {:?}",
            v.description
        );

        // Also verify plaintext_utf8 if present
        if let Some(ref utf8) = v.plaintext_utf8 {
            let decoded = b64_decode(&result.content);
            assert_eq!(
                std::str::from_utf8(&decoded).unwrap(),
                utf8.as_str(),
                "plaintext_utf8 mismatch for {:?}",
                v.description
            );
        }
    }
}

/// Test derive_claim_token_inner for all vectors.
///
/// Verifies: base64url decode of url_key, secrt_core::derive_claim_token(),
/// base64url encode of result.
#[test]
fn test_derive_claim_token_all_vectors() {
    let vf = load_vectors();
    for v in &vf.vectors {
        let token = derive_claim_token_inner(&v.url_key)
            .unwrap_or_else(|e| panic!("derive failed for {:?}: {}", v.description, e));

        assert_eq!(
            token, v.claim_token,
            "claim_token mismatch for {:?}",
            v.description
        );
    }
}

/// Test seal_secret_inner with deterministic RNG produces matching envelopes.
///
/// This is the most important test: it verifies the full Tauri command path
/// (base64 decode content → build PayloadMeta from type/filename/mime strings
/// → seal → base64 encode url_key and claim_hash) produces byte-identical
/// output to the spec vectors.
#[test]
fn test_seal_all_vectors() {
    let vf = load_vectors();
    for v in &vf.vectors {
        let url_key_bytes = b64_decode(&v.url_key);
        let passphrase = v.passphrase.clone();

        // Build the deterministic random byte sequence matching the spec.
        // Order: url_key(32) || [kdf_salt(16) if passphrase] || hkdf_salt(32) || nonce(12)
        let mut rand_data = Vec::new();
        rand_data.extend_from_slice(&url_key_bytes);
        if !passphrase.as_deref().unwrap_or("").is_empty() {
            let kdf_salt_b64 = v.envelope["kdf"]["salt"].as_str().unwrap();
            rand_data.extend_from_slice(&b64_decode(kdf_salt_b64));
        }
        let hkdf_salt_b64 = v.envelope["hkdf"]["salt"].as_str().unwrap();
        rand_data.extend_from_slice(&b64_decode(hkdf_salt_b64));
        let nonce_b64 = v.envelope["enc"]["nonce"].as_str().unwrap();
        rand_data.extend_from_slice(&b64_decode(nonce_b64));

        let rand_data_clone = rand_data.clone();
        let offset = std::cell::Cell::new(0usize);
        let rand_fn = |buf: &mut [u8]| -> Result<(), EnvelopeError> {
            let start = offset.get();
            let end = start + buf.len();
            if end > rand_data_clone.len() {
                return Err(EnvelopeError::RngError("out of random data".into()));
            }
            buf.copy_from_slice(&rand_data_clone[start..end]);
            offset.set(end);
            Ok(())
        };

        let result = seal_secret_inner(
            &v.plaintext,
            &v.metadata.payload_type,
            v.metadata.filename.clone(),
            v.metadata.mime.clone(),
            passphrase,
            &rand_fn,
        )
        .unwrap_or_else(|e| panic!("seal failed for {:?}: {}", v.description, e));

        // Verify url_key (base64url encoded)
        assert_eq!(
            result.url_key, v.url_key,
            "url_key mismatch for {:?}",
            v.description
        );

        // Verify claim_hash
        assert_eq!(
            result.claim_hash, v.claim_hash,
            "claim_hash mismatch for {:?}",
            v.description
        );

        // Verify envelope structure
        let env = &result.envelope;
        let expected = &v.envelope;
        assert_eq!(
            env["v"], expected["v"],
            "v mismatch for {:?}",
            v.description
        );
        assert_eq!(
            env["suite"], expected["suite"],
            "suite mismatch for {:?}",
            v.description
        );
        assert_eq!(
            env["enc"]["alg"], expected["enc"]["alg"],
            "enc.alg mismatch for {:?}",
            v.description
        );
        assert_eq!(
            env["enc"]["nonce"], expected["enc"]["nonce"],
            "enc.nonce mismatch for {:?}",
            v.description
        );
        assert_eq!(
            env["enc"]["ciphertext"], expected["enc"]["ciphertext"],
            "enc.ciphertext mismatch for {:?}",
            v.description
        );
        assert_eq!(
            env["kdf"], expected["kdf"],
            "kdf mismatch for {:?}",
            v.description
        );
        assert_eq!(
            env["hkdf"], expected["hkdf"],
            "hkdf mismatch for {:?}",
            v.description
        );
    }
}

/// Verify seal → open round-trip through the Tauri command layer.
///
/// Uses real system RNG (not deterministic), so we can't check exact values,
/// but we verify the plaintext survives the full cycle.
#[test]
fn test_roundtrip_through_tauri_layer() {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();

    let plaintext = "hello round-trip through tauri";
    let content_b64 = URL_SAFE_NO_PAD.encode(plaintext.as_bytes());

    let rand_fn = |buf: &mut [u8]| -> Result<(), EnvelopeError> {
        rng.fill(buf)
            .map_err(|_| EnvelopeError::RngError("SystemRandom failed".into()))
    };

    let sealed =
        seal_secret_inner(&content_b64, "text", None, None, None, &rand_fn).expect("seal failed");

    let opened = open_secret_inner(sealed.envelope, &sealed.url_key, None).expect("open failed");

    assert_eq!(opened.content, content_b64);
    assert_eq!(opened.payload_type, "text");
    assert_eq!(opened.filename, None);
    assert_eq!(opened.mime, None);
}

/// Verify round-trip with passphrase through the Tauri command layer.
#[test]
fn test_roundtrip_with_passphrase() {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();

    let plaintext = "passphrase-protected round-trip via tauri";
    let content_b64 = URL_SAFE_NO_PAD.encode(plaintext.as_bytes());
    let passphrase = Some("test passphrase".to_string());

    let rand_fn = |buf: &mut [u8]| -> Result<(), EnvelopeError> {
        rng.fill(buf)
            .map_err(|_| EnvelopeError::RngError("SystemRandom failed".into()))
    };

    let sealed = seal_secret_inner(
        &content_b64,
        "text",
        None,
        None,
        passphrase.clone(),
        &rand_fn,
    )
    .expect("seal failed");

    let opened =
        open_secret_inner(sealed.envelope, &sealed.url_key, passphrase).expect("open failed");

    assert_eq!(opened.content, content_b64);
    assert_eq!(opened.payload_type, "text");
}

/// Wrong passphrase should fail decryption.
#[test]
fn test_wrong_passphrase_fails() {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();

    let content_b64 = URL_SAFE_NO_PAD.encode(b"secret data");

    let rand_fn = |buf: &mut [u8]| -> Result<(), EnvelopeError> {
        rng.fill(buf)
            .map_err(|_| EnvelopeError::RngError("SystemRandom failed".into()))
    };

    let sealed = seal_secret_inner(
        &content_b64,
        "text",
        None,
        None,
        Some("correct".into()),
        &rand_fn,
    )
    .expect("seal failed");

    let err = open_secret_inner(sealed.envelope, &sealed.url_key, Some("wrong".into()));
    assert!(err.is_err(), "should fail with wrong passphrase");
}

/// Verify file metadata round-trips correctly through the Tauri command layer.
#[test]
fn test_file_metadata_roundtrip() {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();

    let content_b64 = URL_SAFE_NO_PAD.encode(b"file content here");

    let rand_fn = |buf: &mut [u8]| -> Result<(), EnvelopeError> {
        rng.fill(buf)
            .map_err(|_| EnvelopeError::RngError("SystemRandom failed".into()))
    };

    let sealed = seal_secret_inner(
        &content_b64,
        "file",
        Some("credentials.txt".into()),
        Some("text/plain".into()),
        None,
        &rand_fn,
    )
    .expect("seal failed");

    let opened = open_secret_inner(sealed.envelope, &sealed.url_key, None).expect("open failed");

    assert_eq!(opened.content, content_b64);
    assert_eq!(opened.payload_type, "file");
    assert_eq!(opened.filename.as_deref(), Some("credentials.txt"));
    assert_eq!(opened.mime.as_deref(), Some("text/plain"));
}

/// Verify binary metadata round-trips correctly.
#[test]
fn test_binary_metadata_roundtrip() {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();

    let content_b64 = URL_SAFE_NO_PAD.encode([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a]);

    let rand_fn = |buf: &mut [u8]| -> Result<(), EnvelopeError> {
        rng.fill(buf)
            .map_err(|_| EnvelopeError::RngError("SystemRandom failed".into()))
    };

    let sealed =
        seal_secret_inner(&content_b64, "binary", None, None, None, &rand_fn).expect("seal failed");

    let opened = open_secret_inner(sealed.envelope, &sealed.url_key, None).expect("open failed");

    assert_eq!(opened.content, content_b64);
    assert_eq!(opened.payload_type, "binary");
}

/// Test that invalid base64 inputs are rejected gracefully.
#[test]
fn test_invalid_base64_rejected() {
    let err = open_secret_inner(serde_json::json!({}), "not-valid-base64!!!", None);
    assert!(err.is_err());

    let err = derive_claim_token_inner("not-valid-base64!!!");
    assert!(err.is_err());
}
