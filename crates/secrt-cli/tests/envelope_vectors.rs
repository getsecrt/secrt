use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use std::collections::HashMap;

// We need to access the crate's envelope module
use secrt::envelope;

#[allow(dead_code)]
#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
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
    ikm: String,
    enc_key: String,
    claim_token: String,
    claim_hash: String,
    envelope: serde_json::Value,
}

fn load_vectors() -> VectorFile {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/envelope.vectors.json"
    );
    let data =
        std::fs::read_to_string(path).expect("failed to read tests/fixtures/envelope.vectors.json");
    serde_json::from_str(&data).expect("failed to parse envelope.vectors.json")
}

fn b64_decode(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("b64 decode")
}

fn b64_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Test that open() produces the correct plaintext for each vector.
#[test]
fn test_open_vectors() {
    let vf = load_vectors();
    for v in &vf.vectors {
        let url_key = b64_decode(&v.url_key);
        let passphrase = v.passphrase.clone().unwrap_or_default();

        let plaintext = envelope::open(envelope::OpenParams {
            envelope: v.envelope.clone(),
            url_key,
            passphrase,
        })
        .unwrap_or_else(|e| panic!("open failed for {:?}: {}", v.description, e));

        let expected = b64_decode(&v.plaintext);
        assert_eq!(
            plaintext, expected,
            "plaintext mismatch for {:?}",
            v.description
        );

        // Also verify plaintext_utf8 if present
        if let Some(ref utf8) = v.plaintext_utf8 {
            assert_eq!(
                std::str::from_utf8(&plaintext).unwrap(),
                utf8.as_str(),
                "plaintext_utf8 mismatch for {:?}",
                v.description
            );
        }
    }
}

/// Test claim_token and claim_hash derivation for each vector.
#[test]
fn test_claim_derivation_vectors() {
    let vf = load_vectors();
    for v in &vf.vectors {
        let url_key = b64_decode(&v.url_key);

        let claim_token = envelope::derive_claim_token(&url_key)
            .unwrap_or_else(|e| panic!("derive_claim_token failed for {:?}: {}", v.description, e));

        assert_eq!(
            b64_encode(&claim_token),
            v.claim_token,
            "claim_token mismatch for {:?}",
            v.description
        );

        let claim_hash = envelope::crypto::compute_claim_hash(&claim_token);
        assert_eq!(
            claim_hash, v.claim_hash,
            "claim_hash mismatch for {:?}",
            v.description
        );
    }
}

/// Test that seal() with deterministic RNG produces matching envelopes.
/// Random bytes order: url_key(32) || [kdf_salt(16) if passphrase] || hkdf_salt(32) || nonce(12)
#[test]
fn test_seal_vectors() {
    let vf = load_vectors();
    for v in &vf.vectors {
        let url_key_bytes = b64_decode(&v.url_key);
        let passphrase = v.passphrase.clone().unwrap_or_default();
        let expected_plaintext = b64_decode(&v.plaintext);

        // Build the deterministic random byte sequence
        let mut rand_data = Vec::new();
        // url_key (32 bytes)
        rand_data.extend_from_slice(&url_key_bytes);
        // kdf_salt (16 bytes) if passphrase
        if !passphrase.is_empty() {
            let kdf_salt_b64 = v.envelope["kdf"]["salt"].as_str().unwrap();
            let kdf_salt = b64_decode(kdf_salt_b64);
            rand_data.extend_from_slice(&kdf_salt);
        }
        // hkdf_salt (32 bytes)
        let hkdf_salt_b64 = v.envelope["hkdf"]["salt"].as_str().unwrap();
        let hkdf_salt = b64_decode(hkdf_salt_b64);
        rand_data.extend_from_slice(&hkdf_salt);
        // nonce (12 bytes)
        let nonce_b64 = v.envelope["enc"]["nonce"].as_str().unwrap();
        let nonce = b64_decode(nonce_b64);
        rand_data.extend_from_slice(&nonce);

        let rand_data_clone = rand_data.clone();
        let offset = std::cell::Cell::new(0usize);
        let rand_fn = |buf: &mut [u8]| -> Result<(), envelope::EnvelopeError> {
            let start = offset.get();
            let end = start + buf.len();
            if end > rand_data_clone.len() {
                return Err(envelope::EnvelopeError::RngError(
                    "out of random data".into(),
                ));
            }
            buf.copy_from_slice(&rand_data_clone[start..end]);
            offset.set(end);
            Ok(())
        };

        // Extract hint if present
        let hint: Option<HashMap<String, String>> = v
            .envelope
            .get("hint")
            .and_then(|h| serde_json::from_value(h.clone()).ok());

        // Get iterations from envelope
        let iterations = v.envelope["kdf"]
            .get("iterations")
            .and_then(|i| i.as_u64())
            .unwrap_or(0) as u32;

        let result = envelope::seal(envelope::SealParams {
            plaintext: expected_plaintext,
            passphrase,
            rand_bytes: &rand_fn,
            hint,
            iterations,
        })
        .unwrap_or_else(|e| panic!("seal failed for {:?}: {}", v.description, e));

        // Verify url_key
        assert_eq!(
            b64_encode(&result.url_key),
            v.url_key,
            "url_key mismatch for {:?}",
            v.description
        );

        // Verify claim_token
        assert_eq!(
            b64_encode(&result.claim_token),
            v.claim_token,
            "claim_token mismatch for {:?} (from seal)",
            v.description
        );

        // Verify claim_hash
        assert_eq!(
            result.claim_hash, v.claim_hash,
            "claim_hash mismatch for {:?} (from seal)",
            v.description
        );

        // Verify envelope fields match
        let result_env = &result.envelope;
        let expected_env = &v.envelope;

        assert_eq!(
            result_env["v"], expected_env["v"],
            "envelope.v mismatch for {:?}",
            v.description
        );
        assert_eq!(
            result_env["suite"], expected_env["suite"],
            "envelope.suite mismatch for {:?}",
            v.description
        );
        assert_eq!(
            result_env["enc"]["alg"], expected_env["enc"]["alg"],
            "envelope.enc.alg mismatch for {:?}",
            v.description
        );
        assert_eq!(
            result_env["enc"]["nonce"], expected_env["enc"]["nonce"],
            "envelope.enc.nonce mismatch for {:?}",
            v.description
        );
        assert_eq!(
            result_env["enc"]["ciphertext"], expected_env["enc"]["ciphertext"],
            "envelope.enc.ciphertext mismatch for {:?}",
            v.description
        );
        assert_eq!(
            result_env["kdf"], expected_env["kdf"],
            "envelope.kdf mismatch for {:?}",
            v.description
        );
        assert_eq!(
            result_env["hkdf"], expected_env["hkdf"],
            "envelope.hkdf mismatch for {:?}",
            v.description
        );

        // Verify hint if present
        if expected_env.get("hint").is_some() {
            assert_eq!(
                result_env["hint"], expected_env["hint"],
                "envelope.hint mismatch for {:?}",
                v.description
            );
        }
    }
}

/// Verify round-trip: seal then open recovers plaintext.
#[test]
fn test_roundtrip() {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();

    let plaintext = b"round-trip test data!";

    let rand_fn = |buf: &mut [u8]| -> Result<(), envelope::EnvelopeError> {
        rng.fill(buf)
            .map_err(|_| envelope::EnvelopeError::RngError("SystemRandom failed".into()))
    };

    let result = envelope::seal(envelope::SealParams {
        plaintext: plaintext.to_vec(),
        passphrase: String::new(),
        rand_bytes: &rand_fn,
        hint: None,
        iterations: 0,
    })
    .expect("seal failed");

    let recovered = envelope::open(envelope::OpenParams {
        envelope: result.envelope,
        url_key: result.url_key,
        passphrase: String::new(),
    })
    .expect("open failed");

    assert_eq!(recovered, plaintext);
}

/// Verify round-trip with passphrase.
#[test]
fn test_roundtrip_with_passphrase() {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();

    let plaintext = b"passphrase-protected round-trip";
    let passphrase = "test passphrase";

    let rand_fn = |buf: &mut [u8]| -> Result<(), envelope::EnvelopeError> {
        rng.fill(buf)
            .map_err(|_| envelope::EnvelopeError::RngError("SystemRandom failed".into()))
    };

    let result = envelope::seal(envelope::SealParams {
        plaintext: plaintext.to_vec(),
        passphrase: passphrase.to_string(),
        rand_bytes: &rand_fn,
        hint: None,
        iterations: 0,
    })
    .expect("seal failed");

    let recovered = envelope::open(envelope::OpenParams {
        envelope: result.envelope,
        url_key: result.url_key,
        passphrase: passphrase.to_string(),
    })
    .expect("open failed");

    assert_eq!(recovered, plaintext);
}

/// Wrong passphrase should fail decryption.
#[test]
fn test_wrong_passphrase() {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();

    let plaintext = b"secret data";

    let rand_fn = |buf: &mut [u8]| -> Result<(), envelope::EnvelopeError> {
        rng.fill(buf)
            .map_err(|_| envelope::EnvelopeError::RngError("SystemRandom failed".into()))
    };

    let result = envelope::seal(envelope::SealParams {
        plaintext: plaintext.to_vec(),
        passphrase: "correct".to_string(),
        rand_bytes: &rand_fn,
        hint: None,
        iterations: 0,
    })
    .expect("seal failed");

    let err = envelope::open(envelope::OpenParams {
        envelope: result.envelope,
        url_key: result.url_key,
        passphrase: "wrong".to_string(),
    });

    assert!(err.is_err(), "should fail with wrong passphrase");
}
