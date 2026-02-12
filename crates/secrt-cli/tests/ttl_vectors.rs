use serde::Deserialize;

use secrt::envelope;

#[derive(Deserialize)]
struct VectorFile {
    valid: Vec<ValidVector>,
    invalid: Vec<InvalidVector>,
}

#[derive(Deserialize)]
struct ValidVector {
    input: String,
    ttl_seconds: i64,
    description: String,
}

#[derive(Deserialize)]
struct InvalidVector {
    input: String,
    reason: String,
}

fn load_vectors() -> VectorFile {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/cli.vectors.json"
    );
    let data =
        std::fs::read_to_string(path).expect("failed to read tests/fixtures/cli.vectors.json");
    serde_json::from_str(&data).expect("failed to parse cli.vectors.json")
}

#[test]
fn test_valid_ttl_vectors() {
    let vf = load_vectors();
    for v in &vf.valid {
        let result = envelope::parse_ttl(&v.input);
        match result {
            Ok(seconds) => {
                assert_eq!(
                    seconds, v.ttl_seconds,
                    "TTL mismatch for {:?} ({}): got {}, expected {}",
                    v.input, v.description, seconds, v.ttl_seconds
                );
            }
            Err(e) => {
                panic!(
                    "parse_ttl({:?}) should succeed ({}), got error: {}",
                    v.input, v.description, e
                );
            }
        }
    }
}

#[test]
fn test_invalid_ttl_vectors() {
    let vf = load_vectors();
    for v in &vf.invalid {
        let result = envelope::parse_ttl(&v.input);
        assert!(
            result.is_err(),
            "parse_ttl({:?}) should fail ({}), but got {:?}",
            v.input,
            v.reason,
            result.unwrap()
        );
    }
}
