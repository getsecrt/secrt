use secrt_server::domain::secret_rules::{
    format_bytes, generate_id, validate_envelope, SecretRuleError,
};

#[test]
fn envelope_validation_and_size() {
    assert!(validate_envelope("{\"ct\":\"ok\"}", 64).is_ok());
    assert!(matches!(
        validate_envelope("[]", 64),
        Err(SecretRuleError::InvalidEnvelope)
    ));
    assert!(matches!(
        validate_envelope("{\"ct\":\"x\"}", 2),
        Err(SecretRuleError::EnvelopeTooLarge)
    ));
}

#[test]
fn format_bytes_cases() {
    assert_eq!(format_bytes(256 * 1024), "256 KB");
    assert_eq!(format_bytes(2 * 1024 * 1024), "2 MB");
    assert_eq!(format_bytes(777), "777 bytes");
}

#[test]
fn generated_ids_are_url_safe_and_uniqueish() {
    let a = generate_id().expect("id a");
    let b = generate_id().expect("id b");
    assert_ne!(a, b);
    assert!(a
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
}
