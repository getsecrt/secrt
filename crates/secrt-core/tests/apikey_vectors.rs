use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ApiKeyVectors {
    root_salt_label: String,
    verifier_domain_tag: String,
    cases: Vec<ApiKeyVectorCase>,
}

#[derive(Debug, Deserialize)]
struct ApiKeyVectorCase {
    prefix: String,
    pepper: String,
    root_b64: String,
    auth_b64: String,
    enc_b64: String,
    local_key: String,
    wire_key: String,
    auth_hash_hex: String,
}

#[test]
fn apikey_vectors_match_spec() {
    let vectors: ApiKeyVectors =
        serde_json::from_str(include_str!("../../../spec/v1/apikey.vectors.json"))
            .expect("valid vector json");

    assert_eq!(
        vectors.root_salt_label.as_bytes(),
        secrt_core::ROOT_SALT_LABEL
    );
    assert_eq!(
        vectors.verifier_domain_tag.as_bytes(),
        secrt_core::VERIFIER_DOMAIN_TAG
    );

    for case in vectors.cases {
        let expected_root = URL_SAFE_NO_PAD
            .decode(&case.root_b64)
            .expect("valid root_b64");
        let expected_auth = URL_SAFE_NO_PAD
            .decode(&case.auth_b64)
            .expect("valid auth_b64");
        let expected_enc = URL_SAFE_NO_PAD
            .decode(&case.enc_b64)
            .expect("valid enc_b64");

        let parsed_local = secrt_core::parse_local_api_key(&case.local_key).expect("parse local");
        assert_eq!(parsed_local.prefix, case.prefix);
        assert_eq!(parsed_local.root_b64, case.root_b64);
        assert_eq!(parsed_local.root_key, expected_root);

        let auth = secrt_core::derive_auth_token(&parsed_local.root_key).expect("derive auth");
        assert_eq!(auth, expected_auth);

        let enc = secrt_core::derive_meta_key(&parsed_local.root_key).expect("derive enc");
        assert_eq!(enc, expected_enc);

        let wire = secrt_core::derive_wire_api_key(&case.local_key).expect("derive wire");
        assert_eq!(wire, case.wire_key);

        let parsed_wire = secrt_core::parse_wire_api_key(&wire).expect("parse wire");
        assert_eq!(parsed_wire.prefix, case.prefix);
        assert_eq!(parsed_wire.auth_b64, case.auth_b64);
        assert_eq!(parsed_wire.auth_token, expected_auth);

        let auth_hash = secrt_core::compute_auth_hash_hex(&case.pepper, &case.prefix, &auth)
            .expect("hash auth");
        assert_eq!(auth_hash, case.auth_hash_hex);
    }
}
