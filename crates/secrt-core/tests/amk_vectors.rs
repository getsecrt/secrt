use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

use secrt_core::amk::{
    build_wrap_aad, compute_amk_commit, compute_sas, decrypt_note, derive_amk_wrap_key,
    derive_transfer_key, encrypt_note, unwrap_amk, wrap_amk, EncryptedNote,
};
use secrt_core::types::EnvelopeError;

// ── JSON schema ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AmkVectors {
    constants: Constants,
    vectors: Vectors,
}

#[derive(Debug, Deserialize)]
struct Constants {
    hkdf_info_amk_wrap: String,
    hkdf_info_note: String,
    hkdf_info_amk_transfer: String,
    hkdf_info_sas: String,
    amk_commit_domain_tag: String,
    root_salt_label: String,
}

#[derive(Debug, Deserialize)]
struct Vectors {
    amk_commit: AmkCommitVector,
    wrap_unwrap: WrapUnwrapVector,
    note_encrypt_decrypt: NoteEncryptDecryptVector,
    transfer_key: TransferKeyVector,
    sas: SasVector,
}

#[derive(Debug, Deserialize)]
struct AmkCommitVector {
    amk_hex: String,
    commit_hex: String,
}

#[derive(Debug, Deserialize)]
struct WrapUnwrapVector {
    amk_hex: String,
    root_key_hex: String,
    user_id: String,
    key_prefix: String,
    version: u16,
    nonce_fill_byte: String,
    wrap_key_hex: String,
    aad_hex: String,
    ct_b64url: String,
    nonce_b64url: String,
}

#[derive(Debug, Deserialize)]
struct NoteEncryptDecryptVector {
    amk_hex: String,
    secret_id: String,
    plaintext_utf8: String,
    salt_fill_byte: String,
    nonce_fill_byte: String,
    ct_b64url: String,
    nonce_b64url: String,
    salt_b64url: String,
}

#[derive(Debug, Deserialize)]
struct TransferKeyVector {
    shared_secret_hex: String,
    transfer_key_hex: String,
}

#[derive(Debug, Deserialize)]
struct SasVector {
    shared_secret_hex: String,
    pk_a_hex: String,
    pk_b_hex: String,
    sas_code: u32,
    sas_is_commutative: bool,
}

// ── Helpers ─────────────────────────────────────────────────────────

fn parse_fill_byte(s: &str) -> u8 {
    u8::from_str_radix(s.trim_start_matches("0x"), 16).expect("valid hex fill byte")
}

fn fixed_rand(value: u8) -> impl Fn(&mut [u8]) -> Result<(), EnvelopeError> {
    move |buf: &mut [u8]| {
        buf.fill(value);
        Ok(())
    }
}

// ── Tests ───────────────────────────────────────────────────────────

fn load_vectors() -> AmkVectors {
    serde_json::from_str(include_str!("../../../spec/v1/amk.vectors.json"))
        .expect("valid amk vectors json")
}

#[test]
fn amk_constants_match_spec() {
    let v = load_vectors();
    assert_eq!(
        v.constants.hkdf_info_amk_wrap,
        secrt_core::amk::HKDF_INFO_AMK_WRAP
    );
    assert_eq!(v.constants.hkdf_info_note, secrt_core::amk::HKDF_INFO_NOTE);
    assert_eq!(
        v.constants.hkdf_info_amk_transfer,
        secrt_core::amk::HKDF_INFO_AMK_TRANSFER
    );
    assert_eq!(v.constants.hkdf_info_sas, secrt_core::amk::HKDF_INFO_SAS);
    assert_eq!(
        v.constants.amk_commit_domain_tag.as_bytes(),
        secrt_core::amk::AMK_COMMIT_DOMAIN_TAG
    );
    assert_eq!(
        v.constants.root_salt_label.as_bytes(),
        secrt_core::ROOT_SALT_LABEL
    );
}

#[test]
fn amk_commit_vector() {
    let v = load_vectors().vectors.amk_commit;
    let amk = hex::decode(&v.amk_hex).expect("valid amk hex");
    let expected = hex::decode(&v.commit_hex).expect("valid commit hex");

    let commit = compute_amk_commit(&amk);
    assert_eq!(
        commit.as_slice(),
        expected.as_slice(),
        "amk_commit mismatch"
    );
}

#[test]
fn wrap_unwrap_vector() {
    let v = load_vectors().vectors.wrap_unwrap;
    let amk = hex::decode(&v.amk_hex).expect("valid amk hex");
    let root_key = hex::decode(&v.root_key_hex).expect("valid root_key hex");
    let expected_wrap_key = hex::decode(&v.wrap_key_hex).expect("valid wrap_key hex");
    let expected_aad = hex::decode(&v.aad_hex).expect("valid aad hex");
    let expected_ct = URL_SAFE_NO_PAD
        .decode(&v.ct_b64url)
        .expect("valid ct b64url");
    let expected_nonce = URL_SAFE_NO_PAD
        .decode(&v.nonce_b64url)
        .expect("valid nonce b64url");
    let nonce_fill = parse_fill_byte(&v.nonce_fill_byte);

    // Verify wrap key derivation
    let wrap_key = derive_amk_wrap_key(&root_key).expect("derive wrap key");
    assert_eq!(wrap_key, expected_wrap_key, "wrap_key derivation mismatch");

    // Verify AAD construction
    let aad = build_wrap_aad(&v.user_id, &v.key_prefix, v.version);
    assert_eq!(aad, expected_aad, "AAD mismatch");

    // Verify wrap produces expected ciphertext
    let wrapped = wrap_amk(&amk, &wrap_key, &aad, &fixed_rand(nonce_fill)).expect("wrap amk");
    assert_eq!(wrapped.ct, expected_ct, "ciphertext mismatch");
    assert_eq!(wrapped.nonce, expected_nonce, "nonce mismatch");

    // Verify unwrap round-trip
    let unwrapped = unwrap_amk(&wrapped, &wrap_key, &aad).expect("unwrap amk");
    assert_eq!(unwrapped, amk, "unwrap round-trip mismatch");
}

#[test]
fn note_encrypt_decrypt_vector() {
    let v = load_vectors().vectors.note_encrypt_decrypt;
    let amk = hex::decode(&v.amk_hex).expect("valid amk hex");
    let expected_ct = URL_SAFE_NO_PAD
        .decode(&v.ct_b64url)
        .expect("valid ct b64url");
    let expected_nonce = URL_SAFE_NO_PAD
        .decode(&v.nonce_b64url)
        .expect("valid nonce b64url");
    let expected_salt = URL_SAFE_NO_PAD
        .decode(&v.salt_b64url)
        .expect("valid salt b64url");
    let salt_fill = parse_fill_byte(&v.salt_fill_byte);
    let nonce_fill = parse_fill_byte(&v.nonce_fill_byte);

    // Counter-based RNG: first call = salt_fill, second call = nonce_fill
    let call = std::cell::Cell::new(0u8);
    let counter_rand = |buf: &mut [u8]| -> Result<(), EnvelopeError> {
        let c = call.get();
        call.set(c + 1);
        let val = if c == 0 { salt_fill } else { nonce_fill };
        buf.fill(val);
        Ok(())
    };

    let encrypted = encrypt_note(
        &amk,
        &v.secret_id,
        v.plaintext_utf8.as_bytes(),
        &counter_rand,
    )
    .expect("encrypt note");

    assert_eq!(encrypted.ct, expected_ct, "note ciphertext mismatch");
    assert_eq!(encrypted.nonce, expected_nonce, "note nonce mismatch");
    assert_eq!(encrypted.salt, expected_salt, "note salt mismatch");

    // Verify decrypt round-trip
    let decrypted = decrypt_note(&amk, &v.secret_id, &encrypted).expect("decrypt note");
    assert_eq!(
        decrypted,
        v.plaintext_utf8.as_bytes(),
        "note decrypt round-trip mismatch"
    );

    // Also test from raw expected values (simulates reading from server)
    let from_stored = EncryptedNote {
        ct: expected_ct,
        nonce: expected_nonce,
        salt: expected_salt,
        version: 1,
    };
    let decrypted2 = decrypt_note(&amk, &v.secret_id, &from_stored).expect("decrypt stored note");
    assert_eq!(
        decrypted2,
        v.plaintext_utf8.as_bytes(),
        "stored note decrypt mismatch"
    );
}

#[test]
fn transfer_key_vector() {
    let v = load_vectors().vectors.transfer_key;
    let shared_secret = hex::decode(&v.shared_secret_hex).expect("valid shared_secret hex");
    let expected = hex::decode(&v.transfer_key_hex).expect("valid transfer_key hex");

    let transfer_key = derive_transfer_key(&shared_secret).expect("derive transfer key");
    assert_eq!(transfer_key, expected, "transfer_key derivation mismatch");
}

#[test]
fn sas_vector() {
    let v = load_vectors().vectors.sas;
    let shared_secret = hex::decode(&v.shared_secret_hex).expect("valid shared_secret hex");
    let pk_a = hex::decode(&v.pk_a_hex).expect("valid pk_a hex");
    let pk_b = hex::decode(&v.pk_b_hex).expect("valid pk_b hex");

    let code = compute_sas(&shared_secret, &pk_a, &pk_b).expect("compute sas");
    assert_eq!(code, v.sas_code, "SAS code mismatch");

    if v.sas_is_commutative {
        let code_rev = compute_sas(&shared_secret, &pk_b, &pk_a).expect("compute sas reversed");
        assert_eq!(code, code_rev, "SAS must be commutative");
    }
}
