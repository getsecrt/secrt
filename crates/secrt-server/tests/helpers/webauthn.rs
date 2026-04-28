//! WebAuthn test helper: a P-256 keypair that can emit a COSE_Key and sign
//! synthetic `authenticatorData || SHA256(clientDataJSON)`. Used by passkey
//! tests in place of the old `"pk-test"` placeholder once the server starts
//! verifying assertion signatures.
//!
//! Hand-roll with `ring` only — no CBOR dep. The COSE_Key shape we need is a
//! fixed EC2 P-256 map (`{1: 2, 3: -7, -1: 1, -2: <x>, -3: <y>}`); see
//! `~/.claude/plans/webauthn-sig-verify.md` for the design rationale.

#![allow(dead_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::digest::{digest, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

/// WebAuthn `authenticatorData` flag bits, RFC §6.1.
pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_AT: u8 = 0x40;

/// Default RP ID for tests. Matches the test config's `public_base_url`
/// (`https://example.com`).
pub const TEST_RP_ID: &str = "example.com";
pub const TEST_ORIGIN: &str = "https://example.com";

pub struct TestKeyPair {
    keypair: EcdsaKeyPair,
    rng: SystemRandom,
    public_x: [u8; 32],
    public_y: [u8; 32],
}

impl TestKeyPair {
    pub fn generate() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("generate pkcs8");
        let keypair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .expect("load pkcs8");
        let pub_bytes = keypair.public_key().as_ref();
        assert_eq!(pub_bytes.len(), 65, "P-256 uncompressed point");
        assert_eq!(pub_bytes[0], 0x04, "uncompressed point prefix");
        let mut public_x = [0u8; 32];
        let mut public_y = [0u8; 32];
        public_x.copy_from_slice(&pub_bytes[1..33]);
        public_y.copy_from_slice(&pub_bytes[33..65]);
        Self {
            keypair,
            rng,
            public_x,
            public_y,
        }
    }

    pub fn public_x(&self) -> &[u8; 32] {
        &self.public_x
    }

    pub fn public_y(&self) -> &[u8; 32] {
        &self.public_y
    }

    /// Canonical CBOR-encoded COSE_Key for ECDSA P-256 (ES256).
    /// Layout: `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` (kty, alg, crv, x, y).
    pub fn cose_key(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(77);
        out.push(0xa5); // map(5)
        out.push(0x01); // key 1 (kty)
        out.push(0x02); // val 2 (EC2)
        out.push(0x03); // key 3 (alg)
        out.push(0x26); // val -7 (ES256)
        out.push(0x20); // key -1 (crv)
        out.push(0x01); // val 1 (P-256)
        out.push(0x21); // key -2 (x)
        out.push(0x58); // bstr, 1-byte length follows
        out.push(0x20); // length 32
        out.extend_from_slice(&self.public_x);
        out.push(0x22); // key -3 (y)
        out.push(0x58);
        out.push(0x20);
        out.extend_from_slice(&self.public_y);
        out
    }

    pub fn cose_key_b64u(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.cose_key())
    }

    /// Sign `authenticatorData || SHA256(clientDataJSON)` with ES256 (ASN.1 DER).
    pub fn sign(&self, authenticator_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
        let cdj_hash = digest(&SHA256, client_data_json);
        let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
        signed.extend_from_slice(authenticator_data);
        signed.extend_from_slice(cdj_hash.as_ref());
        let sig = self.keypair.sign(&self.rng, &signed).expect("sign");
        sig.as_ref().to_vec()
    }
}

/// SHA-256 of an RP ID, used as the first 32 bytes of `authenticatorData`.
pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    let d = digest(&SHA256, rp_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Build `authenticatorData` for a login (assertion): no attested credential
/// data section. Layout: rpIdHash(32) || flags(1) || signCount(4).
pub fn build_authenticator_data(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&rp_id_hash(rp_id));
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    out
}

/// Build `authenticatorData` for a registration ceremony: includes attested
/// credential data carrying the new COSE_Key. Sets the AT flag bit.
/// Layout: rpIdHash(32) || flags(1) || signCount(4) || aaguid(16)
///       || credIdLen(2) || credentialId || credentialPublicKey.
pub fn build_register_authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    aaguid: &[u8; 16],
    credential_id: &[u8],
    cose_key: &[u8],
) -> Vec<u8> {
    let mut out = build_authenticator_data(rp_id, flags | FLAG_AT, sign_count);
    out.extend_from_slice(aaguid);
    let len = u16::try_from(credential_id.len()).expect("credential_id len fits in u16");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(credential_id);
    out.extend_from_slice(cose_key);
    out
}

/// Build `clientDataJSON` per WebAuthn §5.10.1. The challenge is base64url-no-pad
/// encoded; the test handler issues already-encoded challenges, so callers
/// pass the string they got back from `/start` verbatim.
pub fn build_client_data_json(type_: &str, challenge_b64u: &str, origin: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "type": type_,
        "challenge": challenge_b64u,
        "origin": origin,
    }))
    .expect("serialize clientDataJSON")
}

// ── End-to-end test passkey ─────────────────────────────────────────────
//
// Higher-level wrapper that owns a TestKeyPair plus the credential_id and
// sign_count. Provides full /start → /finish round-trip helpers so test
// files can register or log in with one call instead of hand-assembling
// wire payloads.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use serde_json::{json, Value};
use tower::ServiceExt;

pub struct TestPasskey {
    pub keypair: TestKeyPair,
    pub credential_id: Vec<u8>,
    pub sign_count: u32,
}

impl TestPasskey {
    pub fn generate() -> Self {
        Self {
            keypair: TestKeyPair::generate(),
            credential_id: random_credential_id(),
            sign_count: 0,
        }
    }

    pub fn with_credential_id(cid: Vec<u8>) -> Self {
        Self {
            keypair: TestKeyPair::generate(),
            credential_id: cid,
            sign_count: 0,
        }
    }

    pub fn credential_id_b64u(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.credential_id)
    }

    /// Run a full registration ceremony. Returns the parsed JSON of the
    /// `/register/finish` response (has `session_token`, `user_id`, etc.).
    /// Panics on transport failure or non-2xx; tests that need to assert
    /// failure should use the lower-level `*_start` / `register_finish`
    /// helpers below.
    pub async fn register(&self, app: &Router, display_name: &str) -> Value {
        let resp = self.register_finish(app, display_name, None).await;
        assert_eq!(
            resp.0,
            StatusCode::OK,
            "register_finish status: {:?}",
            resp.1
        );
        resp.1
    }

    /// Run a full login ceremony. Returns the parsed JSON of the
    /// `/login/finish` response.
    pub async fn login(&mut self, app: &Router) -> Value {
        let resp = self.login_finish(app, None).await;
        assert_eq!(resp.0, StatusCode::OK, "login_finish status: {:?}", resp.1);
        resp.1
    }

    /// Run a full add-passkey ceremony with a session token. Returns the
    /// parsed JSON of `/add/finish`.
    pub async fn add(&self, app: &Router, session_token: &str) -> Value {
        let resp = self.add_finish(app, session_token, None).await;
        assert_eq!(resp.0, StatusCode::OK, "add_finish status: {:?}", resp.1);
        resp.1
    }

    /// Lower-level register with explicit PRF metadata, returns
    /// (status, body). Suitable for tests asserting failure paths.
    pub async fn register_finish(
        &self,
        app: &Router,
        display_name: &str,
        prf: Option<Value>,
    ) -> (StatusCode, Value) {
        let (challenge_id, challenge_b64u) = passkey_register_start(app, display_name).await;
        let auth_data = build_register_authenticator_data(
            TEST_RP_ID,
            FLAG_UP | FLAG_UV,
            self.sign_count,
            &[0u8; 16],
            &self.credential_id,
            &self.keypair.cose_key(),
        );
        let cdj = build_client_data_json("webauthn.create", &challenge_b64u, TEST_ORIGIN);
        let mut body = json!({
            "challenge_id": challenge_id,
            "credential_id": self.credential_id_b64u(),
            "authenticator_data": URL_SAFE_NO_PAD.encode(&auth_data),
            "client_data_json": URL_SAFE_NO_PAD.encode(&cdj),
        });
        if let Some(p) = prf {
            body["prf"] = p;
        }
        post_json(app, "/api/v1/auth/passkeys/register/finish", &body, None).await
    }

    pub async fn login_finish(&mut self, app: &Router, prf: Option<Value>) -> (StatusCode, Value) {
        let cred_b64u = self.credential_id_b64u();
        let (challenge_id, challenge_b64u) = passkey_login_start(app, &cred_b64u).await;

        // Use stored sign_count + 1 so monotonicity holds across repeat logins.
        let new_count = self.sign_count + 1;
        let auth_data = build_authenticator_data(TEST_RP_ID, FLAG_UP | FLAG_UV, new_count);
        let cdj = build_client_data_json("webauthn.get", &challenge_b64u, TEST_ORIGIN);
        let sig = self.keypair.sign(&auth_data, &cdj);

        let mut body = json!({
            "challenge_id": challenge_id,
            "credential_id": cred_b64u,
            "authenticator_data": URL_SAFE_NO_PAD.encode(&auth_data),
            "client_data_json": URL_SAFE_NO_PAD.encode(&cdj),
            "signature": URL_SAFE_NO_PAD.encode(&sig),
        });
        if let Some(p) = prf {
            body["prf"] = p;
        }
        let result = post_json(app, "/api/v1/auth/passkeys/login/finish", &body, None).await;
        if result.0 == StatusCode::OK {
            self.sign_count = new_count;
        }
        result
    }

    pub async fn add_finish(
        &self,
        app: &Router,
        session_token: &str,
        prf: Option<Value>,
    ) -> (StatusCode, Value) {
        let (challenge_id, challenge_b64u) = passkey_add_start(app, session_token).await;

        let auth_data = build_register_authenticator_data(
            TEST_RP_ID,
            FLAG_UP | FLAG_UV,
            self.sign_count,
            &[0u8; 16],
            &self.credential_id,
            &self.keypair.cose_key(),
        );
        let cdj = build_client_data_json("webauthn.create", &challenge_b64u, TEST_ORIGIN);
        let mut body = json!({
            "challenge_id": challenge_id,
            "credential_id": self.credential_id_b64u(),
            "authenticator_data": URL_SAFE_NO_PAD.encode(&auth_data),
            "client_data_json": URL_SAFE_NO_PAD.encode(&cdj),
        });
        if let Some(p) = prf {
            body["prf"] = p;
        }
        post_json(
            app,
            "/api/v1/auth/passkeys/add/finish",
            &body,
            Some(session_token),
        )
        .await
    }
}

fn random_credential_id() -> Vec<u8> {
    use ring::rand::SecureRandom;
    let mut buf = [0u8; 16];
    SystemRandom::new().fill(&mut buf).expect("rng");
    buf.to_vec()
}

/// `/register/start` — returns (challenge_id, challenge_b64u) from a single round-trip.
pub async fn passkey_register_start(app: &Router, display_name: &str) -> (String, String) {
    let (status, body) = post_json(
        app,
        "/api/v1/auth/passkeys/register/start",
        &json!({ "display_name": display_name }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register/start: {body:?}");
    (
        body["challenge_id"]
            .as_str()
            .expect("challenge_id")
            .to_string(),
        body["challenge"].as_str().expect("challenge").to_string(),
    )
}

pub async fn passkey_login_start(app: &Router, credential_id_b64u: &str) -> (String, String) {
    let (status, body) = post_json(
        app,
        "/api/v1/auth/passkeys/login/start",
        &json!({ "credential_id": credential_id_b64u }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login/start: {body:?}");
    (
        body["challenge_id"]
            .as_str()
            .expect("challenge_id")
            .to_string(),
        body["challenge"].as_str().expect("challenge").to_string(),
    )
}

pub async fn passkey_add_start(app: &Router, session_token: &str) -> (String, String) {
    let (status, body) = post_json(
        app,
        "/api/v1/auth/passkeys/add/start",
        &json!({}),
        Some(session_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add/start: {body:?}");
    (
        body["challenge_id"]
            .as_str()
            .expect("challenge_id")
            .to_string(),
        body["challenge"].as_str().expect("challenge").to_string(),
    )
}

pub async fn post_json(
    app: &Router,
    uri: &str,
    body: &Value,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let req = builder.body(Body::from(body.to_string())).expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cose_key_round_trip_shape() {
        let kp = TestKeyPair::generate();
        let cose = kp.cose_key();
        // Fixed length for the EC2 P-256 layout (77 bytes).
        assert_eq!(cose.len(), 77);
        assert_eq!(cose[0], 0xa5); // map(5)
        assert_eq!(&cose[1..7], &[0x01, 0x02, 0x03, 0x26, 0x20, 0x01]);
        assert_eq!(cose[7], 0x21); // key -2 (x)
        assert_eq!(&cose[8..10], &[0x58, 0x20]); // bstr header, length 32
        assert_eq!(&cose[10..42], kp.public_x());
        assert_eq!(cose[42], 0x22); // key -3 (y)
        assert_eq!(&cose[43..45], &[0x58, 0x20]);
        assert_eq!(&cose[45..77], kp.public_y());
    }

    #[test]
    fn sign_then_verify_with_ring() {
        use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
        let kp = TestKeyPair::generate();
        let auth = build_authenticator_data(TEST_RP_ID, FLAG_UP | FLAG_UV, 1);
        let cdj = build_client_data_json("webauthn.get", "ChAlLeNgE", TEST_ORIGIN);
        let sig = kp.sign(&auth, &cdj);

        // Verify against the SEC1 uncompressed point (0x04 || x || y).
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(kp.public_x());
        sec1.extend_from_slice(kp.public_y());

        let cdj_hash = digest(&SHA256, &cdj);
        let mut signed = Vec::with_capacity(auth.len() + 32);
        signed.extend_from_slice(&auth);
        signed.extend_from_slice(cdj_hash.as_ref());

        let pk = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &sec1);
        pk.verify(&signed, &sig).expect("signature verifies");
    }
}
