//! Integration tests for `secrt pair`.
//!
//! Send-mode tests use canned `MockApi` responses. Receive-mode tests need
//! to encrypt the `amk_transfer` blob to the CLI's runtime ECDH public key,
//! so they construct a small closure-based mock via
//! `TestDepsBuilder::make_api`.

mod helpers;

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use helpers::{args, TestDepsBuilder};
use ring::agreement;
use ring::rand::{SecureRandom, SystemRandom};
use secrt_cli::cli;
use secrt_cli::client::{
    AmkWrapperResponse, InfoLimits, InfoRate, InfoResponse, InfoTTL, InfoTier,
    PairChallengeOutcome, PairPollOutcome, PairStartRequest, PairStartResponse, PairTransferBlob,
    SecretApi,
};

/// Build an API key the CLI will accept as locally-parseable. Pair tests
/// only need the key to parse; the server side is mocked.
fn make_local_api_key() -> String {
    let prefix = "ABC123";
    let root_b64 = URL_SAFE_NO_PAD.encode([7u8; 32]);
    format!(
        "{}{}.{}",
        secrt_core::LOCAL_API_KEY_PREFIX,
        prefix,
        root_b64
    )
}

fn ok_info(user_id: Option<&str>) -> InfoResponse {
    InfoResponse {
        authenticated: true,
        user_id: user_id.map(|s| s.to_string()),
        ttl: InfoTTL {
            default_seconds: 3600,
            max_seconds: 86400,
        },
        limits: InfoLimits {
            public: tier(),
            authed: tier(),
        },
        claim_rate: rate(),
        latest_cli_version: None,
        latest_cli_version_checked_at: None,
        min_supported_cli_version: None,
        server_version: None,
    }
}
fn tier() -> InfoTier {
    InfoTier {
        max_envelope_bytes: 1,
        max_secrets: 1,
        max_total_bytes: 1,
        rate: rate(),
    }
}
fn rate() -> InfoRate {
    InfoRate {
        requests_per_second: 1.0,
        burst: 1,
    }
}

// --- Invalid input + mode-selection tests -----------------------------------

/// Construct a deterministic, valid AmkWrapperResponse that the
/// CLI-side `resolve_amk` will unwrap successfully. Lets parser-rejection
/// tests proceed past the key-resolution step to the code-parsing step.
fn valid_amk_wrapper_response() -> AmkWrapperResponse {
    let local_key = secrt_core::parse_local_api_key(&make_local_api_key()).unwrap();
    let wrap_key = secrt_core::amk::derive_amk_wrap_key(&local_key.root_key).unwrap();
    let user_id_bytes = uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111")
        .unwrap()
        .into_bytes();
    let aad = secrt_core::amk::build_wrap_aad(&user_id_bytes, &local_key.prefix, 1);
    let amk = [0xAAu8; 32];
    let wrapped = secrt_core::amk::wrap_amk(&amk, &wrap_key, &aad, &|buf| {
        for b in buf {
            *b = 0xCC;
        }
        Ok(())
    })
    .unwrap();
    AmkWrapperResponse {
        user_id: "11111111-1111-1111-1111-111111111111".into(),
        wrapped_amk: URL_SAFE_NO_PAD.encode(&wrapped.ct),
        nonce: URL_SAFE_NO_PAD.encode(&wrapped.nonce),
        version: 1,
    }
}

#[test]
fn pair_invalid_code_exits_2() {
    let api_key = make_local_api_key();
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .mock_get_amk_wrapper(Ok(Some(valid_amk_wrapper_response())))
        .build();
    let code = cli::run(
        &args(&["secrt", "pair", "this-is-clearly-not-a-valid-code"]),
        &mut deps,
    );
    assert_eq!(code, 2, "stderr: {}", stderr);
}

#[test]
fn pair_missing_amk_with_positional_errors() {
    let api_key = make_local_api_key();
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        // No wrapper → Missing state.
        .mock_get_amk_wrapper(Ok(None))
        .build();
    let code = cli::run(&args(&["secrt", "pair", "K7MQ-QX2Z"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr);
    let err = stderr.to_string();
    assert!(
        err.contains("does not have the account key"),
        "should report missing key + positional combo: {}",
        err
    );
}

#[test]
fn pair_no_api_key_errors() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "pair"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr);
    let err = stderr.to_string();
    assert!(
        err.contains("not signed in") || err.contains("secrt auth login"),
        "should point at auth login: {}",
        err
    );
}

#[test]
fn pair_help_runs() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "pair", "--help"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("Share your account key"));
    assert!(err.contains("Send:"));
    assert!(err.contains("Receive:"));
}

// --- Receive mode happy path (closure-based mock) ----------------------------

/// A pair-aware mock that wires a real ECDH/HKDF/AES-256-GCM exchange so
/// `secrt pair` in Receive mode can decrypt the transfer blob. The mock
/// stores the displayer's pubkey (sent at `/pair/start`) and the AMK that
/// will be encrypted back at `/pair/poll`. All other `SecretApi` methods
/// are stubbed.
struct PairReceiveMock {
    user_code: String,
    poll_token: String,
    /// Set inside `pair_start` so `pair_poll` can encrypt to the right key.
    displayer_pubkey_b64: Arc<Mutex<Option<String>>>,
    /// The AMK bytes the displayer will receive on the first approved poll.
    amk_bytes: Vec<u8>,
    /// Toggled true after the first approved poll so the second returns
    /// `expired` (mirrors the server's one-shot consumption).
    delivered: Arc<Mutex<bool>>,
    /// Captured for assertions.
    upserted: Arc<Mutex<Option<Vec<u8>>>>,
}

impl SecretApi for PairReceiveMock {
    fn create(
        &self,
        _req: secrt_cli::client::CreateRequest,
    ) -> Result<secrt_cli::client::CreateResponse, String> {
        unimplemented!("not used by receive-mode test")
    }
    fn claim(&self, _id: &str, _t: &[u8]) -> Result<secrt_cli::client::ClaimResponse, String> {
        unimplemented!()
    }
    fn burn(&self, _id: &str) -> Result<(), String> {
        unimplemented!()
    }
    fn list(
        &self,
        _l: Option<i64>,
        _o: Option<i64>,
    ) -> Result<secrt_cli::client::ListSecretsResponse, String> {
        unimplemented!()
    }
    fn info(&self) -> Result<InfoResponse, String> {
        Ok(ok_info(Some("11111111-1111-1111-1111-111111111111")))
    }
    fn get_amk_wrapper(&self) -> Result<Option<AmkWrapperResponse>, String> {
        // Trigger Missing → Receive mode.
        Ok(None)
    }
    fn upsert_amk_wrapper(
        &self,
        _key_prefix: &str,
        wrapped_amk: &str,
        _nonce: &str,
        _amk_commit: &str,
        _version: i16,
    ) -> Result<(), String> {
        // Capture the wrapped ciphertext as proof we got here. The test
        // doesn't need to assert the exact value — just that some payload
        // came through.
        let bytes = URL_SAFE_NO_PAD
            .decode(wrapped_amk)
            .map_err(|e| e.to_string())?;
        *self.upserted.lock().unwrap() = Some(bytes);
        Ok(())
    }

    fn pair_start(&self, req: PairStartRequest) -> Result<PairStartResponse, String> {
        *self.displayer_pubkey_b64.lock().unwrap() = Some(req.ecdh_public_key);
        Ok(PairStartResponse {
            user_code: self.user_code.clone(),
            displayer_poll_token: self.poll_token.clone(),
            expires_at: "2099-01-01T00:00:00Z".into(),
        })
    }

    fn pair_poll(&self, poll_token: &str) -> Result<PairPollOutcome, String> {
        if poll_token != self.poll_token {
            return Ok(PairPollOutcome::Expired);
        }
        // First call: build a real Approved transfer encrypted to the
        // captured displayer pubkey. Second call: Expired.
        let mut delivered = self.delivered.lock().unwrap();
        if *delivered {
            return Ok(PairPollOutcome::Expired);
        }
        *delivered = true;

        let displayer_pk_b64 = self
            .displayer_pubkey_b64
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "pair_start was never called".to_string())?;
        let displayer_pk = URL_SAFE_NO_PAD
            .decode(&displayer_pk_b64)
            .map_err(|e| e.to_string())?;

        let rng = SystemRandom::new();
        let joiner_priv = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(|_| "joiner keygen failed".to_string())?;
        let joiner_pub = joiner_priv
            .compute_public_key()
            .map_err(|_| "joiner pubkey failed".to_string())?;
        let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &displayer_pk);

        let shared = agreement::agree_ephemeral(joiner_priv, &peer, |s| s.to_vec())
            .map_err(|_| "ECDH agreement failed".to_string())?;
        let transfer_key =
            secrt_core::amk::derive_transfer_key(&shared).map_err(|e| e.to_string())?;

        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce).map_err(|_| "rng".to_string())?;

        let ct = secrt_core::amk::aes256gcm_encrypt(
            &transfer_key,
            &nonce,
            b"secrt-amk-transfer-v1",
            &self.amk_bytes,
        )
        .map_err(|e| e.to_string())?;

        Ok(PairPollOutcome::Approved {
            amk_transfer: PairTransferBlob {
                ct: URL_SAFE_NO_PAD.encode(&ct),
                nonce: URL_SAFE_NO_PAD.encode(nonce),
                ecdh_public_key: URL_SAFE_NO_PAD.encode(joiner_pub.as_ref()),
            },
        })
    }

    fn pair_cancel(&self, _poll_token: &str) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn pair_receive_happy_path() {
    let api_key = make_local_api_key();
    let displayer_pubkey_b64 = Arc::new(Mutex::new(None));
    let upserted = Arc::new(Mutex::new(None));
    let delivered = Arc::new(Mutex::new(false));

    let amk = vec![0x42u8; 32];
    let dp_clone = displayer_pubkey_b64.clone();
    let up_clone = upserted.clone();
    let del_clone = delivered.clone();
    let amk_clone = amk.clone();

    let make_api: secrt_cli::cli::MakeApiFn =
        Box::new(move |_base: &str, _key: &str| -> Box<dyn SecretApi> {
            Box::new(PairReceiveMock {
                user_code: "K7MQ-QX2Z".into(),
                poll_token: "test-poll-token".into(),
                displayer_pubkey_b64: dp_clone.clone(),
                amk_bytes: amk_clone.clone(),
                delivered: del_clone.clone(),
                upserted: up_clone.clone(),
            })
        });

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .make_api(make_api)
        .build();

    // Run `secrt pair` (no positional — Receive mode).
    let code = cli::run(&args(&["secrt", "pair", "--silent"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr);

    // The mock recorded an upserted wrapper, proving the CLI decrypted the
    // transfer, ran the wrap+upload pipeline, and finished successfully.
    assert!(upserted.lock().unwrap().is_some(), "no AMK was upserted");
    let _ = stderr;
}

// --- Send mode happy path ---------------------------------------------------

/// A pair-aware mock for Send mode: returns Pending(pubkey) from
/// `pair_challenge` and captures the approve payload for assertion.
struct PairSendMock {
    displayer_pubkey_b64: String,
    approved_with_code: Arc<Mutex<Option<String>>>,
    approved_blob: Arc<Mutex<Option<PairTransferBlob>>>,
}

impl SecretApi for PairSendMock {
    fn create(
        &self,
        _req: secrt_cli::client::CreateRequest,
    ) -> Result<secrt_cli::client::CreateResponse, String> {
        unimplemented!()
    }
    fn claim(&self, _id: &str, _t: &[u8]) -> Result<secrt_cli::client::ClaimResponse, String> {
        unimplemented!()
    }
    fn burn(&self, _id: &str) -> Result<(), String> {
        unimplemented!()
    }
    fn list(
        &self,
        _l: Option<i64>,
        _o: Option<i64>,
    ) -> Result<secrt_cli::client::ListSecretsResponse, String> {
        unimplemented!()
    }
    fn info(&self) -> Result<InfoResponse, String> {
        Ok(ok_info(Some("11111111-1111-1111-1111-111111111111")))
    }

    fn get_amk_wrapper(&self) -> Result<Option<AmkWrapperResponse>, String> {
        // Return a wrapper the CLI can unwrap. Use a real AMK and run the
        // local-amk wrap pipeline so the CLI can unwrap deterministically.
        let local_key = secrt_core::parse_local_api_key(&make_local_api_key()).unwrap();
        let wrap_key = secrt_core::amk::derive_amk_wrap_key(&local_key.root_key).unwrap();
        let user_id_bytes = uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111")
            .unwrap()
            .into_bytes();
        let aad = secrt_core::amk::build_wrap_aad(&user_id_bytes, &local_key.prefix, 1);
        let amk = [0xAAu8; 32];
        let wrapped = secrt_core::amk::wrap_amk(&amk, &wrap_key, &aad, &|buf| {
            for b in buf {
                *b = 0xCC;
            }
            Ok(())
        })
        .unwrap();
        Ok(Some(AmkWrapperResponse {
            user_id: "11111111-1111-1111-1111-111111111111".into(),
            wrapped_amk: URL_SAFE_NO_PAD.encode(&wrapped.ct),
            nonce: URL_SAFE_NO_PAD.encode(&wrapped.nonce),
            version: 1,
        }))
    }

    fn pair_challenge(&self, _user_code: &str) -> Result<PairChallengeOutcome, String> {
        Ok(PairChallengeOutcome::Pending {
            displayer_ecdh_public_key: self.displayer_pubkey_b64.clone(),
        })
    }

    fn pair_approve(&self, req: secrt_cli::client::PairApproveRequest) -> Result<(), String> {
        *self.approved_with_code.lock().unwrap() = Some(req.user_code);
        *self.approved_blob.lock().unwrap() = Some(req.amk_transfer);
        Ok(())
    }
}

fn build_displayer_pubkey() -> String {
    // Generate a real P-256 public key the CLI can encrypt to.
    let rng = SystemRandom::new();
    let priv_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
    let pub_key = priv_key.compute_public_key().unwrap();
    URL_SAFE_NO_PAD.encode(pub_key.as_ref())
}

#[test]
fn pair_send_happy_path() {
    let api_key = make_local_api_key();
    let approved_with_code = Arc::new(Mutex::new(None));
    let approved_blob = Arc::new(Mutex::new(None));
    let code_clone = approved_with_code.clone();
    let blob_clone = approved_blob.clone();
    let displayer_pk = build_displayer_pubkey();

    let make_api: secrt_cli::cli::MakeApiFn =
        Box::new(move |_b: &str, _k: &str| -> Box<dyn SecretApi> {
            Box::new(PairSendMock {
                displayer_pubkey_b64: displayer_pk.clone(),
                approved_with_code: code_clone.clone(),
                approved_blob: blob_clone.clone(),
            })
        });

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .make_api(make_api)
        .build();

    let code = cli::run(&args(&["secrt", "pair", "K7MQ-QX2Z"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert!(stderr.to_string().contains("Account key sent"));
    assert_eq!(
        approved_with_code.lock().unwrap().as_deref(),
        Some("K7MQ-QX2Z"),
        "wrong canonical code reached the wire"
    );
    assert!(
        approved_blob.lock().unwrap().is_some(),
        "no transfer blob was captured"
    );
}

#[test]
fn pair_send_normalizes_lowercase_no_dash() {
    let api_key = make_local_api_key();
    let approved_with_code = Arc::new(Mutex::new(None));
    let approved_blob = Arc::new(Mutex::new(None));
    let code_clone = approved_with_code.clone();
    let blob_clone = approved_blob.clone();
    let displayer_pk = build_displayer_pubkey();

    let make_api: secrt_cli::cli::MakeApiFn =
        Box::new(move |_b: &str, _k: &str| -> Box<dyn SecretApi> {
            Box::new(PairSendMock {
                displayer_pubkey_b64: displayer_pk.clone(),
                approved_with_code: code_clone.clone(),
                approved_blob: blob_clone.clone(),
            })
        });

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .make_api(make_api)
        .build();

    // Lowercase + no dash.
    let code = cli::run(&args(&["secrt", "pair", "k7mqqx2z"]), &mut deps);
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert_eq!(
        approved_with_code.lock().unwrap().as_deref(),
        Some("K7MQ-QX2Z"),
        "lenient parser did not canonicalize"
    );
}

#[test]
fn pair_send_challenge_not_found_exits_1() {
    let api_key = make_local_api_key();

    struct M;
    impl SecretApi for M {
        fn create(
            &self,
            _r: secrt_cli::client::CreateRequest,
        ) -> Result<secrt_cli::client::CreateResponse, String> {
            unimplemented!()
        }
        fn claim(&self, _i: &str, _t: &[u8]) -> Result<secrt_cli::client::ClaimResponse, String> {
            unimplemented!()
        }
        fn burn(&self, _i: &str) -> Result<(), String> {
            unimplemented!()
        }
        fn list(
            &self,
            _l: Option<i64>,
            _o: Option<i64>,
        ) -> Result<secrt_cli::client::ListSecretsResponse, String> {
            unimplemented!()
        }
        fn info(&self) -> Result<InfoResponse, String> {
            Ok(ok_info(Some("11111111-1111-1111-1111-111111111111")))
        }
        fn get_amk_wrapper(&self) -> Result<Option<AmkWrapperResponse>, String> {
            // Reuse the same valid-wrapper construction as the send happy
            // path so the CLI proceeds to challenge.
            let local_key = secrt_core::parse_local_api_key(&make_local_api_key()).unwrap();
            let wrap_key = secrt_core::amk::derive_amk_wrap_key(&local_key.root_key).unwrap();
            let user_id_bytes = uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111")
                .unwrap()
                .into_bytes();
            let aad = secrt_core::amk::build_wrap_aad(&user_id_bytes, &local_key.prefix, 1);
            let amk = [0xAAu8; 32];
            let wrapped = secrt_core::amk::wrap_amk(&amk, &wrap_key, &aad, &|buf| {
                for b in buf {
                    *b = 0xCC;
                }
                Ok(())
            })
            .unwrap();
            Ok(Some(AmkWrapperResponse {
                user_id: "11111111-1111-1111-1111-111111111111".into(),
                wrapped_amk: URL_SAFE_NO_PAD.encode(&wrapped.ct),
                nonce: URL_SAFE_NO_PAD.encode(&wrapped.nonce),
                version: 1,
            }))
        }
        fn pair_challenge(&self, _user_code: &str) -> Result<PairChallengeOutcome, String> {
            Ok(PairChallengeOutcome::NotFound)
        }
    }

    let make_api: secrt_cli::cli::MakeApiFn =
        Box::new(|_b: &str, _k: &str| -> Box<dyn SecretApi> { Box::new(M) });

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .make_api(make_api)
        .build();
    let code = cli::run(&args(&["secrt", "pair", "K7MQ-QX2Z"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr);
    let err = stderr.to_string();
    assert!(
        err.contains("no pairing slot for that code") || err.contains("check the code"),
        "should explain NotFound clearly: {}",
        err
    );
}

// --- URL acceptance (full integration through the leak guard) ---------------

/// Helper that runs Send mode with a configurable positional input and a
/// configurable base URL. Returns (exit_code, stderr_string,
/// captured_code_on_wire).
fn run_send_with_positional(base_url: &str, positional: &str) -> (i32, String, Option<String>) {
    let api_key = make_local_api_key();
    let approved_with_code = Arc::new(Mutex::new(None));
    let approved_blob = Arc::new(Mutex::new(None));
    let code_clone = approved_with_code.clone();
    let blob_clone = approved_blob.clone();
    let displayer_pk = build_displayer_pubkey();

    let make_api: secrt_cli::cli::MakeApiFn =
        Box::new(move |_b: &str, _k: &str| -> Box<dyn SecretApi> {
            Box::new(PairSendMock {
                displayer_pubkey_b64: displayer_pk.clone(),
                approved_with_code: code_clone.clone(),
                approved_blob: blob_clone.clone(),
            })
        });

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        .env("SECRET_BASE_URL", base_url)
        .make_api(make_api)
        .build();
    let code = cli::run(&args(&["secrt", "pair", positional]), &mut deps);
    let captured = approved_with_code.lock().unwrap().clone();
    (code, stderr.to_string(), captured)
}

#[test]
fn pair_send_accepts_full_url() {
    let (code, err, captured) =
        run_send_with_positional("https://secrt.ca", "https://secrt.ca/pair?code=K7MQ-QX2Z");
    assert_eq!(code, 0, "stderr: {err}");
    assert_eq!(captured.as_deref(), Some("K7MQ-QX2Z"));
}

#[test]
fn pair_send_accepts_schemeless_url() {
    let (code, err, captured) =
        run_send_with_positional("https://secrt.ca", "secrt.ca/pair?code=K7MQ-QX2Z");
    assert_eq!(code, 0, "stderr: {err}");
    assert_eq!(captured.as_deref(), Some("K7MQ-QX2Z"));
}

#[test]
fn pair_send_accepts_http_localhost_url() {
    let (code, err, captured) = run_send_with_positional(
        "http://localhost:8081",
        "http://localhost:8081/pair?code=k7mqqx2z",
    );
    assert_eq!(code, 0, "stderr: {err}");
    assert_eq!(captured.as_deref(), Some("K7MQ-QX2Z"));
}

#[test]
fn pair_send_accepts_url_with_extra_query_params() {
    let (code, err, captured) = run_send_with_positional(
        "https://secrt.ca",
        "https://secrt.ca/pair?ref=mobile&code=K7MQ-QX2Z&utm_source=qr",
    );
    assert_eq!(code, 0, "stderr: {err}");
    assert_eq!(captured.as_deref(), Some("K7MQ-QX2Z"));
}

#[test]
fn pair_send_accepts_self_hosted_host_when_configured() {
    let (code, err, captured) =
        run_send_with_positional("https://secrt.is", "https://secrt.is/pair?code=K7MQ-QX2Z");
    assert_eq!(code, 0, "stderr: {err}");
    assert_eq!(captured.as_deref(), Some("K7MQ-QX2Z"));
}

#[test]
fn pair_send_rejects_cross_instance_url() {
    // Leak guard fires when (a) no base is explicitly configured AND
    // (b) the URL would override it to a different host. With
    // `SECRET_BASE_URL` set, the configured base wins and the URL host is
    // ignored entirely (so no leak risk) — covered separately above.
    //
    // Here we leave the base URL unset (default `https://secrt.ca` via the
    // CLI's own defaulting) and feed a URL pointing at a hostile host. The
    // guard must catch the mismatch and exit 2 before any approve call.
    let api_key = make_local_api_key();
    let approved_with_code = Arc::new(Mutex::new(None));
    let approved_blob = Arc::new(Mutex::new(None));
    let code_clone = approved_with_code.clone();
    let blob_clone = approved_blob.clone();
    let displayer_pk = build_displayer_pubkey();

    let make_api: secrt_cli::cli::MakeApiFn =
        Box::new(move |_b: &str, _k: &str| -> Box<dyn SecretApi> {
            Box::new(PairSendMock {
                displayer_pubkey_b64: displayer_pk.clone(),
                approved_with_code: code_clone.clone(),
                approved_blob: blob_clone.clone(),
            })
        });

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", &api_key)
        // Intentionally do NOT set SECRET_BASE_URL — source becomes
        // Default, which lets derive_base_url_from_url promote the URL
        // to base_url and the leak guard then catches the mismatch.
        .make_api(make_api)
        .build();
    let code = cli::run(
        &args(&[
            "secrt",
            "pair",
            "https://attacker.example/pair?code=K7MQ-QX2Z",
        ]),
        &mut deps,
    );
    assert_eq!(
        code, 2,
        "cross-instance URL should exit 2 via leak guard. stderr: {stderr}"
    );
    assert!(
        approved_with_code.lock().unwrap().is_none(),
        "approve must not have been called when the leak guard blocked"
    );
}

#[test]
fn pair_send_rejects_non_pair_url() {
    // URL is well-formed but points at the wrong path — parser should
    // reject before any network call.
    let (code, _err, captured) =
        run_send_with_positional("https://secrt.ca", "https://secrt.ca/sync?code=K7MQ-QX2Z");
    assert_eq!(code, 2, "non-pair URL should exit 2");
    assert!(captured.is_none());
}

#[test]
fn pair_send_rejects_pair_url_with_no_code_param() {
    let (code, _err, captured) =
        run_send_with_positional("https://secrt.ca", "https://secrt.ca/pair");
    assert_eq!(code, 2, "pair URL missing code should exit 2");
    assert!(captured.is_none());
}
