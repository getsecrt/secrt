//! Integration tests for the `/api/v1/auth/pair/*` endpoint family.
//!
//! These exercise the web-to-web AMK pairing flow end-to-end against an
//! in-memory store, mirroring the `device_*` test patterns in
//! `crates/secrt-server/src/http/mod.rs` but with the constraints that
//! distinguish web-pair from device-auth:
//!
//! - both displayer and joiner must be authenticated
//! - the slot is bound to a single `user_id` and cross-user access is 403
//! - approve does NOT mint an API key
//! - claim/approve/cancel use compare-and-set transitions
//! - response surface never exposes IP or IP-derived correlation tokens

mod helpers;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use helpers::webauthn::TestPasskey;
use helpers::{test_app_with_store, test_config, with_remote, MemStore};
use serde_json::{json, Value};
use tower::ServiceExt;

// Valid 65-byte uncompressed P-256 public keys (0x04 + 64 bytes), base64url.
// Reused verbatim from the device-auth test fixtures at
// `crates/secrt-server/src/http/mod.rs` so the exact-byte-shape validators
// are exercised on the same shapes the rest of the suite covers.
const ECDH_KEY_A: &str =
    "BEFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE";
const ECDH_KEY_B: &str =
    "BEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";
// Valid 12-byte AES-GCM nonce + 48-byte ciphertext (32 AMK + 16 GCM tag).
const NONCE: &str = "Tk5OTk5OTk5OTk5O";
const CT: &str = "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0ND";

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).expect("json parse")
}

/// Register a fresh user via passkey ceremony and return their session token.
async fn register_user(app: &axum::Router, name: &str) -> String {
    let pk = TestPasskey::generate();
    let v = pk.register(app, name).await;
    v["session_token"].as_str().expect("session_token").into()
}

fn fire(
    app: &axum::Router,
    req: Request<Body>,
) -> impl std::future::Future<Output = axum::response::Response> + 'static {
    let app = app.clone();
    let req = with_remote(req, [198, 51, 100, 10], 12345);
    async move { app.oneshot(req).await.expect("response") }
}

/// POST /api/v1/auth/pair/start
async fn pair_start(app: &axum::Router, token: &str, body: Value) -> axum::response::Response {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/pair/start")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("user-agent", "Mozilla/5.0 (TestBrowser/1.0)")
        .body(Body::from(body.to_string()))
        .expect("request");
    fire(app, req).await
}

async fn pair_poll(app: &axum::Router, token: &str, poll_token: &str) -> axum::response::Response {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/pair/poll")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({ "poll_token": poll_token }).to_string()))
        .expect("request");
    fire(app, req).await
}

async fn pair_claim(
    app: &axum::Router,
    token: &str,
    user_code: &str,
    ecdh_key: &str,
) -> axum::response::Response {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/pair/claim")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("user-agent", "Mozilla/5.0 (Joiner/2.0)")
        .body(Body::from(
            json!({
                "user_code": user_code,
                "ecdh_public_key": ecdh_key,
            })
            .to_string(),
        ))
        .expect("request");
    fire(app, req).await
}

async fn pair_challenge(
    app: &axum::Router,
    token: &str,
    user_code: &str,
) -> axum::response::Response {
    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "/api/v1/auth/pair/challenge?user_code={}",
            urlencoding::encode(user_code)
        ))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    fire(app, req).await
}

async fn pair_approve(
    app: &axum::Router,
    token: &str,
    user_code: &str,
    amk_transfer: Value,
) -> axum::response::Response {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/pair/approve")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "user_code": user_code,
                "amk_transfer": amk_transfer,
            })
            .to_string(),
        ))
        .expect("request");
    fire(app, req).await
}

async fn pair_cancel(
    app: &axum::Router,
    token: &str,
    poll_token: &str,
) -> axum::response::Response {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/pair/cancel")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({ "poll_token": poll_token }).to_string()))
        .expect("request");
    fire(app, req).await
}

fn amk_transfer_json(ecdh_key: &str) -> Value {
    json!({ "ct": CT, "nonce": NONCE, "ecdh_public_key": ecdh_key })
}

fn count_web_pair_rows(store: &Arc<MemStore>) -> usize {
    store
        .challenges
        .lock()
        .unwrap()
        .values()
        .filter(|c| c.purpose == "web-pair")
        .count()
}

// --- Test 1: role=receive end-to-end ---
//
// Receiver displays → sender joins → AMK delivers exactly once.
#[tokio::test]
async fn pair_role_receive_end_to_end() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;

    // Receiver displays: /start with pubkey.
    let start = body_json(
        pair_start(
            &app,
            &token,
            json!({ "role": "receive", "ecdh_public_key": ECDH_KEY_A }),
        )
        .await,
    )
    .await;
    let user_code = start["user_code"].as_str().expect("user_code").to_string();
    let displayer_poll_token = start["displayer_poll_token"]
        .as_str()
        .expect("displayer_poll_token")
        .to_string();

    // Sender (same user, different browser) looks up the slot.
    let chal = body_json(pair_challenge(&app, &token, &user_code).await).await;
    assert_eq!(chal["role"], "receive");
    assert_eq!(chal["displayer_ecdh_public_key"], ECDH_KEY_A);

    // Sender approves with amk_transfer (no /claim — role=receive skips it).
    let approve = pair_approve(&app, &token, &user_code, amk_transfer_json(ECDH_KEY_B)).await;
    assert_eq!(approve.status(), StatusCode::OK);

    // Receiver polls and gets the payload exactly once.
    let poll = body_json(pair_poll(&app, &token, &displayer_poll_token).await).await;
    assert_eq!(poll["status"], "approved");
    assert_eq!(poll["amk_transfer"]["ct"], CT);
    assert_eq!(poll["amk_transfer"]["nonce"], NONCE);
    assert_eq!(poll["amk_transfer"]["ecdh_public_key"], ECDH_KEY_B);

    // Slot is consumed atomically: subsequent poll returns expired terminal.
    let poll2 = body_json(pair_poll(&app, &token, &displayer_poll_token).await).await;
    assert_eq!(poll2["status"], "expired");
    assert!(poll2
        .get("amk_transfer")
        .map(|v| v.is_null())
        .unwrap_or(true));
}

// --- Test 2: role=send end-to-end ---
//
// Sender displays → receiver claims (supplying pubkey) → sender approves.
#[tokio::test]
async fn pair_role_send_end_to_end() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;

    let start = body_json(pair_start(&app, &token, json!({ "role": "send" })).await).await;
    let user_code = start["user_code"].as_str().unwrap().to_string();
    let displayer_token = start["displayer_poll_token"].as_str().unwrap().to_string();

    // Receiver claims with their pubkey.
    let claim = body_json(pair_claim(&app, &token, &user_code, ECDH_KEY_B).await).await;
    let joiner_token = claim["joiner_poll_token"].as_str().unwrap().to_string();

    // Sender's poll surfaces joiner metadata (UA + timestamp + pubkey).
    let displayer_poll = body_json(pair_poll(&app, &token, &displayer_token).await).await;
    assert_eq!(displayer_poll["status"], "claimed");
    assert_eq!(displayer_poll["peer_ecdh_public_key"], ECDH_KEY_B);
    assert!(displayer_poll["joiner_user_agent"]
        .as_str()
        .unwrap()
        .contains("Joiner/2.0"));
    assert!(displayer_poll["joiner_seen_at"].is_string());

    // Sender approves.
    let approve = pair_approve(&app, &token, &user_code, amk_transfer_json(ECDH_KEY_A)).await;
    assert_eq!(approve.status(), StatusCode::OK);

    // Receiver polls with joiner_poll_token and gets the payload.
    let recv_poll = body_json(pair_poll(&app, &token, &joiner_token).await).await;
    assert_eq!(recv_poll["status"], "approved");
    assert_eq!(recv_poll["amk_transfer"]["ct"], CT);
}

// --- Test 3: cross-user reject (Codex #1) ---
//
// Bob's session attempts to access a slot Alice created. Every endpoint 403s,
// even when Bob has the right user_code or stolen displayer_poll_token.
#[tokio::test]
async fn pair_rejects_cross_user() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let alice = register_user(&app, "Alice").await;
    let bob = register_user(&app, "Bob").await;

    let start = body_json(
        pair_start(
            &app,
            &alice,
            json!({ "role": "receive", "ecdh_public_key": ECDH_KEY_A }),
        )
        .await,
    )
    .await;
    let user_code = start["user_code"].as_str().unwrap().to_string();
    let displayer_token = start["displayer_poll_token"].as_str().unwrap().to_string();

    // Bob attempts /challenge — 403.
    let chal = pair_challenge(&app, &bob, &user_code).await;
    assert_eq!(chal.status(), StatusCode::FORBIDDEN);

    // Bob attempts /approve — 403.
    let appr = pair_approve(&app, &bob, &user_code, amk_transfer_json(ECDH_KEY_B)).await;
    assert_eq!(appr.status(), StatusCode::FORBIDDEN);

    // Bob attempts /poll with Alice's token — 403.
    let poll = pair_poll(&app, &bob, &displayer_token).await;
    assert_eq!(poll.status(), StatusCode::FORBIDDEN);

    // Bob attempts /cancel with Alice's token — 403.
    let cancel = pair_cancel(&app, &bob, &displayer_token).await;
    assert_eq!(cancel.status(), StatusCode::FORBIDDEN);

    // Bob attempts /claim against Alice's role=send slot — separate setup
    // because the above slot is role=receive (no claim path).
    let send_start = body_json(pair_start(&app, &alice, json!({ "role": "send" })).await).await;
    let send_user_code = send_start["user_code"].as_str().unwrap();
    let bob_claim = pair_claim(&app, &bob, send_user_code, ECDH_KEY_B).await;
    assert_eq!(bob_claim.status(), StatusCode::FORBIDDEN);
}

// --- Test 4: approve does NOT mint an API key (Codex #2) ---
#[tokio::test]
async fn pair_approve_does_not_mint_api_key() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;
    let api_keys_before = store.keys.lock().unwrap().len();

    let start = body_json(
        pair_start(
            &app,
            &token,
            json!({ "role": "receive", "ecdh_public_key": ECDH_KEY_A }),
        )
        .await,
    )
    .await;
    let user_code = start["user_code"].as_str().unwrap();

    let approve = pair_approve(&app, &token, user_code, amk_transfer_json(ECDH_KEY_B)).await;
    assert_eq!(approve.status(), StatusCode::OK);

    // No API key materialized in the store. This is the contract that
    // distinguishes web-pair from device-auth `/approve` (which DOES mint).
    let api_keys_after = store.keys.lock().unwrap().len();
    assert_eq!(api_keys_before, api_keys_after);
}

// --- Test 5: /claim rejects wrong user_code with 409 (constant-time path) ---
#[tokio::test]
async fn pair_claim_rejects_wrong_code() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;
    let _ = pair_start(&app, &token, json!({ "role": "send" })).await;

    let bad = pair_claim(&app, &token, "WRONG-CODE", ECDH_KEY_B).await;
    assert_eq!(bad.status(), StatusCode::CONFLICT);
}

// --- Test 6: sequential single-claim invariant ---
//
// Once /claim succeeds (status pending → claimed), a second /claim with the
// same user_code returns 409. This is the easy-path counterpart to test 7
// (concurrent double-claim).
#[tokio::test]
async fn pair_claim_rejects_after_pubkey_already_set() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;

    let start = body_json(pair_start(&app, &token, json!({ "role": "send" })).await).await;
    let user_code = start["user_code"].as_str().unwrap().to_string();

    let first = pair_claim(&app, &token, &user_code, ECDH_KEY_B).await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = pair_claim(&app, &token, &user_code, ECDH_KEY_A).await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

// --- Test 7: concurrent double-claim — exactly one winner (Codex #7) ---
//
// Spawn two simultaneous /claim requests against the same role=send slot.
// The compare-and-set predicate in `cas_update_challenge_json` must ensure
// exactly one succeeds and the other gets 409 — no "both succeed" failure
// where the second pubkey silently overwrites the first.
#[tokio::test]
async fn pair_claim_concurrent_double_claim() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;

    let start = body_json(pair_start(&app, &token, json!({ "role": "send" })).await).await;
    let user_code = start["user_code"].as_str().unwrap().to_string();

    let app1 = app.clone();
    let app2 = app.clone();
    let token1 = token.clone();
    let token2 = token.clone();
    let code1 = user_code.clone();
    let code2 = user_code.clone();

    let h1 = tokio::spawn(async move { pair_claim(&app1, &token1, &code1, ECDH_KEY_A).await });
    let h2 = tokio::spawn(async move { pair_claim(&app2, &token2, &code2, ECDH_KEY_B).await });

    let r1 = h1.await.unwrap();
    let r2 = h2.await.unwrap();

    let s1 = r1.status();
    let s2 = r2.status();
    let oks = (s1 == StatusCode::OK) as u8 + (s2 == StatusCode::OK) as u8;
    let conflicts = (s1 == StatusCode::CONFLICT) as u8 + (s2 == StatusCode::CONFLICT) as u8;
    assert_eq!(
        (oks, conflicts),
        (1, 1),
        "expected exactly one OK and one CONFLICT, got {s1:?} and {s2:?}"
    );
}

// --- Test 8: /cancel terminates polls on both sides ---
#[tokio::test]
async fn pair_cancel_terminates_polls() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;

    let start = body_json(pair_start(&app, &token, json!({ "role": "send" })).await).await;
    let user_code = start["user_code"].as_str().unwrap().to_string();
    let displayer_token = start["displayer_poll_token"].as_str().unwrap().to_string();

    let claim = body_json(pair_claim(&app, &token, &user_code, ECDH_KEY_B).await).await;
    let joiner_token = claim["joiner_poll_token"].as_str().unwrap().to_string();

    // Displayer cancels.
    let cancel = pair_cancel(&app, &token, &displayer_token).await;
    assert_eq!(cancel.status(), StatusCode::OK);

    // Both sides see the terminal status on their next poll.
    let d_poll = body_json(pair_poll(&app, &token, &displayer_token).await).await;
    let j_poll = body_json(pair_poll(&app, &token, &joiner_token).await).await;
    assert_eq!(d_poll["status"], "cancelled");
    assert_eq!(j_poll["status"], "cancelled");
    // No payload leaked on cancel.
    assert!(d_poll
        .get("amk_transfer")
        .map(|v| v.is_null())
        .unwrap_or(true));
    assert!(j_poll
        .get("amk_transfer")
        .map(|v| v.is_null())
        .unwrap_or(true));
}

// --- Test 9: poll response never exposes IP / IP-hash; geo_label null in v1 (Codex #6) ---
#[tokio::test]
async fn pair_no_ip_in_poll_response() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;

    let start = body_json(pair_start(&app, &token, json!({ "role": "send" })).await).await;
    let user_code = start["user_code"].as_str().unwrap().to_string();
    let displayer_token = start["displayer_poll_token"].as_str().unwrap().to_string();
    let _ = pair_claim(&app, &token, &user_code, ECDH_KEY_B).await;

    let poll = body_json(pair_poll(&app, &token, &displayer_token).await).await;
    let obj = poll.as_object().expect("object");
    assert!(!obj.contains_key("joiner_ip"));
    assert!(!obj.contains_key("joiner_ip_hash"));
    // geo_label is `null` in v1 — either absent (skip_serializing_if) or null.
    let geo = poll.get("joiner_geo_label");
    assert!(geo.is_none() || geo.unwrap().is_null());
    // UA is surfaced as expected (advisory).
    assert!(poll["joiner_user_agent"].is_string());
}

// --- Test 10: slot rows deleted on expiry — privacy-posture regression guard ---
//
// Run a full pair flow, advance the clock past `expires_at`, run the
// reaper's `delete_expired`, and assert no `purpose='web-pair'` rows
// remain. Captures the contract that captured `joiner_user_agent` strings
// do not outlive their slot.
#[tokio::test]
async fn pair_slot_deleted_at_expiry() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;

    let _ = pair_start(
        &app,
        &token,
        json!({ "role": "receive", "ecdh_public_key": ECDH_KEY_A }),
    )
    .await;
    assert_eq!(count_web_pair_rows(&store), 1);

    // Advance past the 10-minute slot TTL. The production Postgres reaper
    // executes `DELETE_EXPIRED_CHALLENGES_SQL` (see
    // crates/secrt-server/src/storage/postgres.rs) which removes all
    // expired rows wholesale. The in-tree MemStore doesn't share that
    // batch-delete primitive, so simulate the reaper's effect directly.
    let after_expiry = Utc::now() + Duration::seconds(700);
    {
        let mut m = store.challenges.lock().unwrap();
        m.retain(|_, c| c.expires_at > after_expiry);
    }

    assert_eq!(
        count_web_pair_rows(&store),
        0,
        "web-pair slots must be deleted at expiry, not retained"
    );
}

// --- Test 11: /challenge returns distinguishable terminal states (409 + state) ---
#[tokio::test]
async fn pair_challenge_returns_409_for_terminal_states() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;

    // 'cancelled' state.
    let s = body_json(pair_start(&app, &token, json!({ "role": "send" })).await).await;
    let code = s["user_code"].as_str().unwrap().to_string();
    let dt = s["displayer_poll_token"].as_str().unwrap().to_string();
    let _ = pair_cancel(&app, &token, &dt).await;
    let chal = pair_challenge(&app, &token, &code).await;
    assert_eq!(chal.status(), StatusCode::CONFLICT);
    let body = body_json(chal).await;
    assert_eq!(body["state"], "cancelled");

    // 'approved' state.
    let s2 = body_json(
        pair_start(
            &app,
            &token,
            json!({ "role": "receive", "ecdh_public_key": ECDH_KEY_A }),
        )
        .await,
    )
    .await;
    let code2 = s2["user_code"].as_str().unwrap().to_string();
    let _ = pair_approve(&app, &token, &code2, amk_transfer_json(ECDH_KEY_B)).await;
    let chal2 = pair_challenge(&app, &token, &code2).await;
    assert_eq!(chal2.status(), StatusCode::CONFLICT);
    let body2 = body_json(chal2).await;
    assert_eq!(body2["state"], "approved");

    // 'claimed' state (role=send slot after a successful /claim).
    let s3 = body_json(pair_start(&app, &token, json!({ "role": "send" })).await).await;
    let code3 = s3["user_code"].as_str().unwrap().to_string();
    let _ = pair_claim(&app, &token, &code3, ECDH_KEY_B).await;
    let chal3 = pair_challenge(&app, &token, &code3).await;
    assert_eq!(chal3.status(), StatusCode::CONFLICT);
    let body3 = body_json(chal3).await;
    assert_eq!(body3["state"], "claimed");

    // Nonexistent code — 404, not 409.
    let chal4 = pair_challenge(&app, &token, "NOPE-NOPE").await;
    assert_eq!(chal4.status(), StatusCode::NOT_FOUND);
}

// --- Test 12: amk_transfer field-shape validation ---
#[tokio::test]
async fn pair_amk_transfer_field_validation() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;

    let s = body_json(
        pair_start(
            &app,
            &token,
            json!({ "role": "receive", "ecdh_public_key": ECDH_KEY_A }),
        )
        .await,
    )
    .await;
    let code = s["user_code"].as_str().unwrap().to_string();

    // Wrong nonce length.
    let bad_nonce = json!({
        "ct": CT,
        "nonce": "c2hvcnQ", // 5 bytes when decoded
        "ecdh_public_key": ECDH_KEY_B,
    });
    let r = pair_approve(&app, &token, &code, bad_nonce).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // Wrong ct length.
    let bad_ct = json!({
        "ct": "c2hvcnQ",
        "nonce": NONCE,
        "ecdh_public_key": ECDH_KEY_B,
    });
    let r = pair_approve(&app, &token, &code, bad_ct).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // Wrong ecdh key length.
    let bad_ek = json!({
        "ct": CT,
        "nonce": NONCE,
        "ecdh_public_key": "c2hvcnQ",
    });
    let r = pair_approve(&app, &token, &code, bad_ek).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

// --- Test 13: /start role-pubkey validation ---
//
// role=receive must include ecdh_public_key; role=send must not.
#[tokio::test]
async fn pair_start_role_pubkey_validation() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;

    // role=receive without pubkey → 400.
    let r = pair_start(&app, &token, json!({ "role": "receive" })).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // role=send WITH pubkey → 400.
    let r = pair_start(
        &app,
        &token,
        json!({ "role": "send", "ecdh_public_key": ECDH_KEY_A }),
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // role=receive with malformed pubkey → 400.
    let r = pair_start(
        &app,
        &token,
        json!({ "role": "receive", "ecdh_public_key": "not-a-key" }),
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

// --- Test 14: wrong HTTP methods return 405 ---
//
// Each pair endpoint has an explicit `req.method() != ... → method_not_allowed`
// guard. This test fires the wrong verb at each path and asserts 405.
// (Coverage gap fill: every handler had its first "wrong method" branch
// uncovered by the happy-path tests above.)
#[tokio::test]
async fn pair_endpoints_reject_wrong_method() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());

    // Use a real session token so we get past auth and hit the method check.
    // (Method check fires before auth in our handlers.)
    let token = register_user(&app, "Alice").await;

    let cases: Vec<(&str, &str)> = vec![
        // /start, /poll, /claim, /approve, /cancel are POST-only — try GET.
        ("GET", "/api/v1/auth/pair/start"),
        ("GET", "/api/v1/auth/pair/poll"),
        ("GET", "/api/v1/auth/pair/claim"),
        ("GET", "/api/v1/auth/pair/approve"),
        ("GET", "/api/v1/auth/pair/cancel"),
        // /challenge is GET-only — try POST.
        ("POST", "/api/v1/auth/pair/challenge?user_code=X"),
    ];

    for (method, path) in cases {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .expect("request");
        let resp = fire(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "expected 405 for {method} {path}"
        );
    }
}

// --- Test 15: /poll with an unknown token returns terminal 'expired', not 500 ---
//
// A polling client whose slot was reaped between polls (or who fat-fingers
// a token) should see a clean terminal state, not an error. This exercises
// the dual-lookup-then-fallthrough path in handle_pair_poll_entry.
#[tokio::test]
async fn pair_poll_unknown_token_returns_expired() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;

    let resp = pair_poll(&app, &token, "totally-bogus-token-that-does-not-exist").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "expired");
    assert!(body
        .get("amk_transfer")
        .map(|v| v.is_null())
        .unwrap_or(true));
}

// --- Test 16: /cancel works via joiner's poll token, not just displayer's ---
//
// The cancel handler has a dual-lookup (primary key, then JSON scan) so
// either side can cancel. Coverage gap: only displayer-side cancel was
// exercised by `pair_cancel_terminates_polls`.
#[tokio::test]
async fn pair_cancel_by_joiner_poll_token() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;

    let start = body_json(pair_start(&app, &token, json!({ "role": "send" })).await).await;
    let user_code = start["user_code"].as_str().unwrap().to_string();
    let displayer_token = start["displayer_poll_token"].as_str().unwrap().to_string();

    let claim = body_json(pair_claim(&app, &token, &user_code, ECDH_KEY_B).await).await;
    let joiner_token = claim["joiner_poll_token"].as_str().unwrap().to_string();

    // Joiner cancels using their own token.
    let cancel = pair_cancel(&app, &token, &joiner_token).await;
    assert_eq!(cancel.status(), StatusCode::OK);

    // Both sides see 'cancelled'.
    let d_poll = body_json(pair_poll(&app, &token, &displayer_token).await).await;
    let j_poll = body_json(pair_poll(&app, &token, &joiner_token).await).await;
    assert_eq!(d_poll["status"], "cancelled");
    assert_eq!(j_poll["status"], "cancelled");
}

// --- Test 17: /cancel is idempotent after terminal states ---
//
// A second /cancel against an already-cancelled or already-approved slot
// returns OK without corrupting state. Also covers the "unknown token"
// idempotent-success branch.
#[tokio::test]
async fn pair_cancel_idempotent_after_terminal() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());
    let token = register_user(&app, "Alice").await;

    // Already-cancelled slot.
    let s1 = body_json(pair_start(&app, &token, json!({ "role": "send" })).await).await;
    let dt1 = s1["displayer_poll_token"].as_str().unwrap().to_string();
    let r1a = pair_cancel(&app, &token, &dt1).await;
    let r1b = pair_cancel(&app, &token, &dt1).await;
    assert_eq!(r1a.status(), StatusCode::OK);
    assert_eq!(r1b.status(), StatusCode::OK);

    // Already-approved slot.
    let s2 = body_json(
        pair_start(
            &app,
            &token,
            json!({ "role": "receive", "ecdh_public_key": ECDH_KEY_A }),
        )
        .await,
    )
    .await;
    let code2 = s2["user_code"].as_str().unwrap().to_string();
    let dt2 = s2["displayer_poll_token"].as_str().unwrap().to_string();
    let _ = pair_approve(&app, &token, &code2, amk_transfer_json(ECDH_KEY_B)).await;
    let r2 = pair_cancel(&app, &token, &dt2).await;
    assert_eq!(r2.status(), StatusCode::OK);

    // Cancel of a token that never existed at all — idempotent OK.
    let r3 = pair_cancel(&app, &token, "ghost-token-not-in-any-slot").await;
    assert_eq!(r3.status(), StatusCode::OK);
}

// --- Test 18: unauthenticated requests are 401 across all endpoints ---
//
// Defense-in-depth: confirms session-auth is required at every endpoint.
// `device-auth` deliberately allows anonymous /start (CLI flow); web-pair
// must not.
#[tokio::test]
async fn pair_endpoints_require_session_auth() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store.clone(), test_config());

    let no_auth = |method: &str, path: &str, body: Option<Value>| {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        let body = match body {
            Some(v) => Body::from(v.to_string()),
            None => Body::empty(),
        };
        req.body(body).expect("request")
    };

    let endpoints: Vec<(&str, &str, Option<Value>)> = vec![
        (
            "POST",
            "/api/v1/auth/pair/start",
            Some(json!({ "role": "send" })),
        ),
        (
            "POST",
            "/api/v1/auth/pair/poll",
            Some(json!({ "poll_token": "nope" })),
        ),
        (
            "POST",
            "/api/v1/auth/pair/claim",
            Some(json!({ "user_code": "X", "ecdh_public_key": ECDH_KEY_A })),
        ),
        ("GET", "/api/v1/auth/pair/challenge?user_code=X", None),
        (
            "POST",
            "/api/v1/auth/pair/approve",
            Some(json!({
                "user_code": "X",
                "amk_transfer": amk_transfer_json(ECDH_KEY_A)
            })),
        ),
        (
            "POST",
            "/api/v1/auth/pair/cancel",
            Some(json!({ "poll_token": "nope" })),
        ),
    ];

    for (method, path, body) in endpoints {
        let req = no_auth(method, path, body);
        let resp = fire(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "expected 401 for {method} {path}"
        );
    }
}
