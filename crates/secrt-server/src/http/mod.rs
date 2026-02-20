use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::to_bytes;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::services::ServeDir;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::Config;
use crate::domain::auth::Authenticator;
use crate::domain::limiter::Limiter;
use crate::domain::secret_rules::{
    format_bytes, generate_id, validate_envelope, OwnerHasher, SecretRuleError,
};
use crate::storage::{
    AmkStore, AmkUpsertResult, AmkWrapperRecord, ApiKeyRecord, ApiKeyRegistrationLimits,
    ApiKeysStore, AuthStore, SecretQuotaLimits, SecretRecord, SecretsStore, SessionRecord,
    StorageError, UserId,
};

#[derive(Clone)]
pub struct AppState {
    pub cfg: Config,
    pub secrets: Arc<dyn SecretsStore>,
    pub api_keys: Arc<dyn ApiKeysStore>,
    pub auth_store: Arc<dyn AuthStore>,
    pub amk_store: Arc<dyn AmkStore>,
    pub auth: Authenticator<Arc<dyn ApiKeysStore>>,
    pub public_create_limiter: Limiter,
    pub claim_limiter: Limiter,
    pub api_limiter: Limiter,
    pub apikey_register_limiter: Limiter,
    pub owner_hasher: OwnerHasher,
    pub privacy_checked: Arc<AtomicBool>,
}

impl AppState {
    pub fn new(
        cfg: Config,
        secrets: Arc<dyn SecretsStore>,
        api_keys: Arc<dyn ApiKeysStore>,
        auth_store: Arc<dyn AuthStore>,
        amk_store: Arc<dyn AmkStore>,
    ) -> Self {
        Self {
            public_create_limiter: Limiter::new(cfg.public_create_rate, cfg.public_create_burst),
            claim_limiter: Limiter::new(cfg.claim_rate, cfg.claim_burst),
            api_limiter: Limiter::new(cfg.authed_create_rate, cfg.authed_create_burst),
            apikey_register_limiter: Limiter::new(
                cfg.apikey_register_rate,
                cfg.apikey_register_burst,
            ),
            owner_hasher: OwnerHasher::new(),
            privacy_checked: Arc::new(AtomicBool::new(false)),
            auth: Authenticator::new(cfg.api_key_pepper.clone(), api_keys.clone()),
            auth_store,
            amk_store,
            cfg,
            secrets,
            api_keys,
        }
    }

    pub fn start_limiter_gc(&self) {
        let interval = Duration::from_secs(120);
        let max_idle = Duration::from_secs(600);
        self.public_create_limiter.start_gc(interval, max_idle);
        self.claim_limiter.start_gc(interval, max_idle);
        self.api_limiter.start_gc(interval, max_idle);
        self.apikey_register_limiter.start_gc(interval, max_idle);
    }

    pub fn stop_limiter_gc(&self) {
        self.public_create_limiter.stop();
        self.claim_limiter.stop();
        self.api_limiter.stop();
        self.apikey_register_limiter.stop();
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSecretRequest {
    envelope: Box<RawValue>,
    claim_hash: String,
    ttl_seconds: Option<i64>,
}

#[derive(Serialize)]
struct CreateSecretResponse {
    id: String,
    share_url: String,
    expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimSecretRequest {
    claim: String,
}

#[derive(Serialize)]
struct ClaimSecretResponse {
    envelope: Box<RawValue>,
    expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    time: String,
}

#[derive(Serialize)]
struct InfoResponse {
    authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    ttl: InfoTtl,
    limits: InfoLimits,
    claim_rate: InfoRate,
    features: InfoFeatures,
}

#[derive(Serialize)]
struct InfoFeatures {
    encrypted_notes: bool,
}

#[derive(Serialize)]
struct InfoTtl {
    default_seconds: i64,
    max_seconds: i64,
}

#[derive(Serialize)]
struct InfoLimits {
    public: InfoTier,
    authed: InfoTier,
}

#[derive(Serialize)]
struct InfoTier {
    max_envelope_bytes: i64,
    max_secrets: i64,
    max_total_bytes: i64,
    rate: InfoRate,
}

#[derive(Serialize)]
struct InfoRate {
    requests_per_second: f64,
    burst: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyRegisterStartRequest {
    display_name: String,
}

#[derive(Serialize)]
struct PasskeyStartResponse {
    challenge_id: String,
    challenge: String,
    expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyRegisterFinishRequest {
    challenge_id: String,
    credential_id: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyLoginStartRequest {
    credential_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyLoginFinishRequest {
    challenge_id: String,
    credential_id: String,
}

#[derive(Serialize)]
struct SessionResponse {
    authenticated: bool,
    user_id: Option<Uuid>,
    display_name: Option<String>,
    expires_at: Option<DateTime<Utc>>,
}

/// Query parameters for `GET /api/v1/secrets`.
#[derive(Deserialize)]
pub struct ListSecretsQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterApiKeyRequest {
    auth_token: String,
    scopes: Option<String>,
}

#[derive(Serialize)]
struct RegisterApiKeyResponse {
    prefix: String,
    created_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct SecretMetadataItem {
    id: String,
    share_url: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    ciphertext_size: i64,
    passphrase_protected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    enc_meta: Option<secrt_core::api::EncMetaV1>,
}

#[derive(Serialize)]
struct ListSecretsResponse {
    secrets: Vec<SecretMetadataItem>,
    total: i64,
    limit: i64,
    offset: i64,
}

#[derive(Serialize)]
struct SecretsCheckResponse {
    count: i64,
    checksum: String,
}

#[derive(Serialize)]
struct ApiKeyListItem {
    prefix: String,
    scopes: String,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct ListApiKeysResponse {
    api_keys: Vec<ApiKeyListItem>,
}

#[derive(Serialize)]
struct DeleteAccountResponse {
    ok: bool,
    secrets_burned: i64,
    keys_revoked: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateDisplayNameRequest {
    display_name: String,
}

#[derive(Serialize)]
struct UpdateDisplayNameResponse {
    ok: bool,
    display_name: String,
}

#[derive(Serialize)]
struct PasskeyListItem {
    id: i64,
    label: String,
    created_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct ListPasskeysResponse {
    passkeys: Vec<PasskeyListItem>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdatePasskeyLabelRequest {
    label: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyAddFinishRequest {
    challenge_id: String,
    credential_id: String,
    public_key: String,
}

#[derive(Serialize)]
struct PasskeyAddFinishResponse {
    ok: bool,
    passkey: PasskeyListItem,
}

// --- Device authorization flow types ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceStartRequest {
    auth_token: String,
    #[serde(default)]
    ecdh_public_key: Option<String>,
}

#[derive(Serialize)]
struct DeviceStartResponse {
    device_code: String,
    user_code: String,
    verification_url: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DevicePollRequest {
    device_code: String,
}

#[derive(Serialize)]
struct DevicePollResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amk_transfer: Option<AmkTransferJson>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceApproveRequest {
    user_code: String,
    #[serde(default)]
    amk_transfer: Option<AmkTransferJson>,
}

#[derive(Clone, Serialize, Deserialize)]
struct AmkTransferJson {
    ct: String,
    nonce: String,
    ecdh_public_key: String,
}

#[derive(Serialize, Deserialize)]
struct DeviceChallengeJson {
    user_code: String,
    auth_token_b64: String,
    status: String,
    prefix: Option<String>,
    user_id: Option<String>,
    #[serde(default)]
    ecdh_public_key: Option<String>,
    #[serde(default)]
    amk_transfer: Option<AmkTransferJson>,
}

// --- AMK wrapper types ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpsertAmkWrapperRequest {
    /// Required for session auth; implicit for API key auth.
    #[serde(default)]
    key_prefix: Option<String>,
    wrapped_amk: String,
    nonce: String,
    amk_commit: String,
    version: i16,
}

#[derive(Serialize)]
struct AmkWrapperResponse {
    user_id: Uuid,
    wrapped_amk: String,
    nonce: String,
    version: i16,
}

#[derive(Serialize)]
struct AmkWrappersListItem {
    key_prefix: String,
    version: i16,
    created_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct AmkWrappersListResponse {
    wrappers: Vec<AmkWrappersListItem>,
}

#[derive(Serialize)]
struct AmkExistsResponse {
    exists: bool,
}

// --- Encrypted metadata types ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateEncMetaRequest {
    enc_meta: secrt_core::api::EncMetaV1,
    meta_key_version: i16,
}

/// Query parameter for wrapper GET with session auth.
#[derive(Deserialize)]
pub struct AmkWrapperQuery {
    #[serde(default)]
    key_prefix: Option<String>,
}

/// Query parameter for device challenge GET.
#[derive(Deserialize)]
pub struct DeviceChallengeQuery {
    user_code: String,
}

#[derive(Serialize)]
struct DeviceChallengeResponse {
    user_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecdh_public_key: Option<String>,
    status: String,
}

#[derive(Serialize)]
struct AuthFinishResponse {
    session_token: String,
    user_id: Uuid,
    display_name: String,
    expires_at: DateTime<Utc>,
}

/// Character set for user codes (no ambiguous chars: 0/O, 1/I/L).
const USER_CODE_CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const DEVICE_CODE_LEN: usize = 32;
const DEVICE_AUTH_PURPOSE: &str = "device-auth";
const DEVICE_AUTH_EXPIRY_SECS: i64 = 600;

fn generate_user_code() -> Result<String, ()> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes).map_err(|_| ())?;
    let code: String = bytes
        .iter()
        .map(|b| USER_CODE_CHARS[(*b as usize) % USER_CODE_CHARS.len()] as char)
        .collect();
    Ok(format!("{}-{}", &code[..4], &code[4..]))
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let router = Router::new()
        .route("/healthz", get(handle_healthz))
        .route("/", get(handle_index))
        .route("/sw.js", get(handle_service_worker))
        .route("/s/{id}", get(handle_secret_page))
        // SPA client-side routes — serve the same index.html for all of them
        .route("/login", get(handle_index))
        .route("/register", get(handle_index))
        .route("/how-it-works", get(handle_index))
        .route("/privacy", get(handle_index))
        .route("/dashboard", get(handle_index))
        .route("/settings", get(handle_index))
        .route("/device", get(handle_index))
        .route("/sync/{id}", get(handle_index))
        .route("/robots.txt", get(handle_robots_txt))
        .route("/.well-known/security.txt", get(handle_security_txt));

    // Serve static files: env override → embedded assets → filesystem fallback
    let router = if let Ok(dir) = std::env::var("SECRT_WEB_DIST_DIR") {
        router.nest_service("/static", ServeDir::new(dir))
    } else if crate::assets::has_embedded_assets() {
        router.route("/static/{*path}", get(crate::assets::serve_embedded))
    } else {
        router.nest_service("/static", ServeDir::new("web/dist"))
    };

    router
        .route("/api/v1/info", any(handle_info_entry))
        .route("/api/v1/public/secrets", any(handle_create_public_entry))
        .route("/api/v1/secrets/check", any(handle_secrets_check_entry))
        .route("/api/v1/secrets", any(handle_secrets_entry))
        .route(
            "/api/v1/secrets/{id}",
            any(handle_get_secret_metadata_entry),
        )
        .route("/api/v1/secrets/{id}/claim", any(handle_claim_entry))
        .route("/api/v1/secrets/{id}/burn", any(handle_burn_entry))
        .route(
            "/api/v1/auth/passkeys/register/start",
            any(handle_passkey_register_start_entry),
        )
        .route(
            "/api/v1/auth/passkeys/register/finish",
            any(handle_passkey_register_finish_entry),
        )
        .route(
            "/api/v1/auth/passkeys/login/start",
            any(handle_passkey_login_start_entry),
        )
        .route(
            "/api/v1/auth/passkeys/login/finish",
            any(handle_passkey_login_finish_entry),
        )
        .route("/api/v1/auth/session", any(handle_auth_session_entry))
        .route("/api/v1/auth/logout", any(handle_auth_logout_entry))
        .route(
            "/api/v1/apikeys/register",
            any(handle_apikey_register_entry),
        )
        .route("/api/v1/apikeys", any(handle_list_apikeys_entry))
        .route(
            "/api/v1/apikeys/{prefix}/revoke",
            any(handle_revoke_apikey_entry),
        )
        .route("/api/v1/auth/account", any(handle_account_entry))
        .route(
            "/api/v1/auth/passkeys/add/start",
            any(handle_passkey_add_start_entry),
        )
        .route(
            "/api/v1/auth/passkeys/add/finish",
            any(handle_passkey_add_finish_entry),
        )
        .route(
            "/api/v1/auth/passkeys/{id}/revoke",
            any(handle_revoke_passkey_entry),
        )
        .route("/api/v1/auth/passkeys/{id}", any(handle_passkey_entry))
        .route("/api/v1/auth/passkeys", any(handle_passkeys_list_entry))
        .route("/api/v1/auth/device/start", any(handle_device_start_entry))
        .route("/api/v1/auth/device/poll", any(handle_device_poll_entry))
        .route(
            "/api/v1/auth/device/approve",
            any(handle_device_approve_entry),
        )
        .route(
            "/api/v1/auth/device/challenge",
            any(handle_device_challenge_entry),
        )
        .route("/api/v1/amk/wrapper", any(handle_amk_wrapper_entry))
        .route("/api/v1/amk/wrappers", any(handle_amk_wrappers_list_entry))
        .route("/api/v1/amk/commit", any(handle_amk_commit_entry))
        .route("/api/v1/amk/exists", any(handle_amk_exists_entry))
        .route("/api/v1/secrets/{id}/meta", any(handle_secret_meta_entry))
        .layer(CatchPanicLayer::custom(handle_panic))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            request_middleware,
        ))
        .with_state(state)
}

fn handle_panic(_: Box<dyn std::any::Any + Send + 'static>) -> Response {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
}

async fn request_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    check_privacy_log_header_once(&state, req.headers());

    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(generate_request_id);

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let started = Instant::now();
    let mut resp = next.run(req).await;

    insert_header(resp.headers_mut(), "x-request-id", &request_id);
    insert_header(resp.headers_mut(), "x-content-type-options", "nosniff");
    insert_header(resp.headers_mut(), "referrer-policy", "no-referrer");
    insert_header(resp.headers_mut(), "x-frame-options", "DENY");

    let bytes = response_bytes(&resp);
    let status = resp.status().as_u16();

    info!(
        method = %method,
        path = %path,
        status = status,
        bytes = bytes,
        duration_ms = started.elapsed().as_millis() as u64,
        request_id = %request_id,
        "request"
    );

    resp
}

fn check_privacy_log_header_once(state: &Arc<AppState>, headers: &HeaderMap) {
    if state.privacy_checked.load(Ordering::Relaxed) {
        return;
    }

    if headers.get("x-forwarded-for").is_none() {
        return;
    }

    if state.privacy_checked.swap(true, Ordering::SeqCst) {
        return;
    }

    match headers.get("x-privacy-log").and_then(|v| v.to_str().ok()) {
        Some("truncated-ip") => {
            info!(
                status = "ok",
                mode = "truncated-ip",
                detail = "reverse proxy declares truncated-ip access logging",
                "privacy_log_check"
            );
        }
        None => {
            warn!(
                status = "missing",
                detail = "reverse proxy did not send X-Privacy-Log header; access logs may contain full client IP addresses",
                "privacy_log_check"
            );
        }
        Some(mode) => {
            warn!(
                status = "unknown",
                mode = mode,
                detail =
                    "reverse proxy sent unrecognized X-Privacy-Log value; expected 'truncated-ip'",
                "privacy_log_check"
            );
        }
    }
}

fn response_bytes(resp: &Response) -> usize {
    resp.headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0)
}

fn generate_request_id() -> String {
    use ring::rand::{SecureRandom, SystemRandom};

    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    if rng.fill(&mut bytes).is_err() {
        return "00000000000000000000000000000000".to_string();
    }
    hex::encode(bytes)
}

fn insert_header(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (HeaderName::from_str(name), HeaderValue::from_str(value)) {
        headers.insert(name, value);
    }
}

fn add_cache_control_if_missing(headers: &mut HeaderMap) {
    if !headers.contains_key(CACHE_CONTROL) {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}

fn json_response<T: Serialize>(status: StatusCode, payload: T) -> Response {
    let mut resp = (status, Json(payload)).into_response();
    add_cache_control_if_missing(resp.headers_mut());
    resp
}

fn error_response(status: StatusCode, msg: impl Into<String>) -> Response {
    let mut resp = json_response(status, ErrorResponse { error: msg.into() });
    if status == StatusCode::TOO_MANY_REQUESTS {
        insert_header(resp.headers_mut(), "retry-after", "10");
    }
    resp
}

fn method_not_allowed() -> Response {
    error_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
}

fn unauthorized() -> Response {
    error_response(StatusCode::UNAUTHORIZED, "unauthorized")
}

fn bad_request(msg: impl Into<String>) -> Response {
    error_response(StatusCode::BAD_REQUEST, msg)
}

fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not found")
}

fn internal_server_error() -> Response {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
}

fn rate_limited() -> Response {
    error_response(
        StatusCode::TOO_MANY_REQUESTS,
        "rate limit exceeded; please try again in a few seconds",
    )
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/json"))
        .unwrap_or(false)
}

async fn read_json_body<T: for<'de> Deserialize<'de>>(
    req: Request,
    max_bytes: usize,
    too_large_msg: Option<String>,
) -> Result<T, Response> {
    if !is_json_content_type(req.headers()) {
        return Err(bad_request("content-type must be application/json"));
    }

    let body = to_bytes(req.into_body(), max_bytes).await.map_err(|_| {
        if let Some(msg) = too_large_msg {
            bad_request(msg)
        } else {
            bad_request("invalid request body")
        }
    })?;

    serde_json::from_slice::<T>(&body).map_err(map_decode_error)
}

fn map_decode_error(err: serde_json::Error) -> Response {
    if err.is_data() {
        bad_request("invalid json field type")
    } else {
        bad_request("invalid json")
    }
}

fn get_client_ip(headers: &HeaderMap, connect: Option<SocketAddr>) -> String {
    let Some(addr) = connect else {
        return "unknown".to_string();
    };

    let host = addr.ip().to_string();
    if host == "127.0.0.1" || host == "::1" {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            let left = xff.split(',').next().unwrap_or_default().trim();
            if !left.is_empty() {
                return left.to_string();
            }
        }
    }

    host
}

fn request_connect_addr(req: &Request) -> Option<SocketAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
}

fn api_key_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }

    let authz = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok())?;
    if authz.len() >= 7 && authz[..7].eq_ignore_ascii_case("Bearer ") {
        let v = authz[7..].trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }

    None
}

async fn require_api_key(
    state: &Arc<AppState>,
    raw_key: Option<String>,
) -> Result<ApiKeyRecord, Response> {
    let Some(raw_key) = raw_key else {
        return Err(unauthorized());
    };

    state
        .auth
        .authenticate(&raw_key)
        .await
        .map_err(|_| unauthorized())
}

async fn create_secret(
    state: Arc<AppState>,
    req: Request,
    authed: bool,
    owner_key: String,
) -> Response {
    let max_envelope_bytes = if authed {
        state.cfg.authed_max_envelope_bytes
    } else {
        state.cfg.public_max_envelope_bytes
    }
    .max(1);

    let body_limit = (max_envelope_bytes + 16 * 1024) as usize;
    let too_large = format!(
        "envelope exceeds maximum size ({})",
        format_bytes(max_envelope_bytes)
    );
    let payload: CreateSecretRequest = match read_json_body(req, body_limit, Some(too_large)).await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    if let Err(e) = validate_envelope(payload.envelope.get(), max_envelope_bytes) {
        return match e {
            SecretRuleError::EnvelopeTooLarge => {
                let msg = format!(
                    "envelope exceeds maximum size ({})",
                    format_bytes(max_envelope_bytes)
                );
                bad_request(msg)
            }
            _ => bad_request("invalid envelope"),
        };
    }

    if secrt_core::validate_claim_hash(&payload.claim_hash).is_err() {
        return bad_request("invalid claim_hash");
    }

    let ttl_seconds = match secrt_core::normalize_api_ttl(payload.ttl_seconds) {
        Ok(v) => v,
        Err(_) => return bad_request("invalid ttl_seconds"),
    };

    let expires_at = Utc::now() + chrono::Duration::seconds(ttl_seconds);

    let (max_secrets, max_bytes) = if authed {
        (
            state.cfg.authed_max_secrets,
            state.cfg.authed_max_total_bytes,
        )
    } else {
        (
            state.cfg.public_max_secrets,
            state.cfg.public_max_total_bytes,
        )
    };

    let limits = SecretQuotaLimits {
        max_secrets,
        max_total_bytes: max_bytes,
    };

    let mut id = String::new();
    for attempt in 0..=3 {
        id = match generate_id() {
            Ok(v) => v,
            Err(_) => return internal_server_error(),
        };

        let rec = SecretRecord {
            id: id.clone(),
            claim_hash: payload.claim_hash.clone(),
            envelope: payload.envelope.get().to_string().into_boxed_str(),
            expires_at,
            created_at: Utc::now(),
            owner_key: owner_key.clone(),
        };

        match state
            .secrets
            .create_with_quota(rec, limits, Utc::now())
            .await
        {
            Ok(_) => break,
            Err(StorageError::DuplicateId) if attempt < 3 => continue,
            Err(StorageError::QuotaExceeded(scope)) if scope == "secret_count" => {
                let msg = format!("secret limit exceeded (max {max_secrets} active secrets)");
                return error_response(StatusCode::TOO_MANY_REQUESTS, msg);
            }
            Err(StorageError::QuotaExceeded(scope)) if scope == "total_bytes" => {
                let msg = format!("storage quota exceeded (limit {})", format_bytes(max_bytes));
                return error_response(StatusCode::PAYLOAD_TOO_LARGE, msg);
            }
            Err(StorageError::QuotaExceeded(_)) => {
                return error_response(StatusCode::TOO_MANY_REQUESTS, "quota exceeded");
            }
            Err(_) => return internal_server_error(),
        }
    }

    let share_url = format!("{}/s/{id}", state.cfg.public_base_url);

    json_response(
        StatusCode::CREATED,
        CreateSecretResponse {
            id,
            share_url,
            expires_at,
        },
    )
}

pub async fn handle_create_public_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }

    let ip = get_client_ip(req.headers(), request_connect_addr(&req));
    if !state.public_create_limiter.allow(&ip) {
        return rate_limited();
    }

    create_secret(state.clone(), req, false, state.owner_hasher.hash_ip(&ip)).await
}

/// Combined dispatcher for `/api/v1/secrets` — GET lists, POST creates.
pub async fn handle_secrets_entry(
    State(state): State<Arc<AppState>>,
    query: Query<ListSecretsQuery>,
    req: Request,
) -> Response {
    match *req.method() {
        Method::GET => handle_list_secrets(state, query, req).await,
        Method::POST => handle_create_authed(state, req).await,
        _ => method_not_allowed(),
    }
}

async fn handle_create_authed(state: Arc<AppState>, req: Request) -> Response {
    // Try session auth first, then fall back to API key auth.
    let (owner_key, rate_key) =
        if let Ok((user_id, _, _)) = require_session_user(&state, req.headers()).await {
            let uid = user_id.to_string();
            (format!("user:{uid}"), format!("user:{uid}"))
        } else {
            let raw_key = api_key_from_headers(req.headers());
            let api_key = match require_api_key(&state, raw_key).await {
                Ok(k) => k,
                Err(resp) => return resp,
            };
            // When the API key is linked to a user, own the secret under the
            // user identity so it's visible from both web UI and CLI.
            if let Some(uid) = api_key.user_id {
                let uid = uid.to_string();
                (format!("user:{uid}"), format!("apikey:{}", api_key.prefix))
            } else {
                let prefix = &api_key.prefix;
                (format!("apikey:{prefix}"), format!("apikey:{prefix}"))
            }
        };

    if !state.api_limiter.allow(&rate_key) {
        return rate_limited();
    }

    create_secret(state.clone(), req, true, owner_key).await
}

/// Resolve owner_keys for a user: "user:{id}" plus "apikey:{prefix}" for each
/// unrevoked key. This lets listing/burn find secrets created via either session
/// or API key.
async fn owner_keys_for_user(
    state: &Arc<AppState>,
    user_id: UserId,
) -> Result<Vec<String>, Response> {
    let keys = state
        .api_keys
        .list_by_user_id(user_id)
        .await
        .map_err(|_| internal_server_error())?;
    let mut owner_keys = vec![format!("user:{user_id}")];
    owner_keys.extend(
        keys.iter()
            .filter(|k| k.revoked_at.is_none())
            .map(|k| format!("apikey:{}", k.prefix)),
    );
    Ok(owner_keys)
}

/// Resolve owner_keys for an API key: if the key is linked to a user, delegate
/// to `owner_keys_for_user` so it can see secrets created via both session and
/// API key auth. Otherwise fall back to just `["apikey:{prefix}"]`.
async fn owner_keys_for_api_key(
    state: &Arc<AppState>,
    api_key: &ApiKeyRecord,
) -> Result<Vec<String>, Response> {
    if let Some(user_id) = api_key.user_id {
        owner_keys_for_user(state, user_id).await
    } else {
        Ok(vec![format!("apikey:{}", api_key.prefix)])
    }
}

async fn handle_list_secrets(
    state: Arc<AppState>,
    Query(query): Query<ListSecretsQuery>,
    req: Request,
) -> Response {
    let limit = query.limit.unwrap_or(50).clamp(1, 20_000);
    let offset = query.offset.unwrap_or(0).max(0);

    // Try session auth first, then API key auth
    let owner_keys = if let Ok((user_id, _, _)) = require_session_user(&state, req.headers()).await
    {
        match owner_keys_for_user(&state, user_id).await {
            Ok(keys) => keys,
            Err(resp) => return resp,
        }
    } else {
        let raw_key = api_key_from_headers(req.headers());
        let api_key = match require_api_key(&state, raw_key).await {
            Ok(k) => k,
            Err(resp) => return resp,
        };
        match owner_keys_for_api_key(&state, &api_key).await {
            Ok(keys) => keys,
            Err(resp) => return resp,
        }
    };

    let now = Utc::now();
    let total = match state.secrets.count_by_owner_keys(&owner_keys, now).await {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };

    let summaries = match state
        .secrets
        .list_by_owner_keys(&owner_keys, now, limit, offset)
        .await
    {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };

    let secrets = summaries
        .into_iter()
        .map(|s| SecretMetadataItem {
            share_url: format!("{}/s/{}", state.cfg.public_base_url, s.id),
            id: s.id,
            expires_at: s.expires_at,
            created_at: s.created_at,
            ciphertext_size: s.ciphertext_size,
            passphrase_protected: s.passphrase_protected,
            enc_meta: s.enc_meta,
        })
        .collect();

    json_response(
        StatusCode::OK,
        ListSecretsResponse {
            secrets,
            total,
            limit,
            offset,
        },
    )
}

pub async fn handle_secrets_check_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::GET {
        return method_not_allowed();
    }

    // Same auth pattern as list_secrets: session first, API key fallback
    let owner_keys = if let Ok((user_id, _, _)) = require_session_user(&state, req.headers()).await
    {
        match owner_keys_for_user(&state, user_id).await {
            Ok(keys) => keys,
            Err(resp) => return resp,
        }
    } else {
        let raw_key = api_key_from_headers(req.headers());
        let api_key = match require_api_key(&state, raw_key).await {
            Ok(k) => k,
            Err(resp) => return resp,
        };
        match owner_keys_for_api_key(&state, &api_key).await {
            Ok(keys) => keys,
            Err(resp) => return resp,
        }
    };

    let now = Utc::now();
    match state.secrets.checksum_by_owner_keys(&owner_keys, now).await {
        Ok((count, checksum)) => {
            json_response(StatusCode::OK, SecretsCheckResponse { count, checksum })
        }
        Err(_) => internal_server_error(),
    }
}

pub async fn handle_get_secret_metadata_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    if req.method() != Method::GET {
        return method_not_allowed();
    }

    // Same auth pattern as list_secrets: session first, API key fallback
    let owner_keys = if let Ok((user_id, _, _)) = require_session_user(&state, req.headers()).await
    {
        match owner_keys_for_user(&state, user_id).await {
            Ok(keys) => keys,
            Err(resp) => return resp,
        }
    } else {
        let raw_key = api_key_from_headers(req.headers());
        let api_key = match require_api_key(&state, raw_key).await {
            Ok(k) => k,
            Err(resp) => return resp,
        };
        match owner_keys_for_api_key(&state, &api_key).await {
            Ok(keys) => keys,
            Err(resp) => return resp,
        }
    };

    let now = Utc::now();
    let summary = match state.secrets.get_summary_by_id(&id, &owner_keys, now).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(),
        Err(_) => return internal_server_error(),
    };

    let item = SecretMetadataItem {
        share_url: format!("{}/s/{}", state.cfg.public_base_url, summary.id),
        id: summary.id,
        expires_at: summary.expires_at,
        created_at: summary.created_at,
        ciphertext_size: summary.ciphertext_size,
        passphrase_protected: summary.passphrase_protected,
        enc_meta: summary.enc_meta,
    };

    json_response(StatusCode::OK, item)
}

pub async fn handle_claim_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }

    let ip = get_client_ip(req.headers(), request_connect_addr(&req));
    if !state.claim_limiter.allow(&ip) {
        return rate_limited();
    }

    let payload: ClaimSecretRequest = match read_json_body(req, 8 * 1024, None).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    if payload.claim.trim().is_empty() {
        return bad_request("claim is required");
    }

    let claim_hash = match secrt_core::hash_claim_token(&payload.claim) {
        Ok(v) => v,
        Err(_) => return not_found(),
    };

    let sec = match state
        .secrets
        .claim_and_delete(&id, &claim_hash, Utc::now())
        .await
    {
        Ok(v) => v,
        Err(StorageError::NotFound) => return not_found(),
        Err(_) => return internal_server_error(),
    };

    let envelope = match RawValue::from_string(sec.envelope.into()) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };

    json_response(
        StatusCode::OK,
        ClaimSecretResponse {
            envelope,
            expires_at: sec.expires_at,
        },
    )
}

pub async fn handle_burn_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }

    // Try API key auth first (original path), then fall back to session auth
    let raw_key = api_key_from_headers(req.headers());
    let keys = if let Ok(api_key) = require_api_key(&state, raw_key).await {
        match owner_keys_for_api_key(&state, &api_key).await {
            Ok(k) => k,
            Err(resp) => return resp,
        }
    } else {
        // Session auth fallback
        let (user_id, _, _) = match require_session_user(&state, req.headers()).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        match owner_keys_for_user(&state, user_id).await {
            Ok(k) => k,
            Err(resp) => return resp,
        }
    };

    for owner_key in &keys {
        match state.secrets.burn(&id, owner_key).await {
            Ok(true) => {
                return json_response(StatusCode::OK, serde_json::json!({ "ok": true }));
            }
            Ok(false) => continue,
            Err(_) => return internal_server_error(),
        }
    }

    not_found()
}

const SESSION_TOKEN_PREFIX: &str = "uss_";
const SESSION_SID_LEN: usize = 12;
const SESSION_SECRET_LEN: usize = 32;
const CHALLENGE_LEN: usize = 32;

#[derive(Serialize, Deserialize)]
struct RegisterChallengePayload {
    display_name: String,
}

#[derive(Serialize, Deserialize)]
struct LoginChallengePayload {
    credential_id: String,
}

#[derive(Serialize, Deserialize)]
struct AddPasskeyChallengePayload {
    user_id: String,
}

struct ParsedSessionToken {
    sid: String,
    secret: String,
}

fn random_b64(len: usize) -> Result<String, ()> {
    let rng = SystemRandom::new();
    let mut b = vec![0u8; len];
    rng.fill(&mut b).map_err(|_| ())?;
    Ok(URL_SAFE_NO_PAD.encode(b))
}

fn session_token_from_headers(headers: &HeaderMap) -> Option<ParsedSessionToken> {
    let authz = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok())?;
    if authz.len() < 7 || !authz[..7].eq_ignore_ascii_case("Bearer ") {
        return None;
    }
    let token = authz[7..].trim();
    if !token.starts_with(SESSION_TOKEN_PREFIX) {
        return None;
    }
    let rest = &token[SESSION_TOKEN_PREFIX.len()..];
    let (sid, secret) = rest.split_once('.')?;
    if sid.is_empty() || secret.is_empty() {
        return None;
    }
    Some(ParsedSessionToken {
        sid: sid.to_string(),
        secret: secret.to_string(),
    })
}

fn hash_session_token(pepper: &str, sid: &str, secret: &str) -> Result<String, ()> {
    if pepper.is_empty() {
        return Err(());
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, pepper.as_bytes());
    let mut msg = Vec::with_capacity(sid.len() + 1 + secret.len());
    msg.extend_from_slice(sid.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(secret.as_bytes());
    Ok(hex::encode(hmac::sign(&key, &msg).as_ref()))
}

async fn require_session_user(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(UserId, String, DateTime<Utc>), Response> {
    let sess = require_valid_session(state, headers).await?;

    let user = state
        .auth_store
        .get_user_by_id(sess.user_id)
        .await
        .map_err(|_| unauthorized())?;
    Ok((user.id, user.display_name, sess.expires_at))
}

async fn require_valid_session(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<SessionRecord, Response> {
    let parsed = session_token_from_headers(headers).ok_or_else(unauthorized)?;
    let token_hash =
        hash_session_token(&state.cfg.session_token_pepper, &parsed.sid, &parsed.secret)
            .map_err(|_| internal_server_error())?;

    let sess = state
        .auth_store
        .get_session_by_sid(&parsed.sid)
        .await
        .map_err(|_| unauthorized())?;

    if sess.revoked_at.is_some() || sess.expires_at <= Utc::now() {
        return Err(unauthorized());
    }
    if !crate::domain::auth::secure_equals_hex(&sess.token_hash, &token_hash) {
        return Err(unauthorized());
    }

    Ok(sess)
}

async fn issue_session_token(
    state: &Arc<AppState>,
    user_id: UserId,
) -> Result<(String, DateTime<Utc>), Response> {
    let sid = random_b64(SESSION_SID_LEN).map_err(|_| internal_server_error())?;
    let secret = random_b64(SESSION_SECRET_LEN).map_err(|_| internal_server_error())?;
    let token = format!("{SESSION_TOKEN_PREFIX}{sid}.{secret}");
    let token_hash = hash_session_token(&state.cfg.session_token_pepper, &sid, &secret)
        .map_err(|_| internal_server_error())?;
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(24);
    state
        .auth_store
        .insert_session(&sid, user_id, &token_hash, expires_at)
        .await
        .map_err(|_| internal_server_error())?;
    // Best-effort: bump coarse (month-start) activity date for stale-account cleanup.
    let _ = state.auth_store.touch_user_last_active(user_id, now).await;
    Ok((token, expires_at))
}

pub async fn handle_passkey_register_start_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }
    let payload: PasskeyRegisterStartRequest = match read_json_body(req, 8 * 1024, None).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if payload.display_name.trim().is_empty() {
        return bad_request("display_name is required");
    }
    let challenge_id = match random_b64(CHALLENGE_LEN) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    let challenge = match random_b64(CHALLENGE_LEN) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    let challenge_json = match serde_json::to_string(&RegisterChallengePayload {
        display_name: payload.display_name,
    }) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    let expires_at = Utc::now() + chrono::Duration::minutes(10);
    if state
        .auth_store
        .insert_challenge(
            &challenge_id,
            None,
            "passkey-register",
            &challenge_json,
            expires_at,
        )
        .await
        .is_err()
    {
        return internal_server_error();
    }
    json_response(
        StatusCode::OK,
        PasskeyStartResponse {
            challenge_id,
            challenge,
            expires_at,
        },
    )
}

pub async fn handle_passkey_register_finish_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }
    let payload: PasskeyRegisterFinishRequest = match read_json_body(req, 16 * 1024, None).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if payload.credential_id.trim().is_empty() || payload.public_key.trim().is_empty() {
        return bad_request("credential_id and public_key are required");
    }

    let challenge = match state
        .auth_store
        .consume_challenge(&payload.challenge_id, "passkey-register", Utc::now())
        .await
    {
        Ok(v) => v,
        Err(_) => return bad_request("invalid or expired challenge"),
    };
    let parsed: RegisterChallengePayload = match serde_json::from_str(&challenge.challenge_json) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };

    let user = match state
        .auth_store
        .create_user(parsed.display_name.trim())
        .await
    {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    if state
        .auth_store
        .insert_passkey(
            user.id,
            payload.credential_id.trim(),
            payload.public_key.trim(),
            0,
        )
        .await
        .is_err()
    {
        return internal_server_error();
    }
    let (token, expires_at) = match issue_session_token(&state, user.id).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    json_response(
        StatusCode::OK,
        AuthFinishResponse {
            session_token: token,
            user_id: user.id,
            display_name: user.display_name,
            expires_at,
        },
    )
}

pub async fn handle_passkey_login_start_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }
    let payload: PasskeyLoginStartRequest = match read_json_body(req, 8 * 1024, None).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let passkey = match state
        .auth_store
        .get_passkey_by_credential_id(payload.credential_id.trim())
        .await
    {
        Ok(v) => v,
        Err(_) => return bad_request("unknown credential"),
    };
    if passkey.revoked_at.is_some() {
        return unauthorized();
    }
    let challenge_id = match random_b64(CHALLENGE_LEN) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    let challenge = match random_b64(CHALLENGE_LEN) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    let challenge_json = match serde_json::to_string(&LoginChallengePayload {
        credential_id: payload.credential_id.trim().to_string(),
    }) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    let expires_at = Utc::now() + chrono::Duration::minutes(10);
    if state
        .auth_store
        .insert_challenge(
            &challenge_id,
            Some(passkey.user_id),
            "passkey-login",
            &challenge_json,
            expires_at,
        )
        .await
        .is_err()
    {
        return internal_server_error();
    }
    json_response(
        StatusCode::OK,
        PasskeyStartResponse {
            challenge_id,
            challenge,
            expires_at,
        },
    )
}

pub async fn handle_passkey_login_finish_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }
    let payload: PasskeyLoginFinishRequest = match read_json_body(req, 8 * 1024, None).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let challenge = match state
        .auth_store
        .consume_challenge(&payload.challenge_id, "passkey-login", Utc::now())
        .await
    {
        Ok(v) => v,
        Err(_) => return bad_request("invalid or expired challenge"),
    };
    let c: LoginChallengePayload = match serde_json::from_str(&challenge.challenge_json) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    if c.credential_id.trim() != payload.credential_id.trim() {
        return unauthorized();
    }
    let passkey = match state
        .auth_store
        .get_passkey_by_credential_id(payload.credential_id.trim())
        .await
    {
        Ok(v) => v,
        Err(_) => return unauthorized(),
    };
    if passkey.revoked_at.is_some() {
        return unauthorized();
    }
    if state
        .auth_store
        .update_passkey_sign_count(payload.credential_id.trim(), passkey.sign_count + 1)
        .await
        .is_err()
    {
        return internal_server_error();
    }
    let user = match state.auth_store.get_user_by_id(passkey.user_id).await {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    let (token, expires_at) = match issue_session_token(&state, user.id).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    json_response(
        StatusCode::OK,
        AuthFinishResponse {
            session_token: token,
            user_id: user.id,
            display_name: user.display_name,
            expires_at,
        },
    )
}

pub async fn handle_auth_session_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::GET {
        return method_not_allowed();
    }
    let (user_id, display_name, expires_at) =
        match require_session_user(&state, req.headers()).await {
            Ok(v) => v,
            Err(_) => {
                return json_response(
                    StatusCode::OK,
                    SessionResponse {
                        authenticated: false,
                        user_id: None,
                        display_name: None,
                        expires_at: None,
                    },
                )
            }
        };
    json_response(
        StatusCode::OK,
        SessionResponse {
            authenticated: true,
            user_id: Some(user_id),
            display_name: Some(display_name),
            expires_at: Some(expires_at),
        },
    )
}

pub async fn handle_auth_logout_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }
    let sess = match require_valid_session(&state, req.headers()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let revoked = match state.auth_store.revoke_session_by_sid(&sess.sid).await {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    if !revoked {
        return unauthorized();
    }
    json_response(StatusCode::OK, serde_json::json!({ "ok": true }))
}

pub async fn handle_apikey_register_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }
    let (user_id, _, _) = match require_session_user(&state, req.headers()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let ip = get_client_ip(req.headers(), request_connect_addr(&req));
    if !state.apikey_register_limiter.allow(&ip) {
        return rate_limited();
    }

    let payload: RegisterApiKeyRequest = match read_json_body(req, 8 * 1024, None).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let auth_token = match URL_SAFE_NO_PAD.decode(payload.auth_token.trim()) {
        Ok(v) if v.len() == secrt_core::API_KEY_AUTH_LEN => v,
        _ => return bad_request("auth_token must be base64url for 32 bytes"),
    };

    let now = Utc::now();
    let ip_hash = state.owner_hasher.hash_ip(&ip);

    let scopes = payload.scopes.unwrap_or_default();
    let mut prefix = String::new();
    for _ in 0..=3 {
        prefix = match crate::domain::auth::generate_api_key_prefix() {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "failed to generate api key prefix");
                return internal_server_error();
            }
        };
        let auth_hash = match crate::domain::auth::hash_api_key_auth_token(
            &state.cfg.api_key_pepper,
            &prefix,
            &auth_token,
        ) {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "failed to hash api key auth token");
                return internal_server_error();
            }
        };
        let rec = ApiKeyRecord {
            id: 0,
            prefix: prefix.clone(),
            auth_hash,
            scopes: scopes.clone(),
            user_id: Some(user_id),
            created_at: now,
            revoked_at: None,
        };
        match state
            .auth_store
            .register_api_key(
                rec,
                &ip_hash,
                now,
                ApiKeyRegistrationLimits {
                    account_hour: state.cfg.apikey_register_account_max_per_hour,
                    account_day: state.cfg.apikey_register_account_max_per_day,
                    ip_hour: state.cfg.apikey_register_ip_max_per_hour,
                    ip_day: state.cfg.apikey_register_ip_max_per_day,
                },
            )
            .await
        {
            Ok(_) => break,
            Err(StorageError::DuplicateId) => continue,
            Err(StorageError::QuotaExceeded(scope)) => {
                let detail = match scope.as_str() {
                    "account/hour" => "api key registration limit exceeded (account/hour)",
                    "account/day" => "api key registration limit exceeded (account/day)",
                    "ip/hour" => "api key registration limit exceeded (ip/hour)",
                    "ip/day" => "api key registration limit exceeded (ip/day)",
                    _ => "api key registration limit exceeded",
                };
                return error_response(StatusCode::TOO_MANY_REQUESTS, detail);
            }
            Err(e) => {
                error!(error = %e, "failed to register api key");
                return internal_server_error();
            }
        }
    }

    json_response(
        StatusCode::CREATED,
        RegisterApiKeyResponse {
            prefix,
            created_at: now,
        },
    )
}

pub async fn handle_list_apikeys_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::GET {
        return method_not_allowed();
    }
    let (user_id, _, _) = match require_session_user(&state, req.headers()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let keys = match state.api_keys.list_by_user_id(user_id).await {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };

    let api_keys = keys
        .into_iter()
        .map(|k| ApiKeyListItem {
            prefix: k.prefix,
            scopes: k.scopes,
            created_at: k.created_at,
            revoked_at: k.revoked_at,
        })
        .collect();

    json_response(StatusCode::OK, ListApiKeysResponse { api_keys })
}

pub async fn handle_revoke_apikey_entry(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }
    let (user_id, _, _) = match require_session_user(&state, req.headers()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Verify the key belongs to this user
    let key = match state.api_keys.get_by_prefix(&prefix).await {
        Ok(k) => k,
        Err(StorageError::NotFound) => return not_found(),
        Err(_) => return internal_server_error(),
    };
    if key.user_id != Some(user_id) {
        return not_found();
    }

    match state.api_keys.revoke_by_prefix(&prefix).await {
        Ok(true) => json_response(StatusCode::OK, serde_json::json!({ "ok": true })),
        Ok(false) => bad_request("key already revoked"),
        Err(_) => internal_server_error(),
    }
}

pub async fn handle_account_entry(State(state): State<Arc<AppState>>, req: Request) -> Response {
    match req.method().clone() {
        Method::DELETE => handle_delete_account(state, req).await,
        Method::PATCH => handle_update_display_name(state, req).await,
        _ => method_not_allowed(),
    }
}

async fn handle_delete_account(state: Arc<AppState>, req: Request) -> Response {
    let (user_id, _, _) = match require_session_user(&state, req.headers()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // 1. Get all user's owner_keys (including revoked API keys, for cleanup)
    let all_keys = match state.api_keys.list_by_user_id(user_id).await {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    let mut owner_keys: Vec<String> = vec![format!("user:{user_id}")];
    owner_keys.extend(all_keys.iter().map(|k| format!("apikey:{}", k.prefix)));

    // 2. Burn all owned secrets
    let secrets_burned = match state.secrets.burn_all_by_owner_keys(&owner_keys).await {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };

    // 3. Revoke all API keys
    let keys_revoked = match state.api_keys.revoke_all_by_user_id(user_id).await {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };

    // 4. Delete user (cascades passkeys, sessions, challenges)
    match state.auth_store.delete_user(user_id).await {
        Ok(true) => {}
        Ok(false) => return not_found(),
        Err(_) => return internal_server_error(),
    }

    json_response(
        StatusCode::OK,
        DeleteAccountResponse {
            ok: true,
            secrets_burned,
            keys_revoked,
        },
    )
}

async fn handle_update_display_name(state: Arc<AppState>, req: Request) -> Response {
    let (user_id, _, _) = match require_session_user(&state, req.headers()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let payload: UpdateDisplayNameRequest = match read_json_body(req, 4 * 1024, None).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let trimmed = payload.display_name.trim();
    if trimmed.is_empty() {
        return bad_request("display_name is required");
    }
    if trimmed.len() > 100 {
        return bad_request("display_name must be 100 characters or fewer");
    }
    match state.auth_store.update_display_name(user_id, trimmed).await {
        Ok(()) => json_response(
            StatusCode::OK,
            UpdateDisplayNameResponse {
                ok: true,
                display_name: trimmed.to_string(),
            },
        ),
        Err(_) => internal_server_error(),
    }
}

// --- Passkey management endpoints ---

pub async fn handle_passkeys_list_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::GET {
        return method_not_allowed();
    }
    let (user_id, _, _) = match require_session_user(&state, req.headers()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let passkeys = match state.auth_store.list_passkeys_by_user(user_id).await {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    json_response(
        StatusCode::OK,
        ListPasskeysResponse {
            passkeys: passkeys
                .into_iter()
                .map(|p| PasskeyListItem {
                    id: p.id,
                    label: p.label,
                    created_at: p.created_at,
                })
                .collect(),
        },
    )
}

pub async fn handle_revoke_passkey_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }
    let (user_id, _, _) = match require_session_user(&state, req.headers()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    match state.auth_store.revoke_passkey(id, user_id).await {
        Ok(true) => json_response(StatusCode::OK, serde_json::json!({ "ok": true })),
        Ok(false) => bad_request("cannot revoke last active passkey"),
        Err(StorageError::NotFound) => not_found(),
        Err(_) => internal_server_error(),
    }
}

pub async fn handle_passkey_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    req: Request,
) -> Response {
    if req.method() != Method::PATCH {
        return method_not_allowed();
    }
    let (user_id, _, _) = match require_session_user(&state, req.headers()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let payload: UpdatePasskeyLabelRequest = match read_json_body(req, 4 * 1024, None).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let trimmed = payload.label.trim();
    if trimmed.len() > 100 {
        return bad_request("label must be 100 characters or fewer");
    }
    match state
        .auth_store
        .update_passkey_label(id, user_id, trimmed)
        .await
    {
        Ok(()) => json_response(StatusCode::OK, serde_json::json!({ "ok": true })),
        Err(StorageError::NotFound) => not_found(),
        Err(_) => internal_server_error(),
    }
}

pub async fn handle_passkey_add_start_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }
    let (user_id, _, _) = match require_session_user(&state, req.headers()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let challenge_id = match random_b64(CHALLENGE_LEN) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    let challenge = match random_b64(CHALLENGE_LEN) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    let challenge_json = match serde_json::to_string(&AddPasskeyChallengePayload {
        user_id: user_id.to_string(),
    }) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    let expires_at = Utc::now() + chrono::Duration::minutes(10);
    if state
        .auth_store
        .insert_challenge(
            &challenge_id,
            Some(user_id),
            "passkey-add",
            &challenge_json,
            expires_at,
        )
        .await
        .is_err()
    {
        return internal_server_error();
    }
    json_response(
        StatusCode::OK,
        PasskeyStartResponse {
            challenge_id,
            challenge,
            expires_at,
        },
    )
}

pub async fn handle_passkey_add_finish_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }
    let (user_id, _, _) = match require_session_user(&state, req.headers()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let payload: PasskeyAddFinishRequest = match read_json_body(req, 16 * 1024, None).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if payload.credential_id.trim().is_empty() || payload.public_key.trim().is_empty() {
        return bad_request("credential_id and public_key are required");
    }
    let challenge = match state
        .auth_store
        .consume_challenge(&payload.challenge_id, "passkey-add", Utc::now())
        .await
    {
        Ok(v) => v,
        Err(_) => return bad_request("invalid or expired challenge"),
    };
    // Verify the challenge belongs to this user
    let parsed: AddPasskeyChallengePayload = match serde_json::from_str(&challenge.challenge_json) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    if parsed.user_id != user_id.to_string() {
        return unauthorized();
    }
    let passkey = match state
        .auth_store
        .insert_passkey(
            user_id,
            payload.credential_id.trim(),
            payload.public_key.trim(),
            0,
        )
        .await
    {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    json_response(
        StatusCode::OK,
        PasskeyAddFinishResponse {
            ok: true,
            passkey: PasskeyListItem {
                id: passkey.id,
                label: passkey.label,
                created_at: passkey.created_at,
            },
        },
    )
}

// --- Device authorization flow endpoints ---

pub async fn handle_device_start_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }

    let ip = get_client_ip(req.headers(), request_connect_addr(&req));
    if !state.apikey_register_limiter.allow(&ip) {
        return rate_limited();
    }

    let payload: DeviceStartRequest = match read_json_body(req, 4 * 1024, None).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Validate auth_token is valid base64url for 32 bytes
    let auth_token_bytes = match URL_SAFE_NO_PAD.decode(payload.auth_token.trim()) {
        Ok(v) if v.len() == secrt_core::API_KEY_AUTH_LEN => v,
        _ => return bad_request("auth_token must be base64url-encoded 32 bytes"),
    };
    let auth_token_b64 = URL_SAFE_NO_PAD.encode(&auth_token_bytes);

    // Generate device_code and user_code
    let device_code = match random_b64(DEVICE_CODE_LEN) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    let user_code = match generate_user_code() {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };

    let challenge_data = DeviceChallengeJson {
        user_code: user_code.clone(),
        auth_token_b64,
        status: "pending".into(),
        prefix: None,
        user_id: None,
        ecdh_public_key: payload.ecdh_public_key,
        amk_transfer: None,
    };
    let challenge_json = match serde_json::to_string(&challenge_data) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };

    let expires_at = Utc::now() + chrono::Duration::seconds(DEVICE_AUTH_EXPIRY_SECS);
    if let Err(e) = state
        .auth_store
        .insert_challenge(
            &device_code,
            None,
            DEVICE_AUTH_PURPOSE,
            &challenge_json,
            expires_at,
        )
        .await
    {
        error!(error = %e, "failed to insert device challenge");
        return internal_server_error();
    }

    let verification_url = format!(
        "{}/device?code={}",
        state.cfg.public_base_url,
        urlencoding::encode(&user_code)
    );

    json_response(
        StatusCode::OK,
        DeviceStartResponse {
            device_code,
            user_code,
            verification_url,
            expires_in: DEVICE_AUTH_EXPIRY_SECS as u64,
            interval: 5,
        },
    )
}

pub async fn handle_device_poll_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }

    let ip = get_client_ip(req.headers(), request_connect_addr(&req));
    if !state.apikey_register_limiter.allow(&ip) {
        return rate_limited();
    }

    let payload: DevicePollRequest = match read_json_body(req, 4 * 1024, None).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let now = Utc::now();
    let challenge = match state
        .auth_store
        .get_challenge(&payload.device_code, DEVICE_AUTH_PURPOSE, now)
        .await
    {
        Ok(c) => c,
        Err(StorageError::NotFound) => {
            return bad_request("expired_token");
        }
        Err(e) => {
            error!(error = %e, "failed to get device challenge");
            return internal_server_error();
        }
    };

    let data: DeviceChallengeJson = match serde_json::from_str(&challenge.challenge_json) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };

    if data.status == "approved" {
        // Consume the challenge atomically (one-time read)
        match state
            .auth_store
            .consume_challenge(&payload.device_code, DEVICE_AUTH_PURPOSE, now)
            .await
        {
            Ok(_) => {}
            Err(StorageError::NotFound) => {
                // Already consumed by a concurrent poll
                return bad_request("expired_token");
            }
            Err(e) => {
                error!(error = %e, "failed to consume device challenge");
                return internal_server_error();
            }
        }
        return json_response(
            StatusCode::OK,
            DevicePollResponse {
                status: "complete".into(),
                prefix: data.prefix,
                amk_transfer: data.amk_transfer,
            },
        );
    }

    json_response(
        StatusCode::OK,
        DevicePollResponse {
            status: "authorization_pending".into(),
            prefix: None,
            amk_transfer: None,
        },
    )
}

pub async fn handle_device_approve_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }

    let (user_id, _, _) = match require_session_user(&state, req.headers()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let payload: DeviceApproveRequest = match read_json_body(req, 4 * 1024, None).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let now = Utc::now();

    // Find the challenge by user_code
    let challenge = match state
        .auth_store
        .find_device_challenge_by_user_code(&payload.user_code, now)
        .await
    {
        Ok(c) => c,
        Err(StorageError::NotFound) => {
            return bad_request("invalid or expired code");
        }
        Err(e) => {
            error!(error = %e, "failed to find device challenge");
            return internal_server_error();
        }
    };

    let data: DeviceChallengeJson = match serde_json::from_str(&challenge.challenge_json) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };

    // Verify it's still pending
    if data.status != "pending" {
        return bad_request("device already authorized");
    }

    // Constant-time user_code comparison
    if !crate::domain::auth::secure_equals_hex(
        &hex::encode(data.user_code.as_bytes()),
        &hex::encode(payload.user_code.as_bytes()),
    ) {
        return bad_request("invalid or expired code");
    }

    // Decode the stored auth_token
    let auth_token = match URL_SAFE_NO_PAD.decode(&data.auth_token_b64) {
        Ok(v) if v.len() == secrt_core::API_KEY_AUTH_LEN => v,
        _ => return internal_server_error(),
    };

    // Generate prefix and create API key (same logic as apikey/register)
    let ip = "device-auth"; // No IP rate limiting for approve (session-gated)
    let ip_hash = state.owner_hasher.hash_ip(ip);

    let mut prefix = String::new();
    for _ in 0..=3 {
        prefix = match crate::domain::auth::generate_api_key_prefix() {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "failed to generate api key prefix");
                return internal_server_error();
            }
        };
        let auth_hash = match crate::domain::auth::hash_api_key_auth_token(
            &state.cfg.api_key_pepper,
            &prefix,
            &auth_token,
        ) {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "failed to hash api key auth token");
                return internal_server_error();
            }
        };
        let rec = ApiKeyRecord {
            id: 0,
            prefix: prefix.clone(),
            auth_hash,
            scopes: String::new(),
            user_id: Some(user_id),
            created_at: now,
            revoked_at: None,
        };
        match state
            .auth_store
            .register_api_key(
                rec,
                &ip_hash,
                now,
                ApiKeyRegistrationLimits {
                    account_hour: state.cfg.apikey_register_account_max_per_hour,
                    account_day: state.cfg.apikey_register_account_max_per_day,
                    ip_hour: 0, // Don't IP-limit device-auth approve
                    ip_day: 0,
                },
            )
            .await
        {
            Ok(_) => break,
            Err(StorageError::DuplicateId) => continue,
            Err(StorageError::QuotaExceeded(scope)) => {
                let detail = match scope.as_str() {
                    "account/hour" => "api key registration limit exceeded (account/hour)",
                    "account/day" => "api key registration limit exceeded (account/day)",
                    _ => "api key registration limit exceeded",
                };
                return error_response(StatusCode::TOO_MANY_REQUESTS, detail);
            }
            Err(e) => {
                error!(error = %e, "failed to register api key from device auth");
                return internal_server_error();
            }
        }
    }

    // Update challenge to approved state (include amk_transfer atomically)
    let updated = DeviceChallengeJson {
        user_code: data.user_code,
        auth_token_b64: data.auth_token_b64,
        status: "approved".into(),
        prefix: Some(prefix),
        user_id: Some(user_id.to_string()),
        ecdh_public_key: data.ecdh_public_key,
        amk_transfer: payload.amk_transfer,
    };
    let updated_json = match serde_json::to_string(&updated) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };
    if let Err(e) = state
        .auth_store
        .update_challenge_json(
            &challenge.challenge_id,
            DEVICE_AUTH_PURPOSE,
            &updated_json,
            now,
        )
        .await
    {
        error!(error = %e, "failed to update device challenge");
        return internal_server_error();
    }

    json_response(StatusCode::OK, serde_json::json!({ "ok": true }))
}

#[allow(clippy::result_large_err)]
fn require_encrypted_notes(state: &AppState) -> Result<(), Response> {
    if state.cfg.encrypted_notes_enabled {
        Ok(())
    } else {
        Err(not_found())
    }
}

// --- AMK wrapper endpoints ---

/// Resolve user_id and key_prefix from either session auth or API key auth.
/// Tries session auth first so session Bearer tokens aren't misinterpreted as API keys.
/// Returns (user_id, key_prefix) or an error response.
async fn resolve_amk_auth(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    explicit_prefix: Option<&str>,
) -> Result<(UserId, String), Response> {
    // Try session auth first
    if let Ok((user_id, _, _)) = require_session_user(state, headers).await {
        let Some(prefix) = explicit_prefix else {
            return Err(bad_request("key_prefix is required for session auth"));
        };
        // Verify the prefix belongs to a non-revoked key owned by the session's user
        let keys = state
            .api_keys
            .list_by_user_id(user_id)
            .await
            .map_err(|_| internal_server_error())?;
        let valid = keys
            .iter()
            .any(|k| k.prefix == prefix && k.revoked_at.is_none());
        if !valid {
            return Err(bad_request("key_prefix does not match any active key"));
        }
        return Ok((user_id, prefix.to_string()));
    }

    // Fall back to API key auth
    if let Some(raw) = api_key_from_headers(headers) {
        if let Ok(api_key) = state.auth.authenticate(&raw).await {
            let Some(user_id) = api_key.user_id else {
                return Err(bad_request("api key is not linked to a user account"));
            };
            // API key auth: prefix is always the caller's own prefix
            return Ok((user_id, api_key.prefix));
        }
    }

    Err(unauthorized())
}

/// `PUT /api/v1/amk/wrapper` — upsert, `GET /api/v1/amk/wrapper` — get.
pub async fn handle_amk_wrapper_entry(
    State(state): State<Arc<AppState>>,
    query: Query<AmkWrapperQuery>,
    req: Request,
) -> Response {
    if let Err(resp) = require_encrypted_notes(&state) {
        return resp;
    }
    match *req.method() {
        Method::PUT => handle_amk_wrapper_upsert(state, req).await,
        Method::GET => handle_amk_wrapper_get(state, query, req).await,
        _ => method_not_allowed(),
    }
}

async fn handle_amk_wrapper_upsert(state: Arc<AppState>, req: Request) -> Response {
    let headers = req.headers().clone();
    let payload: UpsertAmkWrapperRequest = match read_json_body(req, 8 * 1024, None).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let (user_id, prefix) =
        match resolve_amk_auth(&state, &headers, payload.key_prefix.as_deref()).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // Decode and validate fields
    let wrapped_amk = match URL_SAFE_NO_PAD.decode(&payload.wrapped_amk) {
        Ok(v) if v.len() == 48 => v, // 32 bytes AMK + 16 bytes GCM tag
        _ => return bad_request("wrapped_amk must be base64url-encoded 48 bytes"),
    };
    let nonce = match URL_SAFE_NO_PAD.decode(&payload.nonce) {
        Ok(v) if v.len() == 12 => v,
        _ => return bad_request("nonce must be base64url-encoded 12 bytes"),
    };
    let amk_commit = match URL_SAFE_NO_PAD.decode(&payload.amk_commit) {
        Ok(v) if v.len() == 32 => v,
        _ => return bad_request("amk_commit must be base64url-encoded 32 bytes"),
    };
    if payload.version != 1 {
        return bad_request("unsupported version");
    }

    let rec = AmkWrapperRecord {
        user_id,
        key_prefix: prefix,
        wrapped_amk,
        nonce,
        version: payload.version,
        created_at: Utc::now(),
    };

    match state.amk_store.upsert_wrapper(rec, &amk_commit).await {
        Ok(AmkUpsertResult::Ok) => {
            json_response(StatusCode::OK, serde_json::json!({ "ok": true }))
        }
        Ok(AmkUpsertResult::CommitMismatch) => error_response(
            StatusCode::CONFLICT,
            "a different AMK is already committed for this account; obtain the existing AMK via device sync",
        ),
        Err(e) => {
            error!(error = %e, "failed to upsert AMK wrapper");
            internal_server_error()
        }
    }
}

async fn handle_amk_wrapper_get(
    state: Arc<AppState>,
    Query(query): Query<AmkWrapperQuery>,
    req: Request,
) -> Response {
    let (user_id, prefix) =
        match resolve_amk_auth(&state, req.headers(), query.key_prefix.as_deref()).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    match state.amk_store.get_wrapper(user_id, &prefix).await {
        Ok(Some(w)) => json_response(
            StatusCode::OK,
            AmkWrapperResponse {
                user_id,
                wrapped_amk: URL_SAFE_NO_PAD.encode(&w.wrapped_amk),
                nonce: URL_SAFE_NO_PAD.encode(&w.nonce),
                version: w.version,
            },
        ),
        Ok(None) => not_found(),
        Err(e) => {
            error!(error = %e, "failed to get AMK wrapper");
            internal_server_error()
        }
    }
}

/// `GET /api/v1/amk/wrappers` — list all wrappers (session auth only).
pub async fn handle_amk_wrappers_list_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if let Err(resp) = require_encrypted_notes(&state) {
        return resp;
    }
    if req.method() != Method::GET {
        return method_not_allowed();
    }

    let (user_id, _, _) = match require_session_user(&state, req.headers()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    match state.amk_store.list_wrappers(user_id).await {
        Ok(wrappers) => json_response(
            StatusCode::OK,
            AmkWrappersListResponse {
                wrappers: wrappers
                    .into_iter()
                    .map(|w| AmkWrappersListItem {
                        key_prefix: w.key_prefix,
                        version: w.version,
                        created_at: w.created_at,
                    })
                    .collect(),
            },
        ),
        Err(e) => {
            error!(error = %e, "failed to list AMK wrappers");
            internal_server_error()
        }
    }
}

/// `POST /api/v1/amk/commit` — eagerly commit an AMK hash (session auth only).
pub async fn handle_amk_commit_entry(State(state): State<Arc<AppState>>, req: Request) -> Response {
    if let Err(resp) = require_encrypted_notes(&state) {
        return resp;
    }
    if req.method() != Method::POST {
        return method_not_allowed();
    }

    let (user_id, _, _) = match require_session_user(&state, req.headers()).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    if !is_json_content_type(req.headers()) {
        return bad_request("content-type must be application/json");
    }

    let body = match to_bytes(req.into_body(), 1024).await {
        Ok(b) => b,
        Err(_) => return bad_request("invalid body"),
    };

    #[derive(Deserialize)]
    struct CommitAmkRequest {
        amk_commit: String,
    }

    let payload: CommitAmkRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return bad_request("invalid JSON"),
    };

    let amk_commit = match URL_SAFE_NO_PAD.decode(&payload.amk_commit) {
        Ok(v) if v.len() == 32 => v,
        _ => return bad_request("amk_commit must be base64url-encoded 32 bytes"),
    };

    match state.amk_store.commit_amk(user_id, &amk_commit).await {
        Ok(AmkUpsertResult::Ok) => json_response(StatusCode::OK, serde_json::json!({ "ok": true })),
        Ok(AmkUpsertResult::CommitMismatch) => error_response(
            StatusCode::CONFLICT,
            "a different AMK is already committed for this account",
        ),
        Err(e) => {
            error!(error = %e, "failed to commit AMK");
            internal_server_error()
        }
    }
}

/// `GET /api/v1/amk/exists` — check if user has an AMK committed.
pub async fn handle_amk_exists_entry(State(state): State<Arc<AppState>>, req: Request) -> Response {
    if let Err(resp) = require_encrypted_notes(&state) {
        return resp;
    }
    if req.method() != Method::GET {
        return method_not_allowed();
    }

    // Either auth works — try session first so session Bearer tokens aren't misinterpreted.
    let user_id = if let Ok((uid, _, _)) = require_session_user(&state, req.headers()).await {
        uid
    } else if let Some(raw) = api_key_from_headers(req.headers()) {
        match state.auth.authenticate(&raw).await {
            Ok(k) => match k.user_id {
                Some(uid) => uid,
                None => return bad_request("api key is not linked to a user account"),
            },
            Err(_) => return unauthorized(),
        }
    } else {
        return unauthorized();
    };

    match state.amk_store.get_amk_commit(user_id).await {
        Ok(commit) => json_response(
            StatusCode::OK,
            AmkExistsResponse {
                exists: commit.is_some(),
            },
        ),
        Err(e) => {
            error!(error = %e, "failed to check AMK existence");
            internal_server_error()
        }
    }
}

// --- Encrypted metadata endpoint ---

/// `PUT /api/v1/secrets/:id/meta` — attach or update enc_meta on an existing secret.
pub async fn handle_secret_meta_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    if let Err(resp) = require_encrypted_notes(&state) {
        return resp;
    }
    if req.method() != Method::PUT {
        return method_not_allowed();
    }

    // Auth required (session or API key, must resolve to user).
    // Try session auth first so a session Bearer token isn't misinterpreted as an API key.
    let owner_keys = if let Ok((user_id, _, _)) = require_session_user(&state, req.headers()).await
    {
        match owner_keys_for_user(&state, user_id).await {
            Ok(keys) => keys,
            Err(resp) => return resp,
        }
    } else if let Some(raw) = api_key_from_headers(req.headers()) {
        let api_key = match state.auth.authenticate(&raw).await {
            Ok(k) => k,
            Err(_) => return unauthorized(),
        };
        match owner_keys_for_api_key(&state, &api_key).await {
            Ok(keys) => keys,
            Err(resp) => return resp,
        }
    } else {
        return unauthorized();
    };

    let payload: UpdateEncMetaRequest = match read_json_body(req, 16 * 1024, None).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Validate enc_meta fields
    if payload.enc_meta.v != 1 {
        return bad_request("enc_meta.v must be 1");
    }

    // Validate ct: base64url, max 8192 bytes decoded
    let ct_bytes = match URL_SAFE_NO_PAD.decode(&payload.enc_meta.note.ct) {
        Ok(v) => v,
        Err(_) => return bad_request("enc_meta.note.ct is not valid base64url"),
    };
    if ct_bytes.len() > 8192 {
        return bad_request("enc_meta.note.ct exceeds 8 KiB decoded");
    }

    // Validate nonce: exactly 12 bytes
    let nonce_bytes = match URL_SAFE_NO_PAD.decode(&payload.enc_meta.note.nonce) {
        Ok(v) => v,
        Err(_) => return bad_request("enc_meta.note.nonce is not valid base64url"),
    };
    if nonce_bytes.len() != 12 {
        return bad_request("enc_meta.note.nonce must be exactly 12 bytes");
    }

    // Validate salt: exactly 32 bytes
    let salt_bytes = match URL_SAFE_NO_PAD.decode(&payload.enc_meta.note.salt) {
        Ok(v) => v,
        Err(_) => return bad_request("enc_meta.note.salt is not valid base64url"),
    };
    if salt_bytes.len() != 32 {
        return bad_request("enc_meta.note.salt must be exactly 32 bytes");
    }

    match state
        .amk_store
        .update_enc_meta(
            &id,
            &owner_keys,
            &payload.enc_meta,
            payload.meta_key_version,
        )
        .await
    {
        Ok(()) => json_response(StatusCode::OK, serde_json::json!({ "ok": true })),
        Err(StorageError::NotFound) => not_found(),
        Err(e) => {
            error!(error = %e, "failed to update enc_meta");
            internal_server_error()
        }
    }
}

// --- Device challenge endpoint ---

/// `GET /api/v1/auth/device/challenge?user_code=X` — fetch challenge details for ECDH.
pub async fn handle_device_challenge_entry(
    State(state): State<Arc<AppState>>,
    query: Query<DeviceChallengeQuery>,
    req: Request,
) -> Response {
    if req.method() != Method::GET {
        return method_not_allowed();
    }

    // Session auth only (the approving browser user)
    if let Err(resp) = require_session_user(&state, req.headers()).await {
        return resp;
    }

    let now = Utc::now();
    let challenge = match state
        .auth_store
        .find_device_challenge_by_user_code(&query.user_code, now)
        .await
    {
        Ok(c) => c,
        Err(StorageError::NotFound) => return not_found(),
        Err(e) => {
            error!(error = %e, "failed to find device challenge");
            return internal_server_error();
        }
    };

    let data: DeviceChallengeJson = match serde_json::from_str(&challenge.challenge_json) {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };

    // Only return pending challenges
    if data.status != "pending" {
        return not_found();
    }

    json_response(
        StatusCode::OK,
        DeviceChallengeResponse {
            user_code: data.user_code,
            ecdh_public_key: data.ecdh_public_key,
            status: data.status,
        },
    )
}

pub async fn handle_info_entry(State(state): State<Arc<AppState>>, req: Request) -> Response {
    if req.method() != Method::GET {
        return method_not_allowed();
    }

    let ip = get_client_ip(req.headers(), request_connect_addr(&req));
    if !state.claim_limiter.allow(&ip) {
        return rate_limited();
    }

    let (authenticated, user_id) = if let Some(raw) = api_key_from_headers(req.headers()) {
        match state.auth.authenticate(&raw).await {
            Ok(api_key) => (true, api_key.user_id.map(|uid| uid.to_string())),
            Err(_) => (false, None),
        }
    } else {
        (false, None)
    };

    let mut resp = json_response(
        StatusCode::OK,
        InfoResponse {
            authenticated,
            user_id,
            ttl: InfoTtl {
                default_seconds: secrt_core::DEFAULT_TTL_SECONDS,
                max_seconds: secrt_core::ttl::MAX_TTL_SECONDS,
            },
            limits: InfoLimits {
                public: InfoTier {
                    max_envelope_bytes: state.cfg.public_max_envelope_bytes,
                    max_secrets: state.cfg.public_max_secrets,
                    max_total_bytes: state.cfg.public_max_total_bytes,
                    rate: InfoRate {
                        requests_per_second: state.cfg.public_create_rate,
                        burst: state.cfg.public_create_burst as i64,
                    },
                },
                authed: InfoTier {
                    max_envelope_bytes: state.cfg.authed_max_envelope_bytes,
                    max_secrets: state.cfg.authed_max_secrets,
                    max_total_bytes: state.cfg.authed_max_total_bytes,
                    rate: InfoRate {
                        requests_per_second: state.cfg.authed_create_rate,
                        burst: state.cfg.authed_create_burst as i64,
                    },
                },
            },
            claim_rate: InfoRate {
                requests_per_second: state.cfg.claim_rate,
                burst: state.cfg.claim_burst as i64,
            },
            features: InfoFeatures {
                encrypted_notes: state.cfg.encrypted_notes_enabled,
            },
        },
    );

    if authenticated {
        insert_header(resp.headers_mut(), "cache-control", "private, no-store");
        insert_header(resp.headers_mut(), "vary", "Authorization, X-API-Key");
    } else {
        insert_header(resp.headers_mut(), "cache-control", "public, max-age=300");
    }
    resp
}

pub async fn handle_healthz() -> Response {
    json_response(
        StatusCode::OK,
        HealthResponse {
            ok: true,
            time: Utc::now().to_rfc3339(),
        },
    )
}

pub async fn handle_index() -> Response {
    let html = crate::assets::spa_index_html()
        .unwrap_or_else(|| include_str!("../../templates/index.html").to_string());

    let mut resp = Html(html).into_response();
    insert_header(resp.headers_mut(), "cache-control", "no-store");
    resp
}

pub async fn handle_service_worker() -> Response {
    let Some(body) = crate::assets::web_asset_bytes("sw.js") else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let mut resp = (
        StatusCode::OK,
        [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
        body,
    )
        .into_response();
    insert_header(resp.headers_mut(), "cache-control", "no-store");
    insert_header(resp.headers_mut(), "service-worker-allowed", "/");
    resp
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

pub async fn handle_secret_page(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let base = &state.cfg.public_base_url;
    let escaped_id = escape_html(&id);
    let secret_url = format!("{base}/s/{escaped_id}");
    let secret_image = format!("{base}/static/og-secret.png");

    let html = match crate::assets::spa_index_html() {
        Some(spa) => {
            // Rewrite generic OG/Twitter meta tags for secret-specific previews
            spa.replace(
                "content=\"secrt — Private One-Time Secret Sharing\"",
                "content=\"You've been sent a secret\"",
            )
            .replace(
                "content=\"Share passwords, keys, and sensitive data with zero-knowledge encryption. Secrets self-destruct after being read.\"",
                "content=\"Open to view your secret. It can only be viewed once.\"",
            )
            .replace(
                "content=\"https://secrt.ca/static/og-image.png\"",
                &format!("content=\"{secret_image}\""),
            )
            .replace(
                "content=\"https://secrt.ca\"",
                &format!("content=\"{secret_url}\""),
            )
            .replace(
                "<title>secrt</title>",
                "<title>You've been sent a secret — secrt</title>",
            )
        }
        None => {
            // No SPA built — serve minimal fallback with secret-specific OG tags
            format!(
                "<!doctype html><html lang=\"en\"><head>\
                 <meta charset=\"utf-8\">\
                 <title>You've been sent a secret — secrt</title>\
                 <meta property=\"og:title\" content=\"You've been sent a secret\">\
                 <meta property=\"og:description\" content=\"Open to view your secret. It can only be viewed once.\">\
                 <meta property=\"og:image\" content=\"{secret_image}\">\
                 <meta property=\"og:url\" content=\"{secret_url}\">\
                 </head><body><h1>Secret {escaped_id}</h1></body></html>"
            )
        }
    };

    let mut resp = Html(html).into_response();
    insert_header(resp.headers_mut(), "cache-control", "no-store");
    insert_header(resp.headers_mut(), "x-robots-tag", "noindex");
    resp
}

pub async fn handle_robots_txt() -> Response {
    let mut resp = (
        StatusCode::OK,
        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
        "# secrt.ca — end-to-end encrypted secret sharing\n\
         # Source: https://github.com/getsecrt/secrt\n\
         # Learn more: https://secrt.ca/how-it-works\n\
         \n\
         User-agent: *\n\
         Allow: /\n\
         Allow: /how-it-works\n\
         Allow: /privacy\n\
         Disallow: /s/\n\
         Disallow: /api/\n\
         Disallow: /dashboard\n\
         Disallow: /settings\n\
         Disallow: /login\n\
         Disallow: /register\n\
         \n\
         # Security contact: https://secrt.ca/.well-known/security.txt\n",
    )
        .into_response();
    insert_header(resp.headers_mut(), "cache-control", "no-store");
    resp
}

pub async fn handle_security_txt() -> Response {
    let mut resp = (
        StatusCode::OK,
        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
        "Contact: mailto:security@secrt.ca\n\
         Expires: 2027-02-17T00:00:00.000Z\n\
         Preferred-Languages: en\n\
         Canonical: https://secrt.ca/.well-known/security.txt\n\
         Policy: https://github.com/getsecrt/secrt/blob/main/SECURITY.md\n",
    )
        .into_response();
    insert_header(resp.headers_mut(), "cache-control", "public, max-age=86400");
    resp
}

pub fn parse_socket_addr(addr: &str) -> Result<SocketAddr, std::net::AddrParseError> {
    if addr.starts_with(':') {
        return format!("0.0.0.0{addr}").parse();
    }
    addr.parse()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::storage::{
        ApiKeyRecord, ApiKeyRegistrationLimits, AuthStore, ChallengeRecord, PasskeyRecord,
        SecretSummary, SessionRecord, StorageUsage, UserRecord,
    };
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::Request;
    use chrono::Datelike;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::Mutex;
    use tower::ServiceExt;
    use uuid::Uuid;

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(v) = &self.prev {
                std::env::set_var(self.key, v);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[allow(dead_code)]
    #[derive(Default)]
    struct MemStore {
        secrets: Mutex<HashMap<String, SecretRecord>>,
        keys: Mutex<HashMap<String, ApiKeyRecord>>,
        users: Mutex<HashMap<UserId, UserRecord>>,
        sessions: Mutex<HashMap<String, SessionRecord>>,
        challenges: Mutex<HashMap<String, ChallengeRecord>>,
        amk_wrappers: Mutex<HashMap<String, AmkWrapperRecord>>,
        amk_commits: Mutex<HashMap<Uuid, Vec<u8>>>,
    }

    #[async_trait]
    impl SecretsStore for MemStore {
        async fn create(&self, secret: SecretRecord) -> Result<(), StorageError> {
            let mut m = self.secrets.lock().unwrap();
            if m.contains_key(&secret.id) {
                return Err(StorageError::DuplicateId);
            }
            m.insert(secret.id.clone(), secret);
            Ok(())
        }

        async fn claim_and_delete(
            &self,
            id: &str,
            claim_hash: &str,
            now: DateTime<Utc>,
        ) -> Result<SecretRecord, StorageError> {
            let mut m = self.secrets.lock().unwrap();
            let Some(s) = m.get(id).cloned() else {
                return Err(StorageError::NotFound);
            };
            if s.claim_hash != claim_hash || s.expires_at <= now {
                if s.expires_at <= now {
                    m.remove(id);
                }
                return Err(StorageError::NotFound);
            }
            m.remove(id).ok_or(StorageError::NotFound)
        }

        async fn burn(&self, id: &str, owner_key: &str) -> Result<bool, StorageError> {
            let mut m = self.secrets.lock().unwrap();
            let Some(s) = m.get(id) else {
                return Ok(false);
            };
            if s.owner_key != owner_key {
                return Ok(false);
            }
            m.remove(id);
            Ok(true)
        }

        async fn delete_expired(&self, now: DateTime<Utc>) -> Result<i64, StorageError> {
            let mut m = self.secrets.lock().unwrap();
            let before = m.len();
            m.retain(|_, s| s.expires_at > now);
            Ok((before - m.len()) as i64)
        }

        async fn get_usage(&self, owner_key: &str) -> Result<StorageUsage, StorageError> {
            let m = self.secrets.lock().unwrap();
            let mut usage = StorageUsage {
                secret_count: 0,
                total_bytes: 0,
            };
            for s in m.values() {
                if s.owner_key == owner_key {
                    usage.secret_count += 1;
                    usage.total_bytes += s.envelope.len() as i64;
                }
            }
            Ok(usage)
        }

        async fn list_by_owner_keys(
            &self,
            owner_keys: &[String],
            now: DateTime<Utc>,
            limit: i64,
            offset: i64,
        ) -> Result<Vec<SecretSummary>, StorageError> {
            let m = self.secrets.lock().unwrap();
            let mut matching: Vec<_> = m
                .values()
                .filter(|s| owner_keys.contains(&s.owner_key) && s.expires_at > now)
                .collect();
            matching.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            Ok(matching
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .map(|s| {
                    let passphrase_protected =
                        serde_json::from_str::<serde_json::Value>(&s.envelope)
                            .ok()
                            .and_then(|v| v.get("kdf")?.get("name")?.as_str().map(|n| n != "none"))
                            .unwrap_or(false);
                    SecretSummary {
                        id: s.id.clone(),
                        expires_at: s.expires_at,
                        created_at: s.created_at,
                        ciphertext_size: s.envelope.len() as i64,
                        passphrase_protected,
                        enc_meta: None,
                    }
                })
                .collect())
        }

        async fn count_by_owner_keys(
            &self,
            owner_keys: &[String],
            now: DateTime<Utc>,
        ) -> Result<i64, StorageError> {
            let m = self.secrets.lock().unwrap();
            Ok(m.values()
                .filter(|s| owner_keys.contains(&s.owner_key) && s.expires_at > now)
                .count() as i64)
        }

        async fn burn_all_by_owner_keys(&self, owner_keys: &[String]) -> Result<i64, StorageError> {
            let mut m = self.secrets.lock().unwrap();
            let before = m.len();
            m.retain(|_, s| !owner_keys.contains(&s.owner_key));
            Ok((before - m.len()) as i64)
        }

        async fn checksum_by_owner_keys(
            &self,
            owner_keys: &[String],
            now: DateTime<Utc>,
        ) -> Result<(i64, String), StorageError> {
            let m = self.secrets.lock().unwrap();
            let mut ids: Vec<&str> = m
                .values()
                .filter(|s| owner_keys.contains(&s.owner_key) && s.expires_at > now)
                .map(|s| s.id.as_str())
                .collect();
            ids.sort();
            let count = ids.len() as i64;
            if ids.is_empty() {
                return Ok((0, String::new()));
            }
            let joined = ids.join(",");
            let mut hasher = std::hash::DefaultHasher::new();
            std::hash::Hash::hash(&joined, &mut hasher);
            let checksum = format!("{:016x}", std::hash::Hasher::finish(&hasher));
            Ok((count, checksum))
        }

        async fn get_summary_by_id(
            &self,
            id: &str,
            owner_keys: &[String],
            now: DateTime<Utc>,
        ) -> Result<Option<SecretSummary>, StorageError> {
            let m = self.secrets.lock().unwrap();
            let Some(s) = m.get(id) else {
                return Ok(None);
            };
            if !owner_keys.contains(&s.owner_key) || s.expires_at <= now {
                return Ok(None);
            }
            let passphrase_protected = serde_json::from_str::<serde_json::Value>(&s.envelope)
                .ok()
                .and_then(|v| v.get("kdf")?.get("name")?.as_str().map(|n| n != "none"))
                .unwrap_or(false);
            Ok(Some(SecretSummary {
                id: s.id.clone(),
                expires_at: s.expires_at,
                created_at: s.created_at,
                ciphertext_size: s.envelope.len() as i64,
                passphrase_protected,
                enc_meta: None,
            }))
        }
    }

    #[async_trait]
    impl ApiKeysStore for MemStore {
        async fn get_by_prefix(&self, prefix: &str) -> Result<ApiKeyRecord, StorageError> {
            self.keys
                .lock()
                .unwrap()
                .get(prefix)
                .cloned()
                .ok_or(StorageError::NotFound)
        }

        async fn insert(&self, key: ApiKeyRecord) -> Result<(), StorageError> {
            self.keys.lock().unwrap().insert(key.prefix.clone(), key);
            Ok(())
        }

        async fn revoke_by_prefix(&self, prefix: &str) -> Result<bool, StorageError> {
            let mut m = self.keys.lock().unwrap();
            let Some(k) = m.get_mut(prefix) else {
                return Ok(false);
            };
            if k.revoked_at.is_some() {
                return Ok(false);
            }
            k.revoked_at = Some(Utc::now());
            Ok(true)
        }

        async fn list_by_user_id(
            &self,
            user_id: UserId,
        ) -> Result<Vec<ApiKeyRecord>, StorageError> {
            let m = self.keys.lock().unwrap();
            let mut result: Vec<_> = m
                .values()
                .filter(|k| k.user_id == Some(user_id))
                .cloned()
                .collect();
            result.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            Ok(result)
        }

        async fn revoke_all_by_user_id(&self, user_id: UserId) -> Result<i64, StorageError> {
            let mut m = self.keys.lock().unwrap();
            let mut count = 0i64;
            for k in m.values_mut() {
                if k.user_id == Some(user_id) && k.revoked_at.is_none() {
                    k.revoked_at = Some(Utc::now());
                    count += 1;
                }
            }
            Ok(count)
        }
    }

    #[async_trait]
    impl AuthStore for MemStore {
        async fn create_user(&self, display_name: &str) -> Result<UserRecord, StorageError> {
            let now = Utc::now();
            let user = UserRecord {
                id: Uuid::now_v7(),
                display_name: display_name.to_string(),
                created_at: now,
                last_active_at: now.date_naive().with_day(1).expect("day 1 always valid"),
            };
            self.users.lock().unwrap().insert(user.id, user.clone());
            Ok(user)
        }

        async fn get_user_by_id(&self, user_id: UserId) -> Result<UserRecord, StorageError> {
            self.users
                .lock()
                .unwrap()
                .get(&user_id)
                .cloned()
                .ok_or(StorageError::NotFound)
        }

        async fn insert_passkey(
            &self,
            _user_id: UserId,
            _credential_id: &str,
            _public_key: &str,
            _sign_count: i64,
        ) -> Result<PasskeyRecord, StorageError> {
            Err(StorageError::Other("unsupported".into()))
        }

        async fn get_passkey_by_credential_id(
            &self,
            _credential_id: &str,
        ) -> Result<PasskeyRecord, StorageError> {
            Err(StorageError::NotFound)
        }

        async fn update_passkey_sign_count(
            &self,
            _credential_id: &str,
            _sign_count: i64,
        ) -> Result<(), StorageError> {
            Err(StorageError::NotFound)
        }

        async fn insert_session(
            &self,
            sid: &str,
            user_id: UserId,
            token_hash: &str,
            expires_at: DateTime<Utc>,
        ) -> Result<SessionRecord, StorageError> {
            let sess = SessionRecord {
                id: 0,
                sid: sid.to_string(),
                user_id,
                token_hash: token_hash.to_string(),
                expires_at,
                created_at: Utc::now(),
                revoked_at: None,
            };
            self.sessions
                .lock()
                .unwrap()
                .insert(sid.to_string(), sess.clone());
            Ok(sess)
        }

        async fn get_session_by_sid(&self, sid: &str) -> Result<SessionRecord, StorageError> {
            self.sessions
                .lock()
                .unwrap()
                .get(sid)
                .cloned()
                .ok_or(StorageError::NotFound)
        }

        async fn revoke_session_by_sid(&self, sid: &str) -> Result<bool, StorageError> {
            let mut m = self.sessions.lock().unwrap();
            let Some(sess) = m.get_mut(sid) else {
                return Ok(false);
            };
            if sess.revoked_at.is_some() {
                return Ok(false);
            }
            sess.revoked_at = Some(Utc::now());
            Ok(true)
        }

        async fn insert_challenge(
            &self,
            challenge_id: &str,
            user_id: Option<UserId>,
            purpose: &str,
            challenge_json: &str,
            expires_at: DateTime<Utc>,
        ) -> Result<ChallengeRecord, StorageError> {
            let rec = ChallengeRecord {
                id: 0,
                challenge_id: challenge_id.to_string(),
                user_id,
                purpose: purpose.to_string(),
                challenge_json: challenge_json.to_string(),
                expires_at,
                created_at: Utc::now(),
            };
            self.challenges
                .lock()
                .unwrap()
                .insert(challenge_id.to_string(), rec.clone());
            Ok(rec)
        }

        async fn consume_challenge(
            &self,
            challenge_id: &str,
            purpose: &str,
            now: DateTime<Utc>,
        ) -> Result<ChallengeRecord, StorageError> {
            let mut m = self.challenges.lock().unwrap();
            let rec = m
                .get(challenge_id)
                .filter(|r| r.purpose == purpose && r.expires_at > now)
                .cloned()
                .ok_or(StorageError::NotFound)?;
            m.remove(challenge_id);
            Ok(rec)
        }

        async fn get_challenge(
            &self,
            challenge_id: &str,
            purpose: &str,
            now: DateTime<Utc>,
        ) -> Result<ChallengeRecord, StorageError> {
            self.challenges
                .lock()
                .unwrap()
                .get(challenge_id)
                .filter(|r| r.purpose == purpose && r.expires_at > now)
                .cloned()
                .ok_or(StorageError::NotFound)
        }

        async fn update_challenge_json(
            &self,
            challenge_id: &str,
            purpose: &str,
            challenge_json: &str,
            now: DateTime<Utc>,
        ) -> Result<(), StorageError> {
            let mut m = self.challenges.lock().unwrap();
            let rec = m
                .get_mut(challenge_id)
                .filter(|r| r.purpose == purpose && r.expires_at > now)
                .ok_or(StorageError::NotFound)?;
            rec.challenge_json = challenge_json.to_string();
            Ok(())
        }

        async fn find_device_challenge_by_user_code(
            &self,
            user_code: &str,
            now: DateTime<Utc>,
        ) -> Result<ChallengeRecord, StorageError> {
            let m = self.challenges.lock().unwrap();
            for rec in m.values() {
                if rec.purpose != "device-auth" || rec.expires_at <= now {
                    continue;
                }
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&rec.challenge_json) {
                    if json.get("user_code").and_then(|v| v.as_str()) == Some(user_code) {
                        return Ok(rec.clone());
                    }
                }
            }
            Err(StorageError::NotFound)
        }

        async fn count_apikey_registrations_by_user_since(
            &self,
            _user_id: UserId,
            _since: DateTime<Utc>,
        ) -> Result<i64, StorageError> {
            Ok(0)
        }

        async fn count_apikey_registrations_by_ip_since(
            &self,
            _ip_hash: &str,
            _since: DateTime<Utc>,
        ) -> Result<i64, StorageError> {
            Ok(0)
        }

        async fn register_api_key(
            &self,
            key: ApiKeyRecord,
            _ip_hash: &str,
            _now: DateTime<Utc>,
            _limits: ApiKeyRegistrationLimits,
        ) -> Result<(), StorageError> {
            self.keys.lock().unwrap().insert(key.prefix.clone(), key);
            Ok(())
        }

        async fn insert_apikey_registration_event(
            &self,
            _user_id: UserId,
            _ip_hash: &str,
            _now: DateTime<Utc>,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn delete_user(&self, user_id: UserId) -> Result<bool, StorageError> {
            let removed = self.users.lock().unwrap().remove(&user_id).is_some();
            if removed {
                self.sessions
                    .lock()
                    .unwrap()
                    .retain(|_, s| s.user_id != user_id);
            }
            Ok(removed)
        }

        async fn touch_user_last_active(
            &self,
            user_id: UserId,
            now: DateTime<Utc>,
        ) -> Result<(), StorageError> {
            let month_start = now.date_naive().with_day(1).expect("day 1 always valid");
            let mut m = self.users.lock().unwrap();
            if let Some(u) = m.get_mut(&user_id) {
                if u.last_active_at < month_start {
                    u.last_active_at = month_start;
                }
            }
            Ok(())
        }

        async fn update_display_name(
            &self,
            user_id: UserId,
            display_name: &str,
        ) -> Result<(), StorageError> {
            let mut m = self.users.lock().unwrap();
            let u = m.get_mut(&user_id).ok_or(StorageError::NotFound)?;
            u.display_name = display_name.to_string();
            Ok(())
        }

        async fn list_passkeys_by_user(
            &self,
            _user_id: UserId,
        ) -> Result<Vec<PasskeyRecord>, StorageError> {
            Ok(vec![])
        }

        async fn revoke_passkey(&self, _id: i64, _user_id: UserId) -> Result<bool, StorageError> {
            Ok(false)
        }

        async fn update_passkey_label(
            &self,
            _id: i64,
            _user_id: UserId,
            _label: &str,
        ) -> Result<(), StorageError> {
            Err(StorageError::NotFound)
        }
    }

    #[async_trait]
    impl AmkStore for MemStore {
        async fn upsert_wrapper(
            &self,
            w: AmkWrapperRecord,
            amk_commit: &[u8],
        ) -> Result<AmkUpsertResult, StorageError> {
            {
                let mut commits = self.amk_commits.lock().unwrap();
                let stored = commits
                    .entry(w.user_id)
                    .or_insert_with(|| amk_commit.to_vec());
                if stored.as_slice() != amk_commit {
                    return Ok(AmkUpsertResult::CommitMismatch);
                }
            }
            let key = format!("{}:{}", w.user_id, w.key_prefix);
            self.amk_wrappers.lock().unwrap().insert(key, w);
            Ok(AmkUpsertResult::Ok)
        }

        async fn get_wrapper(
            &self,
            user_id: Uuid,
            key_prefix: &str,
        ) -> Result<Option<AmkWrapperRecord>, StorageError> {
            let key = format!("{user_id}:{key_prefix}");
            Ok(self.amk_wrappers.lock().unwrap().get(&key).cloned())
        }

        async fn list_wrappers(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<AmkWrapperRecord>, StorageError> {
            let m = self.amk_wrappers.lock().unwrap();
            Ok(m.values()
                .filter(|w| w.user_id == user_id)
                .cloned()
                .collect())
        }

        async fn delete_wrapper(
            &self,
            user_id: Uuid,
            key_prefix: &str,
        ) -> Result<bool, StorageError> {
            let key = format!("{user_id}:{key_prefix}");
            Ok(self.amk_wrappers.lock().unwrap().remove(&key).is_some())
        }

        async fn has_any_wrapper(&self, user_id: Uuid) -> Result<bool, StorageError> {
            let m = self.amk_wrappers.lock().unwrap();
            Ok(m.values().any(|w| w.user_id == user_id))
        }

        async fn get_amk_commit(&self, user_id: Uuid) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.amk_commits.lock().unwrap().get(&user_id).cloned())
        }

        async fn commit_amk(
            &self,
            user_id: Uuid,
            amk_commit: &[u8],
        ) -> Result<AmkUpsertResult, StorageError> {
            let mut commits = self.amk_commits.lock().unwrap();
            let stored = commits
                .entry(user_id)
                .or_insert_with(|| amk_commit.to_vec());
            if stored.as_slice() != amk_commit {
                Ok(AmkUpsertResult::CommitMismatch)
            } else {
                Ok(AmkUpsertResult::Ok)
            }
        }

        async fn update_enc_meta(
            &self,
            secret_id: &str,
            owner_keys: &[String],
            _enc_meta: &secrt_core::api::EncMetaV1,
            _meta_key_version: i16,
        ) -> Result<(), StorageError> {
            let m = self.secrets.lock().unwrap();
            let Some(s) = m.get(secret_id) else {
                return Err(StorageError::NotFound);
            };
            if !owner_keys.contains(&s.owner_key) {
                return Err(StorageError::NotFound);
            }
            Ok(())
        }
    }

    #[test]
    fn json_content_type() {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert!(is_json_content_type(&h));
        h.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(!is_json_content_type(&h));
    }

    #[test]
    fn socket_addr_parsing() {
        assert!(parse_socket_addr(":8080").is_ok());
        assert!(parse_socket_addr("127.0.0.1:8080").is_ok());
    }

    #[tokio::test]
    async fn build_router_prefers_env_static_dir() {
        let _guard = EnvVarGuard::set("SECRT_WEB_DIST_DIR", "web/dist");
        let app = build_router(test_state());
        let req = Request::builder()
            .method("GET")
            .uri("/static/index.html")
            .body(Body::empty())
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert!(matches!(
            resp.status(),
            StatusCode::OK | StatusCode::NOT_FOUND
        ));
    }

    #[tokio::test]
    async fn service_worker_route_sets_scope_headers() {
        let app = build_router(test_state());
        let req = Request::builder()
            .method("GET")
            .uri("/sw.js")
            .body(Body::empty())
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert!(matches!(
            resp.status(),
            StatusCode::OK | StatusCode::NOT_FOUND
        ));

        if resp.status() == StatusCode::OK {
            assert_eq!(
                resp.headers()
                    .get("cache-control")
                    .and_then(|v| v.to_str().ok()),
                Some("no-store")
            );
            assert_eq!(
                resp.headers()
                    .get("service-worker-allowed")
                    .and_then(|v| v.to_str().ok()),
                Some("/")
            );
            assert_eq!(
                resp.headers()
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()),
                Some("application/javascript; charset=utf-8")
            );
        }
    }

    #[test]
    fn session_token_parsing_and_hash_helpers() {
        let mut wrong_scheme = HeaderMap::new();
        wrong_scheme.insert(AUTHORIZATION, HeaderValue::from_static("Basic token"));
        assert!(session_token_from_headers(&wrong_scheme).is_none());

        let mut wrong_prefix = HeaderMap::new();
        wrong_prefix.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer sk2_not-a-session"),
        );
        assert!(session_token_from_headers(&wrong_prefix).is_none());

        let mut empty_sid = HeaderMap::new();
        empty_sid.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer uss_.secret"),
        );
        assert!(session_token_from_headers(&empty_sid).is_none());

        let mut empty_secret = HeaderMap::new();
        empty_secret.insert(AUTHORIZATION, HeaderValue::from_static("Bearer uss_sid."));
        assert!(session_token_from_headers(&empty_secret).is_none());

        assert!(hash_session_token("", "sid", "secret").is_err());
    }

    #[test]
    fn api_key_header_parse() {
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_static("ak2_a.b"));
        assert_eq!(api_key_from_headers(&h).unwrap(), "ak2_a.b");
    }

    #[test]
    fn client_ip_from_loopback_proxy() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.5"));
        let ip = get_client_ip(&h, Some(SocketAddr::from(([127, 0, 0, 1], 1234))));
        assert_eq!(ip, "203.0.113.5");
    }

    #[test]
    fn api_key_bearer_parse_and_empty_values() {
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer ak2_token.value"),
        );
        assert_eq!(api_key_from_headers(&h).as_deref(), Some("ak2_token.value"));

        let mut blank = HeaderMap::new();
        blank.insert("x-api-key", HeaderValue::from_static("   "));
        assert!(api_key_from_headers(&blank).is_none());

        let mut blank_bearer = HeaderMap::new();
        blank_bearer.insert(AUTHORIZATION, HeaderValue::from_static("Bearer   "));
        assert!(api_key_from_headers(&blank_bearer).is_none());
    }

    #[test]
    fn client_ip_fallback_paths() {
        let mut loopback_xff_empty = HeaderMap::new();
        loopback_xff_empty.insert(
            "x-forwarded-for",
            HeaderValue::from_static(" , 203.0.113.1"),
        );
        let ip = get_client_ip(
            &loopback_xff_empty,
            Some(SocketAddr::from(([127, 0, 0, 1], 1000))),
        );
        assert_eq!(ip, "127.0.0.1");

        let mut non_loopback = HeaderMap::new();
        non_loopback.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.4"));
        let ip2 = get_client_ip(
            &non_loopback,
            Some(SocketAddr::from(([203, 0, 113, 20], 1000))),
        );
        assert_eq!(ip2, "203.0.113.20");

        let ip3 = get_client_ip(&HeaderMap::new(), None);
        assert_eq!(ip3, "unknown");
    }

    #[test]
    fn panic_handler_returns_internal_server_error() {
        let resp = handle_panic(Box::new("boom"));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn catch_panic_layer_converts_panics_to_500() {
        let app = Router::new()
            .route(
                "/panic",
                get(|| async move {
                    panic!("boom");
                    #[allow(unreachable_code)]
                    {
                        "never"
                    }
                }),
            )
            .layer(CatchPanicLayer::custom(handle_panic));

        let req = Request::builder()
            .method("GET")
            .uri("/panic")
            .body(Body::empty())
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    async fn response_text(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        String::from_utf8(bytes.to_vec()).expect("utf8")
    }

    #[tokio::test]
    async fn read_json_body_too_large_with_and_without_custom_message() {
        let req_custom = Request::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"claim":"abcdefghijklmnopqrstuvwxyz"}"#))
            .expect("request");
        let resp = read_json_body::<ClaimSecretRequest>(req_custom, 8, Some("too large".into()))
            .await
            .err()
            .expect("expected too-large error");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(response_text(resp).await.contains("too large"));

        let req_default = Request::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"claim":"abcdefghijklmnopqrstuvwxyz"}"#))
            .expect("request");
        let resp2 = read_json_body::<ClaimSecretRequest>(req_default, 8, None)
            .await
            .err()
            .expect("expected too-large error");
        assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
        assert!(response_text(resp2).await.contains("invalid request body"));
    }

    #[tokio::test]
    async fn decode_error_maps_data_errors() {
        let err = serde_json::from_slice::<ClaimSecretRequest>(br#"{"claim":1}"#)
            .err()
            .expect("expected type mismatch");
        let resp = map_decode_error(err);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(response_text(resp)
            .await
            .contains("invalid json field type"));
    }

    #[tokio::test]
    async fn passkey_and_apikey_register_entry_method_and_validation_errors() {
        let state = test_state();

        let get_req = Request::builder()
            .method("GET")
            .uri("/x")
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            handle_passkey_register_start_entry(State(state.clone()), get_req)
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );

        let non_json_start = Request::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "text/plain")
            .body(Body::from("x"))
            .expect("request");
        assert_eq!(
            handle_passkey_register_start_entry(State(state.clone()), non_json_start)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );

        let empty_name_start = Request::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"display_name":"   "}"#))
            .expect("request");
        assert_eq!(
            handle_passkey_register_start_entry(State(state.clone()), empty_name_start)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );

        let ok_payload = Request::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"display_name":"Alice"}"#))
            .expect("request");
        assert_eq!(
            handle_passkey_register_start_entry(State(state.clone()), ok_payload)
                .await
                .status(),
            StatusCode::OK
        );

        let get_finish_req = Request::builder()
            .method("GET")
            .uri("/x")
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            handle_passkey_register_finish_entry(State(state.clone()), get_finish_req)
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );

        let non_json_finish = Request::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "text/plain")
            .body(Body::from("x"))
            .expect("request");
        assert_eq!(
            handle_passkey_register_finish_entry(State(state.clone()), non_json_finish)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );

        let missing_fields_finish = Request::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"challenge_id":"c1","credential_id":"","public_key":" "}"#,
            ))
            .expect("request");
        assert_eq!(
            handle_passkey_register_finish_entry(State(state.clone()), missing_fields_finish)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );

        let bad_challenge_finish = Request::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"challenge_id":"missing","credential_id":"c1","public_key":"pk"}"#,
            ))
            .expect("request");
        assert_eq!(
            handle_passkey_register_finish_entry(State(state.clone()), bad_challenge_finish)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );

        let get_login_start = Request::builder()
            .method("GET")
            .uri("/x")
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            handle_passkey_login_start_entry(State(state.clone()), get_login_start)
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );

        let non_json_login_start = Request::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "text/plain")
            .body(Body::from("x"))
            .expect("request");
        assert_eq!(
            handle_passkey_login_start_entry(State(state.clone()), non_json_login_start)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );

        let unknown_credential = Request::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"credential_id":"missing"}"#))
            .expect("request");
        assert_eq!(
            handle_passkey_login_start_entry(State(state.clone()), unknown_credential)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );

        let get_login_finish = Request::builder()
            .method("GET")
            .uri("/x")
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            handle_passkey_login_finish_entry(State(state.clone()), get_login_finish)
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );

        let non_json_login_finish = Request::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "text/plain")
            .body(Body::from("x"))
            .expect("request");
        assert_eq!(
            handle_passkey_login_finish_entry(State(state.clone()), non_json_login_finish)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );

        let missing_challenge_login_finish = Request::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"challenge_id":"missing","credential_id":"cred"}"#,
            ))
            .expect("request");
        assert_eq!(
            handle_passkey_login_finish_entry(State(state.clone()), missing_challenge_login_finish)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );

        let get_session_req = Request::builder()
            .method("POST")
            .uri("/x")
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            handle_auth_session_entry(State(state.clone()), get_session_req)
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );

        let get_logout_req = Request::builder()
            .method("GET")
            .uri("/x")
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            handle_auth_logout_entry(State(state.clone()), get_logout_req)
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );

        let missing_logout_token = Request::builder()
            .method("POST")
            .uri("/x")
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            handle_auth_logout_entry(State(state.clone()), missing_logout_token)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let get_apikey_register = Request::builder()
            .method("GET")
            .uri("/x")
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            handle_apikey_register_entry(State(state), get_apikey_register)
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    #[tokio::test]
    async fn memstore_auth_methods_are_exercised() {
        let store = MemStore::default();
        let now = Utc::now();

        // create_user + get_user_by_id
        let user = store.create_user("alice").await.expect("create user");
        assert_eq!(user.display_name, "alice");
        let fetched = store.get_user_by_id(user.id).await.expect("get user");
        assert_eq!(fetched.id, user.id);

        let missing_id = Uuid::now_v7();
        assert!(matches!(
            store.get_user_by_id(missing_id).await,
            Err(StorageError::NotFound)
        ));

        // passkey stubs
        assert!(matches!(
            store.insert_passkey(user.id, "c", "pk", 0).await,
            Err(StorageError::Other(_))
        ));
        assert!(matches!(
            store.get_passkey_by_credential_id("c").await,
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            store.update_passkey_sign_count("c", 1).await,
            Err(StorageError::NotFound)
        ));

        // sessions
        let sess = store
            .insert_session("sid1", user.id, "hash", now + chrono::Duration::hours(1))
            .await
            .expect("insert session");
        assert_eq!(sess.sid, "sid1");
        let fetched_sess = store.get_session_by_sid("sid1").await.expect("get session");
        assert_eq!(fetched_sess.user_id, user.id);
        assert!(store.revoke_session_by_sid("sid1").await.expect("revoke"));
        assert!(!store
            .revoke_session_by_sid("sid1")
            .await
            .expect("revoke again"));
        assert!(!store
            .revoke_session_by_sid("missing")
            .await
            .expect("revoke missing"));

        // challenges
        let ch = store
            .insert_challenge("cid", None, "p", "{}", now + chrono::Duration::minutes(1))
            .await
            .expect("insert challenge");
        assert_eq!(ch.challenge_id, "cid");
        let fetched_ch = store
            .get_challenge("cid", "p", now)
            .await
            .expect("get challenge");
        assert_eq!(fetched_ch.challenge_id, "cid");
        assert!(matches!(
            store.get_challenge("cid", "wrong", now).await,
            Err(StorageError::NotFound)
        ));
        store
            .update_challenge_json("cid", "p", r#"{"updated":true}"#, now)
            .await
            .expect("update challenge json");
        let consumed = store
            .consume_challenge("cid", "p", now)
            .await
            .expect("consume challenge");
        assert_eq!(consumed.challenge_json, r#"{"updated":true}"#);
        assert!(matches!(
            store.consume_challenge("cid", "p", now).await,
            Err(StorageError::NotFound)
        ));

        // device challenge by user_code
        let _dc = store
            .insert_challenge(
                "dc1",
                None,
                "device-auth",
                r#"{"user_code":"ABCD-1234","status":"pending"}"#,
                now + chrono::Duration::minutes(10),
            )
            .await
            .expect("insert device challenge");
        let found = store
            .find_device_challenge_by_user_code("ABCD-1234", now)
            .await
            .expect("find by user_code");
        assert_eq!(found.challenge_id, "dc1");
        assert!(matches!(
            store
                .find_device_challenge_by_user_code("XXXX-0000", now)
                .await,
            Err(StorageError::NotFound)
        ));

        // rate limit helpers
        assert_eq!(
            store
                .count_apikey_registrations_by_user_since(user.id, now - chrono::Duration::hours(1))
                .await
                .expect("count by user"),
            0
        );
        assert_eq!(
            store
                .count_apikey_registrations_by_ip_since("ip", now - chrono::Duration::hours(1))
                .await
                .expect("count by ip"),
            0
        );

        // register_api_key now works
        store
            .register_api_key(
                ApiKeyRecord {
                    id: 0,
                    prefix: "pref".into(),
                    auth_hash: "a".repeat(64),
                    scopes: String::new(),
                    user_id: Some(user.id),
                    created_at: now,
                    revoked_at: None,
                },
                "ip",
                now,
                ApiKeyRegistrationLimits {
                    account_hour: 10,
                    account_day: 10,
                    ip_hour: 10,
                    ip_day: 10,
                },
            )
            .await
            .expect("register api key");
        assert!(store.get_by_prefix("pref").await.is_ok());

        store
            .insert_apikey_registration_event(user.id, "ip", now)
            .await
            .expect("insert reg event");

        // delete_user
        assert!(store.delete_user(user.id).await.expect("delete user"));
        assert!(!store.delete_user(user.id).await.expect("delete again"));
    }

    fn test_state() -> Arc<AppState> {
        let cfg = Config {
            env: "test".into(),
            listen_addr: "127.0.0.1:0".into(),
            public_base_url: "https://example.com".into(),
            log_level: "error".into(),
            database_url: String::new(),
            db_host: "127.0.0.1".into(),
            db_port: 5432,
            db_name: "secrt".into(),
            db_user: "secrt".into(),
            db_password: String::new(),
            db_sslmode: "disable".into(),
            db_sslrootcert: String::new(),
            api_key_pepper: "pepper".into(),
            session_token_pepper: "session-pepper".into(),
            public_max_envelope_bytes: 1024,
            authed_max_envelope_bytes: 2048,
            public_max_secrets: 10,
            public_max_total_bytes: 16 * 1024,
            authed_max_secrets: 20,
            authed_max_total_bytes: 32 * 1024,
            public_create_rate: 1.0,
            public_create_burst: 2,
            claim_rate: 1.0,
            claim_burst: 2,
            authed_create_rate: 1.0,
            authed_create_burst: 2,
            apikey_register_rate: 0.5,
            apikey_register_burst: 6,
            apikey_register_account_max_per_hour: 5,
            apikey_register_account_max_per_day: 20,
            apikey_register_ip_max_per_hour: 5,
            apikey_register_ip_max_per_day: 20,
            encrypted_notes_enabled: false,
        };
        let store = Arc::new(MemStore::default());
        let secrets: Arc<dyn SecretsStore> = store.clone();
        let keys: Arc<dyn ApiKeysStore> = store.clone();
        let auth_store: Arc<dyn AuthStore> = store.clone();
        let amk_store: Arc<dyn AmkStore> = store;
        Arc::new(AppState::new(cfg, secrets, keys, auth_store, amk_store))
    }

    #[test]
    fn privacy_log_header_modes() {
        let state_missing = test_state();
        check_privacy_log_header_once(&state_missing, &HeaderMap::new());
        assert!(!state_missing.privacy_checked.load(Ordering::Relaxed));

        let state_ok = test_state();
        let mut ok_headers = HeaderMap::new();
        ok_headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.1"));
        ok_headers.insert("x-privacy-log", HeaderValue::from_static("truncated-ip"));
        check_privacy_log_header_once(&state_ok, &ok_headers);
        assert!(state_ok.privacy_checked.load(Ordering::Relaxed));

        let state_unknown = test_state();
        let mut bad_headers = HeaderMap::new();
        bad_headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.2"));
        bad_headers.insert("x-privacy-log", HeaderValue::from_static("full-ip"));
        check_privacy_log_header_once(&state_unknown, &bad_headers);
        assert!(state_unknown.privacy_checked.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn secret_page_includes_id_and_noindex_headers() {
        let resp = handle_secret_page(State(test_state()), Path("abc123".to_string())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            resp.headers()
                .get("x-robots-tag")
                .and_then(|v| v.to_str().ok()),
            Some("noindex")
        );
        // SPA serves generic index.html; the secret ID is handled client-side
        let body = response_text(resp).await;
        assert!(body.contains("<!doctype html>") || body.contains("<!DOCTYPE html>"));
    }

    #[tokio::test]
    async fn security_txt_contains_required_fields() {
        let resp = handle_security_txt().await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        let body = response_text(resp).await;

        // RFC 9116 required fields
        assert!(
            body.contains("Contact: mailto:security@secrt.ca"),
            "must include Contact field"
        );
        assert!(
            body.contains("Expires:"),
            "must include Expires field (RFC 9116)"
        );

        // Recommended fields
        assert!(
            body.contains("Policy: https://github.com/getsecrt/secrt/blob/main/SECURITY.md"),
            "should link to SECURITY.md"
        );
        assert!(
            body.contains("Canonical: https://secrt.ca/.well-known/security.txt"),
            "should include canonical URL"
        );
        assert!(
            body.contains("Preferred-Languages: en"),
            "should specify preferred languages"
        );
    }

    #[tokio::test]
    async fn robots_txt_allows_public_pages_and_blocks_secrets() {
        let resp = handle_robots_txt().await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        let body = response_text(resp).await;

        // Public pages should be allowed
        assert!(body.contains("Allow: /\n"), "homepage should be allowed");
        assert!(
            body.contains("Allow: /how-it-works"),
            "how-it-works should be allowed"
        );

        // Secret URLs and API must be blocked
        assert!(
            body.contains("Disallow: /s/"),
            "secret URLs must be disallowed"
        );
        assert!(body.contains("Disallow: /api/"), "API must be disallowed");

        // Auth and account pages should be blocked
        for path in ["/dashboard", "/settings", "/login", "/register"] {
            assert!(
                body.contains(&format!("Disallow: {path}")),
                "{path} should be disallowed"
            );
        }

        // Must NOT have blanket disallow
        assert!(
            !body.contains("Disallow: /\n"),
            "must not blanket-disallow all paths"
        );
    }

    #[tokio::test]
    async fn secret_page_does_not_reflect_id_into_html() {
        // With SPA serving, the ID should never appear in the server-rendered HTML
        let reflected = "<script>alert(1)</script>";
        let resp = handle_secret_page(State(test_state()), Path(reflected.to_string())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_text(resp).await;
        assert!(
            !body.contains(reflected),
            "id must not be reflected into HTML; body={body}"
        );
    }

    #[tokio::test]
    async fn secret_page_rewrites_og_tags() {
        let state = test_state();
        let resp = handle_secret_page(State(state), Path("test-id-42".to_string())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_text(resp).await;

        // OG title should be rewritten for secret pages
        assert!(
            body.contains("content=\"You've been sent a secret\""),
            "og:title should be rewritten; body={body}"
        );
        // OG description should be rewritten
        assert!(
            body.contains("content=\"Open to view your secret. It can only be viewed once.\""),
            "og:description should be rewritten; body={body}"
        );
        // OG image should point to og-secret.png
        assert!(
            body.contains("og-secret.png"),
            "og:image should use og-secret.png; body={body}"
        );
        // OG url should contain the secret path
        assert!(
            body.contains("/s/test-id-42"),
            "og:url should contain secret path; body={body}"
        );
        // Title should be rewritten
        assert!(
            body.contains("<title>You've been sent a secret — secrt</title>"),
            "title should be rewritten; body={body}"
        );
    }

    #[tokio::test]
    async fn memstore_trait_methods_are_exercised() {
        let store = MemStore::default();
        let now = Utc::now();
        let owner = "owner-a".to_string();
        let sec = SecretRecord {
            id: "id1".into(),
            claim_hash: "claim".into(),
            envelope: "{\"ct\":\"x\"}".into(),
            expires_at: now + chrono::Duration::minutes(5),
            created_at: now,
            owner_key: owner.clone(),
        };

        store.create(sec.clone()).await.expect("create");
        assert!(matches!(
            store.create(sec.clone()).await,
            Err(StorageError::DuplicateId)
        ));
        assert!(matches!(
            store.claim_and_delete("id1", "wrong", now).await,
            Err(StorageError::NotFound)
        ));

        let claimed = store
            .claim_and_delete("id1", "claim", now)
            .await
            .expect("claim");
        assert_eq!(claimed.id, "id1");

        let sec2 = SecretRecord {
            id: "id2".into(),
            claim_hash: "claim2".into(),
            envelope: "{\"ct\":\"y\"}".into(),
            expires_at: now + chrono::Duration::minutes(5),
            created_at: now,
            owner_key: owner.clone(),
        };
        store.create(sec2).await.expect("create2");
        assert!(!store
            .burn("id2", "owner-b")
            .await
            .expect("burn wrong owner"));
        assert!(store
            .burn("id2", "owner-a")
            .await
            .expect("burn right owner"));

        let expired = SecretRecord {
            id: "id3".into(),
            claim_hash: "claim3".into(),
            envelope: "{\"ct\":\"z\"}".into(),
            expires_at: now - chrono::Duration::seconds(1),
            created_at: now,
            owner_key: owner.clone(),
        };
        store.create(expired).await.expect("create expired");
        assert_eq!(store.delete_expired(now).await.expect("delete expired"), 1);
        let usage = store.get_usage(&owner).await.expect("usage");
        assert_eq!(usage.secret_count, 0);

        let key = ApiKeyRecord {
            id: 1,
            prefix: "pref".into(),
            auth_hash: "h".repeat(64),
            scopes: String::new(),
            user_id: None,
            created_at: now,
            revoked_at: None,
        };
        store.insert(key).await.expect("insert key");
        assert!(store.get_by_prefix("pref").await.is_ok());
        assert!(store.revoke_by_prefix("pref").await.expect("revoke"));
        assert!(!store.revoke_by_prefix("pref").await.expect("revoke again"));
        assert!(matches!(
            store.get_by_prefix("missing").await,
            Err(StorageError::NotFound)
        ));
    }

    // ── Helpers for dashboard/settings endpoint tests ───────────────

    /// Create a MemStore-backed state with a user, session token, and API key.
    /// Returns (state, session_token, user_id, api_key_prefix).
    async fn test_state_with_session() -> (Arc<AppState>, String, UserId, String) {
        let state = test_state();

        // Create a user
        let user = state
            .auth_store
            .create_user("alice")
            .await
            .expect("create user");

        // Issue a session
        let (token, _expires) = issue_session_token(&state, user.id)
            .await
            .expect("issue session");

        // Register an API key
        let auth_token = [42u8; 32];
        let prefix = "test1234".to_string();
        let auth_hash = crate::domain::auth::hash_api_key_auth_token(
            &state.cfg.api_key_pepper,
            &prefix,
            &auth_token,
        )
        .expect("hash");

        let key = ApiKeyRecord {
            id: 0,
            prefix: prefix.clone(),
            auth_hash,
            scopes: String::new(),
            user_id: Some(user.id),
            created_at: Utc::now(),
            revoked_at: None,
        };
        state.api_keys.insert(key).await.expect("insert api key");

        (state, token, user.id, prefix)
    }

    /// Create a secret owned by the given owner_key.
    async fn create_test_secret(state: &Arc<AppState>, owner_key: &str, id: &str) {
        let sec = SecretRecord {
            id: id.to_string(),
            claim_hash: format!("claim_{id}"),
            envelope: r#"{"ct":"test"}"#.into(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            owner_key: owner_key.to_string(),
        };
        state.secrets.create(sec).await.expect("create secret");
    }

    fn authed_get(uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request")
    }

    fn authed_post(uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request")
    }

    fn authed_delete(uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request")
    }

    // ── Auth gate tests ────────────────────────────────────

    #[tokio::test]
    async fn list_secrets_requires_auth() {
        let state = test_state();
        let resp = handle_secrets_entry(
            State(state),
            Query(ListSecretsQuery {
                limit: None,
                offset: None,
            }),
            Request::builder()
                .method("GET")
                .uri("/api/v1/secrets")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_apikeys_requires_session_auth() {
        let state = test_state();
        // No auth at all
        let resp = handle_list_apikeys_entry(
            State(state.clone()),
            Request::builder()
                .method("GET")
                .uri("/x")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // API key auth should not work (session-only endpoint)
        let resp2 = handle_list_apikeys_entry(
            State(state),
            Request::builder()
                .method("GET")
                .uri("/x")
                .header("x-api-key", "ak2_fake.key")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoke_apikey_requires_auth() {
        let state = test_state();
        let resp = handle_revoke_apikey_entry(
            State(state),
            Path("some_prefix".into()),
            Request::builder()
                .method("POST")
                .uri("/x")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_account_requires_auth() {
        let state = test_state();
        let resp = handle_account_entry(
            State(state),
            Request::builder()
                .method("DELETE")
                .uri("/x")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn new_endpoints_reject_wrong_methods() {
        let state = test_state();

        // list_apikeys: POST -> 405
        let resp = handle_list_apikeys_entry(
            State(state.clone()),
            Request::builder()
                .method("POST")
                .uri("/x")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        // revoke_apikey: GET -> 405
        let resp = handle_revoke_apikey_entry(
            State(state.clone()),
            Path("pref".into()),
            Request::builder()
                .method("GET")
                .uri("/x")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        // delete_account: POST -> 405
        let resp = handle_account_entry(
            State(state.clone()),
            Request::builder()
                .method("POST")
                .uri("/x")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        // account: GET -> 405
        let resp = handle_account_entry(
            State(state.clone()),
            Request::builder()
                .method("GET")
                .uri("/x")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        // passkeys list: POST -> 405
        let resp = handle_passkeys_list_entry(
            State(state.clone()),
            Request::builder()
                .method("POST")
                .uri("/x")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        // passkey rename: GET -> 405
        let resp = handle_passkey_entry(
            State(state.clone()),
            Path(1),
            Request::builder()
                .method("GET")
                .uri("/x")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        // passkey revoke: GET -> 405
        let resp = handle_revoke_passkey_entry(
            State(state.clone()),
            Path(1),
            Request::builder()
                .method("GET")
                .uri("/x")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        // passkey add start: GET -> 405
        let resp = handle_passkey_add_start_entry(
            State(state.clone()),
            Request::builder()
                .method("GET")
                .uri("/x")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        // passkey add finish: GET -> 405
        let resp = handle_passkey_add_finish_entry(
            State(state),
            Request::builder()
                .method("GET")
                .uri("/x")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    // ── Functional tests ───────────────────────────────────

    #[tokio::test]
    async fn list_secrets_returns_owned_secrets() {
        let (state, token, _user_id, prefix) = test_state_with_session().await;
        let owner_key = format!("apikey:{prefix}");

        create_test_secret(&state, &owner_key, "sec1").await;
        create_test_secret(&state, &owner_key, "sec2").await;
        create_test_secret(&state, "apikey:other", "sec3").await; // different owner

        let resp = handle_secrets_entry(
            State(state),
            Query(ListSecretsQuery {
                limit: None,
                offset: None,
            }),
            authed_get("/api/v1/secrets", &token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        assert_eq!(body["total"], 2);
        assert_eq!(body["secrets"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn list_secrets_respects_limit_offset() {
        let (state, token, _user_id, prefix) = test_state_with_session().await;
        let owner_key = format!("apikey:{prefix}");

        for i in 0..5 {
            create_test_secret(&state, &owner_key, &format!("s{i}")).await;
        }

        let resp = handle_secrets_entry(
            State(state),
            Query(ListSecretsQuery {
                limit: Some(2),
                offset: Some(1),
            }),
            authed_get("/api/v1/secrets?limit=2&offset=1", &token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        assert_eq!(body["total"], 5);
        assert_eq!(body["secrets"].as_array().unwrap().len(), 2);
        assert_eq!(body["limit"], 2);
        assert_eq!(body["offset"], 1);
    }

    #[tokio::test]
    async fn list_secrets_empty_state() {
        let (state, token, _user_id, _prefix) = test_state_with_session().await;
        let resp = handle_secrets_entry(
            State(state),
            Query(ListSecretsQuery {
                limit: None,
                offset: None,
            }),
            authed_get("/api/v1/secrets", &token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        assert_eq!(body["total"], 0);
        assert_eq!(body["secrets"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn burn_with_session_auth_works() {
        let (state, token, _user_id, prefix) = test_state_with_session().await;
        let owner_key = format!("apikey:{prefix}");
        create_test_secret(&state, &owner_key, "burnable").await;

        let resp = handle_burn_entry(
            State(state),
            Path("burnable".into()),
            authed_post("/api/v1/secrets/burnable/burn", &token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_apikeys_returns_user_keys() {
        let (state, token, _user_id, prefix) = test_state_with_session().await;
        let resp =
            handle_list_apikeys_entry(State(state), authed_get("/api/v1/apikeys", &token)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        let keys = body["api_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["prefix"], prefix);
    }

    #[tokio::test]
    async fn revoke_apikey_works() {
        let (state, token, _user_id, prefix) = test_state_with_session().await;
        let resp = handle_revoke_apikey_entry(
            State(state),
            Path(prefix),
            authed_post("/api/v1/apikeys/test1234/revoke", &token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn delete_account_burns_secrets_revokes_keys() {
        let (state, token, user_id, prefix) = test_state_with_session().await;
        let owner_key = format!("apikey:{prefix}");
        create_test_secret(&state, &owner_key, "owned1").await;
        create_test_secret(&state, &owner_key, "owned2").await;

        let resp = handle_account_entry(
            State(state.clone()),
            authed_delete("/api/v1/auth/account", &token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        assert_eq!(body["ok"], true);
        assert_eq!(body["secrets_burned"], 2);
        assert_eq!(body["keys_revoked"], 1);

        // User should be gone
        assert!(matches!(
            state.auth_store.get_user_by_id(user_id).await,
            Err(StorageError::NotFound)
        ));
    }

    // ── Cross-user isolation tests ─────────────────────────

    #[tokio::test]
    async fn cross_user_list_secrets_isolation() {
        // Create user A with secrets
        let (state, _token_a, _user_a, prefix_a) = test_state_with_session().await;
        let owner_key_a = format!("apikey:{prefix_a}");
        create_test_secret(&state, &owner_key_a, "user_a_secret").await;

        // Create user B
        let user_b = state
            .auth_store
            .create_user("bob")
            .await
            .expect("create user b");
        let (token_b, _) = issue_session_token(&state, user_b.id)
            .await
            .expect("session b");
        // Give user B their own API key
        let key_b = ApiKeyRecord {
            id: 0,
            prefix: "bobkey01".into(),
            auth_hash: "x".repeat(64),
            scopes: String::new(),
            user_id: Some(user_b.id),
            created_at: Utc::now(),
            revoked_at: None,
        };
        state.api_keys.insert(key_b).await.expect("insert key b");

        // User B should NOT see user A's secrets
        let resp = handle_secrets_entry(
            State(state),
            Query(ListSecretsQuery {
                limit: None,
                offset: None,
            }),
            authed_get("/api/v1/secrets", &token_b),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        assert_eq!(body["total"], 0);
    }

    #[tokio::test]
    async fn cross_user_burn_isolation() {
        let (state, _token_a, _user_a, prefix_a) = test_state_with_session().await;
        let owner_key_a = format!("apikey:{prefix_a}");
        create_test_secret(&state, &owner_key_a, "a_secret").await;

        // Create user B
        let user_b = state
            .auth_store
            .create_user("bob")
            .await
            .expect("create user b");
        let (token_b, _) = issue_session_token(&state, user_b.id)
            .await
            .expect("session b");
        let key_b = ApiKeyRecord {
            id: 0,
            prefix: "bobkey02".into(),
            auth_hash: "x".repeat(64),
            scopes: String::new(),
            user_id: Some(user_b.id),
            created_at: Utc::now(),
            revoked_at: None,
        };
        state.api_keys.insert(key_b).await.expect("insert key b");

        // User B tries to burn user A's secret — should get 404
        let resp = handle_burn_entry(
            State(state.clone()),
            Path("a_secret".into()),
            authed_post("/api/v1/secrets/a_secret/burn", &token_b),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Secret should still exist
        let count = state
            .secrets
            .count_by_owner_keys(&[owner_key_a], Utc::now())
            .await
            .expect("count");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn cross_user_apikey_list_isolation() {
        let (state, _token_a, _user_a, _prefix_a) = test_state_with_session().await;

        let user_b = state
            .auth_store
            .create_user("bob")
            .await
            .expect("create user b");
        let (token_b, _) = issue_session_token(&state, user_b.id)
            .await
            .expect("session b");

        // User B should see no API keys
        let resp =
            handle_list_apikeys_entry(State(state), authed_get("/api/v1/apikeys", &token_b)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        assert_eq!(body["api_keys"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn cross_user_revoke_apikey_isolation() {
        let (state, _token_a, _user_a, prefix_a) = test_state_with_session().await;

        let user_b = state
            .auth_store
            .create_user("bob")
            .await
            .expect("create user b");
        let (token_b, _) = issue_session_token(&state, user_b.id)
            .await
            .expect("session b");

        // User B tries to revoke user A's key — should get 404
        let resp = handle_revoke_apikey_entry(
            State(state),
            Path(prefix_a.clone()),
            authed_post(&format!("/api/v1/apikeys/{prefix_a}/revoke"), &token_b),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_account_does_not_affect_other_users() {
        let (state, _token_a, user_a, prefix_a) = test_state_with_session().await;

        // Create user B with their own secret + key
        let user_b = state
            .auth_store
            .create_user("bob")
            .await
            .expect("create user b");
        let (token_b, _) = issue_session_token(&state, user_b.id)
            .await
            .expect("session b");
        let key_b = ApiKeyRecord {
            id: 0,
            prefix: "bobkey03".into(),
            auth_hash: "x".repeat(64),
            scopes: String::new(),
            user_id: Some(user_b.id),
            created_at: Utc::now(),
            revoked_at: None,
        };
        state.api_keys.insert(key_b).await.expect("insert key b");
        create_test_secret(&state, "apikey:bobkey03", "bob_secret").await;
        create_test_secret(&state, &format!("apikey:{prefix_a}"), "alice_secret").await;

        // Delete user A
        let (token_a_fresh, _) = issue_session_token(&state, user_a)
            .await
            .expect("fresh session");
        let resp = handle_account_entry(
            State(state.clone()),
            authed_delete("/api/v1/auth/account", &token_a_fresh),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // User B should still exist and their secret should be intact
        assert!(state.auth_store.get_user_by_id(user_b.id).await.is_ok());
        let count = state
            .secrets
            .count_by_owner_keys(&["apikey:bobkey03".to_string()], Utc::now())
            .await
            .expect("count");
        assert_eq!(count, 1);

        // User B can still list their secrets
        let resp_b = handle_secrets_entry(
            State(state),
            Query(ListSecretsQuery {
                limit: None,
                offset: None,
            }),
            authed_get("/api/v1/secrets", &token_b),
        )
        .await;
        assert_eq!(resp_b.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp_b).await).expect("json");
        assert_eq!(body["total"], 1);
    }

    // ── Session-authenticated create tests ─────────────────

    /// Build a valid create-secret JSON payload.
    fn valid_create_payload() -> String {
        let claim = URL_SAFE_NO_PAD.encode([1u8; 32]);
        let claim_hash = secrt_core::hash_claim_token(&claim).expect("claim hash");
        serde_json::json!({
            "envelope": {"ct":"test"},
            "claim_hash": claim_hash,
        })
        .to_string()
    }

    /// POST /api/v1/secrets with session token and JSON body.
    fn authed_create_request(token: &str, payload: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/v1/secrets")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .expect("request")
    }

    #[tokio::test]
    async fn session_auth_create_secret_succeeds() {
        let (state, token, _user_id, _prefix) = test_state_with_session().await;
        let payload = valid_create_payload();

        let resp = handle_secrets_entry(
            State(state),
            Query(ListSecretsQuery {
                limit: None,
                offset: None,
            }),
            authed_create_request(&token, &payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        assert!(body["id"].as_str().is_some(), "response should contain id");
    }

    #[tokio::test]
    async fn session_created_secret_appears_in_listing() {
        let (state, token, _user_id, _prefix) = test_state_with_session().await;
        let payload = valid_create_payload();

        // Create via session auth
        let resp = handle_secrets_entry(
            State(state.clone()),
            Query(ListSecretsQuery {
                limit: None,
                offset: None,
            }),
            authed_create_request(&token, &payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // List via session auth — should see the secret we just created
        let resp = handle_secrets_entry(
            State(state),
            Query(ListSecretsQuery {
                limit: None,
                offset: None,
            }),
            authed_get("/api/v1/secrets", &token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        assert_eq!(body["total"], 1);
    }

    #[tokio::test]
    async fn session_created_secret_can_be_burned() {
        let (state, token, user_id, _prefix) = test_state_with_session().await;
        let owner_key = format!("user:{user_id}");
        create_test_secret(&state, &owner_key, "sess_secret").await;

        let resp = handle_burn_entry(
            State(state),
            Path("sess_secret".into()),
            authed_post("/api/v1/secrets/sess_secret/burn", &token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn delete_account_burns_session_created_secrets() {
        let (state, token, user_id, prefix) = test_state_with_session().await;

        // Create secrets with both owner_key formats
        create_test_secret(&state, &format!("user:{user_id}"), "sess_owned").await;
        create_test_secret(&state, &format!("apikey:{prefix}"), "key_owned").await;

        let resp = handle_account_entry(
            State(state.clone()),
            authed_delete("/api/v1/auth/account", &token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        assert_eq!(body["ok"], true);
        assert_eq!(
            body["secrets_burned"], 2,
            "both session and apikey secrets should be burned"
        );
    }

    #[tokio::test]
    async fn mixed_ownership_listing_shows_all_secrets() {
        let (state, token, user_id, prefix) = test_state_with_session().await;

        // Create secrets with both owner_key formats
        create_test_secret(&state, &format!("user:{user_id}"), "sess1").await;
        create_test_secret(&state, &format!("user:{user_id}"), "sess2").await;
        create_test_secret(&state, &format!("apikey:{prefix}"), "key1").await;
        create_test_secret(&state, "apikey:other_user", "foreign").await; // different owner

        let resp = handle_secrets_entry(
            State(state),
            Query(ListSecretsQuery {
                limit: None,
                offset: None,
            }),
            authed_get("/api/v1/secrets", &token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        assert_eq!(
            body["total"], 3,
            "should see session + apikey secrets, not foreign"
        );
    }

    // ── SPA route tests ────────────────────────────────────

    #[tokio::test]
    async fn dashboard_and_settings_spa_routes() {
        let app = build_router(test_state());

        for path in ["/dashboard", "/settings"] {
            let req = Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .expect("request");
            let resp = app.clone().oneshot(req).await.expect("response");
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "SPA route {path} should serve index"
            );
        }
    }

    // ── Secrets check endpoint tests ──────────────────────

    #[tokio::test]
    async fn secrets_check_requires_auth() {
        let state = test_state();
        let resp = handle_secrets_check_entry(
            State(state),
            Request::builder()
                .method("GET")
                .uri("/api/v1/secrets/check")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn secrets_check_returns_count_and_checksum() {
        let (state, token, _user_id, prefix) = test_state_with_session().await;
        let owner_key = format!("apikey:{prefix}");

        create_test_secret(&state, &owner_key, "chk1").await;
        create_test_secret(&state, &owner_key, "chk2").await;

        let resp =
            handle_secrets_check_entry(State(state), authed_get("/api/v1/secrets/check", &token))
                .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        assert_eq!(body["count"], 2);
        assert!(body["checksum"].as_str().unwrap().len() > 0);
    }

    #[tokio::test]
    async fn secrets_check_changes_on_mutation() {
        let (state, token, _user_id, prefix) = test_state_with_session().await;
        let owner_key = format!("apikey:{prefix}");

        create_test_secret(&state, &owner_key, "mut1").await;

        let resp1 = handle_secrets_check_entry(
            State(state.clone()),
            authed_get("/api/v1/secrets/check", &token),
        )
        .await;
        let body1: serde_json::Value =
            serde_json::from_str(&response_text(resp1).await).expect("json");
        let cs1 = body1["checksum"].as_str().unwrap().to_string();

        // Burn the secret
        state.secrets.burn("mut1", &owner_key).await.expect("burn");

        let resp2 =
            handle_secrets_check_entry(State(state), authed_get("/api/v1/secrets/check", &token))
                .await;
        let body2: serde_json::Value =
            serde_json::from_str(&response_text(resp2).await).expect("json");
        let cs2 = body2["checksum"].as_str().unwrap().to_string();

        assert_ne!(cs1, cs2, "checksum should change after burning a secret");
        assert_eq!(body2["count"], 0);
    }

    #[tokio::test]
    async fn secrets_check_only_shows_own() {
        let (state, _token_a, _user_a, prefix_a) = test_state_with_session().await;
        let owner_key_a = format!("apikey:{prefix_a}");
        create_test_secret(&state, &owner_key_a, "own1").await;
        create_test_secret(&state, &owner_key_a, "own2").await;

        // Create user B
        let user_b = state
            .auth_store
            .create_user("bob")
            .await
            .expect("create user b");
        let (token_b, _) = issue_session_token(&state, user_b.id)
            .await
            .expect("session b");
        let key_b = ApiKeyRecord {
            id: 0,
            prefix: "bobchk01".into(),
            auth_hash: "x".repeat(64),
            scopes: String::new(),
            user_id: Some(user_b.id),
            created_at: Utc::now(),
            revoked_at: None,
        };
        state.api_keys.insert(key_b).await.expect("insert key b");

        // User B should see 0 secrets
        let resp =
            handle_secrets_check_entry(State(state), authed_get("/api/v1/secrets/check", &token_b))
                .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        assert_eq!(body["count"], 0);
        assert_eq!(body["checksum"], "");
    }

    // ── Device authorization flow tests ───────────────────

    /// Helper: build a POST request with JSON body (no auth header).
    fn post_json(uri: &str, body_json: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body_json.to_string()))
            .expect("request")
    }

    /// Helper: build a POST request with JSON body and Bearer auth header.
    fn authed_post_json(uri: &str, token: &str, body_json: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body_json.to_string()))
            .expect("request")
    }

    /// Helper: generate a valid base64url-encoded 32-byte auth_token for device flow tests.
    fn device_auth_token() -> String {
        URL_SAFE_NO_PAD.encode([0x42u8; 32])
    }

    #[tokio::test]
    async fn device_start_returns_codes() {
        let state = test_state();
        let auth_token = device_auth_token();
        let payload = serde_json::json!({ "auth_token": auth_token }).to_string();

        let resp = handle_device_start_entry(State(state.clone()), post_json("/x", &payload)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");

        // device_code should be present and non-empty
        let device_code = body["device_code"].as_str().expect("device_code");
        assert!(!device_code.is_empty());

        // user_code should match XXXX-XXXX pattern
        let user_code = body["user_code"].as_str().expect("user_code");
        assert_eq!(
            user_code.len(),
            9,
            "user_code should be 9 chars (XXXX-XXXX)"
        );
        assert_eq!(
            &user_code[4..5],
            "-",
            "user_code should have dash in middle"
        );

        // verification_url should contain base URL and user_code
        let verification_url = body["verification_url"].as_str().expect("verification_url");
        assert!(
            verification_url.starts_with("https://example.com/device"),
            "verification_url should start with public_base_url/device"
        );

        // expires_in and interval should be present
        assert_eq!(body["expires_in"], DEVICE_AUTH_EXPIRY_SECS as u64);
        assert_eq!(body["interval"], 5);
    }

    #[tokio::test]
    async fn device_start_invalid_auth_token() {
        let state = test_state();

        // Too short (only 16 bytes instead of 32)
        let short_token = URL_SAFE_NO_PAD.encode([0xAAu8; 16]);
        let payload = serde_json::json!({ "auth_token": short_token }).to_string();
        let resp = handle_device_start_entry(State(state.clone()), post_json("/x", &payload)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Missing auth_token field entirely
        let empty_payload = serde_json::json!({}).to_string();
        let resp =
            handle_device_start_entry(State(state.clone()), post_json("/x", &empty_payload)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Not valid base64url
        let bad_payload = serde_json::json!({ "auth_token": "not-base64!!!" }).to_string();
        let resp = handle_device_start_entry(State(state), post_json("/x", &bad_payload)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn device_poll_pending() {
        let state = test_state();
        let auth_token = device_auth_token();

        // Start the device flow
        let start_payload = serde_json::json!({ "auth_token": auth_token }).to_string();
        let start_resp =
            handle_device_start_entry(State(state.clone()), post_json("/x", &start_payload)).await;
        assert_eq!(start_resp.status(), StatusCode::OK);
        let start_body: serde_json::Value =
            serde_json::from_str(&response_text(start_resp).await).expect("json");
        let device_code = start_body["device_code"].as_str().expect("device_code");

        // Poll immediately — should be pending
        let poll_payload = serde_json::json!({ "device_code": device_code }).to_string();
        let poll_resp =
            handle_device_poll_entry(State(state), post_json("/x", &poll_payload)).await;
        assert_eq!(poll_resp.status(), StatusCode::OK);
        let poll_body: serde_json::Value =
            serde_json::from_str(&response_text(poll_resp).await).expect("json");
        assert_eq!(poll_body["status"], "authorization_pending");
        assert!(
            poll_body.get("prefix").is_none() || poll_body["prefix"].is_null(),
            "prefix should not be present while pending"
        );
    }

    #[tokio::test]
    async fn device_poll_approved() {
        let (state, token, _user_id, _prefix) = test_state_with_session().await;
        let auth_token = device_auth_token();

        // 1. Start device flow
        let start_payload = serde_json::json!({ "auth_token": auth_token }).to_string();
        let start_resp =
            handle_device_start_entry(State(state.clone()), post_json("/x", &start_payload)).await;
        assert_eq!(start_resp.status(), StatusCode::OK);
        let start_body: serde_json::Value =
            serde_json::from_str(&response_text(start_resp).await).expect("json");
        let device_code = start_body["device_code"]
            .as_str()
            .expect("device_code")
            .to_string();
        let user_code = start_body["user_code"]
            .as_str()
            .expect("user_code")
            .to_string();

        // 2. Approve with authenticated session
        let approve_payload = serde_json::json!({ "user_code": user_code }).to_string();
        let approve_resp = handle_device_approve_entry(
            State(state.clone()),
            authed_post_json("/x", &token, &approve_payload),
        )
        .await;
        assert_eq!(approve_resp.status(), StatusCode::OK);
        let approve_body: serde_json::Value =
            serde_json::from_str(&response_text(approve_resp).await).expect("json");
        assert_eq!(approve_body["ok"], true);

        // 3. Poll — should get "complete" with prefix
        let poll_payload = serde_json::json!({ "device_code": device_code }).to_string();
        let poll_resp =
            handle_device_poll_entry(State(state.clone()), post_json("/x", &poll_payload)).await;
        assert_eq!(poll_resp.status(), StatusCode::OK);
        let poll_body: serde_json::Value =
            serde_json::from_str(&response_text(poll_resp).await).expect("json");
        assert_eq!(poll_body["status"], "complete");
        let prefix = poll_body["prefix"]
            .as_str()
            .expect("prefix should be present");
        assert!(!prefix.is_empty(), "prefix should be non-empty");

        // 4. Poll again — challenge was consumed, should get expired_token
        let poll_resp2 =
            handle_device_poll_entry(State(state), post_json("/x", &poll_payload)).await;
        assert_eq!(poll_resp2.status(), StatusCode::BAD_REQUEST);
        let poll_body2 = response_text(poll_resp2).await;
        assert!(
            poll_body2.contains("expired_token"),
            "second poll should return expired_token"
        );
    }

    #[tokio::test]
    async fn device_poll_expired() {
        let state = test_state();

        // Poll with a nonexistent device_code
        let poll_payload =
            serde_json::json!({ "device_code": "nonexistent_code_that_does_not_exist" })
                .to_string();
        let resp = handle_device_poll_entry(State(state), post_json("/x", &poll_payload)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = response_text(resp).await;
        assert!(
            body.contains("expired_token"),
            "polling nonexistent device_code should return expired_token"
        );
    }

    #[tokio::test]
    async fn device_approve_requires_session() {
        let state = test_state();
        let auth_token = device_auth_token();

        // Start the device flow
        let start_payload = serde_json::json!({ "auth_token": auth_token }).to_string();
        let start_resp =
            handle_device_start_entry(State(state.clone()), post_json("/x", &start_payload)).await;
        assert_eq!(start_resp.status(), StatusCode::OK);
        let start_body: serde_json::Value =
            serde_json::from_str(&response_text(start_resp).await).expect("json");
        let user_code = start_body["user_code"].as_str().expect("user_code");

        // Try to approve without session token — should get 401
        let approve_payload = serde_json::json!({ "user_code": user_code }).to_string();
        let resp =
            handle_device_approve_entry(State(state), post_json("/x", &approve_payload)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn device_approve_wrong_user_code() {
        let (state, token, _user_id, _prefix) = test_state_with_session().await;
        let auth_token = device_auth_token();

        // Start the device flow
        let start_payload = serde_json::json!({ "auth_token": auth_token }).to_string();
        let start_resp =
            handle_device_start_entry(State(state.clone()), post_json("/x", &start_payload)).await;
        assert_eq!(start_resp.status(), StatusCode::OK);

        // Approve with wrong user_code
        let wrong_code_payload = serde_json::json!({ "user_code": "ZZZZ-9999" }).to_string();
        let resp = handle_device_approve_entry(
            State(state),
            authed_post_json("/x", &token, &wrong_code_payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = response_text(resp).await;
        assert!(
            body.contains("invalid or expired code"),
            "wrong user_code should return 'invalid or expired code'"
        );
    }

    // ── API-key-with-user_id cross-auth tests ─────────────

    /// Build a valid wire API key string and an `ApiKeyRecord` for the given
    /// user, register them in the state, and return `(wire_key, prefix)`.
    async fn register_api_key_for_user(
        state: &Arc<AppState>,
        user_id: UserId,
        prefix: &str,
    ) -> String {
        let auth_token = [42u8; 32];
        let auth_hash = crate::domain::auth::hash_api_key_auth_token(
            &state.cfg.api_key_pepper,
            prefix,
            &auth_token,
        )
        .expect("hash");

        let key = ApiKeyRecord {
            id: 0,
            prefix: prefix.to_string(),
            auth_hash,
            scopes: String::new(),
            user_id: Some(user_id),
            created_at: Utc::now(),
            revoked_at: None,
        };
        state.api_keys.insert(key).await.expect("insert api key");

        secrt_core::apikey::format_wire_api_key(prefix, &auth_token).expect("format wire key")
    }

    fn apikey_get(uri: &str, wire_key: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("x-api-key", wire_key)
            .body(Body::empty())
            .expect("request")
    }

    fn apikey_post(uri: &str, wire_key: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("x-api-key", wire_key)
            .body(Body::empty())
            .expect("request")
    }

    #[tokio::test]
    async fn apikey_list_sees_user_owned_secrets() {
        let state = test_state();
        let user = state.auth_store.create_user("alice").await.expect("user");
        let wire_key = register_api_key_for_user(&state, user.id, "alicekey").await;

        // Create secrets under user:{id} (simulating web UI creation)
        let user_owner = format!("user:{}", user.id);
        create_test_secret(&state, &user_owner, "web1").await;
        create_test_secret(&state, &user_owner, "web2").await;

        // Also create one under the apikey prefix
        create_test_secret(&state, "apikey:alicekey", "cli1").await;

        // API key auth should see all 3
        let resp = handle_secrets_entry(
            State(state),
            Query(ListSecretsQuery {
                limit: None,
                offset: None,
            }),
            apikey_get("/api/v1/secrets", &wire_key),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        assert_eq!(body["total"], 3);
    }

    #[tokio::test]
    async fn apikey_checksum_includes_user_owned_secrets() {
        let state = test_state();
        let user = state.auth_store.create_user("alice").await.expect("user");
        let wire_key = register_api_key_for_user(&state, user.id, "aliceck").await;

        // One via web UI (user-owned), one via CLI (apikey-owned)
        create_test_secret(&state, &format!("user:{}", user.id), "webx").await;
        create_test_secret(&state, "apikey:aliceck", "clix").await;

        let resp = handle_secrets_check_entry(
            State(state),
            apikey_get("/api/v1/secrets/check", &wire_key),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(resp).await).expect("json");
        assert_eq!(body["count"], 2);
    }

    #[tokio::test]
    async fn apikey_burn_user_owned_secret() {
        let state = test_state();
        let user = state.auth_store.create_user("alice").await.expect("user");
        let wire_key = register_api_key_for_user(&state, user.id, "alicebn").await;

        // Create a secret under user:{id} (web UI)
        let user_owner = format!("user:{}", user.id);
        create_test_secret(&state, &user_owner, "webburn").await;

        // Burn it via API key
        let resp = handle_burn_entry(
            State(state),
            Path("webburn".into()),
            apikey_post("/api/v1/secrets/webburn/burn", &wire_key),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn apikey_create_uses_user_owner_key() {
        let state = test_state();
        let user = state.auth_store.create_user("alice").await.expect("user");
        let wire_key = register_api_key_for_user(&state, user.id, "alicecr").await;

        let payload = valid_create_payload();
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/secrets")
            .header("x-api-key", &wire_key)
            .header("content-type", "application/json")
            .body(Body::from(payload))
            .expect("request");

        let resp = handle_secrets_entry(
            State(state.clone()),
            Query(ListSecretsQuery {
                limit: None,
                offset: None,
            }),
            req,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Verify the secret was created with user:{id} owner_key by listing via
        // session auth (which only searches user:{id} and apikey:* keys)
        let (token, _) = issue_session_token(&state, user.id).await.expect("session");
        let list_resp = handle_secrets_entry(
            State(state),
            Query(ListSecretsQuery {
                limit: None,
                offset: None,
            }),
            authed_get("/api/v1/secrets", &token),
        )
        .await;
        assert_eq!(list_resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&response_text(list_resp).await).expect("json");
        assert_eq!(
            body["total"], 1,
            "secret created via API key should be visible via session"
        );
    }
}
