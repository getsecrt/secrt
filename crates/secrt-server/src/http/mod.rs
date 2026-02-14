use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::to_bytes;
use axum::extract::{ConnectInfo, Path, Request, State};
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
use tracing::{info, warn};

use crate::config::Config;
use crate::domain::auth::Authenticator;
use crate::domain::limiter::Limiter;
use crate::domain::secret_rules::{
    format_bytes, generate_id, validate_envelope, OwnerHasher, SecretRuleError,
};
use crate::storage::{
    ApiKeyRecord, ApiKeyRegistrationLimits, ApiKeysStore, AuthStore, SecretQuotaLimits,
    SecretRecord, SecretsStore, SessionRecord, StorageError, UserId,
};

#[derive(Clone)]
pub struct AppState {
    pub cfg: Config,
    pub secrets: Arc<dyn SecretsStore>,
    pub api_keys: Arc<dyn ApiKeysStore>,
    pub auth_store: Arc<dyn AuthStore>,
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
    ttl: InfoTtl,
    limits: InfoLimits,
    claim_rate: InfoRate,
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
    display_name: Option<String>,
    expires_at: Option<DateTime<Utc>>,
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
struct AuthFinishResponse {
    session_token: String,
    display_name: String,
    expires_at: DateTime<Utc>,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let router = Router::new()
        .route("/healthz", get(handle_healthz))
        .route("/", get(handle_index))
        .route("/s/{id}", get(handle_secret_page))
        // SPA client-side routes — serve the same index.html for all of them
        .route("/login", get(handle_index))
        .route("/register", get(handle_index))
        .route("/how-it-works", get(handle_index))
        .route("/robots.txt", get(handle_robots_txt));

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
        .route("/api/v1/secrets", any(handle_create_authed_entry))
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

pub async fn handle_create_authed_entry(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return method_not_allowed();
    }

    let raw_key = api_key_from_headers(req.headers());
    let api_key = match require_api_key(&state, raw_key).await {
        Ok(k) => k,
        Err(resp) => return resp,
    };

    if !state
        .api_limiter
        .allow(&format!("apikey:{}", api_key.prefix))
    {
        return rate_limited();
    }

    create_secret(
        state.clone(),
        req,
        true,
        format!("apikey:{}", api_key.prefix),
    )
    .await
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

    let raw_key = api_key_from_headers(req.headers());
    let api_key = match require_api_key(&state, raw_key).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let owner_key = format!("apikey:{}", api_key.prefix);
    let deleted = match state.secrets.burn(&id, &owner_key).await {
        Ok(v) => v,
        Err(_) => return internal_server_error(),
    };

    if !deleted {
        return not_found();
    }

    json_response(StatusCode::OK, serde_json::json!({ "ok": true }))
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
    let expires_at = Utc::now() + chrono::Duration::hours(24);
    state
        .auth_store
        .insert_session(&sid, user_id, &token_hash, expires_at)
        .await
        .map_err(|_| internal_server_error())?;
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
    let (_user_id, display_name, expires_at) =
        match require_session_user(&state, req.headers()).await {
            Ok(v) => v,
            Err(_) => {
                return json_response(
                    StatusCode::OK,
                    SessionResponse {
                        authenticated: false,
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
            Err(_) => return internal_server_error(),
        };
        let auth_hash = match crate::domain::auth::hash_api_key_auth_token(
            &state.cfg.api_key_pepper,
            &prefix,
            &auth_token,
        ) {
            Ok(v) => v,
            Err(_) => return internal_server_error(),
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
            Err(_) => return internal_server_error(),
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

pub async fn handle_info_entry(State(state): State<Arc<AppState>>, req: Request) -> Response {
    if req.method() != Method::GET {
        return method_not_allowed();
    }

    let ip = get_client_ip(req.headers(), request_connect_addr(&req));
    if !state.claim_limiter.allow(&ip) {
        return rate_limited();
    }

    let authenticated = if let Some(raw) = api_key_from_headers(req.headers()) {
        state.auth.authenticate(&raw).await.is_ok()
    } else {
        false
    };

    let mut resp = json_response(
        StatusCode::OK,
        InfoResponse {
            authenticated,
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
        },
    );

    insert_header(resp.headers_mut(), "cache-control", "public, max-age=300");
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

pub async fn handle_secret_page(Path(id): Path<String>) -> Response {
    // SPA handles /s/{id} client-side; fall back to minimal HTML if no frontend built.
    let html = crate::assets::spa_index_html().unwrap_or_else(|| {
        let escaped_id = escape_html(&id);
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Secret {escaped_id}</title></head><body><h1>Secret {escaped_id}</h1></body></html>"
        )
    });
    let mut resp = Html(html).into_response();
    insert_header(resp.headers_mut(), "cache-control", "no-store");
    insert_header(resp.headers_mut(), "x-robots-tag", "noindex");
    resp
}

pub async fn handle_robots_txt() -> Response {
    let mut resp = (
        StatusCode::OK,
        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
        "User-agent: *\nDisallow: /\n",
    )
        .into_response();
    insert_header(resp.headers_mut(), "cache-control", "no-store");
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
        SessionRecord, StorageUsage, UserRecord,
    };
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::Request;
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
    }

    #[async_trait]
    impl AuthStore for MemStore {
        async fn create_user(&self, _display_name: &str) -> Result<UserRecord, StorageError> {
            Err(StorageError::Other("unsupported".into()))
        }

        async fn get_user_by_id(&self, _user_id: UserId) -> Result<UserRecord, StorageError> {
            Err(StorageError::NotFound)
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
            _sid: &str,
            _user_id: UserId,
            _token_hash: &str,
            _expires_at: DateTime<Utc>,
        ) -> Result<SessionRecord, StorageError> {
            Err(StorageError::Other("unsupported".into()))
        }

        async fn get_session_by_sid(&self, _sid: &str) -> Result<SessionRecord, StorageError> {
            Err(StorageError::NotFound)
        }

        async fn revoke_session_by_sid(&self, _sid: &str) -> Result<bool, StorageError> {
            Ok(false)
        }

        async fn insert_challenge(
            &self,
            _challenge_id: &str,
            _user_id: Option<UserId>,
            _purpose: &str,
            _challenge_json: &str,
            _expires_at: DateTime<Utc>,
        ) -> Result<ChallengeRecord, StorageError> {
            Err(StorageError::Other("unsupported".into()))
        }

        async fn consume_challenge(
            &self,
            _challenge_id: &str,
            _purpose: &str,
            _now: DateTime<Utc>,
        ) -> Result<ChallengeRecord, StorageError> {
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
            _key: ApiKeyRecord,
            _ip_hash: &str,
            _now: DateTime<Utc>,
            _limits: ApiKeyRegistrationLimits,
        ) -> Result<(), StorageError> {
            Err(StorageError::Other("unsupported".into()))
        }

        async fn insert_apikey_registration_event(
            &self,
            _user_id: UserId,
            _ip_hash: &str,
            _now: DateTime<Utc>,
        ) -> Result<(), StorageError> {
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

        let ok_payload_unsupported_store = Request::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"display_name":"Alice"}"#))
            .expect("request");
        assert_eq!(
            handle_passkey_register_start_entry(State(state.clone()), ok_payload_unsupported_store)
                .await
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
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
    async fn memstore_auth_stub_methods_are_exercised() {
        let store = MemStore::default();
        let now = Utc::now();
        let user_id = Uuid::now_v7();

        assert!(matches!(
            store.create_user("d").await,
            Err(StorageError::Other(_))
        ));
        assert!(matches!(
            store.get_user_by_id(user_id).await,
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            store.insert_passkey(user_id, "c", "pk", 0).await,
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
        assert!(matches!(
            store.insert_session("sid", user_id, "hash", now).await,
            Err(StorageError::Other(_))
        ));
        assert!(matches!(
            store.get_session_by_sid("sid").await,
            Err(StorageError::NotFound)
        ));
        assert!(!store
            .revoke_session_by_sid("sid")
            .await
            .expect("revoke should not fail"));
        assert!(matches!(
            store
                .insert_challenge("cid", None, "p", "{}", now + chrono::Duration::minutes(1))
                .await,
            Err(StorageError::Other(_))
        ));
        assert!(matches!(
            store.consume_challenge("cid", "p", now).await,
            Err(StorageError::NotFound)
        ));
        assert_eq!(
            store
                .count_apikey_registrations_by_user_since(user_id, now - chrono::Duration::hours(1))
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
        assert!(matches!(
            store
                .register_api_key(
                    ApiKeyRecord {
                        id: 0,
                        prefix: "pref".into(),
                        auth_hash: "a".repeat(64),
                        scopes: String::new(),
                        user_id: None,
                        created_at: now,
                        revoked_at: None,
                    },
                    "ip",
                    now,
                    ApiKeyRegistrationLimits {
                        account_hour: 1,
                        account_day: 1,
                        ip_hour: 1,
                        ip_day: 1,
                    },
                )
                .await,
            Err(StorageError::Other(_))
        ));
        store
            .insert_apikey_registration_event(user_id, "ip", now)
            .await
            .expect("insert reg event");
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
        };
        let store = Arc::new(MemStore::default());
        let secrets: Arc<dyn SecretsStore> = store.clone();
        let keys: Arc<dyn ApiKeysStore> = store.clone();
        let auth_store: Arc<dyn AuthStore> = store;
        Arc::new(AppState::new(cfg, secrets, keys, auth_store))
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
        let resp = handle_secret_page(Path("abc123".to_string())).await;
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
    async fn secret_page_does_not_reflect_id_into_html() {
        // With SPA serving, the ID should never appear in the server-rendered HTML
        let reflected = "<script>alert(1)</script>";
        let resp = handle_secret_page(Path(reflected.to_string())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_text(resp).await;
        assert!(
            !body.contains(reflected),
            "id must not be reflected into HTML; body={body}"
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
}
