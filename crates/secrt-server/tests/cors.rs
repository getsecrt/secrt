mod helpers;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use helpers::{test_app_with_store, test_config, MemStore};
use tower::ServiceExt;

/// Helper: send an OPTIONS preflight with the given Origin header.
async fn preflight(app: axum::Router, origin: &str, path: &str) -> axum::response::Response {
    let req = Request::builder()
        .method("OPTIONS")
        .uri(path)
        .header("Origin", origin)
        .header("Access-Control-Request-Method", "POST")
        .header(
            "Access-Control-Request-Headers",
            "content-type,authorization",
        )
        .body(Body::empty())
        .expect("build preflight request");
    app.oneshot(req).await.expect("send preflight request")
}

/// Parse the allow-methods header into a sorted list of method names.
fn allowed_methods(resp: &axum::response::Response) -> Vec<String> {
    let raw = resp
        .headers()
        .get("access-control-allow-methods")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut methods: Vec<String> = raw.split(',').map(|s| s.trim().to_uppercase()).collect();
    methods.sort();
    methods
}

/// Parse the allow-headers header into a sorted, lowercased list.
fn allowed_headers(resp: &axum::response::Response) -> Vec<String> {
    let raw = resp
        .headers()
        .get("access-control-allow-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut headers: Vec<String> = raw.split(',').map(|s| s.trim().to_lowercase()).collect();
    headers.sort();
    headers
}

fn test_app() -> axum::Router {
    let store = Arc::new(MemStore::default());
    test_app_with_store(store, test_config())
}

// ── Preflight tests ──────────────────────────────────────

#[tokio::test]
async fn preflight_from_tauri_macos_origin() {
    let resp = preflight(test_app(), "tauri://localhost", "/api/v1/secrets").await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("tauri://localhost"),
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok()),
        Some("true"),
    );
}

#[tokio::test]
async fn preflight_from_tauri_windows_linux_origin() {
    let resp = preflight(
        test_app(),
        "https://tauri.localhost",
        "/api/v1/secrets",
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://tauri.localhost"),
    );
}

#[tokio::test]
async fn preflight_from_unknown_origin_has_no_cors_headers() {
    let resp = preflight(
        test_app(),
        "https://evil.example.com",
        "/api/v1/secrets",
    )
    .await;

    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "unknown origin should not receive CORS headers"
    );
}

// ── Allowed methods/headers tests ────────────────────────

#[tokio::test]
async fn preflight_allow_methods_includes_required_verbs() {
    let resp = preflight(test_app(), "tauri://localhost", "/api/v1/secrets").await;

    let methods = allowed_methods(&resp);
    for required in ["DELETE", "GET", "OPTIONS", "PATCH", "POST", "PUT"] {
        assert!(
            methods.contains(&required.to_string()),
            "access-control-allow-methods should include {required}, got: {methods:?}"
        );
    }
}

#[tokio::test]
async fn preflight_allow_headers_includes_required_headers() {
    let resp = preflight(test_app(), "tauri://localhost", "/api/v1/secrets").await;

    let headers = allowed_headers(&resp);
    for required in ["authorization", "content-type", "accept"] {
        assert!(
            headers.contains(&required.to_string()),
            "access-control-allow-headers should include {required}, got: {headers:?}"
        );
    }
}

// ── Non-preflight (simple/actual) request tests ──────────

#[tokio::test]
async fn normal_get_with_tauri_origin_includes_cors_headers() {
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/info")
        .header("Origin", "tauri://localhost")
        .body(Body::empty())
        .expect("build request");

    let resp = test_app().oneshot(req).await.expect("send request");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("tauri://localhost"),
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok()),
        Some("true"),
    );
}

#[tokio::test]
async fn post_with_json_body_and_tauri_origin_gets_cors_headers() {
    // This mirrors what the Tauri app actually does: POST JSON with
    // content-type and authorization headers from a Tauri origin.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/app/start")
        .header("Origin", "tauri://localhost")
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .expect("build request");

    let resp = test_app().oneshot(req).await.expect("send request");

    // The endpoint may return 4xx (no valid session), but the CORS
    // headers must still be present so the browser exposes the response.
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("tauri://localhost"),
        "actual POST response must include CORS allow-origin"
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok()),
        Some("true"),
        "actual POST response must include CORS allow-credentials"
    );
}

#[tokio::test]
async fn normal_request_without_origin_has_no_cors_headers() {
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/info")
        .body(Body::empty())
        .expect("build request");

    let resp = test_app().oneshot(req).await.expect("send request");

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "requests without Origin should not get CORS headers"
    );
}
