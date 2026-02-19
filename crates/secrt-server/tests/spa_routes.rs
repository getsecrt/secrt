mod helpers;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use helpers::{test_app_with_store, test_config, MemStore};
use tower::ServiceExt;

/// Every client-side route the frontend router handles must return 200 with the
/// SPA index HTML so the browser can boot the JS router. A 404 here means the
/// server forgot to register the route — the user sees a white screen.
#[tokio::test]
async fn spa_routes_return_index_html() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());

    // All SPA routes the frontend defines (see web/src/router.ts).
    // Each must return 200 with HTML content.
    let spa_paths = [
        "/",
        "/login",
        "/register",
        "/how-it-works",
        "/privacy",
        "/dashboard",
        "/settings",
        "/device",
        "/sync/test-sync-id",
    ];

    for path in spa_paths {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("build request for {path}"));

        let resp = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|_| panic!("send request for {path}"));

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "SPA route {path} returned {} instead of 200 — server is missing this route",
            resp.status(),
        );

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.contains("text/html"),
            "SPA route {path} returned content-type '{content_type}' instead of text/html",
        );
    }
}

/// The /s/{id} route is special — it serves a custom OG-tagged HTML page, not
/// the generic SPA index. Verify it returns 200 with HTML.
#[tokio::test]
async fn secret_page_route_returns_html() {
    let store = Arc::new(MemStore::default());
    let app = test_app_with_store(store, test_config());

    let req = Request::builder()
        .method("GET")
        .uri("/s/test-secret-id")
        .body(Body::empty())
        .expect("build request");

    let resp = app.clone().oneshot(req).await.expect("send request");

    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("text/html"),
        "/s/{{id}} returned content-type '{content_type}' instead of text/html",
    );
}
