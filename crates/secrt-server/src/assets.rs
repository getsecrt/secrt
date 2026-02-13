use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../web/dist"]
struct WebAssets;

/// Axum handler that serves embedded web assets at `/static/*path`.
pub async fn serve_embedded(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
    // Try exact path first, then path with /index.html for directory-style requests
    let file = WebAssets::get(&path).or_else(|| {
        let index = format!("{path}/index.html");
        WebAssets::get(&index)
    });

    match file {
        Some(content) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, mime.as_ref().to_string()),
                    (
                        header::CACHE_CONTROL,
                        "public, max-age=31536000, immutable".to_string(),
                    ),
                ],
                content.data.into_owned(),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Returns true if any embedded web assets exist (i.e. web/dist was populated at build time).
pub fn has_embedded_assets() -> bool {
    WebAssets::iter().next().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn serve_embedded_returns_not_found_for_missing_asset() {
        let resp = serve_embedded(axum::extract::Path("missing-file".to_string())).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn serve_embedded_returns_cached_body_for_existing_asset() {
        let Some(path) = WebAssets::iter().next().map(|p| p.to_string()) else {
            eprintln!("skipping: no embedded assets");
            return;
        };
        let resp = serve_embedded(axum::extract::Path(path)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cache = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .expect("cache-control header");
        assert_eq!(cache, "public, max-age=31536000, immutable");

        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn has_embedded_assets_is_callable() {
        let _ = has_embedded_assets();
    }
}
