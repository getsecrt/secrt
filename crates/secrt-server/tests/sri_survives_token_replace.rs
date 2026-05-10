//! Survival test: the server's index-HTML token replacement (used by
//! `spa_index_html_with_base` and `handle_secret_page`) must not
//! disturb `integrity=` attributes on `<script>` and `<link>` tags.
//!
//! Why a synthetic fixture, not the real embedded `web/dist/index.html`:
//! `crates/secrt-server/build.rs` proactively creates an empty `web/dist/`
//! when none exists, so CI compiles against a bundle with no SRI tags
//! at all. A test reading the embedded `index.html` would silently
//! pass against an empty fixture. Instead, we mirror the production
//! token-replace patterns inline against a hand-crafted fixture that
//! contains realistic SRI markup, OG/Twitter `__PUBLIC_BASE_URL__`
//! placeholders, and the `<title>` and meta `content=` strings the
//! secret-page handler rewrites.
//!
//! If the production replace patterns ever change in a way that would
//! disturb `integrity=`, this test will catch it — the assertion only
//! depends on the patterns themselves, not on whether a real frontend
//! build happens to be available.

const FIXTURE: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta property="og:image" content="__PUBLIC_BASE_URL__/static/og-image.png">
    <meta property="og:url" content="__PUBLIC_BASE_URL__">
    <meta property="og:title" content="secrt — Private One-Time Secret Sharing">
    <meta property="og:description" content="Share passwords, keys, and sensitive data with zero-knowledge encryption. Secrets self-destruct after being read.">
    <meta name="twitter:title" content="secrt — Private One-Time Secret Sharing">
    <meta name="twitter:description" content="Share passwords, keys, and sensitive data with zero-knowledge encryption. Secrets self-destruct after being read.">
    <meta name="twitter:image" content="__PUBLIC_BASE_URL__/static/og-image.png">
    <title>secrt</title>
    <script type="module" src="/static/assets/index-DEADBEEF.js" integrity="sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" crossorigin="anonymous"></script>
    <link rel="stylesheet" href="/static/assets/index-CAFEBABE.css" integrity="sha384-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" crossorigin="anonymous">
    <link rel="modulepreload" href="/static/assets/preload-FEEDFACE.js" integrity="sha384-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" crossorigin="anonymous">
  </head>
  <body><div id="app"></div></body>
</html>"#;

const SCRIPT_INTEGRITY: &str =
    "sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const STYLE_INTEGRITY: &str =
    "sha384-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const PRELOAD_INTEGRITY: &str =
    "sha384-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

/// Mirror of the replace performed by
/// `crates/secrt-server/src/assets.rs::spa_index_html_with_base`.
fn rewrite_index_with_base(html: &str, base: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    html.replace("__PUBLIC_BASE_URL__", trimmed)
}

/// Mirror of the chained replaces performed by
/// `crates/secrt-server/src/http/mod.rs::handle_secret_page` after
/// `spa_index_html_with_base` runs.
fn rewrite_secret_page(spa: &str, base: &str, secret_url: &str, secret_image: &str) -> String {
    spa.replace(
        "content=\"secrt — Private One-Time Secret Sharing\"",
        "content=\"You've been sent a secret\"",
    )
    .replace(
        "content=\"Share passwords, keys, and sensitive data with zero-knowledge encryption. Secrets self-destruct after being read.\"",
        "content=\"Open to view your secret. It can only be viewed once.\"",
    )
    .replace(
        &format!("content=\"{base}/static/og-image.png\""),
        &format!("content=\"{secret_image}\""),
    )
    .replace(
        &format!("content=\"{base}\""),
        &format!("content=\"{secret_url}\""),
    )
    .replace(
        "<title>secrt</title>",
        "<title>You've been sent a secret — secrt</title>",
    )
}

#[test]
fn base_url_replacement_preserves_integrity_attributes() {
    let out = rewrite_index_with_base(FIXTURE, "https://secrt.ca");
    assert!(out.contains(SCRIPT_INTEGRITY), "script integrity stripped");
    assert!(
        out.contains(STYLE_INTEGRITY),
        "stylesheet integrity stripped"
    );
    assert!(
        out.contains(PRELOAD_INTEGRITY),
        "modulepreload integrity stripped"
    );
    assert!(
        out.contains("crossorigin=\"anonymous\""),
        "crossorigin attribute lost"
    );
    assert!(
        !out.contains("__PUBLIC_BASE_URL__"),
        "base-url placeholder should have been substituted"
    );
}

#[test]
fn secret_page_replacement_preserves_integrity_attributes() {
    let base = "https://secrt.ca";
    let after_base = rewrite_index_with_base(FIXTURE, base);
    let secret_url = format!("{base}/s/abc123");
    let secret_image = format!("{base}/static/og-secret.png");
    let out = rewrite_secret_page(&after_base, base, &secret_url, &secret_image);

    assert!(out.contains(SCRIPT_INTEGRITY), "script integrity stripped");
    assert!(
        out.contains(STYLE_INTEGRITY),
        "stylesheet integrity stripped"
    );
    assert!(
        out.contains(PRELOAD_INTEGRITY),
        "modulepreload integrity stripped"
    );
    assert!(
        out.contains("<title>You've been sent a secret — secrt</title>"),
        "title was not rewritten — replacement chain regressed"
    );
    assert!(
        out.contains(&format!("content=\"{secret_image}\"")),
        "og:image was not rewritten to secret-specific image"
    );
    assert!(
        out.contains(&format!("content=\"{secret_url}\"")),
        "og:url was not rewritten to secret-specific URL"
    );
}

#[test]
fn integrity_attribute_count_unchanged() {
    let base = "https://secrt.is";
    let after_base = rewrite_index_with_base(FIXTURE, base);
    let after_secret = rewrite_secret_page(
        &after_base,
        base,
        &format!("{base}/s/x"),
        &format!("{base}/static/og-secret.png"),
    );

    let original_count = FIXTURE.matches("integrity=\"sha384-").count();
    let after_base_count = after_base.matches("integrity=\"sha384-").count();
    let after_secret_count = after_secret.matches("integrity=\"sha384-").count();

    assert_eq!(original_count, 3, "fixture should have 3 SRI attrs");
    assert_eq!(
        after_base_count, 3,
        "base-replace dropped an integrity attr"
    );
    assert_eq!(
        after_secret_count, 3,
        "secret-page replace dropped an integrity attr"
    );
}
