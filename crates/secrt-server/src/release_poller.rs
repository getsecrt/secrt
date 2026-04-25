use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::{oneshot, RwLock};
use tracing::{debug, warn};

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const RELEASES_PER_PAGE: u32 = 100;

/// Snapshot of the latest known CLI release, polled from GitHub.
///
/// `latest` and `checked_at` are populated together once the first successful
/// (non-304) poll completes. `etag` is the value seen in the most recent
/// response and is sent back as `If-None-Match` on the next request.
#[derive(Default, Debug, Clone)]
pub struct ReleaseCache {
    pub latest: Option<String>,
    pub checked_at: Option<DateTime<Utc>>,
    pub etag: Option<String>,
}

/// One release entry as parsed from `/repos/{owner}/{repo}/releases`.
#[derive(Debug, Clone, Deserialize)]
pub struct GhRelease {
    pub tag_name: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
}

#[derive(Debug)]
pub enum FetchOutcome {
    Modified {
        releases: Vec<GhRelease>,
        etag: Option<String>,
    },
    NotModified,
}

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("rate limited")]
    RateLimited,
    #[error("forbidden (likely rate limit)")]
    Forbidden,
    #[error("server error: {status}")]
    ServerError { status: u16 },
    #[error("unexpected status: {status}")]
    UnexpectedStatus { status: u16 },
    #[error("transport: {0}")]
    Transport(String),
    #[error("parse: {0}")]
    Parse(String),
}

#[async_trait]
pub trait ReleaseFetcher: Send + Sync {
    async fn fetch(&self, etag: Option<&str>) -> Result<FetchOutcome, FetchError>;
}

/// Production fetcher that talks to the real GitHub API over HTTPS.
pub struct ReqwestFetcher {
    client: reqwest::Client,
    repo: String,
    token: Option<String>,
}

impl ReqwestFetcher {
    pub fn new(repo: String, token: Option<String>) -> Result<Self, FetchError> {
        let client = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .user_agent(concat!("secrt-server/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| FetchError::Transport(e.to_string()))?;
        Ok(Self {
            client,
            repo,
            token,
        })
    }
}

#[async_trait]
impl ReleaseFetcher for ReqwestFetcher {
    async fn fetch(&self, etag: Option<&str>) -> Result<FetchOutcome, FetchError> {
        let url = format!(
            "https://api.github.com/repos/{}/releases?per_page={}",
            self.repo, RELEASES_PER_PAGE
        );
        let mut req = self
            .client
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(tag) = etag {
            req = req.header(reqwest::header::IF_NONE_MATCH, tag);
        }
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| FetchError::Transport(e.to_string()))?;
        let status = resp.status();
        if status.as_u16() == 304 {
            return Ok(FetchOutcome::NotModified);
        }
        if status.as_u16() == 429 {
            return Err(FetchError::RateLimited);
        }
        if status.as_u16() == 403 {
            return Err(FetchError::Forbidden);
        }
        if status.is_server_error() {
            return Err(FetchError::ServerError {
                status: status.as_u16(),
            });
        }
        if !status.is_success() {
            return Err(FetchError::UnexpectedStatus {
                status: status.as_u16(),
            });
        }

        let new_etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body = resp
            .bytes()
            .await
            .map_err(|e| FetchError::Transport(e.to_string()))?;
        let releases: Vec<GhRelease> =
            serde_json::from_slice(&body).map_err(|e| FetchError::Parse(e.to_string()))?;

        Ok(FetchOutcome::Modified {
            releases,
            etag: new_etag,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PollerConfig {
    pub interval: Duration,
}

/// Spawn the background task that periodically refreshes `cache` from GitHub.
///
/// Returns `None` (and does not spawn) when `cfg.interval` is zero — the
/// caller is expected to leave the cache cold. Otherwise returns a oneshot
/// sender that, when dropped or signalled, terminates the task.
pub fn start_release_poller(
    cache: Arc<RwLock<ReleaseCache>>,
    fetcher: Arc<dyn ReleaseFetcher>,
    cfg: PollerConfig,
) -> Option<oneshot::Sender<()>> {
    if cfg.interval.is_zero() {
        return None;
    }

    let (tx, mut rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        // Run an immediate poll on startup so the cache warms up before the
        // first ticker tick.
        poll_once(&cache, fetcher.as_ref()).await;

        let mut ticker = tokio::time::interval(cfg.interval);
        // `interval` ticks immediately once; consume it to avoid a duplicate
        // run right after the warm-up call above.
        ticker.tick().await;

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    poll_once(&cache, fetcher.as_ref()).await;
                }
                _ = &mut rx => {
                    break;
                }
            }
        }
    });

    Some(tx)
}

/// Run a single poll cycle. Public so tests can drive the cache directly
/// without spawning a background task.
pub async fn poll_once(cache: &Arc<RwLock<ReleaseCache>>, fetcher: &dyn ReleaseFetcher) {
    let etag = { cache.read().await.etag.clone() };

    match fetcher.fetch(etag.as_deref()).await {
        Ok(FetchOutcome::NotModified) => {
            // Refresh `checked_at` only — version and etag unchanged.
            let mut guard = cache.write().await;
            guard.checked_at = Some(Utc::now());
            debug!("release poller: 304 not modified");
        }
        Ok(FetchOutcome::Modified { releases, etag }) => {
            let latest = pick_latest_cli_version(&releases);
            let mut guard = cache.write().await;
            guard.checked_at = Some(Utc::now());
            if let Some(tag) = etag {
                guard.etag = Some(tag);
            }
            // Only overwrite `latest` when we actually saw a CLI release. If
            // the response had no matching tags (e.g., only server tags so
            // far), keep last-known-good rather than nulling the field out.
            if let Some(v) = latest {
                guard.latest = Some(v);
            }
            debug!(latest = ?guard.latest, "release poller: cache refreshed");
        }
        Err(err) => {
            // Fail-soft: log internally, leave cache untouched. The CLI
            // distinguishes "never fetched" (latest=null) from "fetched but
            // stale" (latest=Some, checked_at=...) on its own.
            warn!(error = %err, "release poller: fetch failed (last-known-good preserved)");
        }
    }
}

/// Filter to `cli/vX.Y.Z` (strict, no prerelease suffix) and return the
/// highest semver as a bare `X.Y.Z` string. Drafts and prereleases are always
/// skipped, even if their tag would otherwise match.
pub fn pick_latest_cli_version(releases: &[GhRelease]) -> Option<String> {
    releases
        .iter()
        .filter(|r| !r.draft && !r.prerelease)
        .filter_map(|r| parse_cli_tag(&r.tag_name))
        .max()
        .map(|(maj, min, pat)| format!("{maj}.{min}.{pat}"))
}

/// Parse a `cli/vX.Y.Z` tag into a `(major, minor, patch)` tuple. Returns
/// `None` for any tag that doesn't match the strict shape — including
/// prerelease suffixes like `cli/v1.2.3-rc.1`.
fn parse_cli_tag(tag: &str) -> Option<(u64, u64, u64)> {
    let rest = tag.strip_prefix("cli/v")?;
    let mut parts = rest.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    // Reject any remaining suffix on the patch component (e.g., "3-rc.1").
    if !patch.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((major, minor, patch.parse::<u64>().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn release(tag: &str) -> GhRelease {
        GhRelease {
            tag_name: tag.to_string(),
            draft: false,
            prerelease: false,
        }
    }

    fn draft(tag: &str) -> GhRelease {
        GhRelease {
            tag_name: tag.to_string(),
            draft: true,
            prerelease: false,
        }
    }

    fn prerelease(tag: &str) -> GhRelease {
        GhRelease {
            tag_name: tag.to_string(),
            draft: false,
            prerelease: true,
        }
    }

    #[test]
    fn parse_cli_tag_accepts_strict_shape() {
        assert_eq!(parse_cli_tag("cli/v0.15.0"), Some((0, 15, 0)));
        assert_eq!(parse_cli_tag("cli/v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_cli_tag("cli/v10.20.30"), Some((10, 20, 30)));
    }

    #[test]
    fn parse_cli_tag_rejects_other_shapes() {
        assert_eq!(parse_cli_tag("server/v0.15.0"), None);
        assert_eq!(parse_cli_tag("cli/0.15.0"), None);
        assert_eq!(parse_cli_tag("cli/v0.15"), None);
        assert_eq!(parse_cli_tag("cli/v0.15.0.1"), None);
        assert_eq!(parse_cli_tag("cli/v0.15.0-rc.1"), None);
        assert_eq!(parse_cli_tag("cli/v0.15.0+build"), None);
        assert_eq!(parse_cli_tag(""), None);
    }

    #[test]
    fn pick_latest_skips_drafts_and_prereleases() {
        let r = vec![
            release("cli/v0.14.0"),
            draft("cli/v0.16.0"),
            prerelease("cli/v0.16.0-rc.1"),
            release("cli/v0.15.0"),
        ];
        assert_eq!(pick_latest_cli_version(&r), Some("0.15.0".to_string()));
    }

    #[test]
    fn pick_latest_picks_highest_semver_across_mixed_tags() {
        let r = vec![
            release("cli/v0.15.0"),
            release("server/v9.9.9"),
            release("cli/v0.16.0"),
            release("cli/v0.14.10"),
            release("cli/v0.15.1"),
        ];
        assert_eq!(pick_latest_cli_version(&r), Some("0.16.0".to_string()));
    }

    #[test]
    fn pick_latest_returns_none_when_no_cli_tags() {
        let r = vec![release("server/v0.15.0"), draft("cli/v0.16.0")];
        assert_eq!(pick_latest_cli_version(&r), None);
    }

    /// Test fetcher driven by a queue of canned outcomes; records the etag
    /// it was called with so we can assert ETag round-tripping.
    struct MockFetcher {
        queue: Mutex<std::collections::VecDeque<Result<FetchOutcome, FetchError>>>,
        seen_etags: Mutex<Vec<Option<String>>>,
        calls: AtomicUsize,
    }

    impl MockFetcher {
        fn new(items: Vec<Result<FetchOutcome, FetchError>>) -> Arc<Self> {
            Arc::new(Self {
                queue: Mutex::new(items.into_iter().collect()),
                seen_etags: Mutex::new(Vec::new()),
                calls: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl ReleaseFetcher for MockFetcher {
        async fn fetch(&self, etag: Option<&str>) -> Result<FetchOutcome, FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen_etags
                .lock()
                .unwrap()
                .push(etag.map(|s| s.to_string()));
            self.queue
                .lock()
                .unwrap()
                .pop_front()
                .expect("MockFetcher: queue empty")
        }
    }

    fn empty_cache() -> Arc<RwLock<ReleaseCache>> {
        Arc::new(RwLock::new(ReleaseCache::default()))
    }

    #[tokio::test]
    async fn modified_with_etag_populates_cache() {
        let cache = empty_cache();
        let fetcher = MockFetcher::new(vec![Ok(FetchOutcome::Modified {
            releases: vec![release("cli/v0.15.0"), release("cli/v0.16.0")],
            etag: Some("\"abc\"".to_string()),
        })]);
        poll_once(&cache, fetcher.as_ref()).await;
        let snap = cache.read().await.clone();
        assert_eq!(snap.latest.as_deref(), Some("0.16.0"));
        assert_eq!(snap.etag.as_deref(), Some("\"abc\""));
        assert!(snap.checked_at.is_some());
    }

    #[tokio::test]
    async fn not_modified_refreshes_checked_at_only() {
        let cache = empty_cache();
        // Seed the cache with a known version + etag.
        {
            let mut g = cache.write().await;
            g.latest = Some("0.15.0".to_string());
            g.etag = Some("\"abc\"".to_string());
            g.checked_at = Some(Utc::now() - chrono::Duration::hours(2));
        }
        let before = cache.read().await.checked_at.unwrap();

        let fetcher = MockFetcher::new(vec![Ok(FetchOutcome::NotModified)]);
        poll_once(&cache, fetcher.as_ref()).await;

        let after = cache.read().await.clone();
        assert_eq!(after.latest.as_deref(), Some("0.15.0"));
        assert_eq!(after.etag.as_deref(), Some("\"abc\""));
        assert!(after.checked_at.unwrap() > before);

        // Verify the fetcher was called with the cached etag.
        let etags = fetcher.seen_etags.lock().unwrap().clone();
        assert_eq!(etags, vec![Some("\"abc\"".to_string())]);
    }

    #[tokio::test]
    async fn modified_with_same_version_updates_checked_at() {
        let cache = empty_cache();
        {
            let mut g = cache.write().await;
            g.latest = Some("0.15.0".to_string());
            g.etag = Some("\"old\"".to_string());
            g.checked_at = Some(Utc::now() - chrono::Duration::hours(2));
        }
        let before = cache.read().await.checked_at.unwrap();

        let fetcher = MockFetcher::new(vec![Ok(FetchOutcome::Modified {
            releases: vec![release("cli/v0.15.0")],
            etag: Some("\"new\"".to_string()),
        })]);
        poll_once(&cache, fetcher.as_ref()).await;

        let after = cache.read().await.clone();
        assert_eq!(after.latest.as_deref(), Some("0.15.0"));
        assert_eq!(after.etag.as_deref(), Some("\"new\""));
        assert!(after.checked_at.unwrap() > before);
    }

    #[tokio::test]
    async fn modified_with_new_version_replaces_cache() {
        let cache = empty_cache();
        {
            let mut g = cache.write().await;
            g.latest = Some("0.15.0".to_string());
            g.etag = Some("\"old\"".to_string());
            g.checked_at = Some(Utc::now());
        }

        let fetcher = MockFetcher::new(vec![Ok(FetchOutcome::Modified {
            releases: vec![release("cli/v0.16.0"), release("cli/v0.15.0")],
            etag: Some("\"new\"".to_string()),
        })]);
        poll_once(&cache, fetcher.as_ref()).await;

        let after = cache.read().await.clone();
        assert_eq!(after.latest.as_deref(), Some("0.16.0"));
        assert_eq!(after.etag.as_deref(), Some("\"new\""));
    }

    #[tokio::test]
    async fn modified_with_no_cli_tags_keeps_last_known_good() {
        let cache = empty_cache();
        {
            let mut g = cache.write().await;
            g.latest = Some("0.15.0".to_string());
            g.etag = Some("\"old\"".to_string());
            g.checked_at = Some(Utc::now() - chrono::Duration::hours(2));
        }

        let fetcher = MockFetcher::new(vec![Ok(FetchOutcome::Modified {
            releases: vec![release("server/v9.9.9")],
            etag: Some("\"newer\"".to_string()),
        })]);
        poll_once(&cache, fetcher.as_ref()).await;

        let after = cache.read().await.clone();
        // latest is preserved; etag/checked_at advance.
        assert_eq!(after.latest.as_deref(), Some("0.15.0"));
        assert_eq!(after.etag.as_deref(), Some("\"newer\""));
    }

    #[tokio::test]
    async fn errors_leave_cache_untouched() {
        let cases: Vec<FetchError> = vec![
            FetchError::RateLimited,
            FetchError::Forbidden,
            FetchError::ServerError { status: 502 },
            FetchError::UnexpectedStatus { status: 418 },
            FetchError::Transport("timeout".to_string()),
            FetchError::Parse("bad json".to_string()),
        ];
        for err in cases {
            let cache = empty_cache();
            let original = ReleaseCache {
                latest: Some("0.15.0".to_string()),
                etag: Some("\"abc\"".to_string()),
                checked_at: Some(Utc::now() - chrono::Duration::hours(1)),
            };
            *cache.write().await = original.clone();
            let fetcher = MockFetcher::new(vec![Err(err)]);
            poll_once(&cache, fetcher.as_ref()).await;
            let after = cache.read().await.clone();
            assert_eq!(after.latest, original.latest);
            assert_eq!(after.etag, original.etag);
            assert_eq!(after.checked_at, original.checked_at);
        }
    }

    #[tokio::test]
    async fn zero_interval_does_not_spawn_task() {
        let cache = empty_cache();
        let fetcher = MockFetcher::new(vec![]); // No queued items — would panic if called.
        let stop = start_release_poller(
            cache.clone(),
            fetcher.clone(),
            PollerConfig {
                interval: Duration::ZERO,
            },
        );
        assert!(stop.is_none());

        // Give any (incorrectly) spawned task a chance to run.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);
        assert!(cache.read().await.latest.is_none());
    }

    #[tokio::test]
    async fn nonzero_interval_runs_immediate_warmup() {
        let cache = empty_cache();
        let fetcher = MockFetcher::new(vec![Ok(FetchOutcome::Modified {
            releases: vec![release("cli/v0.15.0")],
            etag: Some("\"abc\"".to_string()),
        })]);
        let stop = start_release_poller(
            cache.clone(),
            fetcher.clone(),
            PollerConfig {
                // Long interval so the test only sees the warm-up tick.
                interval: Duration::from_secs(3600),
            },
        );
        assert!(stop.is_some());

        // Wait for the warm-up poll to land.
        for _ in 0..50 {
            if cache.read().await.latest.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(cache.read().await.latest.as_deref(), Some("0.15.0"));
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);

        let _ = stop.unwrap().send(());
    }
}
