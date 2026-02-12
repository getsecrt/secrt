use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::oneshot;

#[derive(Clone)]
pub struct Limiter {
    inner: Arc<Inner>,
}

struct Inner {
    buckets: Mutex<HashMap<String, Bucket>>,
    rate: f64,
    burst: f64,
    hmac_key: hmac::Key,
    now: Arc<dyn Fn() -> Instant + Send + Sync>,
    stop_tx: Mutex<Option<oneshot::Sender<()>>>,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Limiter {
    pub fn new(rate: f64, burst: usize) -> Self {
        Self::new_with_now(rate, burst, Arc::new(Instant::now))
    }

    pub fn new_with_now(
        rate: f64,
        burst: usize,
        now: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        let mut key = [0u8; 32];
        let rng = SystemRandom::new();
        rng.fill(&mut key)
            .expect("ratelimit: crypto/rand failed for hmac key");

        Self {
            inner: Arc::new(Inner {
                buckets: Mutex::new(HashMap::new()),
                rate,
                burst: burst as f64,
                hmac_key: hmac::Key::new(hmac::HMAC_SHA256, &key),
                now,
                stop_tx: Mutex::new(None),
            }),
        }
    }

    fn hash_key(&self, key: &str) -> String {
        let sum = hmac::sign(&self.inner.hmac_key, key.as_bytes());
        hex::encode(sum.as_ref())
    }

    pub fn allow(&self, key: &str) -> bool {
        if key.is_empty() {
            return true;
        }

        let hashed = self.hash_key(key);
        let now = (self.inner.now)();

        let mut buckets = self.inner.buckets.lock().expect("ratelimit lock poisoned");
        let bucket = buckets.entry(hashed).or_insert_with(|| Bucket {
            tokens: self.inner.burst,
            last: now,
        });

        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        if elapsed > 0.0 {
            bucket.tokens += elapsed * self.inner.rate;
            if bucket.tokens > self.inner.burst {
                bucket.tokens = self.inner.burst;
            }
            bucket.last = now;
        }

        if bucket.tokens < 1.0 {
            return false;
        }

        bucket.tokens -= 1.0;
        true
    }

    pub fn start_gc(&self, interval: Duration, max_idle: Duration) {
        let (tx, mut rx) = oneshot::channel();
        {
            let mut stop = self.inner.stop_tx.lock().expect("stop tx lock poisoned");
            *stop = Some(tx);
        }

        let this = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        this.sweep(max_idle);
                    }
                    _ = &mut rx => {
                        break;
                    }
                }
            }
        });
    }

    pub fn stop(&self) {
        let tx = {
            let mut stop = self.inner.stop_tx.lock().expect("stop tx lock poisoned");
            stop.take()
        };
        if let Some(tx) = tx {
            let _ = tx.send(());
        }
    }

    pub fn len(&self) -> usize {
        self.inner
            .buckets
            .lock()
            .expect("ratelimit lock poisoned")
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn sweep(&self, max_idle: Duration) {
        let now = (self.inner.now)();
        let mut buckets = self.inner.buckets.lock().expect("ratelimit lock poisoned");
        buckets.retain(|_, b| now.saturating_duration_since(b.last) <= max_idle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[tokio::test]
    async fn basic_token_bucket() {
        let start = Instant::now();
        let offset_ms = Arc::new(AtomicU64::new(0));
        let clock = {
            let offset_ms = offset_ms.clone();
            Arc::new(move || start + Duration::from_millis(offset_ms.load(Ordering::Relaxed)))
        };

        let limiter = Limiter::new_with_now(1.0, 2, clock);
        assert!(limiter.allow("k"));
        assert!(limiter.allow("k"));
        assert!(!limiter.allow("k"));

        offset_ms.store(1000, Ordering::Relaxed);
        assert!(limiter.allow("k"));
    }

    #[test]
    fn empty_key_is_allowed() {
        let limiter = Limiter::new(1.0, 1);
        assert!(limiter.allow(""));
    }

    #[tokio::test]
    async fn gc_sweeps_and_stop_is_safe() {
        let start = Instant::now();
        let offset_ms = Arc::new(AtomicU64::new(0));
        let clock = {
            let offset_ms = offset_ms.clone();
            Arc::new(move || start + Duration::from_millis(offset_ms.load(Ordering::Relaxed)))
        };

        let limiter = Limiter::new_with_now(1.0, 1, clock);
        assert!(limiter.allow("abc"));
        assert_eq!(limiter.len(), 1);

        offset_ms.store(11_000, Ordering::Relaxed);
        limiter.sweep(Duration::from_secs(10));
        assert_eq!(limiter.len(), 0);

        limiter.start_gc(Duration::from_millis(5), Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(15)).await;
        limiter.stop();
        limiter.stop();
    }
}
