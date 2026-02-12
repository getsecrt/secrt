package ratelimit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// Limiter is a small in-memory token bucket rate limiter.
// It is intended for single-instance deployments and basic abuse protection.
//
// Keys (typically client IPs) are HMAC-hashed with a per-instance random key
// before use as map keys, so raw IPs never sit in process memory.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	rate  float64
	burst float64

	hmacKey [32]byte
	now     func() time.Time

	stop chan struct{} // closed by Stop(); nil until StartGC is called
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter that refills at rate tokens/second up to burst capacity.
// A random HMAC key is generated so raw keys never appear in the bucket map.
func New(rate float64, burst int) *Limiter {
	l := &Limiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   float64(burst),
		now:     time.Now,
	}
	// Panic on rand failure is acceptable at startup.
	if _, err := rand.Read(l.hmacKey[:]); err != nil {
		panic("ratelimit: crypto/rand failed: " + err.Error())
	}
	return l
}

// hashKey returns a hex-encoded HMAC-SHA256 of key, so raw values (IPs)
// are never stored in the bucket map.
func (l *Limiter) hashKey(key string) string {
	mac := hmac.New(sha256.New, l.hmacKey[:])
	mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil))
}

// Allow reports whether a request for key should be allowed right now.
func (l *Limiter) Allow(key string) bool {
	if key == "" {
		return true
	}

	hk := l.hashKey(key)

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[hk]
	if !ok {
		b = &bucket{tokens: l.burst, last: l.now()}
		l.buckets[hk] = b
	}

	now := l.now()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

// StartGC starts a background goroutine that sweeps stale buckets every
// interval, removing any bucket whose last activity is older than maxIdle.
// Call Stop to terminate the goroutine.
func (l *Limiter) StartGC(interval, maxIdle time.Duration) {
	l.stop = make(chan struct{})
	go l.gcLoop(interval, maxIdle)
}

// Stop terminates the GC goroutine started by StartGC. Safe to call even
// if StartGC was never called.
func (l *Limiter) Stop() {
	if l.stop != nil {
		select {
		case <-l.stop:
			// already closed
		default:
			close(l.stop)
		}
	}
}

func (l *Limiter) gcLoop(interval, maxIdle time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
			l.sweep(maxIdle)
		}
	}
}

func (l *Limiter) sweep(maxIdle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	for k, b := range l.buckets {
		if now.Sub(b.last) > maxIdle {
			delete(l.buckets, k)
		}
	}
}

// Len returns the current number of tracked buckets (for testing/monitoring).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
