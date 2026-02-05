package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a small in-memory token bucket rate limiter.
// It is intended for single-instance deployments and basic abuse protection.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	rate  float64
	burst float64

	now func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter that refills at rate tokens/second up to burst capacity.
func New(rate float64, burst int) *Limiter {
	return &Limiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   float64(burst),
		now:     time.Now,
	}
}

// Allow reports whether a request for key should be allowed right now.
func (l *Limiter) Allow(key string) bool {
	if key == "" {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: l.now()}
		l.buckets[key] = b
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

