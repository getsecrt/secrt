package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter_Allow_EmptyKeyAlwaysAllowed(t *testing.T) {
	t.Parallel()

	l := New(0, 0)
	if !l.Allow("") {
		t.Fatalf("expected empty key to be allowed")
	}
}

func TestLimiter_Allow_BurstAndRefill(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := New(1.0, 2) // 1 token/sec, burst 2
	l.now = func() time.Time { return now }

	if !l.Allow("k") {
		t.Fatalf("expected first allow")
	}
	if !l.Allow("k") {
		t.Fatalf("expected second allow (burst)")
	}
	if l.Allow("k") {
		t.Fatalf("expected third request to be rate limited")
	}

	now = now.Add(1 * time.Second)
	if !l.Allow("k") {
		t.Fatalf("expected refill after 1s")
	}
	if l.Allow("k") {
		t.Fatalf("expected to be rate limited again (no tokens left)")
	}
}

func TestLimiter_Allow_RefillCapsAtBurst(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := New(10.0, 3) // fast refill, burst 3
	l.now = func() time.Time { return now }

	// Spend all tokens.
	if !l.Allow("k") || !l.Allow("k") || !l.Allow("k") {
		t.Fatalf("expected initial burst to allow 3 requests")
	}
	if l.Allow("k") {
		t.Fatalf("expected to be limited after burst spent")
	}

	// Large time jump should cap to burst, not grow unbounded.
	now = now.Add(100 * time.Second)
	if !l.Allow("k") || !l.Allow("k") || !l.Allow("k") {
		t.Fatalf("expected refill back to burst capacity")
	}
	if l.Allow("k") {
		t.Fatalf("expected to be limited after spending refilled burst")
	}
}

func TestLimiter_Allow_DoesNotRefillWhenClockGoesBackwards(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := t0
	l := New(1.0, 1)
	l.now = func() time.Time { return now }

	if !l.Allow("k") {
		t.Fatalf("expected allow at burst")
	}
	if l.Allow("k") {
		t.Fatalf("expected deny after spending token")
	}

	// Clock skew backwards should not refill tokens.
	now = t0.Add(-1 * time.Second)
	if l.Allow("k") {
		t.Fatalf("expected deny when time goes backwards")
	}
}

func TestLimiter_Allow_KeysAreHashed(t *testing.T) {
	t.Parallel()

	l := New(1.0, 1)

	// Use a recognisable raw key and verify it doesn't appear in the map.
	l.Allow("192.168.1.1")

	l.mu.Lock()
	defer l.mu.Unlock()

	for k := range l.buckets {
		if k == "192.168.1.1" {
			t.Fatalf("raw IP found as bucket key; expected hashed key")
		}
	}
	if len(l.buckets) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(l.buckets))
	}
}

func TestLimiter_Allow_SameKeyHashesConsistently(t *testing.T) {
	t.Parallel()

	l := New(1.0, 10)

	// Multiple calls with the same key should hit the same bucket.
	for i := 0; i < 5; i++ {
		l.Allow("10.0.0.1")
	}

	if l.Len() != 1 {
		t.Fatalf("expected 1 bucket for repeated key, got %d", l.Len())
	}
}

func TestLimiter_GC_SweepsStale(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := New(1.0, 1)
	l.now = func() time.Time { return now }

	l.Allow("a")
	l.Allow("b")

	if l.Len() != 2 {
		t.Fatalf("expected 2 buckets, got %d", l.Len())
	}

	// Advance time past maxIdle and sweep manually.
	now = now.Add(10 * time.Minute)
	l.sweep(5 * time.Minute)

	if l.Len() != 0 {
		t.Fatalf("expected 0 buckets after sweep, got %d", l.Len())
	}
}

func TestLimiter_GC_KeepsFresh(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := New(1.0, 10)
	l.now = func() time.Time { return now }

	l.Allow("fresh")
	l.Allow("stale")

	// Advance and touch "fresh" but not "stale".
	now = now.Add(6 * time.Minute)
	l.Allow("fresh")

	l.sweep(5 * time.Minute)

	if l.Len() != 1 {
		t.Fatalf("expected 1 bucket (fresh) after sweep, got %d", l.Len())
	}
}

func TestLimiter_Stop_Safe(t *testing.T) {
	t.Parallel()

	l := New(1.0, 1)

	// Stop without StartGC should not panic.
	l.Stop()

	// StartGC then Stop should be clean.
	l.StartGC(100*time.Millisecond, 1*time.Minute)
	l.Stop()

	// Double stop should not panic.
	l.Stop()
}
