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
