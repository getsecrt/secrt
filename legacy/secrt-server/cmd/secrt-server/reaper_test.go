package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

type expiryReaperStoreStub struct {
	deleteExpired func(ctx context.Context, now time.Time) (int64, error)
}

func (s expiryReaperStoreStub) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	return s.deleteExpired(ctx, now)
}

func TestRunExpiryReaperOnceUsesUTCAndTimeout(t *testing.T) {
	t.Parallel()

	called := false
	rawNow := time.Date(2026, time.February, 8, 14, 30, 0, 0, time.FixedZone("UTC+2", 2*60*60))

	store := expiryReaperStoreStub{
		deleteExpired: func(ctx context.Context, gotNow time.Time) (int64, error) {
			called = true

			if !gotNow.Equal(rawNow.UTC()) {
				t.Fatalf("now mismatch: got %s want %s", gotNow, rawNow.UTC())
			}
			if gotNow.Location() != time.UTC {
				t.Fatalf("expected UTC location, got %v", gotNow.Location())
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("expected timeout context with deadline")
			}
			return 0, nil
		},
	}

	runExpiryReaperOnce(context.Background(), testLogger(), store, func() time.Time { return rawNow })

	if !called {
		t.Fatal("expected DeleteExpired to be called")
	}
}

func TestRunExpiryReaperRunsImmediatelyAndStopsOnCancel(t *testing.T) {
	t.Parallel()

	calls := make(chan struct{}, 8)
	store := expiryReaperStoreStub{
		deleteExpired: func(ctx context.Context, now time.Time) (int64, error) {
			select {
			case calls <- struct{}{}:
			default:
			}
			return 0, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runExpiryReaper(ctx, testLogger(), store, 10*time.Millisecond, time.Now)
		close(done)
	}()

	waitForCall(t, calls) // startup run
	waitForCall(t, calls) // at least one ticker run

	cancel()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("reaper did not stop after context cancel")
	}
}

func waitForCall(t *testing.T, calls <-chan struct{}) {
	t.Helper()
	select {
	case <-calls:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for reaper call")
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRunExpiryReaperOnce_CancelledContext(t *testing.T) {
	t.Parallel()

	called := false
	store := expiryReaperStoreStub{
		deleteExpired: func(ctx context.Context, now time.Time) (int64, error) {
			called = true
			return 0, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	runExpiryReaperOnce(ctx, testLogger(), store, time.Now)

	if called {
		t.Fatal("store should not be called when context is already cancelled")
	}
}

func TestRunExpiryReaperOnce_StoreError(t *testing.T) {
	t.Parallel()

	store := expiryReaperStoreStub{
		deleteExpired: func(ctx context.Context, now time.Time) (int64, error) {
			return 0, errors.New("db down")
		},
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))

	runExpiryReaperOnce(context.Background(), logger, store, time.Now)

	if !bytes.Contains(buf.Bytes(), []byte("expiry reaper delete failed")) {
		t.Fatalf("expected error log, got: %s", buf.String())
	}
}

func TestRunExpiryReaperOnce_DeletedCountLogged(t *testing.T) {
	t.Parallel()

	store := expiryReaperStoreStub{
		deleteExpired: func(ctx context.Context, now time.Time) (int64, error) {
			return 5, nil
		},
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	runExpiryReaperOnce(context.Background(), logger, store, time.Now)

	if !bytes.Contains(buf.Bytes(), []byte("expired secrets deleted")) {
		t.Fatalf("expected info log about deleted secrets, got: %s", buf.String())
	}
}

func TestRunExpiryReaper_InvalidInterval(t *testing.T) {
	t.Parallel()

	store := expiryReaperStoreStub{
		deleteExpired: func(ctx context.Context, now time.Time) (int64, error) {
			t.Fatal("should not be called")
			return 0, nil
		},
	}

	runExpiryReaper(context.Background(), testLogger(), store, 0, time.Now)
	runExpiryReaper(context.Background(), testLogger(), store, -1*time.Second, time.Now)
}

func TestRunExpiryReaper_NilLoggerAndNow(t *testing.T) {
	t.Parallel()

	called := make(chan struct{}, 2)
	store := expiryReaperStoreStub{
		deleteExpired: func(ctx context.Context, now time.Time) (int64, error) {
			select {
			case called <- struct{}{}:
			default:
			}
			return 0, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runExpiryReaper(ctx, nil, store, 10*time.Millisecond, nil)
		close(done)
	}()

	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reaper call with nil logger/now")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("reaper did not stop")
	}
}
