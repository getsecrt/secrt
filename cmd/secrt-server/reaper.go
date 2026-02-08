package main

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

const (
	expiryReaperInterval      = 5 * time.Minute
	expiryReaperDeleteTimeout = 10 * time.Second
)

type expiryReaperStore interface {
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

func runExpiryReaper(
	ctx context.Context,
	logger *slog.Logger,
	store expiryReaperStore,
	interval time.Duration,
	now func() time.Time,
) {
	if logger == nil {
		logger = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	if interval <= 0 {
		logger.Error("expiry reaper disabled: interval must be positive", "interval", interval)
		return
	}

	// Run once at startup so long-lived processes do not wait an entire tick
	// before purging expired rows.
	runExpiryReaperOnce(ctx, logger, store, now)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runExpiryReaperOnce(ctx, logger, store, now)
		}
	}
}

func runExpiryReaperOnce(
	ctx context.Context,
	logger *slog.Logger,
	store expiryReaperStore,
	now func() time.Time,
) {
	if ctx.Err() != nil {
		return
	}

	cctx, cancel := context.WithTimeout(ctx, expiryReaperDeleteTimeout)
	defer cancel()

	deleted, err := store.DeleteExpired(cctx, now().UTC())
	if err != nil {
		// Shutdown/timeout cancellation is expected; avoid noisy logs.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		logger.Error("expiry reaper delete failed", "err", err)
		return
	}
	if deleted > 0 {
		logger.Info("expired secrets deleted", "count", deleted)
	}
}
