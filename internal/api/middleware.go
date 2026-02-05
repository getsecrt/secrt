package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

type ctxKey string

const requestIDKey ctxKey = "request_id"

func withMiddleware(h http.Handler) http.Handler {
	h = recoverMiddleware(h)
	h = requestIDMiddleware(h)
	h = securityHeadersMiddleware(h)
	h = loggingMiddleware(h)
	return h
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic", "recover", rec)
				internalServerError(w)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-Id")
		if rid == "" {
			var b [16]byte
			if _, err := rand.Read(b[:]); err == nil {
				rid = hex.EncodeToString(b[:])
			}
		}
		if rid != "" {
			w.Header().Set("X-Request-Id", rid)
			ctx := context.WithValue(r.Context(), requestIDKey, rid)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Conservative defaults; the frontend can add stricter CSP as needed.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(p []byte) (int, error) {
	if sr.status == 0 {
		sr.status = http.StatusOK
	}
	n, err := sr.ResponseWriter.Write(p)
	sr.bytes += n
	return n, err
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sr := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(sr, r)
		dur := time.Since(start)

		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", sr.status,
			"bytes", sr.bytes,
			"duration_ms", dur.Milliseconds(),
		}
		// Note: since this middleware is the outer-most wrapper, r.Context() will
		// not reflect context changes made by inner middleware (e.g., requestID).
		// Prefer reading the request id from the response header.
		rid, _ := r.Context().Value(requestIDKey).(string)
		if rid == "" {
			rid = sr.Header().Get("X-Request-Id")
		}
		if rid != "" {
			attrs = append(attrs, "request_id", rid)
		}
		slog.Info("request", attrs...)
	})
}
