package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestRequestIDMiddleware_UsesIncomingID(t *testing.T) {
	t.Parallel()

	h := requestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid, _ := r.Context().Value(requestIDKey).(string)
		_, _ = w.Write([]byte(rid))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", "req-123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-Id"); got != "req-123" {
		t.Fatalf("header: got %q", got)
	}
	if got := rec.Body.String(); got != "req-123" {
		t.Fatalf("context: got %q", got)
	}
}

func TestRequestIDMiddleware_GeneratesID(t *testing.T) {
	t.Parallel()

	h := requestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid, _ := r.Context().Value(requestIDKey).(string)
		_, _ = w.Write([]byte(rid))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	rid := strings.TrimSpace(rec.Header().Get("X-Request-Id"))
	if rid == "" {
		t.Fatalf("expected generated request id")
	}
	if len(rid) != 32 {
		t.Fatalf("expected 32 hex chars, got %d (%q)", len(rid), rid)
	}
	if _, err := hex.DecodeString(rid); err != nil {
		t.Fatalf("expected hex request id: %v", err)
	}
	if got := rec.Body.String(); got != rid {
		t.Fatalf("context mismatch: got %q want %q", got, rid)
	}
}

func TestSecurityHeadersMiddleware_SetsHeaders(t *testing.T) {
	t.Parallel()

	h := securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options: got %q", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy: got %q", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options: got %q", got)
	}
}

func TestRecoverMiddleware_ConvertsPanicTo500(t *testing.T) {
	t.Parallel()

	h := recoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d", rec.Code)
	}
	var resp errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if resp.Error != "internal server error" {
		t.Fatalf("error: got %q", resp.Error)
	}
}

func TestStatusRecorder_DefaultStatusAndBytes(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec}

	n, err := sr.Write([]byte("hi"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 2 {
		t.Fatalf("Write n: got %d", n)
	}
	if sr.status != http.StatusOK {
		t.Fatalf("status: got %d", sr.status)
	}
	if sr.bytes != 2 {
		t.Fatalf("bytes: got %d", sr.bytes)
	}
}

func TestStatusRecorder_WriteHeader(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec}
	sr.WriteHeader(http.StatusCreated)
	if sr.status != http.StatusCreated {
		t.Fatalf("status: got %d", sr.status)
	}
}

// captureHandler is a slog.Handler that records log entries for test assertions.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *captureHandler) WithGroup(string) slog.Handler             { return h }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *captureHandler) get() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]slog.Record, len(h.records))
	copy(out, h.records)
	return out
}

// Tests for privacyLogCheckMiddleware are NOT parallel because they mutate
// the global slog default logger. Each subtest gets a fresh middleware instance.
func TestPrivacyLogCheckMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		privacyLog string
		wantFired  bool
		wantLevel  slog.Level
		wantStatus string
	}{
		{
			name:      "no proxy headers — skip check",
			wantFired: false,
		},
		{
			name:       "proxied with truncated-ip",
			xff:        "1.2.3.4",
			privacyLog: "truncated-ip",
			wantFired:  true,
			wantLevel:  slog.LevelInfo,
			wantStatus: "ok",
		},
		{
			name:       "proxied with missing header",
			xff:        "1.2.3.4",
			wantFired:  true,
			wantLevel:  slog.LevelWarn,
			wantStatus: "missing",
		},
		{
			name:       "proxied with unrecognized value",
			xff:        "1.2.3.4",
			privacyLog: "full-ip",
			wantFired:  true,
			wantLevel:  slog.LevelWarn,
			wantStatus: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := &captureHandler{}
			origDefault := slog.Default()
			slog.SetDefault(slog.New(ch))
			defer slog.SetDefault(origDefault)

			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			mid := privacyLogCheckMiddleware(inner)

			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.privacyLog != "" {
				req.Header.Set("X-Privacy-Log", tt.privacyLog)
			}

			rec := httptest.NewRecorder()
			mid.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status: got %d", rec.Code)
			}

			records := ch.get()
			if tt.wantFired {
				var matched []slog.Record
				for _, r := range records {
					if r.Message == "privacy_log_check" {
						matched = append(matched, r)
					}
				}
				if len(matched) == 0 {
					t.Fatal("expected privacy_log_check log record, got none")
				}
				if matched[0].Level != tt.wantLevel {
					t.Errorf("level = %v, want %v", matched[0].Level, tt.wantLevel)
				}
				var gotStatus string
				matched[0].Attrs(func(a slog.Attr) bool {
					if a.Key == "status" {
						gotStatus = a.Value.String()
						return false
					}
					return true
				})
				if gotStatus != tt.wantStatus {
					t.Errorf("status attr = %q, want %q", gotStatus, tt.wantStatus)
				}
			} else {
				for _, r := range records {
					if r.Message == "privacy_log_check" {
						t.Fatal("expected no privacy_log_check log, but got one")
					}
				}
			}
		})
	}
}

func TestPrivacyLogCheckMiddleware_FiresOnlyOnce(t *testing.T) {
	ch := &captureHandler{}
	origDefault := slog.Default()
	slog.SetDefault(slog.New(ch))
	defer slog.SetDefault(origDefault)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mid := privacyLogCheckMiddleware(inner)

	// First proxied request — should fire.
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("X-Forwarded-For", "1.2.3.4")
	req1.Header.Set("X-Privacy-Log", "truncated-ip")
	mid.ServeHTTP(httptest.NewRecorder(), req1)

	// Second proxied request — should NOT fire again.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-Forwarded-For", "5.6.7.8")
	mid.ServeHTTP(httptest.NewRecorder(), req2)

	var count int
	for _, r := range ch.get() {
		if r.Message == "privacy_log_check" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 privacy_log_check record, got %d", count)
	}
}

func TestPrivacyLogCheckMiddleware_SkipsDirectThenFiresOnProxy(t *testing.T) {
	ch := &captureHandler{}
	origDefault := slog.Default()
	slog.SetDefault(slog.New(ch))
	defer slog.SetDefault(origDefault)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mid := privacyLogCheckMiddleware(inner)

	// Direct request (no XFF) — should skip.
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	mid.ServeHTTP(httptest.NewRecorder(), req1)

	var count int
	for _, r := range ch.get() {
		if r.Message == "privacy_log_check" {
			count++
		}
	}
	if count != 0 {
		t.Fatalf("expected 0 records after direct request, got %d", count)
	}

	// Now a proxied request — should fire.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-Forwarded-For", "1.2.3.4")
	mid.ServeHTTP(httptest.NewRecorder(), req2)

	count = 0
	for _, r := range ch.get() {
		if r.Message == "privacy_log_check" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 record after proxied request, got %d", count)
	}
}
