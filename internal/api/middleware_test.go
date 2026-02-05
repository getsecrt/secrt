package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
