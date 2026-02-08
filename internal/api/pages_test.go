package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"secrt/internal/auth"
	"secrt/internal/config"
)

func TestPages_IndexAndSecretAndRobots(t *testing.T) {
	t.Parallel()

	secStore := newMemSecretsStore()
	keyStore := newMemAPIKeyStore()
	authn := auth.NewAuthenticator("pepper", keyStore)
	srv := NewServer(config.Config{PublicBaseURL: "https://example.com"}, secStore, authn)

	t.Run("index", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("content-type: got %q", ct)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("cache-control: got %q", rec.Header().Get("Cache-Control"))
		}
		if rec.Header().Get("X-Robots-Tag") != "noindex" {
			t.Fatalf("x-robots-tag: got %q", rec.Header().Get("X-Robots-Tag"))
		}
		if !strings.Contains(rec.Body.String(), "Backend is running") {
			t.Fatalf("unexpected body: %s", rec.Body.String())
		}
	})

	t.Run("secret page", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/s/abc123", nil)
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "abc123") {
			t.Fatalf("expected id in body, got: %s", rec.Body.String())
		}
	})

	t.Run("robots", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Fatalf("content-type: got %q", ct)
		}
		if !strings.Contains(rec.Body.String(), "Disallow: /") {
			t.Fatalf("unexpected robots: %s", rec.Body.String())
		}
	})
}
