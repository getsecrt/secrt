package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"secret/internal/envelope"
)

// testDeps returns a Deps with captured stdout/stderr and sensible defaults.
func testDeps() (Deps, *bytes.Buffer, *bytes.Buffer) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	return Deps{
		Stdin:       strings.NewReader(""),
		Stdout:      stdout,
		Stderr:      stderr,
		HTTPClient:  http.DefaultClient,
		IsTTY:       func() bool { return false },
		IsStdoutTTY: func() bool { return false },
		Getenv:      func(string) string { return "" },
		Rand:        nil,
		ReadPass:    func(prompt string, w io.Writer) (string, error) { return "", nil },
	}, stdout, stderr
}

// --- Dispatch tests ---

func TestRun_NoArgs(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	code := run([]string{"secrt"}, deps)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "secrt") {
		t.Errorf("expected usage hint on stderr, got: %s", stderr.String())
	}
}

func TestRun_Version(t *testing.T) {
	t.Parallel()
	deps, stdout, _ := testDeps()
	code := run([]string{"secrt", "version"}, deps)
	if code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "secrt") {
		t.Errorf("expected version output, got: %s", stdout.String())
	}
}

func TestRun_VersionFlag(t *testing.T) {
	t.Parallel()
	deps, stdout, _ := testDeps()
	code := run([]string{"secrt", "--version"}, deps)
	if code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "secrt") {
		t.Errorf("expected version output, got: %s", stdout.String())
	}
}

func TestRun_VersionShortFlag(t *testing.T) {
	t.Parallel()
	deps, stdout, _ := testDeps()
	code := run([]string{"secrt", "-v"}, deps)
	if code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "secrt") {
		t.Errorf("expected version output, got: %s", stdout.String())
	}
}

func TestRun_Help(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "help"}, deps)
	if code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	out := stderr.String()
	if !strings.Contains(out, "USAGE") {
		t.Errorf("expected USAGE in help, got: %s", out)
	}
	if !strings.Contains(out, "COMMANDS") {
		t.Errorf("expected COMMANDS in help, got: %s", out)
	}
}

func TestRun_HelpFlag(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "--help"}, deps)
	if code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "USAGE") {
		t.Errorf("expected usage on stderr")
	}
}

func TestRun_HelpShortFlag(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "-h"}, deps)
	if code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "USAGE") {
		t.Errorf("expected usage on stderr")
	}
}

func TestRun_SubcommandHelp(t *testing.T) {
	t.Parallel()

	cases := [][]string{
		{"secrt", "help", "create"},
		{"secrt", "create", "--help"},
		{"secrt", "create", "-h"},
		{"secrt", "help", "claim"},
		{"secrt", "claim", "--help"},
		{"secrt", "help", "burn"},
		{"secrt", "burn", "--help"},
	}

	for _, args := range cases {
		t.Run(strings.Join(args[1:], " "), func(t *testing.T) {
			t.Parallel()
			deps, _, stderr := testDeps()
			code := run(args, deps)
			if code != 0 {
				t.Errorf("exit code: got %d, want 0", code)
			}
			if stderr.Len() == 0 {
				t.Error("expected help output on stderr")
			}
		})
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "unknown"}, deps)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("expected 'unknown command' error, got: %s", stderr.String())
	}
}

func TestRun_Completion(t *testing.T) {
	t.Parallel()

	for _, sh := range []string{"bash", "zsh", "fish"} {
		t.Run(sh, func(t *testing.T) {
			t.Parallel()
			deps, stdout, _ := testDeps()
			code := run([]string{"secrt", "completion", sh}, deps)
			if code != 0 {
				t.Errorf("exit code: got %d, want 0", code)
			}
			if stdout.Len() == 0 {
				t.Errorf("expected completion script on stdout for %s", sh)
			}
		})
	}
}

func TestRun_CompletionUnknown(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "completion", "powershell"}, deps)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "supported") {
		t.Errorf("expected supported shells list, got: %s", stderr.String())
	}
}

func TestRun_CompletionNoArg(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "completion"}, deps)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "supported") {
		t.Errorf("expected supported shells list, got: %s", stderr.String())
	}
}

// --- Color tests ---

func TestHelp_ColoredWhenTTY(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	deps.IsStdoutTTY = func() bool { return true }
	code := run([]string{"secrt", "help"}, deps)
	if code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "\033[") {
		t.Error("expected ANSI escape codes in TTY mode")
	}
}

func TestHelp_PlainWhenNotTTY(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	deps.IsStdoutTTY = func() bool { return false }
	code := run([]string{"secrt", "help"}, deps)
	if code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	if strings.Contains(stderr.String(), "\033[") {
		t.Error("expected no ANSI escape codes in non-TTY mode")
	}
}

func TestColor_Helper(t *testing.T) {
	t.Parallel()

	// TTY mode: should include escape codes
	c := colorFunc(true)
	got := c("36", "test")
	if got != "\033[36mtest\033[0m" {
		t.Errorf("color TTY: got %q, want %q", got, "\033[36mtest\033[0m")
	}

	// Non-TTY mode: plain text
	c = colorFunc(false)
	got = c("36", "test")
	if got != "test" {
		t.Errorf("color non-TTY: got %q, want %q", got, "test")
	}
}

// --- Create command tests ---

func TestRun_Create_Stdin(t *testing.T) {
	t.Parallel()

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/public/secrets") {
			t.Errorf("expected public endpoint, got %s", r.URL.Path)
		}

		var req struct {
			Envelope  json.RawMessage `json:"envelope"`
			ClaimHash string          `json:"claim_hash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if len(req.Envelope) == 0 {
			t.Error("empty envelope")
		}
		if req.ClaimHash == "" {
			t.Error("empty claim_hash")
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "test-id-123",
			"share_url":  srvURL + "/s/test-id-123",
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	deps, stdout, stderr := testDeps()
	deps.Stdin = strings.NewReader("my secret data")
	deps.IsTTY = func() bool { return false }

	code := run([]string{"secrt", "create", "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
	}

	// stdout should contain share link with fragment
	out := strings.TrimSpace(stdout.String())
	if !strings.Contains(out, "#v1.") {
		t.Errorf("expected share link with fragment, got: %s", out)
	}
	// stderr should be empty on success (piped mode)
	if stderr.Len() != 0 {
		t.Errorf("expected empty stderr, got: %s", stderr.String())
	}
}

func TestRun_Create_TTYPrompt(t *testing.T) {
	t.Parallel()

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "test-id",
			"share_url":  srvURL + "/s/test-id",
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	deps, stdout, stderr := testDeps()
	deps.Stdin = strings.NewReader("my secret\n")
	deps.IsTTY = func() bool { return true }

	code := run([]string{"secrt", "create", "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
	}

	if !strings.Contains(stderr.String(), "Enter secret") {
		t.Errorf("expected prompt on stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "#v1.") {
		t.Errorf("expected share link, got: %s", stdout.String())
	}
}

func TestRun_Create_TextFlag(t *testing.T) {
	t.Parallel()

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "test-id",
			"share_url":  srvURL + "/s/test-id",
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	deps, stdout, _ := testDeps()
	code := run([]string{"secrt", "create", "--text", "inline secret", "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "#v1.") {
		t.Errorf("expected share link, got: %s", stdout.String())
	}
}

func TestRun_Create_FileFlag(t *testing.T) {
	t.Parallel()

	// Create temp file
	f, err := os.CreateTemp("", "secrt-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("file secret content")
	f.Close()

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "test-id",
			"share_url":  srvURL + "/s/test-id",
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	deps, stdout, _ := testDeps()
	code := run([]string{"secrt", "create", "--file", f.Name(), "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "#v1.") {
		t.Errorf("expected share link, got: %s", stdout.String())
	}
}

func TestRun_Create_ConflictingSources(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "create", "--text", "a", "--file", "b"}, deps)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "exactly one") {
		t.Errorf("expected conflict error, got: %s", stderr.String())
	}
}

func TestRun_Create_EmptyInput(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	deps.Stdin = strings.NewReader("")
	deps.IsTTY = func() bool { return false }
	code := run([]string{"secrt", "create"}, deps)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "empty") {
		t.Errorf("expected empty input error, got: %s", stderr.String())
	}
}

func TestRun_Create_TTL(t *testing.T) {
	t.Parallel()

	var gotTTL int64
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			TTLSeconds *int64 `json:"ttl_seconds"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.TTLSeconds != nil {
			gotTTL = *req.TTLSeconds
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "test-id",
			"share_url":  srvURL + "/s/test-id",
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	deps, _, _ := testDeps()
	deps.Stdin = strings.NewReader("secret")
	code := run([]string{"secrt", "create", "--ttl", "5m", "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if gotTTL != 300 {
		t.Errorf("ttl_seconds: got %d, want 300", gotTTL)
	}
}

func TestRun_Create_InvalidTTL(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	deps.Stdin = strings.NewReader("secret")
	code := run([]string{"secrt", "create", "--ttl", "0"}, deps)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "invalid") || !strings.Contains(strings.ToLower(stderr.String()), "ttl") {
		t.Errorf("expected TTL error, got: %s", stderr.String())
	}
}

func TestRun_Create_APIKey(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotAPIKey string
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAPIKey = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "test-id",
			"share_url":  srvURL + "/s/test-id",
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	deps, _, _ := testDeps()
	deps.Stdin = strings.NewReader("secret")
	code := run([]string{"secrt", "create", "--api-key", "sk_test.secret123", "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if !strings.HasSuffix(gotPath, "/secrets") || strings.Contains(gotPath, "public") {
		t.Errorf("expected authenticated endpoint, got: %s", gotPath)
	}
	if gotAPIKey != "sk_test.secret123" {
		t.Errorf("X-API-Key: got %q, want %q", gotAPIKey, "sk_test.secret123")
	}
}

func TestRun_Create_APIKeyEnv(t *testing.T) {
	t.Parallel()

	var gotAPIKey string
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "test-id",
			"share_url":  srvURL + "/s/test-id",
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	deps, _, _ := testDeps()
	deps.Stdin = strings.NewReader("secret")
	deps.Getenv = func(key string) string {
		if key == "SECRET_API_KEY" {
			return "sk_env.envkey"
		}
		return ""
	}
	code := run([]string{"secrt", "create", "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if gotAPIKey != "sk_env.envkey" {
		t.Errorf("X-API-Key from env: got %q, want %q", gotAPIKey, "sk_env.envkey")
	}
}

func TestRun_Create_BaseURLEnv(t *testing.T) {
	t.Parallel()

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "test-id",
			"share_url":  srvURL + "/s/test-id",
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	deps, _, _ := testDeps()
	deps.Stdin = strings.NewReader("secret")
	deps.Getenv = func(key string) string {
		if key == "SECRET_BASE_URL" {
			return srv.URL
		}
		return ""
	}
	code := run([]string{"secrt", "create"}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
}

func TestRun_Create_FlagOverridesEnv(t *testing.T) {
	t.Parallel()

	var gotAPIKey string
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "test-id",
			"share_url":  srvURL + "/s/test-id",
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	deps, _, _ := testDeps()
	deps.Stdin = strings.NewReader("secret")
	deps.Getenv = func(key string) string {
		if key == "SECRET_API_KEY" {
			return "sk_env.envkey"
		}
		return ""
	}
	code := run([]string{"secrt", "create", "--api-key", "sk_flag.flagkey", "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if gotAPIKey != "sk_flag.flagkey" {
		t.Errorf("flag should override env: got %q", gotAPIKey)
	}
}

func TestRun_Create_JSON(t *testing.T) {
	t.Parallel()

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "test-id",
			"share_url":  srvURL + "/s/test-id",
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	deps, stdout, _ := testDeps()
	deps.Stdin = strings.NewReader("secret")
	code := run([]string{"secrt", "create", "--json", "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON output: %v; raw: %s", err, stdout.String())
	}
	if _, ok := out["id"]; !ok {
		t.Error("missing id in JSON output")
	}
	if _, ok := out["share_link"]; !ok {
		t.Error("missing share_link in JSON output")
	}
	if _, ok := out["expires_at"]; !ok {
		t.Error("missing expires_at in JSON output")
	}
}

func TestRun_Create_ServerError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
	}{
		{"400", http.StatusBadRequest},
		{"429", http.StatusTooManyRequests},
		{"413", http.StatusRequestEntityTooLarge},
		{"500", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				json.NewEncoder(w).Encode(map[string]string{"error": "test error"})
			}))
			defer srv.Close()

			deps, _, stderr := testDeps()
			deps.Stdin = strings.NewReader("secret")
			code := run([]string{"secrt", "create", "--base-url", srv.URL}, deps)
			if code != 1 {
				t.Errorf("exit code: got %d, want 1", code)
			}
			if stderr.Len() == 0 {
				t.Error("expected error message on stderr")
			}
		})
	}
}

func TestRun_Create_NetworkError(t *testing.T) {
	t.Parallel()

	deps, _, stderr := testDeps()
	deps.Stdin = strings.NewReader("secret")
	code := run([]string{"secrt", "create", "--base-url", "http://127.0.0.1:1"}, deps)
	if code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Error("expected error on stderr")
	}
}

func TestRun_Create_Passphrase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		env  func(string) string
		pass func(string, io.Writer) (string, error)
	}{
		{
			"passphrase-env",
			[]string{"--passphrase-env", "MY_PASS"},
			func(k string) string {
				if k == "MY_PASS" {
					return "envpass"
				}
				return ""
			},
			nil,
		},
		{
			"passphrase-prompt",
			[]string{"--passphrase-prompt"},
			nil,
			func(prompt string, w io.Writer) (string, error) {
				return "prompted", nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Capture the envelope to verify passphrase was used
			var gotEnvelope json.RawMessage
			var srvURL string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Envelope json.RawMessage `json:"envelope"`
				}
				json.NewDecoder(r.Body).Decode(&req)
				gotEnvelope = req.Envelope
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"id":         "test-id",
					"share_url":  srvURL + "/s/test-id",
					"expires_at": "2026-02-09T00:00:00Z",
				})
			}))
			defer srv.Close()
			srvURL = srv.URL

			deps, _, _ := testDeps()
			deps.Stdin = strings.NewReader("secret")
			if tt.env != nil {
				deps.Getenv = tt.env
			}
			if tt.pass != nil {
				deps.ReadPass = tt.pass
			}

			args := append([]string{"secrt", "create", "--base-url", srv.URL}, tt.args...)
			code := run(args, deps)
			if code != 0 {
				t.Fatalf("exit code: got %d, want 0", code)
			}

			// Verify the envelope uses PBKDF2 (passphrase was applied)
			var env struct {
				KDF struct {
					Name string `json:"name"`
				} `json:"kdf"`
			}
			if err := json.Unmarshal(gotEnvelope, &env); err != nil {
				t.Fatalf("parse envelope: %v", err)
			}
			if env.KDF.Name != "PBKDF2-SHA256" {
				t.Errorf("expected PBKDF2-SHA256 kdf, got: %s", env.KDF.Name)
			}
		})
	}
}

func TestRun_Create_PassphraseFile(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp("", "secrt-pass-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("filepass\n")
	f.Close()

	var gotEnvelope json.RawMessage
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Envelope json.RawMessage `json:"envelope"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		gotEnvelope = req.Envelope
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "test-id",
			"share_url":  srvURL + "/s/test-id",
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	deps, _, _ := testDeps()
	deps.Stdin = strings.NewReader("secret")
	code := run([]string{"secrt", "create", "--passphrase-file", f.Name(), "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}

	var env struct {
		KDF struct {
			Name string `json:"name"`
		} `json:"kdf"`
	}
	json.Unmarshal(gotEnvelope, &env)
	if env.KDF.Name != "PBKDF2-SHA256" {
		t.Errorf("expected PBKDF2-SHA256 kdf, got: %s", env.KDF.Name)
	}
}

func TestRun_Create_OutputDiscipline(t *testing.T) {
	t.Parallel()

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         "test-id",
			"share_url":  srvURL + "/s/test-id",
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	deps, stdout, stderr := testDeps()
	deps.Stdin = strings.NewReader("secret")
	deps.IsTTY = func() bool { return false }

	code := run([]string{"secrt", "create", "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr should be empty in piped mode, got: %s", stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 {
		t.Errorf("expected exactly one line on stdout, got %d: %v", len(lines), lines)
	}
}

// --- Claim command tests ---

func TestRun_Claim_Success(t *testing.T) {
	t.Parallel()

	// Create a secret first
	plaintext := []byte("claim-test-secret")
	result, err := envelope.Seal(envelope.SealParams{Plaintext: plaintext})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/claim") {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var req struct {
			Claim string `json:"claim"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Claim == "" {
			t.Error("empty claim token")
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"envelope":   json.RawMessage(result.Envelope),
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()

	shareLink := envelope.FormatShareLink(srv.URL+"/s/test-id", result.URLKey)

	deps, stdout, stderr := testDeps()
	code := run([]string{"secrt", "claim", shareLink}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
	}
	if string(stdout.Bytes()) != string(plaintext) {
		t.Errorf("plaintext: got %q, want %q", stdout.String(), plaintext)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr should be empty on success, got: %s", stderr.String())
	}
}

func TestRun_Claim_WithPassphrase(t *testing.T) {
	t.Parallel()

	plaintext := []byte("passphrase-protected")
	result, err := envelope.Seal(envelope.SealParams{
		Plaintext:  plaintext,
		Passphrase: "testpass",
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"envelope":   json.RawMessage(result.Envelope),
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()

	shareLink := envelope.FormatShareLink(srv.URL+"/s/test-id", result.URLKey)

	deps, stdout, _ := testDeps()
	deps.ReadPass = func(prompt string, w io.Writer) (string, error) {
		return "testpass", nil
	}
	code := run([]string{"secrt", "claim", shareLink, "--passphrase-prompt"}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if string(stdout.Bytes()) != string(plaintext) {
		t.Errorf("plaintext: got %q, want %q", stdout.String(), plaintext)
	}
}

func TestRun_Claim_WrongPassphrase(t *testing.T) {
	t.Parallel()

	result, err := envelope.Seal(envelope.SealParams{
		Plaintext:  []byte("secret"),
		Passphrase: "correct",
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"envelope":   json.RawMessage(result.Envelope),
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()

	shareLink := envelope.FormatShareLink(srv.URL+"/s/test-id", result.URLKey)

	deps, _, stderr := testDeps()
	deps.ReadPass = func(prompt string, w io.Writer) (string, error) {
		return "wrong", nil
	}
	code := run([]string{"secrt", "claim", shareLink, "--passphrase-prompt"}, deps)
	if code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
	if !strings.Contains(strings.ToLower(stderr.String()), "decrypt") {
		t.Errorf("expected decryption error, got: %s", stderr.String())
	}
}

func TestRun_Claim_MissingFragment(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "claim", "https://secrt.ca/s/abc123"}, deps)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if stderr.Len() == 0 {
		t.Error("expected error on stderr")
	}
}

func TestRun_Claim_NoArgs(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "claim"}, deps)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "URL") || !strings.Contains(stderr.String(), "required") {
		t.Errorf("expected 'URL required' error, got: %s", stderr.String())
	}
}

func TestRun_Claim_404(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer srv.Close()

	urlKey := make([]byte, 32)
	shareLink := envelope.FormatShareLink(srv.URL+"/s/test-id", urlKey)

	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "claim", shareLink}, deps)
	if code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Error("expected error on stderr")
	}
}

func TestRun_Claim_JSON(t *testing.T) {
	t.Parallel()

	result, err := envelope.Seal(envelope.SealParams{Plaintext: []byte("json-test")})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"envelope":   json.RawMessage(result.Envelope),
			"expires_at": "2026-02-09T00:00:00Z",
		})
	}))
	defer srv.Close()

	shareLink := envelope.FormatShareLink(srv.URL+"/s/test-id", result.URLKey)

	deps, stdout, _ := testDeps()
	code := run([]string{"secrt", "claim", shareLink, "--json"}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestRun_Claim_NetworkError(t *testing.T) {
	t.Parallel()

	urlKey := make([]byte, 32)
	shareLink := envelope.FormatShareLink("http://127.0.0.1:1/s/test-id", urlKey)

	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "claim", shareLink}, deps)
	if code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Error("expected error on stderr")
	}
}

// --- Burn command tests ---

func TestRun_Burn_Success(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/burn") {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-API-Key") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer srv.Close()

	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "burn", "test-id-123", "--api-key", "sk_test.key", "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
	}
}

func TestRun_Burn_ByURL(t *testing.T) {
	t.Parallel()

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer srv.Close()

	urlKey := make([]byte, 32)
	shareLink := envelope.FormatShareLink(srv.URL+"/s/burn-id", urlKey)

	deps, _, _ := testDeps()
	code := run([]string{"secrt", "burn", shareLink, "--api-key", "sk_test.key", "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if !strings.Contains(gotPath, "burn-id") {
		t.Errorf("expected burn-id in path, got: %s", gotPath)
	}
}

func TestRun_Burn_MissingAPIKey(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "burn", "test-id"}, deps)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "api-key") || !strings.Contains(stderr.String(), "required") {
		t.Errorf("expected api-key required error, got: %s", stderr.String())
	}
}

func TestRun_Burn_404(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer srv.Close()

	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "burn", "nonexistent", "--api-key", "sk_test.key", "--base-url", srv.URL}, deps)
	if code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Error("expected error on stderr")
	}
}

func TestRun_Burn_401(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	}))
	defer srv.Close()

	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "burn", "test-id", "--api-key", "sk_bad.key", "--base-url", srv.URL}, deps)
	if code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Error("expected error on stderr")
	}
}

func TestRun_Burn_JSON(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer srv.Close()

	deps, stdout, _ := testDeps()
	code := run([]string{"secrt", "burn", "test-id", "--api-key", "sk_test.key", "--json", "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if out["ok"] != true {
		t.Error("expected ok: true")
	}
}

func TestRun_Burn_NoArgs(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "burn", "--api-key", "sk_test.key"}, deps)
	if code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
	if stderr.Len() == 0 {
		t.Error("expected error on stderr")
	}
}

// --- End-to-end round-trip test ---

func TestRun_EndToEnd_CreateThenClaim(t *testing.T) {
	t.Parallel()

	// Mock server that stores and returns the secret
	var stored struct {
		Envelope  json.RawMessage
		ClaimHash string
	}
	claimed := false

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/public/secrets") && r.Method == http.MethodPost:
			var req struct {
				Envelope  json.RawMessage `json:"envelope"`
				ClaimHash string          `json:"claim_hash"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			stored.Envelope = req.Envelope
			stored.ClaimHash = req.ClaimHash
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":         "e2e-id",
				"share_url":  srvURL + "/s/e2e-id",
				"expires_at": "2026-02-09T00:00:00Z",
			})

		case strings.HasSuffix(r.URL.Path, "/claim") && r.Method == http.MethodPost:
			if claimed {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"error": "already claimed"})
				return
			}
			claimed = true
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"envelope":   stored.Envelope,
				"expires_at": "2026-02-09T00:00:00Z",
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	originalPlaintext := "end-to-end test secret 🔐"

	// Step 1: Create
	createDeps, createStdout, createStderr := testDeps()
	createDeps.Stdin = strings.NewReader(originalPlaintext)
	createCode := run([]string{"secrt", "create", "--base-url", srv.URL}, createDeps)
	if createCode != 0 {
		t.Fatalf("create exit code: %d; stderr: %s", createCode, createStderr.String())
	}
	shareLink := strings.TrimSpace(createStdout.String())
	if !strings.Contains(shareLink, "#v1.") {
		t.Fatalf("invalid share link: %s", shareLink)
	}

	// Step 2: Claim
	claimDeps, claimStdout, claimStderr := testDeps()
	claimCode := run([]string{"secrt", "claim", shareLink}, claimDeps)
	if claimCode != 0 {
		t.Fatalf("claim exit code: %d; stderr: %s", claimCode, claimStderr.String())
	}
	if string(claimStdout.Bytes()) != originalPlaintext {
		t.Errorf("plaintext mismatch:\n  got:  %q\n  want: %q", claimStdout.String(), originalPlaintext)
	}

	// Step 3: Second claim should fail (one-time semantics)
	claim2Deps, _, claim2Stderr := testDeps()
	claim2Code := run([]string{"secrt", "claim", shareLink}, claim2Deps)
	if claim2Code != 1 {
		t.Errorf("second claim should fail: got exit %d", claim2Code)
	}
	_ = claim2Stderr
}

func TestRun_EndToEnd_CreateClaimWithPassphrase(t *testing.T) {
	t.Parallel()

	var stored struct {
		Envelope json.RawMessage
	}

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/public/secrets") {
			var req struct {
				Envelope json.RawMessage `json:"envelope"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			stored.Envelope = req.Envelope
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":         "pass-id",
				"share_url":  srvURL + "/s/pass-id",
				"expires_at": "2026-02-09T00:00:00Z",
			})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/claim") {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"envelope":   stored.Envelope,
				"expires_at": "2026-02-09T00:00:00Z",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	srvURL = srv.URL

	original := "passphrase-protected e2e"

	// Create with passphrase
	createDeps, createStdout, _ := testDeps()
	createDeps.Stdin = strings.NewReader(original)
	createDeps.ReadPass = func(prompt string, w io.Writer) (string, error) {
		return "e2epass", nil
	}
	createCode := run([]string{"secrt", "create", "--passphrase-prompt", "--base-url", srv.URL}, createDeps)
	if createCode != 0 {
		t.Fatalf("create exit code: %d", createCode)
	}
	shareLink := strings.TrimSpace(createStdout.String())

	// Claim with same passphrase
	claimDeps, claimStdout, _ := testDeps()
	claimDeps.ReadPass = func(prompt string, w io.Writer) (string, error) {
		return "e2epass", nil
	}
	claimCode := run([]string{"secrt", "claim", shareLink, "--passphrase-prompt"}, claimDeps)
	if claimCode != 0 {
		t.Fatalf("claim exit code: %d", claimCode)
	}
	if string(claimStdout.Bytes()) != original {
		t.Errorf("plaintext: got %q, want %q", claimStdout.String(), original)
	}
}

// Verify Burn command with env-based API key
func TestRun_Burn_APIKeyEnv(t *testing.T) {
	t.Parallel()

	var gotAPIKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer srv.Close()

	deps, _, _ := testDeps()
	deps.Getenv = func(key string) string {
		if key == "SECRET_API_KEY" {
			return "sk_env.burnkey"
		}
		return ""
	}
	code := run([]string{"secrt", "burn", "test-id", "--base-url", srv.URL}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if gotAPIKey != "sk_env.burnkey" {
		t.Errorf("expected env API key, got: %q", gotAPIKey)
	}
}

// Ensure the create help shows usage for create subcommand
func TestRun_Create_HelpShowsFlags(t *testing.T) {
	t.Parallel()
	deps, _, stderr := testDeps()
	code := run([]string{"secrt", "create", "--help"}, deps)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	out := stderr.String()
	for _, flag := range []string{"--ttl", "--text", "--file", "--passphrase"} {
		if !strings.Contains(out, flag) {
			t.Errorf("expected %s in create help, got: %s", flag, out)
		}
	}
}

// Test that error output in JSON mode is also JSON
func TestRun_Create_JSONError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"bad request"}`)
	}))
	defer srv.Close()

	deps, _, stderr := testDeps()
	deps.Stdin = strings.NewReader("secret")
	code := run([]string{"secrt", "create", "--json", "--base-url", srv.URL}, deps)
	if code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}

	// In JSON mode, error should be JSON on stderr
	var errObj map[string]interface{}
	if err := json.Unmarshal(stderr.Bytes(), &errObj); err != nil {
		t.Errorf("expected JSON error on stderr, got: %s", stderr.String())
	}
}
