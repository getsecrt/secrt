package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDotEnvIfPresent_MissingFileIsOK(t *testing.T) {
	err := LoadDotEnvIfPresent(filepath.Join(t.TempDir(), "does-not-exist.env"))
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestLoadDotEnvIfPresent_DirectoryReturnsError(t *testing.T) {
	dir := t.TempDir()
	err := LoadDotEnvIfPresent(dir)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestLoadDotEnv_ParsesAndDoesNotOverride(t *testing.T) {
	t.Setenv("FOO", "orig")

	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "" +
		"# comment\n" +
		"\n" +
		"FOO=bar\n" + // should NOT override existing env
		"BAR=\"baz\"\n" +
		"BAZ='qux'\n" +
		"SPACED = spaced value \n" +
		"EMPTY=\n" +
		"INVALIDLINE\n" +
		"=noval\n" +
		"QUOTED=\"a=b\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp env: %v", err)
	}

	if err := LoadDotEnv(path); err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}

	if got := os.Getenv("FOO"); got != "orig" {
		t.Fatalf("FOO override: got %q", got)
	}
	if got := os.Getenv("BAR"); got != "baz" {
		t.Fatalf("BAR: got %q", got)
	}
	if got := os.Getenv("BAZ"); got != "qux" {
		t.Fatalf("BAZ: got %q", got)
	}
	if got := os.Getenv("SPACED"); got != "spaced value" {
		t.Fatalf("SPACED: got %q", got)
	}
	if got := os.Getenv("EMPTY"); got != "" {
		t.Fatalf("EMPTY: got %q", got)
	}
	if got := os.Getenv("QUOTED"); got != "a=b" {
		t.Fatalf("QUOTED: got %q", got)
	}
}

func TestLoadDotEnvIfPresent_StatError(t *testing.T) {
	parent := t.TempDir()
	noPerm := filepath.Join(parent, "noperm")
	if err := os.Mkdir(noPerm, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Remove all permissions so Stat on a child path fails (EACCES).
	if err := os.Chmod(noPerm, 0o000); err != nil {
		t.Skipf("chmod not supported: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(noPerm, 0o700) })

	err := LoadDotEnvIfPresent(filepath.Join(noPerm, ".env"))
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "stat") {
		t.Fatalf("expected stat error, got %v", err)
	}
}

func TestLoadDotEnv_ScannerTooLong(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	// bufio.Scanner defaults to a 64K token limit; exceed it to force ErrTooLong.
	longLine := "A=" + strings.Repeat("x", 70*1024)
	if err := os.WriteFile(path, []byte(longLine), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := LoadDotEnv(path)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "scan") {
		t.Fatalf("expected scan error, got %v", err)
	}
}

func TestLoadDotEnv_MissingFileErrors(t *testing.T) {
	err := LoadDotEnv(filepath.Join(t.TempDir(), "missing.env"))
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "open") {
		t.Fatalf("expected open error, got %v", err)
	}
}

func TestLoadDotEnv_SetenvError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	// Environment variable keys containing NUL should cause os.Setenv to error.
	content := []byte{'B', 'A', 'D', 0, 'K', 'E', 'Y', '=', '1', '\n'}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := LoadDotEnv(path)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "setenv") {
		t.Fatalf("expected setenv error, got %v", err)
	}
}
