package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestIsJSONContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ct   string
		want bool
	}{
		{name: "empty", ct: "", want: false},
		{name: "json", ct: "application/json", want: true},
		{name: "json charset", ct: "application/json; charset=utf-8", want: true},
		{name: "other", ct: "text/plain", want: false},
		{name: "prefix only", ct: "application/j", want: false},
		{name: "case sensitive", ct: "Application/JSON", want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r, _ := http.NewRequest(http.MethodPost, "/", nil)
			if tt.ct != "" {
				r.Header.Set("Content-Type", tt.ct)
			}
			if got := isJSONContentType(r); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestMapDecodeError(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		if got := mapDecodeError(nil); got != "invalid json" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("syntax", func(t *testing.T) {
		t.Parallel()
		err := &json.SyntaxError{}
		if got := mapDecodeError(err); got != "invalid json" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("type", func(t *testing.T) {
		t.Parallel()
		err := &json.UnmarshalTypeError{}
		if got := mapDecodeError(err); got != "invalid json field type" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("eof", func(t *testing.T) {
		t.Parallel()
		if got := mapDecodeError(io.EOF); got != "invalid json" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("unexpected eof", func(t *testing.T) {
		t.Parallel()
		if got := mapDecodeError(io.ErrUnexpectedEOF); got != "invalid json" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("body read after close", func(t *testing.T) {
		t.Parallel()
		if got := mapDecodeError(http.ErrBodyReadAfterClose); got != "invalid request body" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("default", func(t *testing.T) {
		t.Parallel()
		if got := mapDecodeError(errors.New("boom")); got != "invalid request body" {
			t.Fatalf("got %q", got)
		}
	})
}
