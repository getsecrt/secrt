package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func methodNotAllowed(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func badRequest(w http.ResponseWriter, msg string) {
	writeError(w, http.StatusBadRequest, msg)
}

func unauthorized(w http.ResponseWriter) {
	writeError(w, http.StatusUnauthorized, "unauthorized")
}

func notFound(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "not found")
}

func internalServerError(w http.ResponseWriter) {
	writeError(w, http.StatusInternalServerError, "internal server error")
}

func rateLimited(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "10")
	writeError(w, http.StatusTooManyRequests, "rate limit exceeded; please try again in a few seconds")
}

func isJSONContentType(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	// Accept common forms: application/json or application/json; charset=utf-8
	return len(ct) >= len("application/json") && ct[:len("application/json")] == "application/json"
}

func mapDecodeError(err error) string {
	if err == nil {
		return "invalid json"
	}
	var synErr *json.SyntaxError
	if errors.As(err, &synErr) {
		return "invalid json"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "invalid json"
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return "invalid json field type"
	}
	if errors.Is(err, http.ErrBodyReadAfterClose) {
		return "invalid request body"
	}
	return "invalid request body"
}
