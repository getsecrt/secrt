package storage

import (
	"errors"
	"testing"
)

func TestErrNotFound_IsSentinel(t *testing.T) {
	t.Parallel()

	if !errors.Is(ErrNotFound, ErrNotFound) {
		t.Fatal("ErrNotFound should match itself via errors.Is")
	}
	if ErrNotFound.Error() != "not found" {
		t.Fatalf("unexpected message: %q", ErrNotFound.Error())
	}
}
