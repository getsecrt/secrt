package envelope

import (
	"encoding/json"
	"os"
	"testing"
)

type cliVectorsFile struct {
	Valid   []ttlValidVector   `json:"valid"`
	Invalid []ttlInvalidVector `json:"invalid"`
}

type ttlValidVector struct {
	Input       string `json:"input"`
	TTLSeconds  int64  `json:"ttl_seconds"`
	Description string `json:"description"`
}

type ttlInvalidVector struct {
	Input  string `json:"input"`
	Reason string `json:"reason"`
}

func loadCLIVectors(t *testing.T) cliVectorsFile {
	t.Helper()
	data, err := os.ReadFile("../../spec/v1/cli.vectors.json")
	if err != nil {
		t.Fatalf("read cli vectors: %v", err)
	}
	var vf cliVectorsFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse cli vectors: %v", err)
	}
	return vf
}

func TestParseTTL_Valid(t *testing.T) {
	t.Parallel()
	vf := loadCLIVectors(t)

	for _, vec := range vf.Valid {
		t.Run(vec.Description, func(t *testing.T) {
			t.Parallel()
			got, err := ParseTTL(vec.Input)
			if err != nil {
				t.Fatalf("ParseTTL(%q): %v", vec.Input, err)
			}
			if got != vec.TTLSeconds {
				t.Errorf("ParseTTL(%q) = %d, want %d", vec.Input, got, vec.TTLSeconds)
			}
		})
	}
}

func TestParseTTL_Invalid(t *testing.T) {
	t.Parallel()
	vf := loadCLIVectors(t)

	for _, vec := range vf.Invalid {
		t.Run(vec.Reason, func(t *testing.T) {
			t.Parallel()
			_, err := ParseTTL(vec.Input)
			if err == nil {
				t.Errorf("ParseTTL(%q): expected error for %s, got nil", vec.Input, vec.Reason)
			}
		})
	}
}
