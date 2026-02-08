// Package v1_test verifies the envelope test vectors are self-consistent.
//
// For each vector it:
//  1. Re-derives IKM, enc_key, and claim_token from the inputs.
//  2. Verifies claim_hash matches SHA-256(claim_token).
//  3. Decrypts the ciphertext and verifies it matches the expected plaintext.
//
// This ensures any implementation that passes these vectors is interoperable.
package v1_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"testing"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

const (
	aad           = "secrt.ca/envelope/v1"
	hkdfInfoEnc   = "secret:v1:enc"
	hkdfInfoClaim = "secret:v1:claim"
)

type vectorsFile struct {
	Vectors []testVector `json:"vectors"`
}

type testVector struct {
	Description string   `json:"description"`
	URLKey      string   `json:"url_key"`
	Plaintext   string   `json:"plaintext"`
	Passphrase  *string  `json:"passphrase"`
	IKM         string   `json:"ikm"`
	EncKey      string   `json:"enc_key"`
	ClaimToken  string   `json:"claim_token"`
	ClaimHash   string   `json:"claim_hash"`
	Envelope    envelope `json:"envelope"`
}

type envelope struct {
	Enc  encBlock  `json:"enc"`
	KDF  kdfBlock  `json:"kdf"`
	HKDF hkdfBlock `json:"hkdf"`
}

type encBlock struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type kdfBlock struct {
	Name       string `json:"name"`
	Salt       string `json:"salt,omitempty"`
	Iterations int    `json:"iterations,omitempty"`
}

type hkdfBlock struct {
	Salt string `json:"salt"`
}

func b64decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url decode %q: %v", s, err)
	}
	return b
}

func deriveHKDF(t *testing.T, ikm, salt []byte, info string, length int) []byte {
	t.Helper()
	r := hkdf.New(sha256.New, ikm, salt, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		t.Fatalf("HKDF read: %v", err)
	}
	return out
}

func TestEnvelopeVectors(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("envelope.vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vf vectorsFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	if len(vf.Vectors) == 0 {
		t.Fatal("no vectors found")
	}

	for _, vec := range vf.Vectors {
		t.Run(vec.Description, func(t *testing.T) {
			t.Parallel()

			urlKey := b64decode(t, vec.URLKey)
			if len(urlKey) != 32 {
				t.Fatalf("url_key length: got %d, want 32", len(urlKey))
			}

			expectedPlaintext := b64decode(t, vec.Plaintext)

			// Step 1: Compute IKM
			var ikm []byte
			if vec.Passphrase == nil {
				ikm = urlKey
			} else {
				kdfSalt := b64decode(t, vec.Envelope.KDF.Salt)
				passKey := pbkdf2.Key(
					[]byte(*vec.Passphrase),
					kdfSalt,
					vec.Envelope.KDF.Iterations,
					32,
					sha256.New,
				)
				h := sha256.New()
				h.Write(urlKey)
				h.Write(passKey)
				ikm = h.Sum(nil)
			}

			expectedIKM := b64decode(t, vec.IKM)
			if !bytesEqual(ikm, expectedIKM) {
				t.Fatalf("IKM mismatch:\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(ikm), vec.IKM)
			}

			// Step 2: Derive enc_key (from ikm + hkdf.salt) and claim_token (from url_key alone)
			hkdfSalt := b64decode(t, vec.Envelope.HKDF.Salt)
			encKey := deriveHKDF(t, ikm, hkdfSalt, hkdfInfoEnc, 32)
			claimToken := deriveHKDF(t, urlKey, nil, hkdfInfoClaim, 32)

			expectedEncKey := b64decode(t, vec.EncKey)
			if !bytesEqual(encKey, expectedEncKey) {
				t.Fatalf("enc_key mismatch:\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(encKey), vec.EncKey)
			}

			expectedClaimToken := b64decode(t, vec.ClaimToken)
			if !bytesEqual(claimToken, expectedClaimToken) {
				t.Fatalf("claim_token mismatch:\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(claimToken), vec.ClaimToken)
			}

			// Step 3: Verify claim_hash = base64url(SHA-256(claim_token))
			claimHashRaw := sha256.Sum256(claimToken)
			gotClaimHash := base64.RawURLEncoding.EncodeToString(claimHashRaw[:])
			if gotClaimHash != vec.ClaimHash {
				t.Fatalf("claim_hash mismatch:\n  got:  %s\n  want: %s", gotClaimHash, vec.ClaimHash)
			}

			// Step 4: Decrypt and verify plaintext
			nonce := b64decode(t, vec.Envelope.Enc.Nonce)
			if len(nonce) != 12 {
				t.Fatalf("nonce length: got %d, want 12", len(nonce))
			}

			ciphertext := b64decode(t, vec.Envelope.Enc.Ciphertext)
			if len(ciphertext) < 16 {
				t.Fatalf("ciphertext too short: %d bytes (need at least 16 for GCM tag)", len(ciphertext))
			}

			block, err := aes.NewCipher(encKey)
			if err != nil {
				t.Fatalf("AES cipher: %v", err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatalf("GCM: %v", err)
			}

			plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(aad))
			if err != nil {
				t.Fatalf("GCM decrypt: %v", err)
			}

			if !bytesEqual(plaintext, expectedPlaintext) {
				t.Fatalf("plaintext mismatch:\n  got:  %x\n  want: %x", plaintext, expectedPlaintext)
			}
		})
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
