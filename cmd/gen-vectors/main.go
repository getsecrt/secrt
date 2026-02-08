// Command gen-vectors generates envelope.vectors.json from fixed inputs
// using the exact crypto workflow defined in spec/v1/envelope.md.
//
// Usage: go run ./cmd/gen-vectors > spec/v1/envelope.vectors.json
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// b64 encodes bytes as base64url without padding.
func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// hexToBytes parses a hex string to bytes (for fixed test inputs).
func hexToBytes(h string) []byte {
	b := make([]byte, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		fmt.Sscanf(h[i:i+2], "%02x", &b[i/2])
	}
	return b
}

const (
	aad          = "secrt.ca/envelope/v1"
	hkdfInfoEnc  = "secret:v1:enc"
	hkdfInfoClaim = "secret:v1:claim"
)

type vectorInput struct {
	description string
	urlKey      []byte // 32 bytes
	hkdfSalt    []byte // 32 bytes
	nonce       []byte // 12 bytes
	plaintext   []byte
	passphrase  *string // nil = no passphrase
	kdfSalt     []byte  // 16+ bytes, only if passphrase
	kdfIter     int     // only if passphrase
	hint        map[string]string // optional hint metadata
}

type envelope struct {
	V     int         `json:"v"`
	Suite string      `json:"suite"`
	Enc   encBlock    `json:"enc"`
	KDF   interface{} `json:"kdf"`
	HKDF  hkdfBlock   `json:"hkdf"`
	Hint  map[string]string `json:"hint,omitempty"`
}

type encBlock struct {
	Alg        string `json:"alg"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type hkdfBlock struct {
	Hash      string `json:"hash"`
	Salt      string `json:"salt"`
	EncInfo   string `json:"enc_info"`
	ClaimInfo string `json:"claim_info"`
	Length    int    `json:"length"`
}

type kdfNone struct {
	Name string `json:"name"`
}

type kdfPBKDF2 struct {
	Name       string `json:"name"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	Length     int    `json:"length"`
}

type vector struct {
	Description        string      `json:"description"`
	URLKey             string      `json:"url_key"`
	Plaintext          string      `json:"plaintext"`
	PlaintextUTF8      *string     `json:"plaintext_utf8,omitempty"`
	Passphrase         *string     `json:"passphrase"`
	IKM                string      `json:"ikm"`
	EncKey             string      `json:"enc_key"`
	ClaimToken         string      `json:"claim_token"`
	ClaimHash          string      `json:"claim_hash"`
	Envelope           envelope    `json:"envelope"`
}

type vectorsFile struct {
	Description string   `json:"_description"`
	Spec        string   `json:"_spec"`
	AAD         string   `json:"aad"`
	HKDFInfoEnc string   `json:"hkdf_info_enc"`
	HKDFInfoClaim string `json:"hkdf_info_claim"`
	Vectors     []vector `json:"vectors"`
}

func deriveHKDF(ikm, salt []byte, info string, length int) []byte {
	r := hkdf.New(sha256.New, ikm, salt, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err)
	}
	return out
}

func encrypt(key, nonce, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm.Seal(nil, nonce, plaintext, []byte(aad))
}

func generateVector(input vectorInput) vector {
	// Step 1: Compute IKM
	var ikm []byte
	var kdf interface{}

	if input.passphrase == nil {
		// No passphrase: ikm = url_key
		ikm = input.urlKey
		kdf = kdfNone{Name: "none"}
	} else {
		// With passphrase:
		// pass_key = PBKDF2-HMAC-SHA-256(passphrase_utf8, kdf.salt, iterations, 32)
		passKey := pbkdf2.Key([]byte(*input.passphrase), input.kdfSalt, input.kdfIter, 32, sha256.New)
		// ikm = SHA-256(url_key || pass_key)
		h := sha256.New()
		h.Write(input.urlKey)
		h.Write(passKey)
		ikm = h.Sum(nil)
		kdf = kdfPBKDF2{
			Name:       "PBKDF2-SHA256",
			Salt:       b64(input.kdfSalt),
			Iterations: input.kdfIter,
			Length:     32,
		}
	}

	// Step 2: Derive enc_key (from ikm + hkdf.salt) and claim_token (from url_key alone)
	encKey := deriveHKDF(ikm, input.hkdfSalt, hkdfInfoEnc, 32)
	claimToken := deriveHKDF(input.urlKey, nil, hkdfInfoClaim, 32)

	// Step 3: Compute claim_hash = base64url(SHA-256(claim_token_bytes))
	claimHashRaw := sha256.Sum256(claimToken)

	// Step 4: Encrypt
	ciphertext := encrypt(encKey, input.nonce, input.plaintext)

	// Step 5: Build envelope
	env := envelope{
		V:     1,
		Suite: "v1-pbkdf2-hkdf-aes256gcm",
		Enc: encBlock{
			Alg:        "A256GCM",
			Nonce:      b64(input.nonce),
			Ciphertext: b64(ciphertext),
		},
		KDF: kdf,
		HKDF: hkdfBlock{
			Hash:      "SHA-256",
			Salt:      b64(input.hkdfSalt),
			EncInfo:   hkdfInfoEnc,
			ClaimInfo: hkdfInfoClaim,
			Length:    32,
		},
		Hint: input.hint,
	}

	// Build vector
	v := vector{
		Description:  input.description,
		URLKey:       b64(input.urlKey),
		Plaintext:    b64(input.plaintext),
		Passphrase:   input.passphrase,
		IKM:          b64(ikm),
		EncKey:       b64(encKey),
		ClaimToken:   b64(claimToken),
		ClaimHash:    b64(claimHashRaw[:]),
		Envelope:     env,
	}

	// Add plaintext_utf8 if it's valid UTF-8 text
	s := string(input.plaintext)
	v.PlaintextUTF8 = &s

	return v
}

func main() {
	// Fixed test inputs — deterministic, not random.
	// Each set of bytes is chosen to be distinct and easy to identify.

	pass1 := "correct horse battery staple"
	pass2 := "hunter2"

	vectors := []vectorInput{
		{
			description: "simple text, no passphrase",
			urlKey:      hexToBytes("0102030405060708091011121314151617181920212223242526272829303132"),
			hkdfSalt:    hexToBytes("a1a2a3a4a5a6a7a8a9b0b1b2b3b4b5b6b7b8b9c0c1c2c3c4c5c6c7c8c9d0d1d2"),
			nonce:       hexToBytes("f0f1f2f3f4f5f6f7f8f9fafb"),
			plaintext:   []byte("hello, world"),
		},
		{
			description: "text with passphrase (PBKDF2, 600000 iterations)",
			urlKey:      hexToBytes("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"),
			hkdfSalt:    hexToBytes("1111111111111111111111111111111122222222222222222222222222222222"),
			nonce:       hexToBytes("deadbeefcafebabe12345678"),
			plaintext:   []byte("secret passphrase-protected message"),
			passphrase:  &pass1,
			kdfSalt:     hexToBytes("ccccccccccccccccdddddddddddddddd"),
			kdfIter:     600000,
		},
		{
			description: "binary payload, no passphrase",
			urlKey:      hexToBytes("ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00"),
			hkdfSalt:    hexToBytes("0000000000000000000000000000000011111111111111111111111111111111"),
			nonce:       hexToBytes("aabbccddeeff00112233aabb"),
			plaintext:   hexToBytes("00010203040506070809ff"),
		},
		{
			description: "minimal plaintext (1 byte), no passphrase",
			urlKey:      hexToBytes("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
			hkdfSalt:    hexToBytes("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"),
			nonce:       hexToBytes("010203040506070809101112"),
			plaintext:   []byte("x"),
		},
		{
			description: "passphrase with minimum iterations (300000)",
			urlKey:      hexToBytes("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			hkdfSalt:    hexToBytes("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
			nonce:       hexToBytes("112233445566778899001122"),
			plaintext:   []byte("minimum iterations test"),
			passphrase:  &pass2,
			kdfSalt:     hexToBytes("eeeeeeeeeeeeeeeeffffffffffffffff"),
			kdfIter:     300000,
		},
		{
			description: "text with hint metadata, no passphrase",
			urlKey:      hexToBytes("5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344"),
			hkdfSalt:    hexToBytes("99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa"),
			nonce:       hexToBytes("a0b1c2d3e4f506172839a0b1"),
			plaintext:   []byte("DB_PASSWORD=s3cret_v4lue"),
			hint: map[string]string{
				"type": "text",
				"mime": "text/plain",
				"filename": "credentials.txt",
			},
		},
		{
			description: "unicode plaintext with passphrase",
			urlKey:      hexToBytes("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
			hkdfSalt:    hexToBytes("d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"),
			nonce:       hexToBytes("c0c1c2c3c4c5c6c7c8c9cacb"),
			plaintext:   []byte("こんにちは世界 🌍"),
			passphrase:  &pass1,
			kdfSalt:     hexToBytes("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"),
			kdfIter:     600000,
		},
	}

	// For the binary payload, don't set plaintext_utf8
	results := make([]vector, len(vectors))
	for i, input := range vectors {
		results[i] = generateVector(input)
	}

	// Clear plaintext_utf8 for binary payload (index 2)
	results[2].PlaintextUTF8 = nil

	output := vectorsFile{
		Description:   "Interoperability test vectors for secrt.ca envelope v1 crypto. Generated by cmd/gen-vectors.",
		Spec:          "spec/v1/envelope.md",
		AAD:           aad,
		HKDFInfoEnc:   hkdfInfoEnc,
		HKDFInfoClaim: hkdfInfoClaim,
		Vectors:       results,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "json encode: %v\n", err)
		os.Exit(1)
	}
}
