package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"testing"
)

// vectorsFile matches the structure of spec/v1/envelope.vectors.json.
type vectorsFile struct {
	Vectors []testVector `json:"vectors"`
}

type testVector struct {
	Description string          `json:"description"`
	URLKey      string          `json:"url_key"`
	Plaintext   string          `json:"plaintext"`
	Passphrase  *string         `json:"passphrase"`
	IKM         string          `json:"ikm"`
	EncKey      string          `json:"enc_key"`
	ClaimToken  string          `json:"claim_token"`
	ClaimHash   string          `json:"claim_hash"`
	Envelope    json.RawMessage `json:"envelope"`
}

func loadVectors(t *testing.T) vectorsFile {
	t.Helper()
	data, err := os.ReadFile("../../spec/v1/envelope.vectors.json")
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
	return vf
}

func b64dec(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("b64 decode %q: %v", s, err)
	}
	return b
}

// deterministicReader provides deterministic bytes for Seal tests.
// For no-passphrase vectors, read order: url_key(32) + hkdf_salt(32) + nonce(12)
// For passphrase vectors, read order: url_key(32) + kdf_salt(16) + hkdf_salt(32) + nonce(12)
type deterministicReader struct {
	data []byte
	pos  int
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// vectorEnvelope is a minimal struct for extracting fields from vectors.
type vectorEnvelope struct {
	KDF struct {
		Name       string `json:"name"`
		Salt       string `json:"salt,omitempty"`
		Iterations int    `json:"iterations,omitempty"`
	} `json:"kdf"`
	HKDF struct {
		Salt string `json:"salt"`
	} `json:"hkdf"`
	Enc struct {
		Nonce string `json:"nonce"`
	} `json:"enc"`
	Hint map[string]string `json:"hint,omitempty"`
}

func buildDeterministicRand(t *testing.T, vec testVector) io.Reader {
	t.Helper()

	var ve vectorEnvelope
	if err := json.Unmarshal(vec.Envelope, &ve); err != nil {
		t.Fatalf("parse vector envelope: %v", err)
	}

	urlKey := b64dec(t, vec.URLKey)
	hkdfSalt := b64dec(t, ve.HKDF.Salt)
	nonce := b64dec(t, ve.Enc.Nonce)

	var data []byte
	data = append(data, urlKey...)

	if vec.Passphrase != nil {
		kdfSalt := b64dec(t, ve.KDF.Salt)
		data = append(data, kdfSalt...)
	}

	data = append(data, hkdfSalt...)
	data = append(data, nonce...)

	return &deterministicReader{data: data}
}

func TestSeal_Vectors(t *testing.T) {
	t.Parallel()
	vf := loadVectors(t)

	for _, vec := range vf.Vectors {
		t.Run(vec.Description, func(t *testing.T) {
			t.Parallel()

			passphrase := ""
			if vec.Passphrase != nil {
				passphrase = *vec.Passphrase
			}

			// Extract hint and iterations from vector envelope
			var ve2 vectorEnvelope
			if err := json.Unmarshal(vec.Envelope, &ve2); err != nil {
				t.Fatalf("parse vector envelope for hint: %v", err)
			}

			r := buildDeterministicRand(t, vec)
			result, err := Seal(SealParams{
				Plaintext:  b64dec(t, vec.Plaintext),
				Passphrase: passphrase,
				Rand:       r,
				Hint:       ve2.Hint,
				Iterations: ve2.KDF.Iterations,
			})
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}

			// Verify URL key
			if !bytes.Equal(result.URLKey, b64dec(t, vec.URLKey)) {
				t.Errorf("URLKey mismatch")
			}

			// Verify claim token
			if !bytes.Equal(result.ClaimToken, b64dec(t, vec.ClaimToken)) {
				t.Errorf("ClaimToken mismatch:\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(result.ClaimToken), vec.ClaimToken)
			}

			// Verify claim hash
			if result.ClaimHash != vec.ClaimHash {
				t.Errorf("ClaimHash mismatch:\n  got:  %s\n  want: %s", result.ClaimHash, vec.ClaimHash)
			}

			// Verify envelope produces same ciphertext by decrypting it
			plaintext, err := Open(OpenParams{
				Envelope:   result.Envelope,
				URLKey:     result.URLKey,
				Passphrase: passphrase,
			})
			if err != nil {
				t.Fatalf("Open(sealed): %v", err)
			}
			if !bytes.Equal(plaintext, b64dec(t, vec.Plaintext)) {
				t.Errorf("round-trip plaintext mismatch")
			}

			// Verify envelope matches expected structure
			var gotEnv, wantEnv map[string]interface{}
			if err := json.Unmarshal(result.Envelope, &gotEnv); err != nil {
				t.Fatalf("parse got envelope: %v", err)
			}
			if err := json.Unmarshal(vec.Envelope, &wantEnv); err != nil {
				t.Fatalf("parse want envelope: %v", err)
			}

			// Compare serialized forms (canonical JSON comparison)
			gotJSON, _ := json.Marshal(gotEnv)
			wantJSON, _ := json.Marshal(wantEnv)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("envelope JSON mismatch:\n  got:  %s\n  want: %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestOpen_Vectors(t *testing.T) {
	t.Parallel()
	vf := loadVectors(t)

	for _, vec := range vf.Vectors {
		t.Run(vec.Description, func(t *testing.T) {
			t.Parallel()

			passphrase := ""
			if vec.Passphrase != nil {
				passphrase = *vec.Passphrase
			}

			plaintext, err := Open(OpenParams{
				Envelope:   vec.Envelope,
				URLKey:     b64dec(t, vec.URLKey),
				Passphrase: passphrase,
			})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}

			expected := b64dec(t, vec.Plaintext)
			if !bytes.Equal(plaintext, expected) {
				t.Errorf("plaintext mismatch:\n  got:  %x\n  want: %x", plaintext, expected)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		plaintext  []byte
		passphrase string
	}{
		{"no passphrase", []byte("hello, world"), ""},
		{"with passphrase", []byte("secret message"), "mypassword123"},
		{"binary data", []byte{0, 1, 2, 255, 254, 253}, ""},
		{"unicode", []byte("こんにちは 🌍"), "パスワード"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := Seal(SealParams{
				Plaintext:  tt.plaintext,
				Passphrase: tt.passphrase,
			})
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}

			plaintext, err := Open(OpenParams{
				Envelope:   result.Envelope,
				URLKey:     result.URLKey,
				Passphrase: tt.passphrase,
			})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}

			if !bytes.Equal(plaintext, tt.plaintext) {
				t.Errorf("plaintext mismatch:\n  got:  %x\n  want: %x", plaintext, tt.plaintext)
			}
		})
	}
}

func TestDeriveClaimToken(t *testing.T) {
	t.Parallel()
	vf := loadVectors(t)

	for _, vec := range vf.Vectors {
		t.Run(vec.Description, func(t *testing.T) {
			t.Parallel()

			urlKey := b64dec(t, vec.URLKey)
			ct, err := DeriveClaimToken(urlKey)
			if err != nil {
				t.Fatalf("DeriveClaimToken: %v", err)
			}

			expected := b64dec(t, vec.ClaimToken)
			if !bytes.Equal(ct, expected) {
				t.Errorf("claim_token mismatch:\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(ct), vec.ClaimToken)
			}
		})
	}
}

func TestDeriveClaimToken_InvalidKey(t *testing.T) {
	t.Parallel()
	_, err := DeriveClaimToken([]byte("short"))
	if err != ErrInvalidURLKey {
		t.Errorf("expected ErrInvalidURLKey, got: %v", err)
	}
}

func TestComputeClaimHash(t *testing.T) {
	t.Parallel()
	vf := loadVectors(t)

	for _, vec := range vf.Vectors {
		t.Run(vec.Description, func(t *testing.T) {
			t.Parallel()

			claimToken := b64dec(t, vec.ClaimToken)
			got := ComputeClaimHash(claimToken)
			if got != vec.ClaimHash {
				t.Errorf("claim_hash mismatch:\n  got:  %s\n  want: %s", got, vec.ClaimHash)
			}

			// Also verify directly: base64url(SHA-256(claim_token))
			h := sha256.Sum256(claimToken)
			expected := base64.RawURLEncoding.EncodeToString(h[:])
			if got != expected {
				t.Errorf("claim_hash doesn't match SHA-256:\n  got:  %s\n  want: %s", got, expected)
			}
		})
	}
}

func TestSeal_RejectsEmpty(t *testing.T) {
	t.Parallel()
	_, err := Seal(SealParams{Plaintext: nil})
	if err != ErrEmptyPlaintext {
		t.Errorf("expected ErrEmptyPlaintext, got: %v", err)
	}
	_, err = Seal(SealParams{Plaintext: []byte{}})
	if err != ErrEmptyPlaintext {
		t.Errorf("expected ErrEmptyPlaintext for empty slice, got: %v", err)
	}
}

func TestOpen_WrongPassphrase(t *testing.T) {
	t.Parallel()

	result, err := Seal(SealParams{
		Plaintext:  []byte("secret"),
		Passphrase: "correct",
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	_, err = Open(OpenParams{
		Envelope:   result.Envelope,
		URLKey:     result.URLKey,
		Passphrase: "wrong",
	})
	if err != ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestOpen_TamperedCiphertext(t *testing.T) {
	t.Parallel()

	result, err := Seal(SealParams{Plaintext: []byte("secret")})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Tamper with ciphertext in the envelope
	var env Envelope
	if err := json.Unmarshal(result.Envelope, &env); err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	ct, _ := b64Decode(env.Enc.Ciphertext)
	ct[0] ^= 0xff // flip a byte
	env.Enc.Ciphertext = b64Encode(ct)
	tampered, _ := json.Marshal(env)

	_, err = Open(OpenParams{
		Envelope: tampered,
		URLKey:   result.URLKey,
	})
	if err != ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestOpen_InvalidEnvelope(t *testing.T) {
	t.Parallel()

	urlKey := make([]byte, 32)

	tests := []struct {
		name     string
		envelope string
	}{
		{"wrong version", `{"v":2,"suite":"v1-pbkdf2-hkdf-aes256gcm","enc":{"alg":"A256GCM","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA"},"kdf":{"name":"none"},"hkdf":{"hash":"SHA-256","salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enc_info":"secret:v1:enc","claim_info":"secret:v1:claim","length":32}}`},
		{"wrong suite", `{"v":1,"suite":"v2-something","enc":{"alg":"A256GCM","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA"},"kdf":{"name":"none"},"hkdf":{"hash":"SHA-256","salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enc_info":"secret:v1:enc","claim_info":"secret:v1:claim","length":32}}`},
		{"wrong enc.alg", `{"v":1,"suite":"v1-pbkdf2-hkdf-aes256gcm","enc":{"alg":"ChaCha20","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA"},"kdf":{"name":"none"},"hkdf":{"hash":"SHA-256","salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enc_info":"secret:v1:enc","claim_info":"secret:v1:claim","length":32}}`},
		{"bad nonce length", `{"v":1,"suite":"v1-pbkdf2-hkdf-aes256gcm","enc":{"alg":"A256GCM","nonce":"AAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA"},"kdf":{"name":"none"},"hkdf":{"hash":"SHA-256","salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enc_info":"secret:v1:enc","claim_info":"secret:v1:claim","length":32}}`},
		{"ciphertext too short", `{"v":1,"suite":"v1-pbkdf2-hkdf-aes256gcm","enc":{"alg":"A256GCM","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAA"},"kdf":{"name":"none"},"hkdf":{"hash":"SHA-256","salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enc_info":"secret:v1:enc","claim_info":"secret:v1:claim","length":32}}`},
		{"unknown kdf", `{"v":1,"suite":"v1-pbkdf2-hkdf-aes256gcm","enc":{"alg":"A256GCM","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA"},"kdf":{"name":"scrypt"},"hkdf":{"hash":"SHA-256","salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enc_info":"secret:v1:enc","claim_info":"secret:v1:claim","length":32}}`},
		{"pbkdf2 low iterations", `{"v":1,"suite":"v1-pbkdf2-hkdf-aes256gcm","enc":{"alg":"A256GCM","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA"},"kdf":{"name":"PBKDF2-SHA256","salt":"AAAAAAAAAAAAAAAAAAAAAA","iterations":1000,"length":32},"hkdf":{"hash":"SHA-256","salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enc_info":"secret:v1:enc","claim_info":"secret:v1:claim","length":32}}`},
		{"invalid JSON", `not json`},
		{"wrong hkdf.hash", `{"v":1,"suite":"v1-pbkdf2-hkdf-aes256gcm","enc":{"alg":"A256GCM","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA"},"kdf":{"name":"none"},"hkdf":{"hash":"SHA-512","salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enc_info":"secret:v1:enc","claim_info":"secret:v1:claim","length":32}}`},
		{"wrong hkdf.length", `{"v":1,"suite":"v1-pbkdf2-hkdf-aes256gcm","enc":{"alg":"A256GCM","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA"},"kdf":{"name":"none"},"hkdf":{"hash":"SHA-256","salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enc_info":"secret:v1:enc","claim_info":"secret:v1:claim","length":16}}`},
		{"wrong hkdf.enc_info", `{"v":1,"suite":"v1-pbkdf2-hkdf-aes256gcm","enc":{"alg":"A256GCM","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA"},"kdf":{"name":"none"},"hkdf":{"hash":"SHA-256","salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enc_info":"wrong","claim_info":"secret:v1:claim","length":32}}`},
		{"wrong hkdf.claim_info", `{"v":1,"suite":"v1-pbkdf2-hkdf-aes256gcm","enc":{"alg":"A256GCM","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA"},"kdf":{"name":"none"},"hkdf":{"hash":"SHA-256","salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enc_info":"secret:v1:enc","claim_info":"wrong","length":32}}`},
		{"pbkdf2 wrong kdf.length", `{"v":1,"suite":"v1-pbkdf2-hkdf-aes256gcm","enc":{"alg":"A256GCM","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA"},"kdf":{"name":"PBKDF2-SHA256","salt":"AAAAAAAAAAAAAAAAAAAAAA","iterations":600000,"length":16},"hkdf":{"hash":"SHA-256","salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enc_info":"secret:v1:enc","claim_info":"secret:v1:claim","length":32}}`},
		{"pbkdf2 short kdf.salt", `{"v":1,"suite":"v1-pbkdf2-hkdf-aes256gcm","enc":{"alg":"A256GCM","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA"},"kdf":{"name":"PBKDF2-SHA256","salt":"AAAA","iterations":600000,"length":32},"hkdf":{"hash":"SHA-256","salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enc_info":"secret:v1:enc","claim_info":"secret:v1:claim","length":32}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Open(OpenParams{
				Envelope: json.RawMessage(tt.envelope),
				URLKey:   urlKey,
			})
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestOpen_InvalidURLKey(t *testing.T) {
	t.Parallel()

	result, err := Seal(SealParams{Plaintext: []byte("test")})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	_, err = Open(OpenParams{
		Envelope: result.Envelope,
		URLKey:   []byte("short"),
	})
	if err != ErrInvalidURLKey {
		t.Errorf("expected ErrInvalidURLKey, got: %v", err)
	}
}

func TestParseShareURL(t *testing.T) {
	t.Parallel()

	// Create a known url_key for testing
	urlKey := make([]byte, 32)
	for i := range urlKey {
		urlKey[i] = byte(i + 1)
	}
	keyB64 := base64.RawURLEncoding.EncodeToString(urlKey)

	tests := []struct {
		name    string
		input   string
		wantID  string
		wantKey []byte
		wantErr bool
	}{
		{
			"full URL",
			"https://secrt.ca/s/abc123#v1." + keyB64,
			"abc123", urlKey, false,
		},
		{
			"full URL with base64url ID",
			"https://secrt.ca/s/Xy_Z-abc#v1." + keyB64,
			"Xy_Z-abc", urlKey, false,
		},
		{
			"missing fragment",
			"https://secrt.ca/s/abc123",
			"", nil, true,
		},
		{
			"wrong fragment prefix",
			"https://secrt.ca/s/abc123#v2." + keyB64,
			"", nil, true,
		},
		{
			"no /s/ path",
			"https://secrt.ca/other/abc123#v1." + keyB64,
			"", nil, true,
		},
		{
			"bad url_key encoding",
			"https://secrt.ca/s/abc123#v1.!!!invalid!!!",
			"", nil, true,
		},
		{
			"url_key wrong length",
			"https://secrt.ca/s/abc123#v1.AAAA",
			"", nil, true,
		},
		{
			"bare ID with fragment",
			"abc123#v1." + keyB64,
			"abc123", urlKey, false,
		},
		{
			"empty input",
			"",
			"", nil, true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			id, key, err := ParseShareURL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id != tt.wantID {
				t.Errorf("id: got %q, want %q", id, tt.wantID)
			}
			if !bytes.Equal(key, tt.wantKey) {
				t.Errorf("urlKey mismatch")
			}
		})
	}
}

func TestFormatShareLink(t *testing.T) {
	t.Parallel()

	urlKey := make([]byte, 32)
	for i := range urlKey {
		urlKey[i] = byte(i + 1)
	}
	keyB64 := base64.RawURLEncoding.EncodeToString(urlKey)

	got := FormatShareLink("https://secrt.ca/s/abc123", urlKey)
	want := "https://secrt.ca/s/abc123#v1." + keyB64
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSeal_HintMetadata(t *testing.T) {
	t.Parallel()

	hint := map[string]string{
		"type":     "file",
		"mime":     "text/plain",
		"filename": "test.txt",
	}

	result, err := Seal(SealParams{
		Plaintext: []byte("hello"),
		Hint:      hint,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var env Envelope
	if err := json.Unmarshal(result.Envelope, &env); err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	if env.Hint["type"] != "file" {
		t.Errorf("hint.type: got %q, want %q", env.Hint["type"], "file")
	}
	if env.Hint["mime"] != "text/plain" {
		t.Errorf("hint.mime: got %q, want %q", env.Hint["mime"], "text/plain")
	}
	if env.Hint["filename"] != "test.txt" {
		t.Errorf("hint.filename: got %q, want %q", env.Hint["filename"], "test.txt")
	}

	// Decrypt should still work with hint
	plaintext, err := Open(OpenParams{
		Envelope: result.Envelope,
		URLKey:   result.URLKey,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(plaintext) != "hello" {
		t.Errorf("plaintext: got %q, want %q", plaintext, "hello")
	}
}
