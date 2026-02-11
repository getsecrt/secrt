// Package envelope implements the client-side crypto workflow for secrt.ca v1.
//
// It provides Seal (encrypt), Open (decrypt), key derivation, claim token/hash
// computation, URL fragment parsing, and TTL parsing. All operations are pure
// (no I/O, no network) and safe for concurrent use.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// Crypto constants from spec/v1/envelope.md.
const (
	URLKeyLen     = 32
	PassKeyLen    = 32
	HKDFLen       = 32
	GCMNonceLen   = 12
	HKDFSaltLen   = 32
	KDFSaltLen    = 16
	AAD           = "secrt.ca/envelope/v1"
	HKDFInfoEnc   = "secret:v1:enc"
	HKDFInfoClaim = "secret:v1:claim"
	Suite         = "v1-pbkdf2-hkdf-aes256gcm"

	DefaultPBKDF2Iterations = 600000
	MinPBKDF2Iterations     = 300000
)

// Errors returned by envelope operations.
var (
	ErrEmptyPlaintext   = errors.New("plaintext must not be empty")
	ErrInvalidEnvelope  = errors.New("invalid envelope")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrInvalidFragment  = errors.New("invalid URL fragment")
	ErrInvalidURLKey    = errors.New("url_key must be 32 bytes")
)

// Envelope is the JSON structure stored on the server.
type Envelope struct {
	V     int               `json:"v"`
	Suite string            `json:"suite"`
	Enc   EncBlock          `json:"enc"`
	KDF   json.RawMessage   `json:"kdf"`
	HKDF  HKDFBlock         `json:"hkdf"`
	Hint  map[string]string `json:"hint,omitempty"`
}

// EncBlock holds the AES-GCM ciphertext.
type EncBlock struct {
	Alg        string `json:"alg"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// HKDFBlock holds the HKDF parameters.
type HKDFBlock struct {
	Hash      string `json:"hash"`
	Salt      string `json:"salt"`
	EncInfo   string `json:"enc_info"`
	ClaimInfo string `json:"claim_info"`
	Length    int    `json:"length"`
}

// KDFNone is the KDF block when no passphrase is used.
type KDFNone struct {
	Name string `json:"name"`
}

// KDFPBKDF2 is the KDF block when a passphrase is used.
type KDFPBKDF2 struct {
	Name       string `json:"name"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	Length     int    `json:"length"`
}

// kdfParsed is the internal representation after parsing KDF JSON.
type kdfParsed struct {
	Name       string
	Salt       []byte
	Iterations int
}

// SealParams holds inputs for creating an encrypted envelope.
type SealParams struct {
	Plaintext  []byte
	Passphrase string            // empty = no passphrase
	Rand       io.Reader         // nil = crypto/rand.Reader
	Hint       map[string]string // optional hint metadata
	Iterations int               // PBKDF2 iterations; 0 = DefaultPBKDF2Iterations
}

// SealResult holds outputs from creating an encrypted envelope.
type SealResult struct {
	Envelope   json.RawMessage // envelope JSON
	URLKey     []byte          // 32-byte URL key (for share link fragment)
	ClaimToken []byte          // 32-byte claim token
	ClaimHash  string          // base64url(SHA-256(claim_token))
}

// OpenParams holds inputs for decrypting an envelope.
type OpenParams struct {
	Envelope   json.RawMessage // envelope JSON from server
	URLKey     []byte          // 32-byte URL key from share link
	Passphrase string          // empty = no passphrase
}

func rng(r io.Reader) io.Reader {
	if r != nil {
		return r
	}
	return rand.Reader
}

func readRand(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return buf, nil
}

func b64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func b64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func deriveHKDF(ikm, salt []byte, info string, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("HKDF derive: %w", err)
	}
	return out, nil
}

// DeriveClaimToken derives a claim token from url_key alone.
// claim_token = HKDF-SHA-256(url_key, nil, "secret:v1:claim", 32)
func DeriveClaimToken(urlKey []byte) ([]byte, error) {
	if len(urlKey) != URLKeyLen {
		return nil, ErrInvalidURLKey
	}
	return deriveHKDF(urlKey, nil, HKDFInfoClaim, HKDFLen)
}

// ComputeClaimHash returns base64url(SHA-256(claim_token)).
func ComputeClaimHash(claimToken []byte) string {
	h := sha256.Sum256(claimToken)
	return b64Encode(h[:])
}

// Seal creates an encrypted envelope from plaintext.
func Seal(p SealParams) (SealResult, error) {
	if len(p.Plaintext) == 0 {
		return SealResult{}, ErrEmptyPlaintext
	}

	r := rng(p.Rand)

	// 1. Generate url_key
	urlKey, err := readRand(r, URLKeyLen)
	if err != nil {
		return SealResult{}, err
	}

	// 2. Build KDF + compute IKM
	var ikm []byte
	var kdfJSON json.RawMessage

	if p.Passphrase == "" {
		ikm = urlKey
		kdfJSON, err = json.Marshal(KDFNone{Name: "none"})
		if err != nil {
			return SealResult{}, err
		}
	} else {
		kdfSalt, err := readRand(r, KDFSaltLen)
		if err != nil {
			return SealResult{}, err
		}
		iterations := p.Iterations
		if iterations == 0 {
			iterations = DefaultPBKDF2Iterations
		}
		passKey := pbkdf2.Key([]byte(p.Passphrase), kdfSalt, iterations, PassKeyLen, sha256.New)
		h := sha256.New()
		h.Write(urlKey)
		h.Write(passKey)
		ikm = h.Sum(nil)
		kdfJSON, err = json.Marshal(KDFPBKDF2{
			Name:       "PBKDF2-SHA256",
			Salt:       b64Encode(kdfSalt),
			Iterations: iterations,
			Length:     PassKeyLen,
		})
		if err != nil {
			return SealResult{}, err
		}
	}

	// 3. Generate HKDF salt
	hkdfSalt, err := readRand(r, HKDFSaltLen)
	if err != nil {
		return SealResult{}, err
	}

	// 4. Derive enc_key
	encKey, err := deriveHKDF(ikm, hkdfSalt, HKDFInfoEnc, HKDFLen)
	if err != nil {
		return SealResult{}, err
	}

	// 5. Derive claim_token (from url_key alone)
	claimToken, err := DeriveClaimToken(urlKey)
	if err != nil {
		return SealResult{}, err
	}

	// 6. Generate nonce
	nonce, err := readRand(r, GCMNonceLen)
	if err != nil {
		return SealResult{}, err
	}

	// 7. Encrypt
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return SealResult{}, fmt.Errorf("AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return SealResult{}, fmt.Errorf("GCM: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, p.Plaintext, []byte(AAD))

	// 8. Build envelope
	env := Envelope{
		V:     1,
		Suite: Suite,
		Enc: EncBlock{
			Alg:        "A256GCM",
			Nonce:      b64Encode(nonce),
			Ciphertext: b64Encode(ciphertext),
		},
		KDF: kdfJSON,
		HKDF: HKDFBlock{
			Hash:      "SHA-256",
			Salt:      b64Encode(hkdfSalt),
			EncInfo:   HKDFInfoEnc,
			ClaimInfo: HKDFInfoClaim,
			Length:    HKDFLen,
		},
		Hint: p.Hint,
	}

	envJSON, err := json.Marshal(env)
	if err != nil {
		return SealResult{}, fmt.Errorf("marshal envelope: %w", err)
	}

	return SealResult{
		Envelope:   envJSON,
		URLKey:     urlKey,
		ClaimToken: claimToken,
		ClaimHash:  ComputeClaimHash(claimToken),
	}, nil
}

// Open decrypts an envelope, returning plaintext.
func Open(p OpenParams) ([]byte, error) {
	if len(p.URLKey) != URLKeyLen {
		return nil, ErrInvalidURLKey
	}

	// Parse envelope
	var env Envelope
	if err := json.Unmarshal(p.Envelope, &env); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
	}

	if err := validateEnvelope(&env); err != nil {
		return nil, err
	}

	// Parse KDF
	kdf, err := parseKDF(env.KDF)
	if err != nil {
		return nil, err
	}

	// Compute IKM
	var ikm []byte
	if kdf.Name == "none" {
		ikm = p.URLKey
	} else {
		passKey := pbkdf2.Key([]byte(p.Passphrase), kdf.Salt, kdf.Iterations, PassKeyLen, sha256.New)
		h := sha256.New()
		h.Write(p.URLKey)
		h.Write(passKey)
		ikm = h.Sum(nil)
	}

	// Derive enc_key
	hkdfSalt, err := b64Decode(env.HKDF.Salt)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hkdf.salt", ErrInvalidEnvelope)
	}
	encKey, err := deriveHKDF(ikm, hkdfSalt, HKDFInfoEnc, HKDFLen)
	if err != nil {
		return nil, err
	}

	// Decode nonce and ciphertext
	nonce, err := b64Decode(env.Enc.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid nonce", ErrInvalidEnvelope)
	}
	ciphertext, err := b64Decode(env.Enc.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ciphertext", ErrInvalidEnvelope)
	}

	// Decrypt
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(AAD))
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

func validateEnvelope(env *Envelope) error {
	if env.V != 1 {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidEnvelope, env.V)
	}
	if env.Suite != Suite {
		return fmt.Errorf("%w: unsupported suite %q", ErrInvalidEnvelope, env.Suite)
	}
	if env.Enc.Alg != "A256GCM" {
		return fmt.Errorf("%w: unsupported enc.alg %q", ErrInvalidEnvelope, env.Enc.Alg)
	}

	nonce, err := b64Decode(env.Enc.Nonce)
	if err != nil || len(nonce) != GCMNonceLen {
		return fmt.Errorf("%w: nonce must be %d bytes", ErrInvalidEnvelope, GCMNonceLen)
	}

	ct, err := b64Decode(env.Enc.Ciphertext)
	if err != nil || len(ct) < 16 {
		return fmt.Errorf("%w: ciphertext too short (need at least GCM tag)", ErrInvalidEnvelope)
	}

	if env.HKDF.Hash != "SHA-256" {
		return fmt.Errorf("%w: unsupported hkdf.hash %q", ErrInvalidEnvelope, env.HKDF.Hash)
	}
	hkdfSalt, err := b64Decode(env.HKDF.Salt)
	if err != nil || len(hkdfSalt) != HKDFSaltLen {
		return fmt.Errorf("%w: hkdf.salt must be %d bytes", ErrInvalidEnvelope, HKDFSaltLen)
	}
	if env.HKDF.EncInfo != HKDFInfoEnc {
		return fmt.Errorf("%w: invalid hkdf.enc_info", ErrInvalidEnvelope)
	}
	if env.HKDF.ClaimInfo != HKDFInfoClaim {
		return fmt.Errorf("%w: invalid hkdf.claim_info", ErrInvalidEnvelope)
	}
	if env.HKDF.Length != HKDFLen {
		return fmt.Errorf("%w: hkdf.length must be %d", ErrInvalidEnvelope, HKDFLen)
	}

	return nil
}

func parseKDF(raw json.RawMessage) (kdfParsed, error) {
	var probe struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return kdfParsed{}, fmt.Errorf("%w: invalid kdf", ErrInvalidEnvelope)
	}

	switch probe.Name {
	case "none":
		return kdfParsed{Name: "none"}, nil
	case "PBKDF2-SHA256":
		var k KDFPBKDF2
		if err := json.Unmarshal(raw, &k); err != nil {
			return kdfParsed{}, fmt.Errorf("%w: invalid kdf", ErrInvalidEnvelope)
		}
		salt, err := b64Decode(k.Salt)
		if err != nil || len(salt) < KDFSaltLen {
			return kdfParsed{}, fmt.Errorf("%w: kdf.salt must be at least %d bytes", ErrInvalidEnvelope, KDFSaltLen)
		}
		if k.Iterations < MinPBKDF2Iterations {
			return kdfParsed{}, fmt.Errorf("%w: kdf.iterations must be >= %d", ErrInvalidEnvelope, MinPBKDF2Iterations)
		}
		if k.Length != PassKeyLen {
			return kdfParsed{}, fmt.Errorf("%w: kdf.length must be %d", ErrInvalidEnvelope, PassKeyLen)
		}
		return kdfParsed{
			Name:       "PBKDF2-SHA256",
			Salt:       salt,
			Iterations: k.Iterations,
		}, nil
	default:
		return kdfParsed{}, fmt.Errorf("%w: unsupported kdf.name %q", ErrInvalidEnvelope, probe.Name)
	}
}

// ParseShareURL extracts id and url_key from a share URL with fragment.
// Accepts formats:
//   - https://host/s/<id>#<url_key_b64>
//   - <id>#<url_key_b64> (bare ID with fragment)
func ParseShareURL(rawURL string) (id string, urlKey []byte, err error) {
	// Try parsing as full URL
	u, parseErr := url.Parse(rawURL)
	if parseErr == nil && u.Scheme != "" {
		// Full URL: extract ID from path
		path := strings.TrimPrefix(u.Path, "/s/")
		if path == u.Path || path == "" {
			return "", nil, fmt.Errorf("%w: expected /s/<id> path", ErrInvalidFragment)
		}
		id = path
	} else {
		// Bare format: id#fragment
		parts := strings.SplitN(rawURL, "#", 2)
		if len(parts) != 2 || parts[0] == "" {
			return "", nil, fmt.Errorf("%w: missing fragment", ErrInvalidFragment)
		}
		id = parts[0]
		if u == nil {
			u = &url.URL{}
		}
		u.Fragment = parts[1]
	}

	// Parse fragment
	frag := u.Fragment
	if frag == "" {
		// url.Parse may strip fragment; try manual extraction
		if idx := strings.Index(rawURL, "#"); idx >= 0 {
			frag = rawURL[idx+1:]
		}
	}

	keyB64 := frag
	urlKey, err = b64Decode(keyB64)
	if err != nil {
		return "", nil, fmt.Errorf("%w: invalid url_key encoding", ErrInvalidFragment)
	}
	if len(urlKey) != URLKeyLen {
		return "", nil, fmt.Errorf("%w: url_key must be %d bytes, got %d", ErrInvalidFragment, URLKeyLen, len(urlKey))
	}

	return id, urlKey, nil
}

// FormatShareLink builds a share URL with fragment.
func FormatShareLink(shareURL string, urlKey []byte) string {
	return shareURL + "#" + b64Encode(urlKey)
}
