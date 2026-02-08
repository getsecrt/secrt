# Envelope Specification (v1)

Status: Draft v1 (normative for client interoperability once accepted)

This document defines the client-side envelope format and crypto workflow used by `secrt.ca`.

The server must treat `envelope` as opaque JSON and store/return it exactly once. The server must not need decryption keys.

## Why This Exists

We need one contract that both client types implement:

- Browser UI (future)
- CLI client (planned)

If both clients follow this spec and pass the same test vectors, they are interoperable even if implemented in different languages.

## Normative Language

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used as defined in RFC 2119.

## Security Model

- Plaintext encryption/decryption happens only in clients.
- The server stores ciphertext envelope + `claim_hash`.
- Decryption key material is carried in the URL fragment (not sent to server in normal HTTP requests).
- Optional passphrase/PIN is shared out-of-band and never included in API payloads.

## Encoding Rules

- Strings are UTF-8.
- Binary fields use base64url without padding (RFC 4648, URL-safe alphabet, no `=`).
- JSON field names are case-sensitive.
- Clients MUST reject malformed base64url.

## Cryptographic Suite (v1)

Required primitives:

- AES-256-GCM for authenticated encryption
- HKDF-SHA-256 for key expansion
- SHA-256 for `claim_hash`
- Optional passphrase KDF: PBKDF2-HMAC-SHA-256

Constants:

- `URL_KEY_LEN = 32` bytes
- `PASS_KEY_LEN = 32` bytes
- `HKDF_LEN = 32` bytes
- `GCM_NONCE_LEN = 12` bytes
- `AAD = "secrt.ca/envelope/v1"` (ASCII bytes)
- `HKDF_INFO_ENC = "secret:v1:enc"` (ASCII bytes)
- `HKDF_INFO_CLAIM = "secret:v1:claim"` (ASCII bytes)

## Envelope JSON Shape

`envelope` MUST be a JSON object with this structure:

```json
{
  "v": 1,
  "suite": "v1-pbkdf2-hkdf-aes256gcm",
  "enc": {
    "alg": "A256GCM",
    "nonce": "<base64url 12 bytes>",
    "ciphertext": "<base64url (ciphertext||tag)>"
  },
  "kdf": {
    "name": "none"
  },
  "hkdf": {
    "hash": "SHA-256",
    "salt": "<base64url 32 bytes>",
    "enc_info": "secret:v1:enc",
    "claim_info": "secret:v1:claim",
    "length": 32
  }
}
```

Clients MAY include optional advisory metadata for UX:

```json
{
  "hint": {
    "type": "file",
    "mime": "text/plain",
    "filename": "credentials.txt"
  }
}
```

If a passphrase is used, `kdf` MUST be:

```json
{
  "name": "PBKDF2-SHA256",
  "salt": "<base64url 16+ bytes>",
  "iterations": 600000,
  "length": 32
}
```

Field requirements:

- `v`: MUST be integer `1`.
- `suite`: MUST be exactly `v1-pbkdf2-hkdf-aes256gcm`.
- `enc.alg`: MUST be `A256GCM`.
- `enc.nonce`: MUST decode to 12 bytes.
- `enc.ciphertext`: MUST decode to at least 16 bytes (GCM tag).
- `kdf.name`: MUST be `none` or `PBKDF2-SHA256`.
- `hkdf.hash`: MUST be `SHA-256`.
- `hkdf.salt`: MUST decode to exactly 32 bytes.
- `hkdf.enc_info`: MUST be `secret:v1:enc`.
- `hkdf.claim_info`: MUST be `secret:v1:claim`.
- `hkdf.length`: MUST be `32`.

For `kdf.name == "PBKDF2-SHA256"`:

- `kdf.salt` MUST decode to >= 16 bytes (16 recommended minimum; 16 or 32 preferred).
- `kdf.iterations` MUST be >= 300000.
- `kdf.length` MUST be `32`.

For `kdf.name == "none"`:

- `kdf` MUST NOT include `salt`, `iterations`, or `length`.

For optional `hint` metadata:

- `hint` is optional and MAY be omitted entirely.
- `hint` fields are optional and MUST NOT affect key derivation, claim token derivation, or AEAD inputs.
- `hint` is advisory only and MUST NOT be used for authorization or other security decisions.
- Clients SHOULD sanitize `hint.filename` and `hint.mime` before display/use.
- If `hint.mime` is absent for file download UX, clients SHOULD default to `application/octet-stream`.

Unknown fields:

- Clients SHOULD ignore unknown fields for forward compatibility.
- Clients MUST validate all required fields strictly.

## URL Fragment Format

The shared link format is:

`https://<host>/s/<id>#v1.<url_key_b64>`

- `<url_key_b64>` MUST decode to exactly 32 random bytes.
- The fragment MUST NOT include passphrase/PIN.
- Passphrase/PIN, when used, MUST be shared via a separate channel.

## Claim Token Derivation

The claim token is derived from `url_key` alone, independent of passphrase and envelope contents:

`claim_token_bytes = HKDF-SHA-256(url_key, nil, "secret:v1:claim", 32)`

This separation ensures:

- **Claim authorization = link possession.** Anyone with the share URL can claim (consume) the secret.
- **Decryption = passphrase knowledge.** Only someone with the passphrase (when used) can decrypt the claimed envelope.
- **No circular dependency.** The claim token can be computed before the envelope is retrieved, since it does not depend on `hkdf.salt` (which is inside the envelope).

The claim hash sent during create is: `claim_hash = base64url(SHA-256(claim_token_bytes))`.

## Create Flow (Normative)

Inputs:

- Plaintext bytes (`plaintext`)
- Optional passphrase string (`passphrase`)

Steps:

1. Generate `url_key` as 32 random bytes.
2. Build `kdf`:
   - If no passphrase: `kdf.name = "none"`.
   - If passphrase is used:
     - Generate random `kdf.salt`.
     - Compute `pass_key = PBKDF2-HMAC-SHA-256(passphrase_utf8, kdf.salt, kdf.iterations, 32)`.
3. Build input keying material (`ikm`):
   - No passphrase: `ikm = url_key`.
   - With passphrase: `ikm = SHA-256(url_key || pass_key)`.
4. Generate random `hkdf.salt` (32 bytes).
5. Derive encryption key:
   - `enc_key = HKDF-SHA-256(ikm, hkdf.salt, "secret:v1:enc", 32)`
6. Derive claim token (from `url_key` alone, not `ikm`):
   - `claim_token_bytes = HKDF-SHA-256(url_key, nil, "secret:v1:claim", 32)`
7. Generate random `nonce` (12 bytes).
8. Encrypt:
   - `ciphertext = AES-256-GCM-Seal(enc_key, nonce, plaintext, AAD)`
   - `ciphertext` is encoded as a single byte string that includes GCM tag (`ciphertext||tag`).
9. Build envelope JSON with fields above.
   - Optional: include `hint` metadata for UX (`type`, `mime`, `filename`), if available.
10. Compute `claim_hash` for create API:
    - `claim_hash = base64url( SHA-256(claim_token_bytes) )`
11. Send API create request:
    - `envelope` (JSON object from step 8)
    - `claim_hash` (step 10)
12. Share:
    - URL with fragment `#v1.<base64url(url_key)>`
    - passphrase separately if used

## Claim + Decrypt Flow (Normative)

Inputs:

- URL fragment `#v1.<url_key_b64>`
- Optional passphrase

Steps:

1. Decode `url_key_b64` from fragment and enforce 32 bytes.
2. Derive claim token (from `url_key` alone):
   - `claim_token_bytes = HKDF-SHA-256(url_key, nil, "secret:v1:claim", 32)`
3. Claim API call:
   - `POST /api/v1/secrets/{id}/claim`
   - Body: `{ "claim": base64url(claim_token_bytes) }`
4. On `200`, parse and validate envelope fields from response.
5. Recompute `ikm` using the `kdf` params from the envelope:
   - No passphrase (`kdf.name == "none"`): `ikm = url_key`.
   - With passphrase (`kdf.name == "PBKDF2-SHA256"`): compute `pass_key`, then `ikm = SHA-256(url_key || pass_key)`.
6. Derive encryption key:
   - `enc_key = HKDF-SHA-256(ikm, hkdf.salt, "secret:v1:enc", 32)`
7. Decrypt:
   - `plaintext = AES-256-GCM-Open(enc_key, nonce, ciphertext, AAD)`
8. If decryption fails, treat as invalid link/passphrase or tampering.
9. Optional UX behavior:
   - If `hint` is present, clients MAY use it to choose display/download defaults.
   - If `hint.mime` is missing and bytes are downloaded as a file, use `application/octet-stream`.

## API Mapping

This spec maps to `spec/v1/api.md`:

- Create request:
  - `claim_hash = base64url(sha256(claim_token_bytes))`
- Claim request:
  - `claim = base64url(claim_token_bytes)`

Important:

- `claim` is not the hash; it is raw derived bytes encoded as base64url.
- Server hashes claim bytes and compares with stored `claim_hash`.

## Validation and Rejection Rules

Clients MUST fail closed for:

- Unsupported `v` or `suite`
- Unsupported `kdf.name` or `enc.alg`
- Any required field missing or wrong type
- Base64url decoding errors
- Invalid lengths (nonce/salts/keys)
- `kdf.iterations < 300000` when PBKDF2 is used
- AEAD authentication failure during decrypt

Servers SHOULD reject envelopes over service size limits. Default limits are 256 KB (public) and 1 MB (authenticated), configurable per instance via `PUBLIC_MAX_ENVELOPE_BYTES` and `AUTHED_MAX_ENVELOPE_BYTES`.

## Interoperability Test Vectors

Before freezing v1, add machine-readable vectors (recommended path: `spec/v1/envelope.vectors.json`) that include:

- URL key bytes
- passphrase (if any)
- kdf params
- hkdf salt
- nonce
- plaintext
- expected envelope
- expected claim token and claim hash
- optional hint metadata (when present)

Both CLI and browser implementations MUST pass these vectors.
