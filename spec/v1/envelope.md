# Envelope Specification (v1)

Status: Active (normative).

This document defines the client-side envelope format and cryptographic workflow for `secrt`.

The server treats `envelope` as opaque JSON and stores/returns it unchanged. Decryption keys are never sent to the server.

## Normative language

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are interpreted as in RFC 2119.

## Security model

- Encryption and decryption happen only on clients.
- The server stores ciphertext envelope JSON plus claim verifier material.
- URL fragments carry the `url_key`; fragments are not sent in normal HTTP requests.
- Optional passphrases are shared out of band.
- Metadata (`filename`, `mime`, `type`, etc.) is encrypted inside ciphertext payload bytes.

## Encoding rules

- JSON strings are UTF-8.
- Binary values use base64url without padding (`RFC 4648`, URL-safe alphabet, no `=`).
- JSON field names are case-sensitive.
- Clients MUST reject malformed base64url values.

## Cryptographic suite (v1 sealed payload)

Required primitives:

- AES-256-GCM
- HKDF-SHA-256
- SHA-256
- Optional Argon2id

Constants:

- `URL_KEY_LEN = 32`
- `PASS_KEY_LEN = 32`
- `HKDF_LEN = 32`
- `GCM_NONCE_LEN = 12`
- `HKDF_SALT_LEN = 32`
- `KDF_SALT_LEN = 16`
- `AAD = "secrt.ca/envelope/v1-sealed-payload"`
- `HKDF_INFO_ENC = "secrt:v1:enc:sealed-payload"`
- `HKDF_INFO_CLAIM = "secrt:v1:claim:sealed-payload"`
- `CLAIM_SALT = SHA256("secrt-envelope-v1-claim-salt")`

## Envelope JSON shape

`envelope` MUST be a JSON object with this structure:

```json
{
  "v": 1,
  "suite": "v1-argon2id-hkdf-aes256gcm-sealed-payload",
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
    "enc_info": "secrt:v1:enc:sealed-payload",
    "claim_info": "secrt:v1:claim:sealed-payload",
    "length": 32
  }
}
```

If a passphrase is used, `kdf` MUST be:

```json
{
  "name": "argon2id",
  "version": 19,
  "salt": "<base64url 16+ bytes>",
  "m_cost": 19456,
  "t_cost": 2,
  "p_cost": 1,
  "length": 32
}
```

Field validation:

- `v` MUST be integer `1`.
- `suite` MUST equal `v1-argon2id-hkdf-aes256gcm-sealed-payload`.
- `enc.alg` MUST equal `A256GCM`.
- `enc.nonce` MUST decode to 12 bytes.
- `enc.ciphertext` MUST decode to at least 16 bytes.
- `kdf.name` MUST be `none` or `argon2id`.
- `hkdf.hash` MUST equal `SHA-256`.
- `hkdf.salt` MUST decode to exactly 32 bytes.
- `hkdf.enc_info` MUST equal `secrt:v1:enc:sealed-payload`.
- `hkdf.claim_info` MUST equal `secrt:v1:claim:sealed-payload`.
- `hkdf.length` MUST equal `32`.

For `kdf.name == "argon2id"`:

- `kdf.salt` MUST decode to at least 16 bytes.
- `kdf.version` MUST equal `19`.
- `kdf.m_cost` MUST satisfy `19456 <= m_cost <= 65536`.
- `kdf.t_cost` MUST satisfy `2 <= t_cost <= 10`.
- `kdf.p_cost` MUST satisfy `1 <= p_cost <= 4`.
- `kdf.m_cost * kdf.t_cost` MUST be `<= 262144`.
- `kdf.length` MUST equal `32`.

For `kdf.name == "none"`:

- `kdf` MUST NOT include `version`, `salt`, `m_cost`, `t_cost`, `p_cost`, or `length`.

Plaintext metadata prohibition:

- Envelope top-level metadata keys (`hint`, `filename`, `mime`, `type`, and similar advisory fields) MUST NOT appear in plaintext envelope JSON.
- Metadata is only valid inside the encrypted payload frame.

Unknown fields:

- Clients MAY ignore unknown fields for forward compatibility.
- Clients MUST strictly validate required fields.

## URL fragment format

Share links use:

`https://<host>/s/<id>#<url_key_b64>`

- `<url_key_b64>` MUST decode to 32 bytes.
- Fragment MUST NOT include passphrase.

## Claim token derivation

Claim token derivation is independent of passphrase and envelope body:

`claim_token = HKDF-SHA-256(url_key, CLAIM_SALT, "secrt:v1:claim:sealed-payload", 32)`

Create API sends:

`claim_hash = base64url(SHA-256(claim_token))`

## Encrypted payload frame (normative)

The decrypted plaintext bytes are a framed payload with metadata and body:

1. `magic` (4 bytes): ASCII `SCRT`
2. `frame_version` (u8): `1`
3. `codec` (u8): `0 = none`, `1 = zstd`
4. `reserved` (u16be): `0`
5. `meta_len` (u32be)
6. `raw_len` (u32be)
7. `meta_json` (`meta_len` bytes UTF-8 JSON object)
8. `body` (raw bytes or zstd-compressed bytes per `codec`)

`meta_json` requirements:

- `type` is required and MUST be one of: `text`, `file`, `binary`.
- `filename` is optional string.
- `mime` is optional string.
- Unknown keys are allowed.

Decode validation rules:

- `magic` MUST equal `SCRT`.
- `frame_version` MUST equal `1`.
- `reserved` MUST equal `0`.
- Length fields MUST be in-bounds and non-overflowing.
- `raw_len <= 104857600` (100 MiB).
- If `codec=none`, then `len(body) == raw_len`.
- If `codec=zstd`, decompressed length MUST equal `raw_len` and MUST NOT exceed 100 MiB.

## Compression policy (normative create behavior)

Clients MUST follow this default policy:

- Attempt compression only when `raw_len >= 2048`.
- Skip compression attempt when content signature indicates pre-compressed/media data:
  - png, jpg/jpeg, gif, webp, zip, gz, bz2, xz, zst, 7z, pdf, mp4, mp3.
- Compression codec: zstd level `3`.
- Use compressed form only if both are true:
  - `raw_len - compressed_len >= 64`
  - `(raw_len - compressed_len) / raw_len >= 0.10`
- Otherwise store `codec=none`.

## Create flow (normative)

Inputs:

- plaintext content bytes
- metadata object (`type`, optional `filename`/`mime`/extra)
- optional passphrase

Default passphrase KDF parameters (when client does not expose tuning controls):

- `version = 19`
- `m_cost = 19456`
- `t_cost = 2`
- `p_cost = 1`
- `length = 32`

Steps:

1. Generate `url_key` (32 random bytes).
2. Build `kdf`:
   - no passphrase: `kdf.name = "none"`, `ikm = url_key`
   - passphrase:
     - generate `kdf.salt`
     - derive `pass_key = Argon2id(passphrase, kdf.salt, m_cost, t_cost, p_cost, 32)`
     - `ikm = SHA-256(url_key || pass_key)`
3. Generate random `hkdf.salt` (32 bytes).
4. Derive `enc_key = HKDF-SHA-256(ikm, hkdf.salt, HKDF_INFO_ENC, 32)`.
5. Derive `claim_token = HKDF-SHA-256(url_key, CLAIM_SALT, HKDF_INFO_CLAIM, 32)`.
6. Build framed payload bytes from metadata + content using compression policy.
7. Generate nonce (12 random bytes).
8. Encrypt framed payload with `AES-256-GCM(enc_key, nonce, AAD)`.
9. Build envelope JSON.
10. Compute `claim_hash = base64url(SHA-256(claim_token))`.
11. Send create request with `{ envelope, claim_hash, ttl_seconds? }`.
12. Share link with fragment `#<base64url(url_key)>`.

## Claim + decrypt flow (normative)

1. Parse `url_key` from URL fragment and enforce 32 bytes.
2. Derive claim token using fixed claim salt.
3. `POST /api/v1/secrets/{id}/claim` with `{ "claim": base64url(claim_token) }`.
4. Validate envelope structure.
5. Recompute `ikm` from `url_key` + envelope `kdf`.
6. Derive `enc_key` with envelope `hkdf.salt`.
7. Decrypt ciphertext with AES-256-GCM + `AAD`.
8. Decode payload frame and validate frame invariants.
9. Return plaintext content bytes + decrypted metadata to caller.

## Validation and rejection rules

Clients MUST fail closed for:

- unsupported `v`, `suite`, `enc.alg`, `kdf.name`, `hkdf` constants
- missing or malformed required fields
- invalid base64url encodings
- invalid nonce/salt lengths
- Argon2id parameters outside allowed bounds
- AEAD authentication failure
- invalid payload frame (bad magic/version/lengths/codec)
- decompressed payload exceeding 100 MiB cap

Server-side behavior:

- The server still treats `envelope` as opaque JSON and cannot read metadata.
- Server envelope size limits still apply to the serialized envelope bytes.

## Interoperability vectors

Canonical vectors live at:

- `spec/v1/envelope.vectors.json`

All clients MUST pass vectors, including:

- no-passphrase + `codec=none`
- no-passphrase + `codec=zstd`
- passphrase + `codec=zstd`
- file metadata encrypted in payload frame
- pre-compressed signature skip (`codec=none`)
