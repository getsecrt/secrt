# secrt Technical Whitepaper

**Zero-Knowledge One-Time Secret Sharing**

Version 1.0 — February 2026

---

## Table of Contents

1. [Introduction](#introduction)
2. [Threat Model & Design Goals](#threat-model--design-goals)
3. [Cryptographic Architecture](#cryptographic-architecture)
   - [Primitives & Constants](#primitives--constants)
   - [Key Derivation](#key-derivation)
   - [Passphrase Protection Layer](#passphrase-protection-layer)
   - [Claim Token Derivation](#claim-token-derivation)
   - [Payload Frame Format](#payload-frame-format)
   - [Compression Policy](#compression-policy)
   - [Encryption & Decryption Flow](#encryption--decryption-flow)
4. [The Envelope Format](#the-envelope-format)
5. [Zero-Knowledge Architecture](#zero-knowledge-architecture)
6. [Server Architecture](#server-architecture)
   - [Database Schema & What We Store](#database-schema--what-we-store)
   - [Atomic One-Time Claim](#atomic-one-time-claim)
   - [Background Reaper](#background-reaper)
   - [IP Privacy & Hashing](#ip-privacy--hashing)
   - [Reverse Proxy & Privacy Logging](#reverse-proxy--privacy-logging)
7. [Abuse Prevention](#abuse-prevention)
   - [Rate Limiting](#rate-limiting)
   - [Per-Owner Quotas](#per-owner-quotas)
   - [Input Validation & Error Opacity](#input-validation--error-opacity)
8. [Account System & Authentication](#account-system--authentication)
   - [Why Accounts Exist](#why-accounts-exist)
   - [Passkey Authentication (No Passwords)](#passkey-authentication-no-passwords)
   - [Privacy-Friendly Nicknames](#privacy-friendly-nicknames)
   - [API Key v2 Architecture](#api-key-v2-architecture)
   - [Policy Tiers](#policy-tiers)
9. [CLI Application](#cli-application)
   - [Design Philosophy](#design-philosophy)
   - [Keychain Integration](#keychain-integration)
   - [Why Am I Getting Password Prompts?](#why-am-i-getting-password-prompts)
10. [Signed Binary Releases](#signed-binary-releases)
    - [macOS Code Signing & Notarization](#macos-code-signing--notarization)
    - [Windows Code Signing](#windows-code-signing)
    - [Verification & Checksums](#verification--checksums)
    - [Why Use the CLI for Sensitive Exchanges](#why-use-the-cli-for-sensitive-exchanges)
11. [Web Application](#web-application)
12. [Specification & Test Vectors](#specification--test-vectors)
13. [Data Residency](#data-residency)
14. [FAQ](#faq)
15. [Contact & Responsible Disclosure](#contact--responsible-disclosure)

---

## Introduction

secrt is a zero-knowledge, one-time secret sharing service. It allows you to share passwords, API keys, credentials, files, and other sensitive information through links that can only be opened once and then self-destruct.

All encryption happens on your device — in the browser or on the command line — before any data reaches the server. The server stores only opaque ciphertext that it cannot decrypt. It never sees your plaintext, your encryption keys, your passphrases, or even the filenames or content types of what you share.

The project is fully open source and the protocol is defined by a rigorous, versioned [specification](https://github.com/getsecrt/secrt/tree/main/spec/v1) with mandatory test vectors that all implementations must pass.

**Repository:** [github.com/getsecrt/secrt](https://github.com/getsecrt/secrt)

---

## Threat Model & Design Goals

secrt is designed to protect shared secrets against:

- **Server compromise.** Even if an attacker gains full access to the database, they obtain only ciphertext that cannot be decrypted without the URL key (which the server never receives).
- **Network interception.** Share links use HTTPS. The decryption key is carried in the URL fragment, which browsers never transmit over the network.
- **Link interception without passphrase.** When a passphrase is set, intercepting the share link alone is insufficient — the attacker also needs the passphrase.
- **Replay attacks.** Each secret can be claimed exactly once via an atomic delete-and-return operation. There is no second retrieval.
- **Metadata leakage.** Filenames, MIME types, and content type indicators are encrypted inside the ciphertext payload. The server never sees them.
- **IP surveillance.** Client IP addresses are never stored in the database. They are HMAC-hashed with per-process ephemeral keys for rate limiting only, and the reverse proxy is configured to truncate IPs in access logs.
- **Log forensics.** The server never logs request bodies, plaintext, passphrases, claim tokens, or URL fragments. Only HTTP metadata (method, path, status code, response size, duration, request ID) is logged.

**Non-goals:**

- Protection against a compromised client device (if the sender or recipient's device is compromised, the plaintext is exposed regardless).
- Long-term archival storage (secrets have a maximum TTL of one year and are deleted after retrieval).
- Anonymity at the network level (use Tor or a VPN for transport-layer anonymity; see [FAQ](#does-secrt-work-with-tor)).

---

## Cryptographic Architecture

### Primitives & Constants

secrt uses a single, well-defined cryptographic suite identified as `v1-pbkdf2-hkdf-aes256gcm-sealed-payload`. All cryptographic operations use the [`ring`](https://github.com/briansmith/ring) library in Rust and the [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) in the browser. No custom cryptography is used.

| Primitive | Algorithm | Library |
|-----------|-----------|---------|
| Authenticated encryption | AES-256-GCM | ring / WebCrypto |
| Key derivation | HKDF-SHA-256 | ring / WebCrypto |
| Passphrase stretching | PBKDF2-HMAC-SHA-256 | ring / WebCrypto |
| Hashing | SHA-256 | ring / WebCrypto |
| Compression | zstd (level 3) | zstd crate / @bokuweb/zstd-wasm |
| Encoding | base64url (no padding, RFC 4648) | base64 crate / browser btoa |

Key constants (defined in [`crates/secrt-core/src/types.rs`](https://github.com/getsecrt/secrt/blob/main/crates/secrt-core/src/types.rs)):

| Constant | Value | Purpose |
|----------|-------|---------|
| `URL_KEY_LEN` | 32 bytes | Random master key in URL fragment |
| `HKDF_SALT_LEN` | 32 bytes | Random per-secret HKDF salt |
| `HKDF_LEN` | 32 bytes | Derived encryption key length |
| `GCM_NONCE_LEN` | 12 bytes | AES-GCM nonce |
| `KDF_SALT_LEN` | 16 bytes minimum | PBKDF2 salt |
| `DEFAULT_PBKDF2_ITERATIONS` | 600,000 | Passphrase stretching rounds |
| `MIN_PBKDF2_ITERATIONS` | 300,000 | Minimum accepted iterations |
| `AAD` | `secrt.ca/envelope/v1-sealed-payload` | AES-GCM additional authenticated data |
| `HKDF_INFO_ENC` | `secrt:v1:enc:sealed-payload` | HKDF info for encryption key |
| `HKDF_INFO_CLAIM` | `secrt:v1:claim:sealed-payload` | HKDF info for claim token |
| `CLAIM_SALT_LABEL` | `secrt-envelope-v1-claim-salt` | Label for deriving the claim salt |

### Key Derivation

When a secret is created, the client generates a random 32-byte `url_key`. This key is embedded in the share link's URL fragment (the part after `#`), which browsers never transmit to the server.

**Without a passphrase:**

```
url_key = random(32 bytes)          # never sent to server
hkdf_salt = random(32 bytes)        # stored in envelope
enc_key = HKDF-SHA-256(
    ikm   = url_key,
    salt  = hkdf_salt,
    info  = "secrt:v1:enc:sealed-payload",
    len   = 32
)
```

**With a passphrase:**

```
url_key  = random(32 bytes)         # never sent to server
kdf_salt = random(16 bytes)         # stored in envelope
pass_key = PBKDF2-HMAC-SHA-256(
    password   = passphrase,        # never sent to server
    salt       = kdf_salt,
    iterations = 600000,
    dklen      = 32
)
ikm = SHA-256(url_key || pass_key)  # combine both keys
hkdf_salt = random(32 bytes)        # stored in envelope
enc_key = HKDF-SHA-256(
    ikm   = ikm,
    salt  = hkdf_salt,
    info  = "secrt:v1:enc:sealed-payload",
    len   = 32
)
```

The two-layer derivation (PBKDF2 then HKDF) ensures that even if one of the two inputs (URL key or passphrase) is compromised, the attacker must still obtain the other to derive the encryption key.

See: [`spec/v1/envelope.md`](https://github.com/getsecrt/secrt/blob/main/spec/v1/envelope.md), [`crates/secrt-core/src/crypto.rs`](https://github.com/getsecrt/secrt/blob/main/crates/secrt-core/src/crypto.rs)

### Passphrase Protection Layer

The optional passphrase layer adds a second factor to the encryption. When set:

- A 16-byte random salt is generated and stored in the envelope's `kdf` block.
- The passphrase is stretched through PBKDF2-HMAC-SHA-256 with 600,000 iterations (minimum 300,000 accepted).
- The resulting 32-byte `pass_key` is concatenated with the `url_key` and hashed through SHA-256 to produce the input keying material (IKM) for HKDF.
- The passphrase itself is never transmitted to the server.

This means intercepting the share link is not enough — the attacker must also know the passphrase. The passphrase can be communicated through a separate channel (e.g., in person, via phone, or a different messaging platform).

### Claim Token Derivation

The claim token is a cryptographic proof that the requester possesses the URL key. It is derived independently of any passphrase:

```
claim_salt  = SHA-256("secrt-envelope-v1-claim-salt")     # fixed, public
claim_token = HKDF-SHA-256(
    ikm  = url_key,
    salt = claim_salt,
    info = "secrt:v1:claim:sealed-payload",
    len  = 32
)
claim_hash  = base64url(SHA-256(claim_token))
```

At creation time, the client sends only the `claim_hash` to the server. At retrieval time, the client derives the `claim_token` from the URL key and sends it. The server computes `SHA-256(claim_token)` and compares it to the stored `claim_hash`. The server never sees the raw `claim_token` at rest.

This design ensures:
- The claim token is deterministically derived from the URL key alone (no passphrase needed for claim verification).
- The server stores only a hash of the claim token, not the token itself.
- Even with database access, an attacker cannot forge a valid claim token.

### Payload Frame Format

Before encryption, the plaintext is wrapped in a binary frame that carries metadata and supports compression. This frame is defined in [`crates/secrt-core/src/payload.rs`](https://github.com/getsecrt/secrt/blob/main/crates/secrt-core/src/payload.rs):

```
Offset  Length     Field          Description
------  ---------  ----------     ---------------------------
0       4 bytes    magic          ASCII "SCRT"
4       1 byte     frame_version  1
5       1 byte     codec          0 = none, 1 = zstd
6       2 bytes    reserved       0x0000 (big-endian)
8       4 bytes    meta_len       Metadata JSON byte length (big-endian)
12      4 bytes    raw_len        Uncompressed content length (big-endian)
16      meta_len   meta_json      UTF-8 JSON metadata
16+N    variable   body           Content bytes (plain or zstd-compressed)
```

The metadata JSON carries content type, filename, and MIME type — all encrypted inside the ciphertext:

```json
{
  "type": "text",
  "filename": "credentials.txt",
  "mime": "text/plain"
}
```

Because this metadata is inside the encrypted frame, the server never knows whether you shared a text snippet, a file, or binary data — nor any filename or content type.

### Compression Policy

Large payloads are compressed with [zstd](https://facebook.github.io/zstd/) (level 3) before encryption to reduce ciphertext size and improve transfer speed. The compression decision follows a strict policy:

1. **Skip if small:** Content under 2,048 bytes is never compressed (overhead outweighs benefit).
2. **Skip if pre-compressed:** Files with signatures indicating they are already compressed (PNG, JPEG, GIF, WebP, ZIP, gzip, bzip2, xz, zstd, 7z, PDF, MP4, MP3) are not re-compressed.
3. **Attempt and evaluate:** For eligible content, zstd compression is attempted. The compressed form is used only if it saves at least 64 bytes AND at least 10% of the original size.
4. **Transparent to encryption:** The codec byte in the frame header tells the decryptor whether decompression is needed. The encryption layer does not need to know.

Decompression validates the result against the `raw_len` header field to prevent decompression bombs. The maximum decompressed size is 100 MiB.

See: [`spec/v1/envelope.md` § Compression](https://github.com/getsecrt/secrt/blob/main/spec/v1/envelope.md)

### Encryption & Decryption Flow

**Encryption (sender):**

1. Generate random 32-byte `url_key`.
2. If passphrase set: derive `pass_key` via PBKDF2, compute `ikm = SHA-256(url_key || pass_key)`.
3. Otherwise: `ikm = url_key`.
4. Generate random 32-byte HKDF salt.
5. Derive `enc_key = HKDF-SHA-256(ikm, salt, "secrt:v1:enc:sealed-payload", 32)`.
6. Build payload frame (metadata + optional compression + content).
7. Generate random 12-byte nonce.
8. Encrypt: `ciphertext = AES-256-GCM-SEAL(enc_key, nonce, frame_bytes, AAD)`.
9. Derive claim hash from `url_key`.
10. Build envelope JSON with ciphertext, nonce, KDF params, HKDF params.
11. Send `{envelope, claim_hash, ttl_seconds}` to server; embed `url_key` in share link fragment.

**Decryption (recipient):**

1. Parse share URL to extract secret ID and `url_key` from fragment.
2. Derive `claim_token` from `url_key` via HKDF.
3. Send `{claim: base64url(claim_token)}` to server.
4. Server atomically returns envelope and deletes the secret.
5. If passphrase needed (envelope `kdf.name == "PBKDF2-SHA256"`): derive `pass_key`, compute `ikm`.
6. Otherwise: `ikm = url_key`.
7. Derive `enc_key` from `ikm` + envelope's HKDF salt.
8. Decrypt: `frame_bytes = AES-256-GCM-OPEN(enc_key, nonce, ciphertext, AAD)`.
9. Validate frame (magic bytes, version, reserved field).
10. If `codec == zstd`: decompress body, validate against `raw_len`.
11. Parse metadata JSON; return plaintext content and metadata.

---

## The Envelope Format

The envelope is the JSON object stored on the server. It is opaque to the server — treated as a blob that is stored and returned unchanged.

```json
{
  "v": 1,
  "suite": "v1-pbkdf2-hkdf-aes256gcm-sealed-payload",
  "enc": {
    "alg": "A256GCM",
    "nonce": "<base64url, 12 bytes>",
    "ciphertext": "<base64url, ciphertext + 16-byte GCM tag>"
  },
  "kdf": {
    "name": "none"
  },
  "hkdf": {
    "hash": "SHA-256",
    "salt": "<base64url, 32 bytes>",
    "enc_info": "secrt:v1:enc:sealed-payload",
    "claim_info": "secrt:v1:claim:sealed-payload",
    "length": 32
  }
}
```

When a passphrase is used, the `kdf` block becomes:

```json
{
  "name": "PBKDF2-SHA256",
  "salt": "<base64url, 16+ bytes>",
  "iterations": 600000,
  "length": 32
}
```

Top-level metadata fields like `hint`, `filename`, `mime`, or `type` are forbidden in the envelope JSON. All metadata is encrypted inside the ciphertext as part of the payload frame. Unknown fields are allowed for forward compatibility.

The envelope is self-describing: it contains all the parameters needed to reconstruct the decryption key (given the URL key and optional passphrase). This makes the format portable — any compliant implementation can decrypt a secret created by any other.

See: [`spec/v1/envelope.md`](https://github.com/getsecrt/secrt/blob/main/spec/v1/envelope.md)

---

## Zero-Knowledge Architecture

The zero-knowledge property is the central design constraint. Here is exactly what the server sees and does not see at each stage:

**What the server receives at creation:**
- Opaque envelope JSON (ciphertext + key derivation parameters; no plaintext, no keys)
- Claim hash (`base64url(SHA-256(claim_token))`)
- TTL in seconds
- For authenticated requests: API key wire credential (prefix + auth token hash, not the root key)

**What the server stores:**
- Envelope JSON (opaque ciphertext)
- Claim hash
- Expiry timestamp
- Owner key (hashed IP for public, API key prefix for authenticated)
- Creation timestamp

**What the server never sees or stores:**
- URL key (carried in the URL fragment, which browsers never transmit)
- Plaintext content of any kind
- Passphrases
- Encryption keys (derived client-side only)
- Claim tokens (only the hash is stored)
- Filenames, MIME types, or content type indicators (encrypted inside the payload)
- Raw client IP addresses (only HMAC hashes are used in memory; never persisted)
- API key root secrets (only the auth hash and prefix are stored)

**Why this holds even if the server is compromised:**

An attacker who gains full database access obtains only ciphertext envelopes. To decrypt any secret, they would need the `url_key` from the share link's URL fragment, which was never sent to the server. There is no key escrow, no recovery mechanism, and no server-side decryption capability by design.

---

## Server Architecture

The server is built with [Axum](https://github.com/tokio-rs/axum) (async Rust HTTP framework) backed by PostgreSQL. Its role is strictly limited to storing and serving ciphertext — it performs no cryptographic operations on secret content.

Source: [`crates/secrt-server/`](https://github.com/getsecrt/secrt/tree/main/crates/secrt-server)

### Database Schema & What We Store

The database is designed for minimal data retention and maximum privacy. Here is the complete schema:

**`secrets` — Ciphertext storage**

| Column | Type | Purpose |
|--------|------|---------|
| `id` | TEXT (PK) | Random 12-character alphanumeric ID |
| `claim_hash` | TEXT | `base64url(SHA-256(claim_token))` — never the token itself |
| `envelope` | JSONB | Opaque ciphertext blob — server does not inspect contents |
| `expires_at` | TIMESTAMPTZ | When the secret expires |
| `created_at` | TIMESTAMPTZ | Creation timestamp |
| `owner_key` | TEXT | `ip:<hmac_hash>` or `apikey:<prefix>` — for quota enforcement only |

**`users` — Minimal account records**

| Column | Type | Purpose |
|--------|------|---------|
| `id` | UUID (PK) | Server-generated UUIDv7 |
| `display_name` | TEXT | User-chosen nickname (auto-generated privacy-friendly names available) |
| `created_at` | TIMESTAMPTZ | Account creation time |

No email, phone number, real name, or other personally identifiable information is collected or stored.

**`passkeys` — WebAuthn credentials**

| Column | Type | Purpose |
|--------|------|---------|
| `credential_id` | TEXT (UNIQUE) | WebAuthn credential identifier |
| `public_key` | TEXT | Credential public key |
| `user_id` | UUID (FK) | Link to user account |
| `sign_count` | BIGINT | Counter for clone detection |
| `revoked_at` | TIMESTAMPTZ | Soft-delete marker |

**`api_keys` — API key verification (v2 auth-hash model)**

| Column | Type | Purpose |
|--------|------|---------|
| `key_prefix` | TEXT (UNIQUE) | First 6 characters of the key (client-visible identifier) |
| `auth_hash` | TEXT | `hex(HMAC-SHA256(API_KEY_PEPPER, verifier_message))` |
| `user_id` | UUID (FK) | Link to user account |
| `revoked_at` | TIMESTAMPTZ | Revocation marker |

The API key root secret is never stored on the server. Only the HMAC-derived `auth_hash` is persisted, making it impossible to reconstruct the original key from database contents.

**`sessions`, `webauthn_challenges`, `api_key_registrations`** — Ephemeral records for authentication flows, automatically cleaned up by the background reaper.

See: [`crates/secrt-server/migrations/001_initial.sql`](https://github.com/getsecrt/secrt/blob/main/crates/secrt-server/migrations/001_initial.sql)

### Atomic One-Time Claim

The claim operation is the most security-critical path. It must guarantee that a secret is returned at most once, even under concurrent requests. This is implemented as a single atomic SQL statement:

```sql
DELETE FROM secrets
WHERE id = $1 AND claim_hash = $2 AND expires_at > $3
RETURNING envelope::text, expires_at, created_at, owner_key
```

This combines verification, retrieval, and deletion in a single database operation:
- If the ID doesn't exist, the claim hash doesn't match, or the secret has expired: zero rows affected, return `404`.
- If successful: the envelope is returned and simultaneously deleted. A concurrent request for the same secret will see zero rows.
- All failure modes (wrong token, expired, already claimed, nonexistent) return an identical `404` response, preventing information leakage about secret existence.

See: [`crates/secrt-server/src/storage/postgres.rs`](https://github.com/getsecrt/secrt/blob/main/crates/secrt-server/src/storage/postgres.rs)

### Background Reaper

A background task runs every 5 minutes to clean up expired data:

- Deletes expired secrets (defense-in-depth; claim-time TTL check is the authoritative enforcement)
- Deletes expired WebAuthn challenges (10-minute window)
- Deletes expired or revoked sessions
- Deletes stale API key registration records (24-hour rolling window)

The reaper is best-effort housekeeping — it is not required for correctness. The claim query's `expires_at > now` check is the authoritative TTL enforcement.

### IP Privacy & Hashing

Raw client IP addresses are never persisted to the database and never stored in plaintext in process memory.

**For rate limiting:** IPs are HMAC-SHA-256 hashed with a per-process random key generated at startup. The rate limiter's internal data structure uses only these hashed values as keys. A background garbage collector sweeps stale rate-limit buckets every 2 minutes, evicting entries idle for more than 10 minutes.

**For quota tracking:** The `owner_key` column in the secrets table stores `ip:<hmac_hash>` for anonymous requests — never the raw IP. Because the HMAC key is per-process and ephemeral, these hashes cannot be correlated across server restarts.

**Proxy trust model:** The server trusts the `X-Forwarded-For` header only when the direct connection comes from a loopback address (127.0.0.1 or ::1), indicating a trusted local reverse proxy. In all other cases, the socket's remote address is used directly.

See: [`crates/secrt-server/src/http/mod.rs`](https://github.com/getsecrt/secrt/blob/main/crates/secrt-server/src/http/mod.rs)

### Reverse Proxy & Privacy Logging

In production, secrt runs behind a reverse proxy (nginx or Caddy) configured with privacy-preserving logging:

- **IPv4 addresses** are masked to /24 (last octet zeroed)
- **IPv6 addresses** are masked to /48 (last 80 bits zeroed)
- **User-Agent** is stripped from access logs
- **Referer** is stripped from access logs (could leak secret page URLs)
- **Query strings** are stripped from logged URIs (defense-in-depth)
- **Cookies and Authorization headers** are redacted

The server checks for an `X-Privacy-Log: truncated-ip` header from the reverse proxy on startup and logs a warning if it is missing. This is advisory — the server does not block requests without it — but it ensures operators are aware of the logging requirements.

See: [`docs/caddy-privacy-logging.md`](https://github.com/getsecrt/secrt/blob/main/docs/caddy-privacy-logging.md)

---

## Abuse Prevention

### Rate Limiting

Rate limiting uses in-memory token buckets with HMAC-hashed keys (raw IPs never stored in the limiter's data structures):

| Endpoint | Rate | Burst | Key |
|----------|------|-------|-----|
| Public secret creation | 0.5 rps | 6 | HMAC(client IP) |
| Secret claiming | 1.0 rps | 10 | HMAC(client IP) |
| Authenticated creation | 2.0 rps | 20 | API key prefix |
| API key registration | 0.5 rps | 6 | HMAC(client IP) |

All rate limits are configurable via environment variables.

### Per-Owner Quotas

Beyond rate limiting, per-owner quotas prevent storage abuse:

| Limit | Public (Anonymous) | Authenticated (API Key) |
|-------|-------------------|------------------------|
| Max active secrets | 10 | 1,000 |
| Max active bytes (total) | 2 MiB | 20 MiB |
| Max single envelope | 256 KiB | 1 MiB |

Quota checks are enforced atomically within a PostgreSQL transaction using advisory locks on the owner key. This prevents time-of-check/time-of-use (TOCTOU) race conditions.

API key registration has additional rolling-window quotas: 5 keys per hour and 20 per day, enforced both per-account and per-IP.

### Input Validation & Error Opacity

- All API endpoints require `Content-Type: application/json`.
- JSON deserialization rejects unknown fields (prevents injection of unexpected data).
- Claim token values are validated (must base64url-decode to exactly 32 bytes).
- All claim, burn, and lookup failures return identical `404` responses — the server never reveals whether a secret existed, expired, was already claimed, or had the wrong token.
- Responses include security headers: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`.
- JSON responses always include `Cache-Control: no-store`.

See: [`spec/v1/api.md`](https://github.com/getsecrt/secrt/blob/main/spec/v1/api.md), [`spec/v1/server.md`](https://github.com/getsecrt/secrt/blob/main/spec/v1/server.md)

---

## Account System & Authentication

### Why Accounts Exist

secrt allows creating and sharing secrets without any account. The account system exists for three specific reasons:

1. **API key management.** Accounts allow users to generate API keys for automated workflows, CI/CD pipelines, and CLI usage with higher limits.
2. **Higher quotas.** Authenticated users get significantly higher storage limits (1,000 secrets / 20 MiB vs. 10 secrets / 2 MiB) to support legitimate use cases like large file transfers that would be abuse vectors without authentication.
3. **Secret management.** API keys enable burning (destroying) secrets before they are claimed, which is useful for credential rotation workflows.

Accounts do not unlock any decryption capability — the zero-knowledge property holds regardless of authentication status. Accounts exist purely for operational governance.

### Passkey Authentication (No Passwords)

secrt uses [WebAuthn passkeys](https://passkeys.dev/) exclusively for authentication. There are no passwords.

This is actually **more secure** than password-based authentication:

- **Phishing-resistant.** Passkeys are bound to the origin (secrt.ca) at the protocol level. They cannot be phished or replayed on a different site.
- **No password reuse risk.** Users cannot reuse a compromised password from another service.
- **No credential stuffing.** Without passwords, there is nothing to stuff.
- **Hardware-backed option.** Users with YubiKeys, Titan keys, or other FIDO2 hardware tokens get the strongest authentication available — private keys that never leave the hardware device.
- **Platform support.** Modern browsers and operating systems support passkeys natively (macOS/iOS via iCloud Keychain, Windows via Windows Hello, Android via Google Password Manager, and cross-platform via hardware security keys).

The registration and login flows use the WebAuthn browser API with discoverable credentials (`residentKey: required`), supporting both ES256 and RS256 algorithms.

### Privacy-Friendly Nicknames

When creating an account, users are asked for a display name (called a "Nickname"). This is purely cosmetic — it appears in the navigation bar when logged in and helps users identify their account.

For maximum privacy, secrt auto-generates random, friendly display names from an adjective-animal combination (e.g., "Swift Falcon", "Quiet Otter"). There are approximately 2,500 unique combinations. Users are free to use one of these auto-generated names instead of anything personally identifiable.

No email address, phone number, or real name is required to create an account. The only data stored is the display name and the passkey credential.

### API Key v2 Architecture

API keys use a derived-key architecture that prevents the server from ever storing the root secret:

**Client-side (stored locally):** `sk2_<prefix>.<root_key_base64>`

**Wire format (sent in requests):** `ak2_<prefix>.<auth_token_base64>`

The client derives the auth token from the root key using HKDF:

```
ROOT_SALT   = SHA-256("secrt-apikey-v2-root-salt")
auth_token  = HKDF-SHA-256(root_key, ROOT_SALT, "secrt-auth", 32)
```

The server verifies the auth token by computing:

```
message   = "secrt-apikey-v2-verifier" || u16be(len(prefix)) || prefix || auth_token
auth_hash = hex(HMAC-SHA256(API_KEY_PEPPER, message))
```

And comparing the result to the stored `auth_hash` using constant-time comparison. The `API_KEY_PEPPER` is an environment-only secret that is never persisted to disk.

This means:
- The root key (`sk2_...`) never leaves the client.
- The auth token is derived, not the root key itself.
- The server stores only a peppered HMAC hash — even with database access and the pepper, the original key cannot be reconstructed.

See: [`spec/v1/api.md` § API Key v2](https://github.com/getsecrt/secrt/blob/main/spec/v1/api.md)

### Policy Tiers

| Capability | Anonymous | Authenticated |
|------------|-----------|---------------|
| Create secrets | Yes | Yes |
| Claim secrets | Yes | Yes |
| Burn secrets | No | Yes (own secrets) |
| Max single secret | 256 KiB | 1 MiB |
| Max active secrets | 10 | 1,000 |
| Max active storage | 2 MiB | 20 MiB |
| Create rate | 0.5 rps (burst 6) | 2.0 rps (burst 20) |

All limits are configurable per deployment.

---

## CLI Application

### Design Philosophy

The secrt CLI ([`crates/secrt-cli/`](https://github.com/getsecrt/secrt/tree/main/crates/secrt-cli)) is a single static binary with no runtime dependencies. It is designed for:

- **Minimal dependencies.** Uses `ring` for crypto, `ureq` for blocking HTTP, and hand-rolled argument parsing (no clap). The release binary is approximately 1.5 MB.
- **No async runtime.** Blocking I/O keeps the control flow simple and predictable.
- **Config file safety.** On Unix, the config file is created with `0600` permissions and the CLI warns if group/world-readable permissions are detected, stripping sensitive fields in that case.
- **Piping and scripting.** Supports JSON output (`--json`), stdin input, and non-interactive modes for automation.
- **Implicit URL detection.** Running `secrt https://secrt.ca/s/abc#key` automatically detects a share URL and runs the `get` command without requiring the subcommand.

### Keychain Integration

The CLI optionally integrates with your operating system's credential store:

| Platform | Backend |
|----------|---------|
| macOS | Keychain (Login keychain) |
| Windows | Windows Credential Manager (DPAPI) |
| Linux | Secret Service (systemd) or kernel keyutils |

Keychain integration is **off by default** and must be enabled with `use_keychain = true` in `~/.config/secrt/config.toml`. This is intentional — without explicit opt-in, the CLI will not trigger OS-level credential prompts.

When enabled, the keychain can store your API key, default passphrase, and decryption passphrase list. The resolution order is:

1. CLI flags (e.g., `--api-key`, `--passphrase-prompt`)
2. Environment variables (e.g., `SECRET_API_KEY`)
3. Keychain (if enabled)
4. Config file
5. Built-in defaults

### Why Am I Getting Password Prompts?

If you are seeing OS-level password prompts (macOS Keychain Access dialog, Windows credential prompt), it means:

1. **Keychain is enabled** in your config (`use_keychain = true`).
2. **Your OS credential store requires authorization** to access stored secrets.

**To stop the prompts:**
- Set `use_keychain = false` in `~/.config/secrt/config.toml` (or remove the line — it defaults to `false`).
- Alternatively, on macOS, you can grant the `secrt` binary "Always Allow" access in Keychain Access.

**If you are not seeing prompts but expected to:** Keychain integration is off by default. Enable it with `use_keychain = true` and store credentials with `secrt config set-passphrase`.

---

## Signed Binary Releases

Every secrt CLI release is code-signed and published with SHA-256 checksums. The release pipeline is fully automated via GitHub Actions.

### macOS Code Signing & Notarization

macOS binaries are signed with an Apple Developer ID certificate and notarized through Apple's notary service:

1. **Code signing:** Each binary (ARM64, Intel, and a universal binary created via `lipo`) is signed with `codesign` using a Developer ID Application certificate, with hardened runtime (`--options runtime`) and a trusted timestamp (`--timestamp`).
2. **Notarization:** All three binaries are submitted to Apple's notary service via `xcrun notarytool`. Apple scans the binaries and, upon approval, issues a notarization ticket that allows the binaries to pass Gatekeeper without warnings.
3. **Verification:** After signing, `codesign --verify` confirms the signature is valid.

This means macOS users can run the binary without Gatekeeper quarantine warnings or needing to bypass security prompts.

### Windows Code Signing

Windows binaries are signed using Azure Trusted Signing (formerly Azure Code Signing) with a publicly trusted certificate:

- The certificate is issued through Azure's Trusted Signing service and is recognized by Windows SmartScreen.
- Signing is performed in CI using the `azure/trusted-signing-action` GitHub Action.
- Signed binaries will not trigger SmartScreen warnings for most users.

### Verification & Checksums

Every release includes a `secrt-checksums-sha256.txt` file containing SHA-256 hashes of all binaries:

```
<hash>  secrt-darwin-arm64
<hash>  secrt-darwin-amd64
<hash>  secrt-darwin-universal
<hash>  secrt-linux-amd64
<hash>  secrt-linux-arm64
<hash>  secrt-windows-amd64.exe
<hash>  secrt-windows-arm64.exe
```

Users can verify downloads with:

```bash
sha256sum -c secrt-checksums-sha256.txt
```

Release artifacts are available on the [GitHub Releases page](https://github.com/getsecrt/secrt/releases).

See: [`.github/workflows/release-cli.yml`](https://github.com/getsecrt/secrt/blob/main/.github/workflows/release-cli.yml)

### Why Use the CLI for Sensitive Exchanges

For highly sensitive exchanges that demand the utmost confidence in transmission integrity, we recommend using the signed CLI binaries rather than the web interface.

The web application provides an excellent user experience and uses the same cryptographic protocol. However, browser-based JavaScript has a larger attack surface:

- **Supply chain risk.** The JavaScript served by the web server could theoretically be modified (by a compromised server, CDN, or browser extension) to exfiltrate keys before encryption.
- **Browser extension interference.** Malicious or compromised browser extensions can inspect page content, modify DOM elements, or intercept WebCrypto calls.
- **No binary verification.** Users cannot easily verify that the JavaScript running in their browser matches the published source code.

The CLI binary eliminates these risks:
- **Signed and verifiable.** macOS binaries are notarized by Apple; Windows binaries are signed with a trusted certificate. You can verify the binary's integrity and provenance.
- **No runtime code loading.** The binary is a static, compiled artifact. There is no code download at runtime.
- **Checksum verification.** SHA-256 checksums allow you to verify the binary matches exactly what was built in CI.
- **Open source build.** The [release workflow](https://github.com/getsecrt/secrt/blob/main/.github/workflows/release-cli.yml) is public — you can inspect exactly how binaries are built and signed.

For most users, the web application is perfectly adequate. For exchanging production database credentials, root certificates, or other high-value secrets, the CLI provides the strongest guarantees.

---

## Web Application

The web frontend is built with [Preact](https://preactjs.com/) + TypeScript, bundled by [Vite](https://vitejs.dev/), and styled with [Tailwind CSS](https://tailwindcss.com/).

All cryptographic operations use the browser's native [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) — no external JavaScript crypto libraries are used. Compression uses zstd via a [WebAssembly module](https://github.com/nicolo-ribaudo/nicolo-ribaudo/nicolo-ribaudo) that runs entirely in the browser.

The encryption and decryption flow is identical to the CLI: the same envelope format, the same key derivation, the same compression policy. A secret created in the browser can be decrypted by the CLI and vice versa.

Source: [`web/`](https://github.com/getsecrt/secrt/tree/main/web)

---

## Specification & Test Vectors

The protocol is defined by a versioned specification at [`spec/v1/`](https://github.com/getsecrt/secrt/tree/main/spec/v1):

| Document | Purpose |
|----------|---------|
| [`envelope.md`](https://github.com/getsecrt/secrt/blob/main/spec/v1/envelope.md) | Client-side crypto workflow, key derivation, payload framing, compression |
| [`api.md`](https://github.com/getsecrt/secrt/blob/main/spec/v1/api.md) | HTTP API contract, endpoints, authentication, error semantics, policy tiers |
| [`server.md`](https://github.com/getsecrt/secrt/blob/main/spec/v1/server.md) | Server runtime behavior, middleware, storage, reaper, rate limiting |
| [`cli.md`](https://github.com/getsecrt/secrt/blob/main/spec/v1/cli.md) | CLI interface contract, commands, TTL grammar, output discipline |
| [`openapi.yaml`](https://github.com/getsecrt/secrt/blob/main/spec/v1/openapi.yaml) | OpenAPI 3.1 machine-readable schema |

**Test vectors are mandatory.** The specification includes:

- **7 cryptographic test vectors** ([`envelope.vectors.json`](https://github.com/getsecrt/secrt/blob/main/spec/v1/envelope.vectors.json)) covering text with and without passphrase, file metadata encryption, compression, and pre-compressed file detection.
- **34 TTL parsing vectors** ([`cli.vectors.json`](https://github.com/getsecrt/secrt/blob/main/spec/v1/cli.vectors.json)) — 17 valid and 17 invalid inputs.
- **API key derivation vectors** ([`apikey.vectors.json`](https://github.com/getsecrt/secrt/blob/main/spec/v1/apikey.vectors.json)) for v2 key format.

Every implementation — Rust CLI, Rust server, TypeScript web client — must pass all test vectors. When spec and code disagree, code is fixed to match the spec (or the spec is updated first with rationale, then code is updated in the same changeset).

The specification is meticulously maintained and rigidly adhered to. It is the normative contract for all behavior.

---

## Data Residency

secrt's production infrastructure is hosted in **Toronto, Canada** on [DigitalOcean](https://www.digitalocean.com/).

Canada has strong privacy protections under the [Personal Information Protection and Electronic Documents Act (PIPEDA)](https://laws-lois.justice.gc.ca/eng/acts/p-8.6/) and the [Privacy Act](https://laws-lois.justice.gc.ca/eng/acts/p-21/). Canadian privacy law is generally considered more protective than US law, particularly with respect to government access to data:

- Canada's PIPEDA requires consent for collection, use, and disclosure of personal information.
- Canadian law enforcement access to data generally requires a warrant.
- Canada is not subject to US laws like the PATRIOT Act or CLOUD Act that can compel disclosure of data stored by US companies.

That said, secrt's zero-knowledge architecture means that even with lawful access to the database, no plaintext can be recovered. The server stores only ciphertext that cannot be decrypted without the URL key, which is never transmitted to or stored on the server.

---

## FAQ

### How can I trust you?

You don't have to take our word for it. The entire codebase is [open source](https://github.com/getsecrt/secrt), including the cryptographic specification and test vectors. You can:

- **Audit the code.** Every line of the client-side encryption, server storage, and API is publicly available.
- **Verify the crypto.** The specification includes [test vectors](https://github.com/getsecrt/secrt/tree/main/spec/v1) that you can independently verify against the implementation.
- **Run your own instance.** The server and web client can be self-hosted. You don't need to trust our infrastructure at all.
- **Use the CLI.** The signed CLI binary performs all encryption locally on your machine. You can verify its integrity via code signature and SHA-256 checksums.

The zero-knowledge design means you do not need to trust the server operator. Even if the server is compromised, your secrets remain encrypted with keys the server never had.

### How do I know this is safe?

The cryptographic primitives used (AES-256-GCM, HKDF-SHA-256, PBKDF2) are industry-standard algorithms used by governments, financial institutions, and security-critical systems worldwide. We do not use any custom or novel cryptography.

The implementation uses well-audited libraries: [`ring`](https://github.com/briansmith/ring) for Rust and the browser's native [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) for JavaScript. These are among the most scrutinized cryptographic implementations available.

The protocol specification includes mandatory test vectors that are checked in every build. The CI pipeline runs `cargo test --workspace` and `cargo clippy -- -D warnings` on every commit.

### Were AI or LLMs used in creating this application?

Yes, and we are transparent about this. AI assistants (Claude) were used extensively throughout the development process, including for:

- Code generation and review
- Specification drafting and refinement
- Test vector generation
- Documentation writing (including this whitepaper)

All AI-generated code was reviewed, tested against the specification's test vectors, and verified by human developers. The cryptographic design was informed by established best practices, not invented by AI. The use of AI accelerated development while maintaining the same standards of correctness and security that would apply to any human-written code.

### Does secrt work with Tor?

Yes. The secrt server is accessible over Tor, and the API works normally through Tor exit nodes.

However, for maximum privacy when using Tor, we recommend using the **CLI application** rather than the web interface. The Tor Browser project generally [recommends against enabling JavaScript](https://tb-manual.torproject.org/security-settings/) at the highest security level, and the web application requires JavaScript for client-side encryption.

The CLI performs all encryption locally and communicates with the server over simple HTTPS API calls, making it fully compatible with Tor (via `torsocks` or by configuring a SOCKS proxy).

```bash
torsocks secrt send --text "secret message"
```

Note that rate limiting is per-IP, so requests through Tor exit nodes may share rate limit buckets with other Tor users using the same exit node.

### Why do you allow making accounts?

Accounts are entirely optional. You can create and share secrets without ever registering.

Accounts exist for three reasons:
1. **Higher limits.** Authenticated users get 1,000 active secrets and 20 MiB of storage (vs. 10 secrets and 2 MiB for anonymous users). This supports legitimate use cases like sharing large files or using secrt in automated workflows.
2. **API keys.** Accounts let you generate API keys for CLI automation, CI/CD integration, and scripting.
3. **Secret management.** API keys enable burning (destroying) your own secrets before they are claimed.

Accounts do not affect the zero-knowledge property. The server cannot decrypt your secrets regardless of whether you are authenticated.

### What is a passkey? Why no passwords?

A [passkey](https://passkeys.dev/) is a modern, phishing-resistant authentication credential based on the [WebAuthn/FIDO2 standard](https://fidoalliance.org/fido2/). Instead of typing a password, you authenticate using your device's biometric sensor (fingerprint, face), a PIN, or a hardware security key (like a [YubiKey](https://www.yubico.com/)).

We chose passkeys over passwords because they are strictly more secure:

- **No phishing.** Passkeys are cryptographically bound to the website's origin. They cannot be phished or replayed on a different site.
- **No password reuse.** There is no password to reuse from a compromised service.
- **No credential stuffing.** Without passwords, there is nothing for attackers to stuff.
- **Hardware-backed.** Users with YubiKeys or other FIDO2 tokens get the strongest possible authentication — private keys that never leave the physical device.

If your device supports passkeys (most modern devices do), you already have everything you need.

### Are there desktop GUI apps or mobile apps?

Not yet. Currently, secrt is available as:
- A **web application** at [secrt.ca](https://secrt.ca)
- A **CLI application** for macOS, Windows, and Linux

We have plans for native desktop and mobile applications if demand warrants it. The CLI covers most automation and power-user workflows, and the web application works on all devices including mobile browsers.

### Where is my data stored?

Production data is stored on DigitalOcean servers in **Toronto, Canada**. See [Data Residency](#data-residency) for details on Canadian privacy protections.

Remember that the "data" stored is exclusively encrypted ciphertext that the server cannot decrypt. Even in the event of a data breach, no plaintext would be exposed.

### What happens if secrt goes down?

If the server is unavailable, existing share links cannot be claimed until the server is restored. However:

- Secrets are protected by their TTL. If the server is down past a secret's expiry, the secret is automatically deleted when the server comes back online.
- No plaintext is at risk during downtime — the server only stores ciphertext.
- The protocol and codebase are open source, so you can self-host an instance as a backup.

---

## Contact & Responsible Disclosure

For security concerns, vulnerability reports, or questions about our architecture:

**security@secrt.ca**

We take all security reports seriously and will respond promptly. If you discover a vulnerability, please disclose it responsibly via email before any public disclosure.

For general questions and feature requests, please open an issue on [GitHub](https://github.com/getsecrt/secrt/issues).
