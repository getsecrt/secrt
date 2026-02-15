# secrt White Paper

**Zero-Knowledge One-Time Secret Sharing**

Version 1.1 — February 2026

---

## Abstract

secrt is a zero-knowledge, one-time secret sharing service that allows individuals and organizations to share passwords, API keys, credentials, files, and other sensitive information through links that self-destruct after a single use. All encryption happens on the sender's device — in the browser or on the command line — before any data reaches the server. The server stores only opaque ciphertext that it cannot decrypt, and never sees plaintext, encryption keys, passphrases, or even filenames.

The project is fully open source, built on a rigorous versioned [specification](https://github.com/getsecrt/secrt/tree/main/spec/v1) with mandatory test vectors, and uses only industry-standard cryptographic primitives (AES-256-GCM, HKDF-SHA-256, PBKDF2). It offers signed CLI binaries for macOS and Windows, a web application, passkey-based authentication (no passwords), and a self-hostable architecture where the zero-knowledge property means operators get the same security guarantees as the hosted service.

This white paper describes the threat model, cryptographic architecture, server design, abuse prevention mechanisms, and specification philosophy behind secrt.

**Repository:** [github.com/getsecrt/secrt](https://github.com/getsecrt/secrt)

---

## Table of Contents

1. [Abstract](#abstract)
2. [Problem Statement](#problem-statement)
3. [Solution Overview](#solution-overview)
4. [Competitive Landscape](#competitive-landscape)
5. [Threat Model & Design Goals](#threat-model--design-goals)
6. [Cryptographic Architecture](#cryptographic-architecture)
7. [Server Architecture](#server-architecture)
8. [Abuse Prevention](#abuse-prevention)
9. [Account System & Authentication](#account-system--authentication)
10. [Clients](#clients)
    - [CLI Application](#cli-application)
    - [Signed Binary Releases](#signed-binary-releases)
    - [Web Application](#web-application)
11. [Specification & Test Vectors](#specification--test-vectors)
12. [Self-Hosting](#self-hosting)
13. [Data Residency](#data-residency)
14. [FAQ](#faq)
15. [Contact & Responsible Disclosure](#contact--responsible-disclosure)
16. [Appendices](#appendices)

---

## Problem Statement

Every day, teams share credentials through channels never designed for secrets: Slack messages, email threads, SMS, sticky notes, shared documents. These channels persist data indefinitely, are searchable, are backed up to third-party servers, and are routinely accessed by administrators, compliance tools, and — in breach scenarios — attackers.

The consequences are well-documented. Credential exposure through messaging platforms is a leading vector in data breaches. A password shared in a Slack DM six months ago is still sitting in Slack's search index, in the company's Slack export archive, and on every device that synced that conversation. The sender has no way to revoke it.

The problem is not that people are careless — it's that the tools they reach for are optimized for convenience, not security. Sharing a database password should be as easy as sending a message, but the result should be ephemeral, encrypted, and verifiable.

Existing solutions fall short in various ways: some encrypt server-side (the server sees your plaintext), some lack a formal specification (making independent auditing difficult), some require complex infrastructure to self-host, and most lack the supply chain integrity of signed, verifiable binaries.

secrt addresses this gap with a zero-knowledge architecture where the server is cryptographically unable to access shared secrets, combined with an open specification, signed binaries, and a self-hostable design.

---

## Solution Overview

secrt works by performing all encryption on the client before any data leaves the sender's device:

1. **The sender** creates a secret (text, file, or binary data). The client generates a random 32-byte key, encrypts the content with AES-256-GCM, and uploads only the opaque ciphertext to the server.
2. **The share link** embeds the encryption key in the URL fragment (the part after `#`), which browsers never transmit over the network. The server never sees this key.
3. **The recipient** opens the link. The client extracts the key from the URL fragment, retrieves the ciphertext from the server (which atomically deletes it), and decrypts locally.
4. **The secret is gone.** After one retrieval, the ciphertext is permanently deleted from the server. There is no second chance, no recovery, no admin override.

An optional passphrase adds a second factor: even if the link is intercepted, the attacker must also know the passphrase (communicated via a separate channel) to decrypt.

<!-- TODO: Architecture diagram placeholder — visual showing client-side encryption flow, URL fragment separation, and server storing only ciphertext -->

---

## Competitive Landscape

Several tools address secret sharing. Here is how secrt compares:

| Feature | secrt | OneTimeSecret | Yopass | PrivateBin | HashiCorp Vault |
|---------|-------|---------------|--------|------------|-----------------|
| Zero-knowledge (client-side encryption) | ✅ | ❌ Server-side | ✅ | ✅ | ❌ Server-managed |
| One-time retrieval | ✅ | ✅ | ✅ (configurable) | Optional | N/A |
| Open specification with test vectors | ✅ | ❌ | ❌ | ❌ | ❌ |
| Signed binary CLI | ✅ (macOS notarized, Windows signed) | ❌ | CLI available (unsigned) | ❌ | ✅ |
| Passkey auth (no passwords) | ✅ | ❌ (email/password) | ❌ (no accounts) | ❌ (no accounts) | ❌ (tokens/LDAP/etc.) |
| File sharing | ✅ | ❌ | ✅ | ✅ | N/A |
| Self-hostable | ✅ | ✅ | ✅ | ✅ | ✅ |
| Passphrase protection | ✅ (PBKDF2, 600k rounds) | ✅ | ❌ | ✅ (password) | N/A |

<!-- TODO: Verify OneTimeSecret still lacks client-side encryption — the GitHub issue #190 from 2020 requested it but it may have been added since. -->
<!-- TODO: Verify Yopass doesn't support passphrase protection — their docs mention "encryption key" but it may function differently. -->

**What makes secrt different:**

- **Open specification.** The protocol is defined by a versioned spec with mandatory test vectors. Anyone can build a compatible client or audit the cryptographic design without reading implementation code. No other tool in this space publishes a formal specification.
- **Signed binaries.** macOS binaries are Apple-notarized; Windows binaries are signed via Azure Trusted Signing. Users can verify binary integrity and provenance — important for a security tool.
- **Passkey authentication.** No passwords are stored or transmitted. Authentication uses WebAuthn/FIDO2, which is phishing-resistant by design.
- **Zero-knowledge with metadata encryption.** Filenames, MIME types, and content type indicators are encrypted inside the payload. The server doesn't know if you shared text or a file.
- **No password storage at all.** API keys use a derived-key architecture where the server stores only an HMAC hash — even database access cannot reconstruct the original key.

HashiCorp Vault is included for context but serves a fundamentally different purpose: it is an infrastructure secrets management system for machines, not a tool for humans to share one-time secrets with each other.

---

## Threat Model & Design Goals

secrt is designed to protect shared secrets against:

- **Server compromise.** Even with full database access, an attacker obtains only ciphertext that cannot be decrypted without the URL key (which the server never receives).
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
| Compression | zstd (level 3) | zstd crate / [@bokuweb/zstd-wasm](https://github.com/bokuweb/zstd-wasm) |
| Encoding | base64url (no padding, RFC 4648) | base64 crate / browser btoa |

Key constants are defined in [`crates/secrt-core/src/types.rs`](https://github.com/getsecrt/secrt/blob/main/crates/secrt-core/src/types.rs). See [Appendix A](#appendix-a-key-constants) for the full table.

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

At creation time, the client sends only the `claim_hash` to the server. At retrieval time, the client derives the `claim_token` from the URL key and sends it. The server computes `SHA-256(claim_token)` and compares it to the stored `claim_hash`. This ensures:

- The server stores only a hash of the claim token, not the token itself.
- Even with database access, an attacker cannot forge a valid claim token.

### Payload Frame & Compression

Before encryption, the plaintext is wrapped in a binary frame that carries metadata (content type, filename, MIME type) and supports optional zstd compression. Because this metadata is inside the encrypted frame, the server never knows whether you shared a text snippet, a file, or binary data.

Large payloads are compressed with [zstd](https://facebook.github.io/zstd/) (level 3) before encryption. Compression is skipped for small content (< 2 KiB) and pre-compressed formats (PNG, JPEG, ZIP, etc.), and the compressed form is only used if it saves meaningful space (≥ 64 bytes and ≥ 10%). Decompression validates against the declared size to prevent decompression bombs (max 100 MiB).

See [Appendix B](#appendix-b-payload-frame-format) for the full byte-level frame specification.

### The Envelope Format

The envelope is the JSON object stored on the server. It is opaque to the server — treated as a blob that is stored and returned unchanged. It contains the ciphertext, nonce, and key derivation parameters needed to reconstruct the decryption key (given the URL key and optional passphrase). This makes the format portable — any compliant implementation can decrypt a secret created by any other.

Top-level metadata fields like `hint`, `filename`, `mime`, or `type` are forbidden in the envelope JSON. All metadata is encrypted inside the ciphertext as part of the payload frame. Unknown fields are allowed for forward compatibility.

See [Appendix C](#appendix-c-envelope-json-format) for the full envelope JSON schema and [`spec/v1/envelope.md`](https://github.com/getsecrt/secrt/blob/main/spec/v1/envelope.md).

### Encryption & Decryption Flow

**Encryption (sender):**

1. Generate random 32-byte `url_key`.
2. If passphrase set: derive `pass_key` via PBKDF2, compute `ikm = SHA-256(url_key || pass_key)`. Otherwise: `ikm = url_key`.
3. Generate random 32-byte HKDF salt.
4. Derive `enc_key = HKDF-SHA-256(ikm, salt, "secrt:v1:enc:sealed-payload", 32)`.
5. Build payload frame (metadata + optional compression + content).
6. Generate random 12-byte nonce.
7. Encrypt: `ciphertext = AES-256-GCM-SEAL(enc_key, nonce, frame_bytes, AAD)`.
8. Derive claim hash from `url_key`.
9. Build envelope JSON; send `{envelope, claim_hash, ttl_seconds}` to server; embed `url_key` in share link fragment.

**Decryption (recipient):**

1. Parse share URL to extract secret ID and `url_key` from fragment.
2. Derive `claim_token` from `url_key` via HKDF.
3. Send `{claim: base64url(claim_token)}` to server.
4. Server atomically returns envelope and deletes the secret.
5. Derive `enc_key` from `url_key` (and passphrase if required) + envelope's HKDF salt.
6. Decrypt: `frame_bytes = AES-256-GCM-OPEN(enc_key, nonce, ciphertext, AAD)`.
7. Validate frame, decompress if needed, parse metadata, return plaintext.

### Zero-Knowledge Property

The zero-knowledge property is the central design constraint. The server receives and stores only opaque ciphertext, claim hashes, expiry timestamps, and owner keys (hashed IPs or API key prefixes). It never sees or stores URL keys, plaintext, passphrases, encryption keys, claim tokens, filenames, MIME types, or raw IP addresses.

An attacker who gains full database access obtains only ciphertext envelopes. To decrypt any secret, they would need the `url_key` from the share link's URL fragment, which was never sent to the server. There is no key escrow, no recovery mechanism, and no server-side decryption capability by design.

---

## Server Architecture

The server is built with [Axum](https://github.com/tokio-rs/axum) (async Rust HTTP framework) backed by PostgreSQL. Its role is strictly limited to storing and serving ciphertext — it performs no cryptographic operations on secret content.

Source: [`crates/secrt-server/`](https://github.com/getsecrt/secrt/tree/main/crates/secrt-server)

### Database Design

The database stores minimal data: ciphertext blobs, claim hashes, expiry timestamps, owner keys, and account records. No personally identifiable information (email, phone, real name) is collected. API key root secrets are never stored — only HMAC-derived hashes.

See [Appendix D](#appendix-d-database-schema) for the full schema.

### Atomic One-Time Claim

The claim operation is the most security-critical path. It must guarantee that a secret is returned at most once, even under concurrent requests. This is implemented as a single atomic SQL statement that combines verification, retrieval, and deletion:

```sql
DELETE FROM secrets
WHERE id = $1 AND claim_hash = $2 AND expires_at > $3
RETURNING envelope::text, expires_at, created_at, owner_key
```

If the ID doesn't exist, the claim hash doesn't match, or the secret has expired: zero rows affected, return `404`. If successful: the envelope is returned and simultaneously deleted. All failure modes return an identical `404` response, preventing information leakage about secret existence.

See: [`crates/secrt-server/src/storage/postgres.rs`](https://github.com/getsecrt/secrt/blob/main/crates/secrt-server/src/storage/postgres.rs)

### Background Reaper

A background task runs every 5 minutes to clean up expired secrets, WebAuthn challenges, sessions, and stale API key registration records. The reaper is best-effort housekeeping — the claim query's `expires_at > now` check is the authoritative TTL enforcement.

### IP Privacy & Hashing

Raw client IP addresses are never persisted to the database and never stored in plaintext in process memory.

- **Rate limiting:** IPs are HMAC-SHA-256 hashed with a per-process random key generated at startup. A background garbage collector sweeps stale rate-limit buckets every 2 minutes.
- **Quota tracking:** The `owner_key` column stores `ip:<hmac_hash>` for anonymous requests — never the raw IP. Because the HMAC key is per-process and ephemeral, these hashes cannot be correlated across server restarts.
- **Proxy trust:** The server trusts `X-Forwarded-For` only from loopback addresses (127.0.0.1 or ::1), indicating a trusted local reverse proxy.

### Reverse Proxy & Privacy Logging

In production, secrt runs behind a reverse proxy configured with privacy-preserving logging: IPv4 masked to /24, IPv6 masked to /48, User-Agent and Referer stripped, query strings stripped, cookies and Authorization headers redacted.

See: [`docs/caddy-privacy-logging.md`](https://github.com/getsecrt/secrt/blob/main/docs/caddy-privacy-logging.md)

---

## Abuse Prevention

### Rate Limiting

Rate limiting uses in-memory token buckets with HMAC-hashed keys (raw IPs never stored):

| Endpoint | Rate | Burst | Key |
|----------|------|-------|-----|
| Public secret creation | 0.5 rps | 6 | HMAC(client IP) |
| Secret claiming | 1.0 rps | 10 | HMAC(client IP) |
| Authenticated creation | 2.0 rps | 20 | `user:<uuid>` (session) or `apikey:<prefix>` (API key) |
| API key registration | 0.5 rps | 6 | HMAC(client IP) |

All rate limits are configurable per deployment.

### Per-Owner Quotas

| Limit | Anonymous | Authenticated |
|-------|-----------|---------------|
| Max active secrets | 10 | 1,000 |
| Max active bytes (total) | 2 MiB | 20 MiB |
| Max single envelope | 256 KiB | 1 MiB |

Quota checks are enforced atomically within a PostgreSQL transaction using advisory locks to prevent TOCTOU race conditions. API key registration has additional rolling-window quotas: 5 keys per hour and 20 per day.

### Input Validation & Error Opacity

- All API endpoints require `Content-Type: application/json`; JSON deserialization rejects unknown fields.
- Claim token values must base64url-decode to exactly 32 bytes.
- All claim, burn, and lookup failures return identical `404` responses — the server never reveals whether a secret existed, expired, was already claimed, or had the wrong token.
- Security headers: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Cache-Control: no-store`.

See: [`spec/v1/api.md`](https://github.com/getsecrt/secrt/blob/main/spec/v1/api.md), [`spec/v1/server.md`](https://github.com/getsecrt/secrt/blob/main/spec/v1/server.md)

---

## Account System & Authentication

### Why Accounts Exist

secrt allows creating and sharing secrets without any account. The account system exists for three specific reasons:

1. **API key management.** Accounts allow users to generate API keys for automated workflows, CI/CD pipelines, and CLI usage with higher limits.
2. **Higher quotas.** Authenticated users get significantly higher storage limits (1,000 secrets / 20 MiB vs. 10 secrets / 2 MiB).
3. **Secret management.** API keys enable burning (destroying) secrets before they are claimed.

Accounts do not unlock any decryption capability — the zero-knowledge property holds regardless of authentication status.

### Passkey Authentication (No Passwords)

secrt uses [WebAuthn passkeys](https://passkeys.dev/) exclusively for authentication. There are no passwords. This is more secure than password-based authentication:

- **Phishing-resistant.** Passkeys are bound to the origin at the protocol level.
- **No password reuse risk.** No credential stuffing possible.
- **Hardware-backed option.** YubiKeys and other FIDO2 tokens provide the strongest authentication — private keys never leave the device.
- **Platform support.** macOS/iOS via iCloud Keychain, Windows via Windows Hello, Android via Google Password Manager, cross-platform via hardware security keys.

### Privacy-Friendly Nicknames

No email, phone number, or real name is required. secrt auto-generates random, friendly display names from an adjective-animal combination (e.g., "Swift Falcon", "Quiet Otter") with approximately 2,500 unique combinations.

### API Key v2 Architecture

API keys use a derived-key architecture that prevents the server from ever storing the root secret:

- **Client stores:** `sk2_<prefix>.<root_key_base64>` (the root key never leaves the client)
- **Wire format:** `ak2_<prefix>.<auth_token_base64>` (derived via HKDF from the root key)
- **Server stores:** Only a peppered HMAC hash of the auth token — even with database access and the pepper, the original key cannot be reconstructed.

See [Appendix E](#appendix-e-api-key-v2-derivation) for the full derivation and [`spec/v1/api.md`](https://github.com/getsecrt/secrt/blob/main/spec/v1/api.md).

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

## Clients

### CLI Application

The secrt CLI ([`crates/secrt-cli/`](https://github.com/getsecrt/secrt/tree/main/crates/secrt-cli)) is a single static binary (~1.5 MB) with no runtime dependencies. Design principles:

- **Minimal dependencies.** Uses `ring` for crypto, `ureq` for blocking HTTP, hand-rolled argument parsing (no clap).
- **No async runtime.** Blocking I/O keeps the control flow simple and predictable.
- **Config file safety.** On Unix, config files are created with `0600` permissions; the CLI warns if group/world-readable.
- **Piping and scripting.** Supports JSON output (`--json`), stdin input, and non-interactive modes.
- **Implicit URL detection.** Running `secrt https://secrt.ca/s/abc#key` automatically runs the `get` command.

**Keychain integration** (opt-in via `use_keychain = true` in config) supports macOS Keychain, Windows Credential Manager, and Linux Secret Service. Resolution order: CLI flags → environment variables → keychain → config file → defaults.

### Signed Binary Releases

Every release is code-signed and published with SHA-256 checksums:

- **macOS:** Signed with a Developer ID certificate and notarized through Apple's notary service. Passes Gatekeeper without warnings.
- **Windows:** Signed via Azure Trusted Signing with a publicly trusted certificate. No SmartScreen warnings.
- **Verification:** Every release includes `secrt-checksums-sha256.txt` for integrity verification. Release artifacts are on the [GitHub Releases page](https://github.com/getsecrt/secrt/releases).

See: [`.github/workflows/release-cli.yml`](https://github.com/getsecrt/secrt/blob/main/.github/workflows/release-cli.yml)

**Why use the CLI for sensitive exchanges?** The web application provides an excellent user experience and uses the same protocol. However, for highly sensitive secrets, the CLI offers stronger guarantees: signed and verifiable binaries, no runtime code loading, no browser extension interference, and no supply chain risk from served JavaScript. For most users, the web application is perfectly adequate. For production database credentials or root certificates, the CLI provides the strongest guarantees.

### Web Application

The web frontend is built with [Preact](https://preactjs.com/) + TypeScript, bundled by [Vite](https://vitejs.dev/), styled with [Tailwind CSS](https://tailwindcss.com/). All cryptographic operations use the browser's native [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). Compression uses zstd via a [WebAssembly module](https://github.com/bokuweb/zstd-wasm) that runs entirely in the browser.

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

- **5 cryptographic test vectors** ([`envelope.vectors.json`](https://github.com/getsecrt/secrt/blob/main/spec/v1/envelope.vectors.json)) covering text with and without passphrase, file metadata encryption, compression, and pre-compressed file detection.
- **35 TTL parsing vectors** ([`cli.vectors.json`](https://github.com/getsecrt/secrt/blob/main/spec/v1/cli.vectors.json)) — 17 valid and 18 invalid inputs.
- **API key derivation vectors** ([`apikey.vectors.json`](https://github.com/getsecrt/secrt/blob/main/spec/v1/apikey.vectors.json)) for v2 key format.

Every implementation — Rust CLI, Rust server, TypeScript web client — must pass all test vectors. When spec and code disagree, code is fixed to match the spec (or the spec is updated first with rationale, then code is updated in the same changeset).

---

## Self-Hosting

secrt is fully open source and designed to be self-hosted. The repository at [github.com/getsecrt/secrt](https://github.com/getsecrt/secrt) contains the complete server, web client, CLI, and specification.

Because of the zero-knowledge architecture, self-hosting provides the same security guarantees as the hosted service at secrt.ca. The server never has access to encryption keys or plaintext regardless of who operates it. Self-hosters gain additional benefits:

- **Data sovereignty.** Complete control over where ciphertext is stored.
- **Custom policy.** Configure rate limits, quotas, TTL maximums, and other operational parameters for your organization's needs.
- **Network isolation.** Run secrt on an internal network with no public internet exposure.
- **Auditability.** Full access to server logs, database contents, and infrastructure configuration.

<!-- TODO: Add link to self-hosting guide / docker-compose setup once available -->

---

## Data Residency

secrt's production infrastructure is hosted in **Toronto, Canada** on [DigitalOcean](https://www.digitalocean.com/).

Canada has strong privacy protections under [PIPEDA](https://laws-lois.justice.gc.ca/eng/acts/p-8.6/) and the [Privacy Act](https://laws-lois.justice.gc.ca/eng/acts/p-21/). Canadian privacy law is generally considered more protective than US law — Canadian law enforcement access to data generally requires a warrant, and Canada is not subject to US laws like the PATRIOT Act or CLOUD Act.

That said, secrt's zero-knowledge architecture means that even with lawful access to the database, no plaintext can be recovered.

---

## FAQ

### How can I trust you?

You don't have to. The entire codebase is [open source](https://github.com/getsecrt/secrt), including the specification and test vectors. You can audit the code, verify the crypto against test vectors, run your own instance, or use the signed CLI binary with checksum verification. The zero-knowledge design means you do not need to trust the server operator.

### How do I know this is safe?

The cryptographic primitives (AES-256-GCM, HKDF-SHA-256, PBKDF2) are industry-standard. The implementation uses well-audited libraries: [`ring`](https://github.com/briansmith/ring) for Rust and the browser's native WebCrypto API. The CI pipeline runs full test suites including spec test vectors on every commit.

### Were AI or LLMs used in creating this application?

Yes, and we are transparent about this. AI assistants (Claude) were used extensively throughout the development process, including for code generation and review, specification drafting and refinement, test vector generation, and documentation writing (including this white paper).

All AI-generated code was reviewed, tested against the specification's test vectors, and verified by human developers. The cryptographic design was informed by established best practices, not invented by AI. The use of AI accelerated development while maintaining the same standards of correctness and security that would apply to any human-written code.

### Does secrt work with Tor?

Yes. For maximum privacy, use the CLI rather than the web application (Tor Browser recommends disabling JavaScript at the highest security level). The CLI works via `torsocks secrt send --text "secret message"`. Note that rate limiting is per-IP, so Tor exit nodes may share buckets.

### What is a passkey?

A [passkey](https://passkeys.dev/) is a modern, phishing-resistant credential based on [WebAuthn/FIDO2](https://fidoalliance.org/fido2/). You authenticate using biometrics, a PIN, or a hardware security key instead of a password. Most modern devices support passkeys natively.

### Are there desktop GUI apps or mobile apps?

Not yet. secrt is currently available as a [web application](https://secrt.ca) and a CLI for macOS, Windows, and Linux. Native apps may follow if demand warrants it.

### What happens if secrt goes down?

Existing share links cannot be claimed until the server is restored. Secrets past their TTL are automatically deleted when the server comes back online. No plaintext is at risk — the server only stores ciphertext. The open-source codebase means you can self-host as a backup.

---

## Contact & Responsible Disclosure

For security concerns, vulnerability reports, or questions about our architecture:

**security@secrt.ca**

We take all security reports seriously and will respond promptly. If you discover a vulnerability, please disclose it responsibly via email before any public disclosure.

For general questions and feature requests, please open an issue on [GitHub](https://github.com/getsecrt/secrt/issues).

---

## Appendices

### Appendix A: Key Constants

Constants defined in [`crates/secrt-core/src/types.rs`](https://github.com/getsecrt/secrt/blob/main/crates/secrt-core/src/types.rs):

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

### Appendix B: Payload Frame Format

Defined in [`crates/secrt-core/src/payload.rs`](https://github.com/getsecrt/secrt/blob/main/crates/secrt-core/src/payload.rs):

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

Metadata JSON example:

```json
{
  "type": "text",
  "filename": "credentials.txt",
  "mime": "text/plain"
}
```

### Appendix C: Envelope JSON Format

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

### Appendix D: Database Schema

See: [`crates/secrt-server/migrations/001_initial.sql`](https://github.com/getsecrt/secrt/blob/main/crates/secrt-server/migrations/001_initial.sql)

**`secrets`** — Ciphertext storage

| Column | Type | Purpose |
|--------|------|---------|
| `id` | TEXT (PK) | Random 12-character alphanumeric ID |
| `claim_hash` | TEXT | `base64url(SHA-256(claim_token))` — never the token itself |
| `envelope` | JSONB | Opaque ciphertext blob — server does not inspect contents |
| `expires_at` | TIMESTAMPTZ | When the secret expires |
| `created_at` | TIMESTAMPTZ | Creation timestamp |
| `owner_key` | TEXT | `ip:<hmac_hash>` or `apikey:<prefix>` — for quota enforcement only |
| `meta_key_version` | SMALLINT | Reserved for future encrypted metadata key versioning (nullable) |
| `enc_meta` | JSONB | Reserved for future encrypted metadata (nullable) |

**`users`** — Minimal account records (id, display_name, created_at). No PII collected.

**`passkeys`** — WebAuthn credentials (credential_id, public_key, user_id, sign_count, revoked_at).

**`api_keys`** — API key verification (key_prefix, auth_hash, user_id, revoked_at). Root secret never stored.

**`sessions`, `webauthn_challenges`, `api_key_registrations`** — Ephemeral records, automatically cleaned up by the background reaper.

### Appendix E: API Key v2 Derivation

The client derives the auth token from the root key:

```
ROOT_SALT   = SHA-256("secrt-apikey-v2-root-salt")
auth_token  = HKDF-SHA-256(root_key, ROOT_SALT, "secrt-auth", 32)
```

The server verifies via peppered HMAC:

```
message   = "secrt-apikey-v2-verifier" || u16be(len(prefix)) || prefix || auth_token
auth_hash = hex(HMAC-SHA256(API_KEY_PEPPER, message))
```

Compared using constant-time comparison. The `API_KEY_PEPPER` is an environment-only secret never persisted to disk.
