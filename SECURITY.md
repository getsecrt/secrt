# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in secrt, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email **security@secrt.ca** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional)

You should receive an acknowledgment within 48 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Scope

The following are in scope for security reports:

- **Cryptographic issues** — weaknesses in the AES-256-GCM, HKDF-SHA256, or PBKDF2 implementation
- **Server-side data leaks** — any path where the server could access or log plaintext, decryption keys, or passphrases
- **Claim atomicity failures** — scenarios where a secret could be read more than once
- **Authentication bypass** — unauthorized access to API-key-protected endpoints
- **Rate limiter bypass** — circumventing per-IP or per-key rate limits
- **Injection attacks** — SQL injection, command injection, or header injection

## Design Principles

secrt is built on a zero-knowledge architecture:

- All encryption and decryption happens client-side
- The server only stores and serves ciphertext
- Decryption keys are never sent to the server (they live in the URL fragment)
- Secrets are atomically claimed and deleted — read-once by design
- No plaintext, passphrases, PINs, or URL fragments are ever logged

## Supported Versions

Security fixes are applied to the latest release only. We recommend always running the most recent version.

| Component | Supported |
|-----------|-----------|
| secrt-cli (latest) | Yes |
| secrt-server (latest) | Yes |
| Legacy Go server | No — deprecated, use the Rust server |
