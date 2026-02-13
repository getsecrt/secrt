# Changelog

## 0.6.0 — 2026-02-13

### Added

- **API key v2 primitives:** new `apikey` module with `sk2_`/`ak2_` parsing, HKDF derivation (`auth_token`, `enc_key`), wire formatting, and structured verifier-message hashing.
- **Spec vectors:** `secrt-core` now validates API-key derivation and verifier outputs against `spec/v1/apikey.vectors.json`.

## 0.5.1 — 2026-02-12

No changes to secrt-core in this release.

## 0.5.0 — 2026-02-12

No changes to secrt-core in this release.

## 0.4.1 — 2026-02-11

### Added

- **Initial release** as a standalone crate, extracted from `secrt-cli`.
- `seal()` and `open()` — AES-256-GCM encryption/decryption with HKDF-SHA256 key derivation.
- Optional PBKDF2 passphrase-based key derivation.
- `derive_claim_token()` and `hash_claim_token()` — HKDF-based claim token derivation.
- `parse_ttl()` — human-readable TTL string parsing (e.g., `1h`, `3d`, `30m`).
- `parse_share_url()` and `format_share_link()` — share URL construction and parsing.
- `SecretApi` trait — async API client abstraction.
- `Envelope`, `EncBlock`, `HkdfBlock`, and KDF types.
- Deterministic RNG injection for reproducible test vectors.
