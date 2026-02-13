# Changelog

## 0.6.1 — 2026-02-13

No `secrt-core` API/behavior changes in this release. Version bump to align workspace at 0.6.1.

## 0.6.0 — 2026-02-13

### Added

- **API key v2 primitives:** new `apikey` module with `sk2_`/`ak2_` parsing, HKDF derivation (`auth_token`, `enc_key`), wire formatting, and structured verifier-message hashing.
- **Spec vectors:** `secrt-core` now validates API-key derivation and verifier outputs against `spec/v1/apikey.vectors.json`.

### Changed

- **Breaking envelope hard-cut:** `seal()`/`open()` now use `v1-pbkdf2-hkdf-aes256gcm-sealed-payload` with updated AAD/HKDF labels and reject legacy plaintext-metadata envelope shapes.
- **Encrypted payload frame:** envelope plaintext is now a framed structure carrying encrypted metadata (`type`, optional `filename`/`mime`) plus body bytes.
- **Compression support:** added zstd codec support with default policy `threshold=2048`, `min_savings=64`, `min_savings_ratio=10%`, `level=3`, and decode cap `100 MiB`.
- **Claim derivation salt:** `derive_claim_token()` now uses fixed domain salt `SHA256("secrt-envelope-v1-claim-salt")` instead of nil/zero salt behavior.
- **No legacy envelope compatibility:** previous pre-frame envelope payload format is intentionally unsupported in 0.6.0.
- **Envelope vectors alignment:** crypto behavior now matches rewritten `spec/v1/envelope.vectors.json` coverage for `none/zstd` codecs and encrypted metadata framing.

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
