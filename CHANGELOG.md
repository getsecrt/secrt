# Changelog

All notable changes to the secrt monorepo are documented here. Individual crate changelogs track crate-specific changes:

- [secrt-cli](crates/secrt-cli/CHANGELOG.md)
- [secrt-core](crates/secrt-core/CHANGELOG.md)
- [secrt-server](crates/secrt-server/CHANGELOG.md)

## 0.6.0 — 2026-02-13

### Changed

- **Breaking API-key auth format:** authenticated API calls now use v2 wire credentials (`ak2_<prefix>.<auth_b64>`), with local client keys in `sk2_<prefix>.<root_b64>`.
- **Passkey-gated API-key registration:** API-key registration moved to `POST /api/v1/apikeys/register` and now requires a passkey-backed session bearer token (`uss_<sid>.<secret>`).
- **Registration quotas:** dual quota enforcement is now active and configurable per account and per IP, with defaults of `5/hour` and `20/day`.
- **Legacy API key compatibility:** legacy `sk_` authentication paths are removed from server runtime (no backward compatibility).
- **Breaking envelope hard-cut:** v1 envelope internals now use the sealed-payload suite (`v1-pbkdf2-hkdf-aes256gcm-sealed-payload`) with updated AAD/HKDF labels; legacy envelope payloads are intentionally unsupported.
- **Encrypted metadata contract:** advisory metadata (`type`, `filename`, `mime`) moved from plaintext envelope fields into encrypted payload-frame bytes; server operators can no longer read metadata.
- **Compression policy defaults:** client envelope creation now supports zstd framing with defaults `threshold=2048`, `min_savings=64`, `min_savings_ratio=10%`, `level=3`, and `decompress_cap=100 MiB`.
- **Spec contract rewrite:** `spec/v1/envelope.md`, `spec/v1/api.md`, `spec/v1/openapi.yaml`, `spec/v1/server.md`, and `spec/v1/cli.md` are now aligned to sealed payload framing, encrypted metadata-only visibility, and hard-cut non-compatibility semantics.
- **Envelope vectors refresh:** `spec/v1/envelope.vectors.json` now covers `codec=none` and `codec=zstd` flows, passphrase + zstd, encrypted file metadata, and pre-compressed signature skip behavior.

## 0.5.1 — 2026-02-12

### Fixed

- **secrt-server:** Database error logging now includes the full error source chain instead of truncated "db error" messages.

## 0.5.0 — 2026-02-12

### Added

- **secrt-server:** Embedded web assets via `rust-embed` — the server binary is now a single artifact with the frontend baked in. `SECRT_WEB_DIST_DIR` env var overrides embedded assets for development.
- **secrt-server:** GitHub Actions release workflow (`server/v*` tags) — cross-compiles Linux amd64/arm64 musl binaries with embedded web frontend.
- **Web frontend:** Switched from npm to pnpm as the package manager.
- **Docs:** Added `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, and per-crate changelogs.

### Changed

- **secrt-cli:** Expiry timestamps now show relative time with UTC in parentheses instead of converting to local timezone.
- **secrt-cli:** Removed `chrono` dependency — replaced with hand-rolled date math.

## 0.4.1 — 2026-02-11

### Changed

- **Monorepo migration:** Merged `secrt-cli`, `secrt-server` (Go), and `spec` into a unified Cargo workspace. Extracted shared crypto and protocol logic into `secrt-core`.
- **CI:** Unified CI workflow covering all workspace crates.
- **Release:** CLI release tags changed from `v*` to `cli/v*`.

## 0.4.0 — 2026-02-11

### Added

- **secrt-server:** Full Rust rewrite of the Go server — Axum, Postgres, rate limiting, API key auth, secret reaper, admin CLI, and legacy parity.
- **secrt-core:** New shared crate with crypto (`seal`/`open`), types, TTL parsing, URL handling, and `SecretApi` trait.
- **Web frontend:** Vite + Preact scaffold.

### Changed

- **secrt-cli:** Shorter share URLs — dropped `#v1.` prefix from URL fragments.
