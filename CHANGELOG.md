# Changelog

All notable changes to the secrt monorepo are documented here. Individual crate changelogs track crate-specific changes:

- [secrt-cli](crates/secrt-cli/CHANGELOG.md)
- [secrt-core](crates/secrt-core/CHANGELOG.md)
- [secrt-server](crates/secrt-server/CHANGELOG.md)

## 0.12.1 — 2026-02-18

### Added

- **CLI `secrt list` command:** view active secrets in a formatted table with prefix-based burn support for partial IDs.

### Fixed

- **Cross-auth secret visibility:** API key auth now resolves the full owner key set when linked to a user account — secrets created via web UI are visible from CLI and vice versa.

### Changed

- **Web UI polish:** nav menu reorganization, PWA safe area insets, footer styling, login/register redirect preservation.

See [CLI](crates/secrt-cli/CHANGELOG.md) and [server](crates/secrt-server/CHANGELOG.md) changelogs for details.

## 0.12.0 — 2026-02-18

### Added

- **Device authorization flow:** end-to-end CLI-to-browser auth via `secrt auth login` with QR codes, device codes, and secure key generation. Server endpoints, web approval page, and CLI polling all wired together.
- **CLI auth commands:** `auth login`, `auth setup`, `auth status`, `auth logout` for managing API key credentials.
- **QR codes:** share URLs displayed as terminal QR codes (`send --qr`); web frontend shows QR on share result page.
- **Privacy policy and security.txt:** `/privacy` SPA route and `/.well-known/security.txt` per RFC 9116.

See [CLI](crates/secrt-cli/CHANGELOG.md) and [server](crates/secrt-server/CHANGELOG.md) changelogs for details.

## 0.11.0 — 2026-02-17

### Changed

- **Passphrase KDF migration:** hard-cut from the legacy passphrase KDF to Argon2id across spec, core, CLI, server/web frontend, vectors, and tests.
- **Envelope suite update:** `v1-argon2id-hkdf-aes256gcm-sealed-payload` is now the only supported sealed-payload suite.
- **KDF schema update:** passphrase envelopes now use Argon2id parameters (`version`, `m_cost`, `t_cost`, `p_cost`, `length`) with bounded validation and work-cap limits.
- **Web performance/security:** passphrase KDF in web now lazy-loads Argon2id (`hash-wasm`) only when needed and surfaces clear load failures.
- **Documentation refresh:** whitepaper and all active docs now reflect Argon2id and remove legacy passphrase-KDF references.

## 0.9.0 — 2026-02-14

### Added

- **Secrets check endpoint:** `GET /api/v1/secrets/check` returns count + opaque checksum for lightweight dashboard change-detection polling.
- **Dashboard live polling:** dashboard polls the check endpoint every 4 seconds and auto-refreshes on changes.

### Changed

- **Settings page redesign:** centered headings, clearer API key creation success state, destructive-subtle button style for revoke, polished delete-account confirmation flow.
- **Dashboard page size:** increased from 5 to 10 secrets per page.
- **Spec updates:** documented session auth, list/check endpoints, API key list/revoke, account deletion, and owner key types.

## 0.8.0 — 2026-02-14

### Added

- **Dashboard page:** authenticated users can view their secrets with status, expiry, and burn controls.
- **Settings page:** account management with display name editing and account deletion.
- **Open Graph and Twitter Card meta tags** for rich link previews when sharing secrt.ca URLs.

### Changed

- **Nav bar overhaul:** popover user menu with avatar, display name, dashboard/settings links, and logout.
- **Session token auth for secret creation:** authenticated web users can now create secrets using their session token (not just API keys).

### Fixed

- **Friendly passkey login errors:** "unknown credential" server errors now show a user-friendly explanation instead of the raw error string.
- **OG tags in fallback HTML:** secret pages now include proper Open Graph meta tags even when no SPA frontend is built.

## 0.7.0 — 2026-02-14

### Added

- **Technical whitepaper:** comprehensive `docs/whitepaper.md` covering cryptographic architecture, zero-knowledge design, database schema, abuse prevention, signed releases, and FAQ.
- **Passkey icon** SVG asset for auth pages.

### Changed

- **User identity hardening:** user IDs are now server-generated UUIDv7 values; `user_id` is no longer exposed in auth/session API responses.
- **Registration page overhaul:** auto-generated privacy-friendly display names (adjective + animal), polished passkey flow.
- **Font Awesome icons** across nav, login, and registration UI.
- **SPA serving:** all frontend routes (`/`, `/s/{id}`, `/login`, `/register`, `/how-it-works`) now serve the Preact SPA instead of placeholder HTML. Falls back to placeholder when no frontend is built.
- **Spec updates:** API and server spec amendments for UUID user IDs and session privacy.
- **Release process:** documented dual-tag release (both `cli/v*` and `server/v*`) in CLAUDE.md.

## 0.6.1 — 2026-02-13

### Fixed

- **Web static asset base path:** frontend bundles now resolve under `/static/assets/*`, matching server static routing and preventing blank-page loads caused by `/assets/*` 404s.
- **Server operator ergonomics:** `secrt-server --version` and `secrt-server --help` now return immediately without touching config/DB startup paths.
- **Web package manager enforcement:** web workspace now requires `pnpm`, with updated docs and ignore rules for web-local env/log/store artifacts.

## 0.6.0 — 2026-02-13

### Changed

- **Breaking API-key auth format:** authenticated API calls now use v2 wire credentials (`ak2_<prefix>.<auth_b64>`), with local client keys in `sk2_<prefix>.<root_b64>`.
- **Passkey-gated API-key registration:** API-key registration moved to `POST /api/v1/apikeys/register` and now requires a passkey-backed session bearer token (`uss_<sid>.<secret>`).
- **Registration quotas:** dual quota enforcement is now active and configurable per account and per IP, with defaults of `5/hour` and `20/day`.
- **Legacy API key compatibility:** legacy `sk_` authentication paths are removed from server runtime (no backward compatibility).
- **Breaking envelope hard-cut:** v1 envelope internals now use the sealed-payload suite (`v1-argon2id-hkdf-aes256gcm-sealed-payload`) with updated AAD/HKDF labels; legacy envelope payloads are intentionally unsupported.
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
