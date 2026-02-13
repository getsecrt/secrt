# Changelog

## 0.6.1 — 2026-02-13

### Fixed

- **Static web bundle routing:** frontend bundles now load from `/static/assets/*` (instead of root `/assets/*`), aligning Vite output with server static routing.
- **No-side-effects CLI flags:** `secrt-server --version` and `secrt-server --help` now exit before config, DB connection, and migration startup paths.

## 0.6.0 — 2026-02-13

### Added

- **Passkey auth/session endpoints:** `register/start`, `register/finish`, `login/start`, `login/finish`, `auth/session`, and `auth/logout` with 24h bearer sessions (`uss_<sid>.<secret>`).
- **API-key registration endpoint:** `POST /api/v1/apikeys/register` requiring session auth.
- **Registration controls:** configurable account/IP quotas (`5/hour`, `20/day` defaults) and registration limiter settings.
- **Auth schema expansion:** new DB tables for users, passkeys, sessions, challenges, and API-key registration events.

### Changed

- **Breaking API-key auth format:** authenticated routes now accept only `ak2_<prefix>.<auth_b64>`; legacy `sk_` auth is removed.
- **Verifier contract update:** API key hashes now use structured v2 verifier input (`"secrt-apikey-v2-verifier" || u16be(prefix_len) || prefix || auth_token_bytes`).
- **Atomic registration write path:** quota checks + API-key insert + registration event insert execute in one transaction.
- **Admin CLI surface:** removed `secrt-admin apikey create`; kept `secrt-admin apikey revoke <prefix>`.
- **Envelope privacy contract alignment:** runtime/spec now explicitly treat all metadata as encrypted payload content; plaintext metadata fields are not part of the accepted envelope contract.
- **Legacy envelope compatibility policy:** 0.6.0 documents a hard-cut expectation for sealed-payload envelopes; compatibility with prior envelope internals is intentionally out of scope.
- **Compression policy visibility:** docs now reflect client-side compression defaults (`threshold=2048`, `min_savings=64`, `min_savings_ratio=10%`, `zstd level=3`, decode cap `100 MiB`).
- **OpenAPI/API text alignment:** server-facing contract docs now explicitly describe envelope JSON as opaque ciphertext metadata, with advisory metadata accessible only client-side after decrypt.

## 0.5.2 — 2026-02-12

### Added

- **Branded landing page:** Homepage now shows the secrt logo with light/dark mode support, explains zero-knowledge encryption, and links to CLI downloads. HTML moved from inline Rust to a `templates/index.html` file loaded via `include_str!`.

## 0.5.1 — 2026-02-12

### Fixed

- **Database error logging:** Storage errors now include the full error source chain instead of a truncated "db error" message. Root causes like connection failures, auth errors, and missing tables are now visible in logs.

## 0.5.0 — 2026-02-12

### Added

- **Embedded web assets:** Frontend is compiled into the server binary via `rust-embed`. No filesystem dependency for static files in production.
- **Static file fallback chain:** `SECRT_WEB_DIST_DIR` env var (dev override) → embedded assets (production) → filesystem `web/dist` (fallback).
- **Release workflow:** GitHub Actions workflow triggered by `server/v*` tags. Builds web frontend, cross-compiles Linux amd64/arm64 musl binaries, and publishes GitHub Release with checksums.

## 0.4.0 — 2026-02-11

### Added

- **Full Rust rewrite** of the legacy Go server, achieving complete feature and test parity.
- **Axum HTTP server** with structured JSON logging via `tracing`.
- **Postgres storage** with `deadpool-postgres` connection pooling and atomic claim-and-delete.
- **API key authentication** with HMAC-SHA256 hashing and pepper.
- **Per-IP and per-key rate limiting** with configurable rates and bursts.
- **Per-owner storage quotas** — max secrets and max total bytes per owner tier (public/authenticated).
- **Secret reaper** — background task that deletes expired secrets on a configurable interval.
- **Admin CLI** (`secrt-admin`) — API key management (create, revoke, list).
- **Privacy-aware logging** — `X-Privacy-Log` header check, IP hashing for owner keys, truncated IP support.
- **Security headers** — `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`, `X-Robots-Tag` on all responses.
- **Request middleware** — request ID generation, timing, cache-control defaults.
- **Placeholder HTML pages** for `/` and `/s/{id}` routes.
- **`/healthz` endpoint** for health checks.
- **`/robots.txt`** returning `Disallow: /`.
- **CI coverage gate** at 90% line coverage with legacy parity checks.
