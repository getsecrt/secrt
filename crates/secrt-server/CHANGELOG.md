# Changelog

## 0.9.0 — 2026-02-14

### Added

- **Secrets check endpoint:** `GET /api/v1/secrets/check` returns count + opaque checksum for lightweight dashboard polling without refetching full metadata.
- **Dashboard live polling:** dashboard polls the check endpoint every 4 seconds and auto-refreshes on changes.

### Changed

- **Settings page redesign:** centered headings, clearer API key creation success state, destructive-subtle button style for revoke, polished delete-account confirmation flow.
- **Dashboard page size:** increased from 5 to 10 secrets per page.
- **Popover positioning:** user menu and burn confirmation popovers now use `useLayoutEffect` to prevent position flash on mount.
- **Shared UI components:** added `btn-destructive-subtle` and `code` utility classes.
- **v1 spec updates:** documented session auth, list/check endpoints, API key list/revoke, account deletion, and owner key types.

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
- **OG tags in fallback HTML:** secret pages now include proper Open Graph meta tags even when no SPA frontend is built, fixing CI test failures and ensuring social previews work in all configurations.

## 0.7.0 — 2026-02-14

### Added

- **Technical whitepaper** documenting cryptographic architecture, zero-knowledge design, abuse prevention, and FAQ.
- **Font Awesome icons** across nav and auth UI.
- **Passkey icon** SVG asset for auth pages.

### Changed

- **User identity storage hardening:** user IDs are now server-generated UUIDv7 values, and all auth-linked `user_id` foreign keys are UUID-typed.
- **Auth/session response privacy:** `user_id` is no longer returned by passkey `register/finish`, `login/finish`, or `GET /api/v1/auth/session` responses.
- **Registration page overhaul:** auto-generated privacy-friendly display names, polished passkey flow.
- **Nav and login UI polish:** updated styling, icon integration, responsive improvements.
- **Spec updates:** API and server spec amendments for UUID user IDs and session privacy.

### Fixed

- **SPA serving:** `/`, `/s/{id}`, `/login`, `/register`, and `/how-it-works` now serve the Preact SPA `index.html` instead of the old placeholder page. Falls back to the placeholder when no frontend is built.

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
- **Security headers** — `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options` on all responses; `X-Robots-Tag` on `/s/{id}` route.
- **Request middleware** — request ID generation, timing, cache-control defaults.
- **Placeholder HTML pages** for `/` and `/s/{id}` routes.
- **`/healthz` endpoint** for health checks.
- **`/robots.txt`** returning `Disallow: /`.
- **CI coverage gate** at 90% line coverage with legacy parity checks.
