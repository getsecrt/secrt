# Changelog

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
