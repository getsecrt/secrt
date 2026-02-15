<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/secrt-logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/images/secrt-logo.svg">
    <img alt="secrt" src="docs/images/secrt-logo.svg" width="250">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/getsecrt/secrt/actions/workflows/ci.yml"><img src="https://github.com/getsecrt/secrt/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/MSRV-1.82-blue" alt="MSRV: 1.82">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

Zero-knowledge one-time secret sharing server, built with [Axum](https://github.com/tokio-rs/axum) + PostgreSQL. The server never sees plaintext — all encryption happens client-side.

The web frontend (Preact + TypeScript) is embedded into the binary via `rust-embed`, producing a single artifact with zero filesystem dependencies.

**Download:** [Linux x64](https://github.com/getsecrt/secrt/releases/download/server%2Fv0.5.0/secrt-server-linux-amd64) | [Linux ARM64](https://github.com/getsecrt/secrt/releases/download/server%2Fv0.5.0/secrt-server-linux-arm64)

## Quick start

1. **Start PostgreSQL** and create a database:

```sql
CREATE USER secrt_app WITH PASSWORD 'your-password';
CREATE DATABASE secrt OWNER secrt_app;
```

2. **Configure environment** — copy `.env.example` to `.env` and set at minimum:

```sh
DATABASE_URL=postgres://secrt_app:your-password@127.0.0.1:5432/secrt?sslmode=disable
API_KEY_PEPPER=<openssl rand -base64 32>
SESSION_TOKEN_PEPPER=<openssl rand -base64 32>
```

3. **Run the server:**

```sh
cargo run -p secrt-server
```

Migrations run automatically on startup. The server listens on `127.0.0.1:8080` by default.

### From source

```sh
git clone https://github.com/getsecrt/secrt.git
cd secrt
cargo build --release -p secrt-server
# Binaries at target/release/secrt-server and target/release/secrt-admin
```

## Configuration

All configuration is via environment variables (or a `.env` file, loaded automatically when `ENV != production`).

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `ENV` | `development` | Environment name. `production` enforces stricter validation (peppers required). |
| `LISTEN_ADDR` | `:8080` | Bind address. A bare `:PORT` binds to `0.0.0.0`. |
| `PUBLIC_BASE_URL` | `http://localhost:8080` | Public origin for share URLs returned by the API. No trailing slash. |
| `LOG_LEVEL` | `info` | Tracing filter: `error`, `warn`, `info`, `debug`, `trace`. |

### Database

Set `DATABASE_URL` for a full connection string, **or** use the individual `DB_*` fields (ignored when `DATABASE_URL` is set).

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | Full Postgres connection string. |
| `DB_HOST` | `127.0.0.1` | Postgres host. |
| `DB_PORT` | `5432` | Postgres port. |
| `DB_NAME` | `secrt` | Database name. |
| `DB_USER` | `secrt_app` | Database user. |
| `DB_PASSWORD` | — | Database password. |
| `DB_SSLMODE` | `disable` | SSL mode: `disable`, `require`, `verify-ca`, `verify-full`. |
| `DB_SSLROOTCERT` | — | Path to CA cert file for certificate verification. |

### Security

HMAC peppers are mixed into hashes stored at rest. **Changing them after deployment invalidates all existing API keys and sessions.** Required when `ENV=production`.

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY_PEPPER` | `dev-api-pepper-not-for-production` | HMAC pepper for API-key verifier hashes. |
| `SESSION_TOKEN_PEPPER` | `dev-session-pepper-not-for-production` | HMAC pepper for session bearer-token hashes. |

Generate production values with: `openssl rand -base64 32`

### Quotas

| Variable | Default | Description |
|----------|---------|-------------|
| `PUBLIC_MAX_ENVELOPE_BYTES` | `262144` (256 KiB) | Max envelope size for anonymous requests. |
| `AUTHED_MAX_ENVELOPE_BYTES` | `1048576` (1 MiB) | Max envelope size for authenticated requests. |
| `PUBLIC_MAX_SECRETS` | `10` | Max active secrets per anonymous owner. |
| `PUBLIC_MAX_TOTAL_BYTES` | `2097152` (2 MiB) | Max stored bytes per anonymous owner. |
| `AUTHED_MAX_SECRETS` | `1000` | Max active secrets per authenticated owner. |
| `AUTHED_MAX_TOTAL_BYTES` | `20971520` (20 MiB) | Max stored bytes per authenticated owner. |

### Rate limits

Token bucket rate limiters, per client IP (public/claim) or per API key/user (authenticated).

| Variable | Default | Description |
|----------|---------|-------------|
| `PUBLIC_CREATE_RATE` | `0.5` | Public create — requests per second. |
| `PUBLIC_CREATE_BURST` | `6` | Public create — burst size. |
| `CLAIM_RATE` | `1.0` | Claim endpoint — requests per second. |
| `CLAIM_BURST` | `10` | Claim — burst size. |
| `AUTHED_CREATE_RATE` | `2.0` | Authenticated create — requests per second. |
| `AUTHED_CREATE_BURST` | `20` | Authenticated create — burst size. |
| `APIKEY_REGISTER_RATE` | `0.5` | API key registration — requests per second (per IP). |
| `APIKEY_REGISTER_BURST` | `6` | API key registration — burst size. |

### API key registration limits

Hard caps on API key creation, enforced atomically in the database.

| Variable | Default | Description |
|----------|---------|-------------|
| `APIKEY_REGISTER_ACCOUNT_MAX_PER_HOUR` | `5` | Per account, rolling 1-hour window. |
| `APIKEY_REGISTER_ACCOUNT_MAX_PER_DAY` | `20` | Per account, rolling 24-hour window. |
| `APIKEY_REGISTER_IP_MAX_PER_HOUR` | `5` | Per client IP, rolling 1-hour window. |
| `APIKEY_REGISTER_IP_MAX_PER_DAY` | `20` | Per client IP, rolling 24-hour window. |

## Database setup

**Requirements:** PostgreSQL (tested with 14+).

**Migrations** run automatically on startup — no manual migration step needed. The initial schema creates tables for secrets, users, passkeys, sessions, challenges, API keys, and registration accounting.

Key tables:
- `secrets` — encrypted envelopes with TTL-based expiry
- `users` / `passkeys` / `sessions` — WebAuthn passkey authentication
- `api_keys` — HMAC-verified API key credentials
- `api_key_registrations` — rate limiting accounting for key creation

See [`migrations/001_initial.sql`](migrations/001_initial.sql) for the full schema.

## API overview

All API endpoints live under `/api/v1/`. The server treats envelope contents as opaque ciphertext — it cannot read secret payloads or metadata.

### Public

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Health check |
| `GET` | `/api/v1/info` | Server capabilities, limits, and auth status |
| `POST` | `/api/v1/public/secrets` | Create a secret (anonymous) |
| `POST` | `/api/v1/secrets/{id}/claim` | Claim and destroy a secret |

### Authenticated (API key or session)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/secrets` | Create a secret (authenticated) |
| `GET` | `/api/v1/secrets` | List your secrets |
| `GET` | `/api/v1/secrets/check` | Lightweight count + checksum for polling |
| `POST` | `/api/v1/secrets/{id}/burn` | Destroy a secret you own |

### Auth (passkeys + sessions)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/auth/passkeys/register/start` | Start passkey registration |
| `POST` | `/api/v1/auth/passkeys/register/finish` | Complete registration |
| `POST` | `/api/v1/auth/passkeys/login/start` | Start passkey login |
| `POST` | `/api/v1/auth/passkeys/login/finish` | Complete login |
| `GET` | `/api/v1/auth/session` | Check current session |
| `POST` | `/api/v1/auth/logout` | Revoke session |
| `DELETE` | `/api/v1/auth/account` | Delete account + all data |

### API key management (session-authenticated)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/apikeys/register` | Create an API key |
| `GET` | `/api/v1/apikeys` | List your API keys |
| `POST` | `/api/v1/apikeys/{prefix}/revoke` | Revoke an API key |

For the full contract, see the [API spec](../../spec/v1/api.md) and [OpenAPI schema](../../spec/v1/openapi.yaml).

## Privacy features

The server is designed to minimize stored and logged personal data:

- **No plaintext storage** — the server only stores encrypted envelopes; it cannot read secret content or metadata.
- **IP hashing** — anonymous owner keys are `HMAC-SHA256(client_ip)` with a per-process random key. Raw IPs are **never persisted** to the database.
- **Rate limiter privacy** — rate limiter keys are also HMAC-hashed; raw IPs never appear in in-memory data structures.
- **Limiter garbage collection** — stale buckets are evicted every 2 minutes (idle > 10 minutes), bounding the window during which any IP-derived data exists in memory.
- **Privacy log header** — on the first proxied request, the server checks for `X-Privacy-Log: truncated-ip` from the reverse proxy and warns if missing.
- **Security headers** — all responses include `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`.
- **Atomic one-time claim** — secrets are deleted in the same SQL statement that reads them (`DELETE ... RETURNING`), guaranteeing at most one successful claim.

## Reverse proxy setup

In production, run behind a reverse proxy that:

1. Terminates TLS
2. Truncates client IPs in access logs (IPv4 `/24`, IPv6 `/48`)
3. Strips `User-Agent`, `Referer`, and query strings from logs
4. Sends `X-Privacy-Log: truncated-ip` header to the backend

See [`docs/caddy-privacy-logging.md`](../../docs/caddy-privacy-logging.md) for a complete Caddy configuration.

## Admin CLI

The `secrt-admin` binary provides API key management:

```sh
# Revoke an API key
secrt-admin apikey revoke <prefix>

# List API keys
secrt-admin apikey list
```

## Development

### Local dev setup

Run backend and frontend in separate terminals:

```sh
# Terminal A: API server
cargo run -p secrt-server

# Terminal B: Vite dev server (with API proxy)
pnpm -C web install --frozen-lockfile
SECRT_API_ORIGIN=http://127.0.0.1:8080 pnpm -C web dev
```

Open `http://127.0.0.1:5173` for live frontend dev. WebAuthn passkeys work on `localhost`/`127.0.0.1`.

### Static file fallback chain

1. `SECRT_WEB_DIST_DIR` env var (dev override)
2. Embedded assets via `rust-embed` (production)
3. Filesystem `web/dist` (fallback)

### Build and test

```sh
cargo build -p secrt-server              # Debug build
cargo build --release -p secrt-server    # Release build
cargo test -p secrt-server               # Run server tests
cargo test --workspace                   # Run all tests
cargo clippy --workspace -- -D warnings  # Lint
cargo fmt --all                          # Format
```

## Links

- [Main repo README](../../README.md)
- [Protocol spec](../../spec/v1/) — envelope format, API contract, CLI spec, server runtime behavior
- [OpenAPI schema](../../spec/v1/openapi.yaml)
- [Caddy privacy logging guide](../../docs/caddy-privacy-logging.md)
- [CLI README](../secrt-cli/README.md)
- [Changelog](CHANGELOG.md)

## License

MIT
