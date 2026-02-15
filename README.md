<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/secrt-logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/images/secrt-logo.svg">
    <img alt="secrt" src="docs/images/secrt-logo.svg" width="250">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/getsecrt/secrt/actions/workflows/ci.yml"><img src="https://github.com/getsecrt/secrt/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

<p align="center">
  Zero-knowledge one-time secret sharing — <a href="https://secrt.ca">secrt.ca</a>
</p>

---

Monorepo for the [secrt.ca](https://secrt.ca) protocol. Share secrets that self-destruct after a single view, with all encryption happening client-side. The server never sees plaintext.

**AES-256-GCM + HKDF-SHA256 + optional PBKDF2 passphrase protection**, powered by [ring](https://github.com/briansmith/ring).

## Downloads

### CLI

| Platform | Download |
|----------|----------|
| macOS (Universal) | [secrt-darwin-universal](https://github.com/getsecrt/secrt/releases/latest/download/secrt-darwin-universal) |
| Linux x64 | [secrt-linux-amd64](https://github.com/getsecrt/secrt/releases/latest/download/secrt-linux-amd64) |
| Linux ARM64 | [secrt-linux-arm64](https://github.com/getsecrt/secrt/releases/latest/download/secrt-linux-arm64) |
| Windows x64 | [secrt-windows-amd64.exe](https://github.com/getsecrt/secrt/releases/latest/download/secrt-windows-amd64.exe) |
| Windows ARM64 | [secrt-windows-arm64.exe](https://github.com/getsecrt/secrt/releases/latest/download/secrt-windows-arm64.exe) |

### Server

Server releases use separate tags (`server/v*`). Download from the [latest server release](https://github.com/getsecrt/secrt/releases?q=server).

| Platform | Download |
|----------|----------|
| Linux x64 | [secrt-server-linux-amd64](https://github.com/getsecrt/secrt/releases/download/server%2Fv0.9.0/secrt-server-linux-amd64) |
| Linux ARM64 | [secrt-server-linux-arm64](https://github.com/getsecrt/secrt/releases/download/server%2Fv0.9.0/secrt-server-linux-arm64) |

## Quick start

```sh
# Share a secret
echo "s3cret-password" | secrt send

# Claim a secret
secrt get https://secrt.ca/s/abc123#key...

# Or just paste the URL directly (implicit get)
secrt https://secrt.ca/s/abc123#key...

# Generate and share a password
secrt send gen --ttl 1h
```

See the [CLI README](crates/secrt-cli/README.md) for full documentation.

## Repository structure

```
secrt/
├── crates/
│   ├── secrt-core/         Shared crypto, envelope types, and protocol logic
│   ├── secrt-cli/          CLI binary (secrt send / secrt get / secrt gen)
│   └── secrt-server/       Axum server + admin CLI (secrt-server / secrt-admin)
├── web/                    Web frontend (Vite + Preact + TypeScript)
└── spec/                   Protocol specification, test vectors, OpenAPI schema
```

### [`secrt-core`](crates/secrt-core/)

Shared library crate containing the cryptographic protocol implementation:

- **Envelope format** — AES-256-GCM encryption with HKDF-SHA256 key derivation
- **Passphrase protection** — PBKDF2-HMAC-SHA256 (600,000 iterations)
- **TTL parsing** — duration grammar (`30s`, `5m`, `2h`, `1d`, `1w`)
- **Share URL handling** — URL parsing and formatting
- **API types** — request/response types and the `SecretApi` trait

### [`secrt-cli`](crates/secrt-cli/)

Command-line tool for creating, claiming, and managing secrets. No async runtime, no framework overhead. Builds to a small static binary (~1.5 MB).

Commands: `send`, `get`, `burn`, `gen`, `config`, `completion`

### [`secrt-server`](crates/secrt-server/)

Axum-based server with Postgres storage, rate limiting, API key auth, and a background secret reaper. The web frontend is embedded in the binary via `rust-embed` — a single artifact with zero filesystem dependencies.

Includes `secrt-admin` for API key management (create, revoke, list).

### [`web`](web/)

Preact + TypeScript web frontend, built with Vite and bundled with pnpm. Embedded into the server binary at compile time.

### [`spec`](spec/)

Protocol specification for v1, including:

- [Envelope format and crypto](spec/v1/envelope.md)
- [HTTP API contract](spec/v1/api.md)
- [CLI interface contract](spec/v1/cli.md)
- [Server runtime behavior](spec/v1/server.md)
- [OpenAPI schema](spec/v1/openapi.yaml)
- Crypto and TTL test vectors

## Development

```sh
# Build all crates
cargo build --workspace

# Run all tests
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Format
cargo fmt --all
```

### Local web + server dev

Run backend and frontend in separate terminals.

1. Start Postgres (or point `DATABASE_URL` at an existing dev DB).
2. Create `crates/secrt-server/.env` (or export env vars directly), for example:

```sh
ENV=development
LISTEN_ADDR=127.0.0.1:8080
PUBLIC_BASE_URL=http://127.0.0.1:8080
DATABASE_URL=postgres://secrt_app:password@127.0.0.1:5432/secrt?sslmode=disable
API_KEY_PEPPER=dev-pepper
SESSION_TOKEN_PEPPER=dev-session-pepper
```

3. Terminal A: run the API/server

```sh
cargo run -p secrt-server
```

4. Terminal B: run Vite (with API proxy to `secrt-server`)

```sh
pnpm -C web install --frozen-lockfile
SECRT_API_ORIGIN=http://127.0.0.1:8080 pnpm -C web dev
```

5. Open `http://127.0.0.1:5173` for live frontend dev.

Notes:

- WebAuthn passkeys work on `localhost`/`127.0.0.1` in modern browsers.
- Production-style static build path remains `/static/*`; the Vite build emits `/static/assets/*`.

## License

MIT
