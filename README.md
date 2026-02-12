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

## Quick start

**Download the CLI:** [macOS (Universal)](https://github.com/getsecrt/secrt/releases/latest/download/secrt-darwin-universal) | [Linux (x86_64)](https://github.com/getsecrt/secrt/releases/latest/download/secrt-linux-amd64) | [Windows (x86_64)](https://github.com/getsecrt/secrt/releases/latest/download/secrt-windows-amd64.exe)

```sh
# Share a secret
echo "s3cret-password" | secrt send

# Claim a secret
secrt get https://secrt.ca/s/abc123#key...

# Generate and share a password
secrt send gen --ttl 1h
```

See the [CLI README](crates/secrt-cli/README.md) for full documentation.

## Repository structure

```
secrt/
├── crates/
│   ├── secrt-core/         Shared crypto, envelope types, and protocol logic
│   └── secrt-cli/          CLI binary (secrt send / secrt get / secrt gen)
├── spec/                   Protocol specification, test vectors, OpenAPI schema
└── legacy/
    └── secrt-server/       Go server (reference implementation, being replaced)
```

### [`secrt-core`](crates/secrt-core/)

Shared library crate containing the cryptographic protocol implementation:

- **Envelope format** — AES-256-GCM encryption with HKDF-SHA256 key derivation
- **Passphrase protection** — PBKDF2-HMAC-SHA256 (600,000 iterations)
- **TTL parsing** — duration grammar (`30s`, `5m`, `2h`, `1d`, `1w`)
- **Share URL handling** — URL parsing and formatting
- **API types** — request/response types and the `SecretApi` trait

Used by the CLI today, and will be shared with the Rust server and WASM browser crypto in the future.

### [`secrt-cli`](crates/secrt-cli/)

Command-line tool for creating, claiming, and managing secrets. No async runtime, no framework overhead. Builds to a small static binary (~1.5 MB).

Commands: `send`, `get`, `burn`, `gen`, `config`, `completion`

### [`spec`](spec/)

Protocol specification for v1, including:

- [Envelope format and crypto](spec/v1/envelope.md)
- [HTTP API contract](spec/v1/api.md)
- [CLI interface contract](spec/v1/cli.md)
- [Server runtime behavior](spec/v1/server.md)
- [OpenAPI schema](spec/v1/openapi.yaml)
- Crypto and TTL test vectors

### [`legacy/secrt-server`](legacy/secrt-server/)

The original Go server implementation. Being replaced by a Rust (Axum) server that shares `secrt-core` for protocol logic.

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

## License

MIT
