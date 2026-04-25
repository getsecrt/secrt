# secrt.ca Protocol Specification

Normative specifications for the [secrt.ca](https://secrt.ca) one-time secret sharing protocol.

This spec lives in the [secrt monorepo](https://github.com/getsecrt/secrt) at `spec/`. It was previously mirrored at `getsecrt/spec` (now archived); the monorepo copy is canonical.

## Where to start

If you want to **reimplement a client** (CLI, library, web frontend), read in this order:

1. **[v1/envelope.md](v1/envelope.md)** — client-side crypto, envelope JSON shape, payload frame. Everything ciphertext-shaped happens here.
2. **[v1/api.md](v1/api.md)** — HTTP wire contract. What you POST/GET, request and response shapes, error codes.
3. **[v1/cli.md](v1/cli.md)** — only if you're matching the reference CLI's UX (commands, flags, output discipline, TTL grammar).
4. **[v1/envelope.vectors.json](v1/envelope.vectors.json)** and **[v1/cli.vectors.json](v1/cli.vectors.json)** — must-pass interop vectors.

If you want to **reimplement the server**, read:

1. **[v1/api.md](v1/api.md)** — the wire contract you must serve.
2. **[v1/server.md](v1/server.md)** — runtime behavior: middleware, atomic claim semantics, TTL enforcement, ownership/quota, rate limits, DB schema.
3. **[v1/openapi.yaml](v1/openapi.yaml)** — machine-readable schema, useful for codegen and validation.

## Index of v1 files

| File | What it covers |
|---|---|
| [v1/envelope.md](v1/envelope.md) | Client-side crypto: AES-256-GCM + HKDF-SHA-256 + optional Argon2id, envelope JSON, payload frame, claim-token derivation, compression policy |
| [v1/api.md](v1/api.md) | HTTP API contract: endpoints, auth (API key v2, passkey sessions, device auth, app login), policy tiers, AMK wrappers, encrypted notes, error semantics |
| [v1/server.md](v1/server.md) | Server runtime: startup/shutdown, DB schema, middleware, route surface, auth resolution order, ownership/quota, rate limits, atomic claim, expiry reaper |
| [v1/cli.md](v1/cli.md) | CLI UX: commands (`send`, `get`, `burn`, `list`, `info`, `sync`, `gen`, `auth`, `config`), flags, TTL grammar, output discipline, config file, keychain |
| [v1/openapi.yaml](v1/openapi.yaml) | OpenAPI 3.1 schema |
| [v1/envelope.vectors.json](v1/envelope.vectors.json) | Crypto interop vectors (no-passphrase, passphrase, codec=none/zstd, file metadata) |
| [v1/cli.vectors.json](v1/cli.vectors.json) | TTL parsing vectors (valid + invalid) |
| [v1/apikey.vectors.json](v1/apikey.vectors.json) | API key v2 derivation vectors |
| [v1/amk.vectors.json](v1/amk.vectors.json) | AMK derivation/wrapping vectors |

## Implementations

All implementations live in the [secrt monorepo](https://github.com/getsecrt/secrt):

- **Core library (Rust):** [`crates/secrt-core/`](https://github.com/getsecrt/secrt/tree/main/crates/secrt-core)
- **CLI (Rust):** [`crates/secrt-cli/`](https://github.com/getsecrt/secrt/tree/main/crates/secrt-cli)
- **Server (Rust):** [`crates/secrt-server/`](https://github.com/getsecrt/secrt/tree/main/crates/secrt-server)

## Versioning

When spec and code disagree, fix code to match spec — or update spec first with rationale, then update code in the same changeset.

A conforming implementation MUST pass all vector files in `v1/`.
