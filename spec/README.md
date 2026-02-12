# secrt.ca Protocol Specification

Normative specifications for the [secrt.ca](https://secrt.ca) one-time secret sharing protocol.

This spec lives in the [secrt monorepo](https://github.com/getsecrt/secrt) at `spec/` and is also available standalone at [getsecrt/spec](https://github.com/getsecrt/spec).

## Structure

```
v1/
  api.md                 # HTTP API contract
  cli.md                 # CLI UX contract
  envelope.md            # Client-side crypto workflow
  server.md              # Server runtime behavior
  openapi.yaml           # OpenAPI 3.1 schema
  envelope.vectors.json  # Crypto interop test vectors
  cli.vectors.json       # TTL parsing test vectors
```

## Implementations

All implementations live in the [secrt monorepo](https://github.com/getsecrt/secrt):

- **Core library (Rust):** [`crates/secrt-core/`](https://github.com/getsecrt/secrt/tree/main/crates/secrt-core)
- **CLI (Rust):** [`crates/secrt-cli/`](https://github.com/getsecrt/secrt/tree/main/crates/secrt-cli)
- **Server (Go, legacy):** [`legacy/secrt-server/`](https://github.com/getsecrt/secrt/tree/main/legacy/secrt-server)

## Versioning

When spec and code disagree, fix code to match spec — or update spec first with rationale, then update code in the same changeset.
