# secrt.ca Protocol Specification

Normative specifications for the [secrt.ca](https://secrt.ca) one-time secret sharing protocol.

This repo is intended to be consumed as a **git submodule** (mounted at `spec/`) by implementation repos so that all clients and servers share the same versioned contract.

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

## Usage as a submodule

```bash
# Add to your project
git submodule add git@github.com:getsecrt/spec.git spec

# Update to latest
git submodule update --remote spec
```

## Implementations

- **Server (Go):** [getsecrt/secrt](https://github.com/getsecrt/secrt)
- **CLI (Rust):** [getsecrt/secrt-cli](https://github.com/getsecrt/secrt-cli)

## Versioning

When spec and code disagree, fix code to match spec — or update spec first with rationale, then update code in the same changeset.
