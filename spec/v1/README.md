# v1 Specification Files

This directory is the versioned contract for client/server interoperability. See the [parent README](../README.md) for a recommended reading order.

| File | What it covers |
|---|---|
| [envelope.md](envelope.md) | Client-side envelope format, crypto workflow, payload frame, claim-token derivation, compression policy |
| [api.md](api.md) | HTTP API: endpoints, auth (API key v2, sessions, device auth, app login), AMK, encrypted notes, error semantics |
| [server.md](server.md) | Server runtime behavior: startup, DB schema, middleware, route surface, ownership/quota, rate limits, atomic claim, reaper |
| [cli.md](cli.md) | CLI UX contract: commands, flags, TTL grammar, output discipline, config, keychain |
| [openapi.yaml](openapi.yaml) | OpenAPI 3.1 schema |
| [envelope.vectors.json](envelope.vectors.json) | Crypto interop test vectors |
| [cli.vectors.json](cli.vectors.json) | TTL parsing test vectors |
| [apikey.vectors.json](apikey.vectors.json) | API key v2 derivation test vectors |
| [amk.vectors.json](amk.vectors.json) | AMK derivation/wrapping test vectors |
