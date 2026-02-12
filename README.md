# secrt

Zero-knowledge one-time secret sharing.

Monorepo for the [secrt.ca](https://secrt.ca) protocol — CLI, server, core library, and specification.

## Structure

```
crates/
  secrt-core/       Shared crypto, envelope types, and protocol logic
  secrt-cli/        CLI binary (secrt send / secrt get)
  secrt-server/     Rust server (Axum) — future
spec/               Protocol specification, test vectors, OpenAPI schema
legacy/
  secrt-server/     Go server (reference, to be retired)
```

## License

MIT
