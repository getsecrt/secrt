# secrt-rs — Rust CLI for secrt.ca

Rust reimplementation of the Go `secrt` CLI. One-time secret sharing with
zero-knowledge client-side encryption (AES-256-GCM + HKDF + optional PBKDF2).

## Canonical spec

The living spec documents live in `../secrt/spec/v1/`:
- `envelope.md` — envelope format and crypto
- `cli.md` — CLI interface and TTL grammar
- `envelope.vectors.json` — crypto test vectors (7 vectors)
- `cli.vectors.json` — TTL test vectors (17 valid + 17 invalid)

Reference those files directly; do NOT copy spec content here.

## Architecture

- **No async runtime** — uses `ureq` (blocking HTTP).
- **No clap** — hand-rolled arg parsing (3 commands, ~10 flags).
- **ring** for all crypto (AES-256-GCM, HKDF-SHA256, SHA-256, PBKDF2, CSPRNG).
- Deterministic RNG injection via `&dyn Fn(&mut [u8]) -> Result<()>` for test vectors.

## File layout

```
src/
├── main.rs          # Wires real dependencies, calls run()
├── cli.rs           # Arg parsing, command dispatch, help text
├── create.rs        # create command
├── claim.rs         # claim command
├── burn.rs          # burn command
├── client.rs        # HTTP API client (ureq)
├── passphrase.rs    # Passphrase resolution
├── color.rs         # TTY-aware ANSI color
├── completion.rs    # Shell completion scripts
└── envelope/
    ├── mod.rs       # Re-exports
    ├── types.rs     # Envelope structs, constants, errors
    ├── crypto.rs    # seal(), open(), HKDF, PBKDF2, AES-GCM
    ├── ttl.rs       # TTL parser
    └── url.rs       # Share URL parser/formatter
```

## Build & test

```sh
make build    # debug build
make release  # optimized release build
make test     # cargo test
make check    # clippy + fmt check
make size     # show release binary size
```
