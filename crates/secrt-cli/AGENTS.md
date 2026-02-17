# secrt-cli — CLI-specific Agent Notes

> See the root [AGENTS.md](../../AGENTS.md) for project-wide conventions (commits, testing, builds, versioning, security).

## Architecture

- **No async runtime** — uses `ureq` (blocking HTTP).
- **No clap** — hand-rolled arg parsing in `cli.rs`.
- **ring** + **argon2** for all crypto (AES-256-GCM, HKDF-SHA256, SHA-256, Argon2id, CSPRNG).
- Deterministic RNG injection via `&dyn Fn(&mut [u8]) -> Result<()>` for test vectors.
- `pub use secrt_core as envelope;` in `lib.rs` for backward-compatible internal imports.

## CLI-specific Makefile

The `Makefile` in this directory wraps common commands for convenience when working on just the CLI:

```sh
make build     # cargo build
make release   # cargo build --release
make test      # cargo test
make check     # clippy + fmt check
make size      # show release binary size
make coverage  # llvm-cov HTML report
```

These are equivalent to running the workspace-level commands with `-p secrt-cli`.

## Changelog

The [CHANGELOG.md](CHANGELOG.md) in this directory tracks all user-facing CLI changes. Update it with every release.
