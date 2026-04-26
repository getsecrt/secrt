# Contributing to secrt

## Getting Started

```sh
git clone https://github.com/getsecrt/secrt.git
cd secrt
cargo install --locked cargo-nextest    # ~3.5× faster test runs
make build-rust
make test-rust
```

The `Makefile` is the entry point — run `make help` to see all targets. The
Rust toolchain is pinned via `rust-toolchain.toml` so your local `rustc`
matches CI exactly.

## Repository Structure

This is a Cargo workspace with three crates:

- **secrt-core** — shared crypto, types, and protocol logic (no I/O)
- **secrt-cli** — CLI binary
- **secrt-server** — Axum server and admin tooling

The web frontend lives in `web/` (Vite + Preact + TypeScript).

## Before Submitting a PR

```sh
cargo fmt --all
make lint-rust
make test-rust
```

CI enforces formatting, linting, and tests — PRs that fail any of them will
not be merged. `make test-rust` and `make lint-rust` exclude `secrt-app`
(Tauri) by default to keep iteration fast; if you're touching the desktop
app, run `make test-app` and `cargo clippy -p secrt-app -- -D warnings`
explicitly.

For scoped iteration, `make test-cli`, `make test-server`, and
`make test-core` only build and test one crate at a time.

## Commit Style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new feature
fix: resolve bug
test: add or update tests
refactor: code quality improvement
docs: documentation changes
chore: config, deps, maintenance
```

Keep subjects concise (< 52 characters), lowercase, no trailing period.

## Security

secrt is a security-focused project. Please review `SECURITY.md` before contributing changes that touch crypto, authentication, or data handling. Key rules:

- Never log secrets, plaintext, passphrases, or URL fragments
- Use `ring` for all cryptographic operations — no rolling your own
- Test vectors in `spec/v1/` are mandatory and must pass in all implementations
- When spec and code disagree, fix code to match spec (or update spec first with rationale)

## Changelogs

Each crate maintains its own `CHANGELOG.md` following [Keep a Changelog](https://keepachangelog.com/). Update the relevant changelog with every user-facing change.

## Adding Dependencies

Minimize dependencies. Shared deps are pinned in the workspace root `Cargo.toml`. Justify new dependencies — document what they replace and why they're worth it.
