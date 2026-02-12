# Contributing to secrt

## Getting Started

```sh
git clone https://github.com/getsecrt/secrt.git
cd secrt
cargo build --workspace
cargo test --workspace
```

## Repository Structure

This is a Cargo workspace with three crates:

- **secrt-core** — shared crypto, types, and protocol logic (no I/O)
- **secrt-cli** — CLI binary
- **secrt-server** — Axum server and admin tooling

The web frontend lives in `web/` (Vite + Preact + TypeScript).

## Before Submitting a PR

```sh
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

CI enforces all three — PRs that fail formatting, linting, or tests will not be merged.

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
