# secrt — Monorepo Agent Notes

Zero-knowledge one-time secret sharing. All encryption is client-side (AES-256-GCM + HKDF-SHA256 + optional PBKDF2). The server never sees plaintext.

## Repository layout

```
secrt/
├── Cargo.toml                  # workspace root
├── crates/
│   ├── secrt-core/             # shared: crypto, envelope types, TTL, URL, API traits
│   │   └── src/
│   │       ├── lib.rs          # re-exports
│   │       ├── crypto.rs       # seal(), open(), HKDF, PBKDF2, AES-GCM
│   │       ├── types.rs        # Envelope, EncBlock, HkdfBlock, KDF types, errors
│   │       ├── ttl.rs          # parse_ttl()
│   │       ├── url.rs          # parse_share_url(), format_share_link()
│   │       └── api.rs          # CreateRequest/Response, ClaimRequest/Response, SecretApi trait
│   ├── secrt-cli/              # CLI binary (`secrt`)
│   │   ├── AGENTS.md           # CLI-specific notes
│   │   └── src/
│   │       ├── main.rs         # wires real deps, calls run()
│   │       ├── lib.rs          # pub use secrt_core as envelope (compat alias)
│   │       ├── cli.rs          # arg parsing, command dispatch, help text
│   │       ├── client.rs       # HTTP API client (ureq, implements SecretApi)
│   │       ├── send.rs         # send command
│   │       ├── get.rs          # get command
│   │       ├── burn.rs         # burn command
│   │       ├── gen.rs          # password generator
│   │       ├── config.rs       # TOML config + keychain + env resolution
│   │       ├── passphrase.rs   # passphrase resolution (prompt, env, file, config)
│   │       ├── fileutil.rs     # file I/O helpers
│   │       ├── mime.rs         # MIME type detection
│   │       ├── color.rs        # TTY-aware ANSI color
│   │       ├── completion.rs   # shell completion scripts
│   │       └── keychain.rs     # OS credential store (optional feature)
│   └── secrt-server/           # Axum server + admin CLI
├── web/                        # Web frontend (Vite + Preact + TypeScript)
└── spec/                       # protocol specification (v1)
    └── v1/
        ├── envelope.md         # client-side crypto workflow
        ├── api.md              # HTTP API contract
        ├── cli.md              # CLI interface and TTL grammar
        ├── server.md           # server runtime behavior
        ├── openapi.yaml        # OpenAPI 3.1 schema
        ├── envelope.vectors.json   # crypto test vectors (7 vectors)
        └── cli.vectors.json    # TTL test vectors (17 valid + 17 invalid)
```

## Security non-negotiables

- **Zero-knowledge by default.** The server stores and serves ciphertext only. It must never require or have access to decryption keys.
- **Never log secrets.** No request bodies, plaintext, passphrases, PINs, or URL fragments. Assume logs are retained and searchable.
- **Atomic claim+delete.** The read path must return ciphertext at most once and delete it in the same atomic operation/transaction.
- **Minimize crypto dependencies.** Use `ring` for Rust, WebCrypto in the browser. Never roll your own crypto.
- **No credentials in plaintext files.** Production credentials use systemd `EnvironmentFile=` with root-owned `0600` permissions. Never commit credentials to git.

## Specification

The spec at `spec/v1/` is the normative contract for all implementations. **Read the spec before making changes to crypto, API, or CLI behavior.**

- `envelope.md` — client-side crypto workflow (AES-256-GCM, HKDF, PBKDF2, envelope JSON shape)
- `api.md` — HTTP API contract (endpoints, auth, error semantics, policy tiers)
- `server.md` — server runtime behavior (middleware, storage, atomic claim, reaper, rate limits)
- `cli.md` — CLI UX contract (commands, flags, TTL grammar, output discipline, completions)

**Test vectors are mandatory.** Both `envelope.vectors.json` and `cli.vectors.json` must pass in all implementations. When spec and code disagree, fix code to match spec — or update spec first with rationale, then update code in the same changeset.

## Build & test

This is a Cargo workspace. Always work from the repo root.

```sh
# Build everything
cargo build --workspace

# Run all tests (unit + integration, excluding e2e)
cargo test --workspace

# Lint (CI enforces these)
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check

# Build a specific crate
cargo build -p secrt-core
cargo build -p secrt-cli

# Release build (size-optimized, LTO, stripped)
cargo build --release -p secrt-cli
```

### E2E tests

E2E tests hit a real server and are gated behind environment variables:

```sh
# Basic e2e (no API key needed)
SECRET_E2E_BASE_URL=https://secrt.ca cargo test -p secrt-cli e2e -- --ignored

# Full e2e (including burn, authenticated send)
SECRET_E2E_BASE_URL=https://secrt.ca SECRET_E2E_API_KEY=sk_... cargo test -p secrt-cli e2e -- --ignored
```

### Test architecture

- **secrt-core** tests: crypto unit tests with deterministic RNG injection, TTL parsing, URL handling
- **secrt-cli** tests:
  - `tests/envelope_vectors.rs` — spec crypto vectors
  - `tests/ttl_vectors.rs` — spec TTL vectors
  - `tests/cli_get.rs` — CLI argument parsing and command behavior
  - `tests/e2e.rs` — full roundtrip against a live server (`#[ignore]`)
  - `tests/helpers/` — `TestDepsBuilder` for injecting stdin, env vars, and capturing stdout/stderr

### Key testing patterns

- **Deterministic RNG.** Crypto functions accept `&dyn Fn(&mut [u8]) -> Result<()>` for injecting fixed randomness in test vectors.
- **TestDepsBuilder.** CLI tests use `TestDepsBuilder::new().stdin(b"...").env("KEY", "val").build()` to create isolated test environments.
- **TDD for behavior changes.** Write tests that capture expected behavior before implementing. Bug fixes start with a regression test.
- Prefer table-driven tests. Avoid flakiness by injecting clocks/time when needed.

## Before committing

Always run before committing code changes:

```sh
cargo fmt --all             # auto-fix formatting
cargo clippy --workspace -- -D warnings   # lint
cargo test --workspace      # all tests pass
```

CI runs `cargo fmt --check` and `cargo clippy -- -D warnings` — commits that fail formatting or linting will break the build.

## Git commits

Atomic commits — one logical change per commit. This makes bisecting and reverting straightforward.

Use **Conventional Commits** style:

```
type: subject
```

**Types:**
- `feat:` new feature
- `fix:` bug fix
- `test:` edits to tests
- `refactor:` code quality improvements
- `docs:` documentation
- `style:` formatting/whitespace
- `perf:` performance improvement
- `chore:` config, dependencies, maintenance
- `ci:` CI/CD pipeline changes
- `build:` build system changes
- `revert:` revert a prior commit

**Subject rules:**
- Concise (< 52 characters)
- Start with lowercase (except proper nouns)
- No period at end

When non-trivial, add a body with bullet points explaining key changes and rationale.

**Before large refactors:** commit any uncommitted files first, especially files likely to be touched. This makes reverting easy if things go wrong.

## Versioning & changelog

All crates share the workspace version in `Cargo.toml` (`[workspace.package] version`). Bump it in one place and all crates update together.

**CHANGELOG.md** lives at `crates/secrt-cli/CHANGELOG.md` and follows [Keep a Changelog](https://keepachangelog.com/) format. Update it with every user-facing change under the appropriate heading (`Added`, `Changed`, `Fixed`, `Removed`).

### Release process

1. Update `version` in the workspace `Cargo.toml`
2. Update `secrt-core` version in `crates/secrt-cli/Cargo.toml` dependency
3. Add a changelog entry in `crates/secrt-cli/CHANGELOG.md`
4. Commit: `chore: bump version to X.Y.Z`
5. Tag: `git tag cli/vX.Y.Z`
6. Push: `git push origin main --tags`

The `cli/v*` tag triggers the release workflow which:
- Runs `cargo test --workspace` and `cargo clippy --workspace`
- Cross-compiles for 6 targets (macOS arm64/amd64, Linux amd64/arm64, Windows amd64/arm64)
- Creates a universal macOS binary via `lipo`
- Code-signs macOS binaries (Developer ID + notarization)
- Code-signs Windows binaries (Azure Trusted Signing)
- Generates SHA256 checksums
- Publishes a GitHub Release with all artifacts

## Dependency policy

- **Minimize dependencies.** Prefer stdlib and `ring`. The CLI uses `ureq` (blocking HTTP) — no async runtime.
- **No clap** — the CLI uses hand-rolled arg parsing.
- **Justify new deps** — document what they replace and why they're worth it. Pin versions. Avoid framework-sized transitive graphs.
- **Workspace dependencies** — shared deps are pinned in the root `Cargo.toml` `[workspace.dependencies]` and referenced via `.workspace = true` in crate-level `Cargo.toml` files.

## Crate architecture

### secrt-core

Pure library. No I/O, no HTTP, no filesystem. Only crypto, types, and protocol logic. This crate will be shared by the CLI, server, and WASM builds.

Public API: `seal()`, `open()`, `derive_claim_token()`, `parse_ttl()`, `parse_share_url()`, `format_share_link()`, plus all envelope types and the `SecretApi` trait.

### secrt-cli

Binary crate. Depends on `secrt-core`. Handles all I/O: HTTP (via `ureq`), filesystem, stdin/stdout, TTY interaction, config files, OS keychain.

The CLI re-exports secrt-core as `envelope` for internal compatibility: `pub use secrt_core as envelope;` in `lib.rs`. This means internal code can use `crate::envelope::` paths.

Package name is `secrt-cli`, binary name is `secrt` (via `[[bin]]` in Cargo.toml).

## Project task tracking

This project uses [taskmaster](https://github.com/eyaltoledano/claude-task-master) conventions for tracking tasks, with a `.taskmaster/tasks/tasks.json` using the following structure:

### Directory Structure
```
.taskmaster/
├── tasks/
│   └── tasks.json    # Active tasks
├── docs/
│   └── prd.txt       # Project requirements (optional)
└── archive.json      # Completed tasks (optional)
```

### Schema
```json
{
  "master": {
    "tasks": [
      {
        "id": 1,
        "title": "Brief task title",
        "description": "What needs to be done",
        "status": "pending|in-progress|done|review|deferred|cancelled",
        "priority": "high|medium|low",
        "dependencies": [],
        "subtasks": [
          {
            "id": 1,
            "title": "Subtask title",
            "description": "Subtask details",
            "status": "pending"
          }
        ]
      }
    ]
  }
}
```
