# secrt — Monorepo Agent Notes

> **Note:** `CLAUDE.md` is a symlink to this file so that both Cursor (AGENTS.md) and Claude Code (CLAUDE.md) read the same instructions. Always edit `AGENTS.md` directly — never replace the symlink with a regular file.

Zero-knowledge one-time secret sharing. All encryption is client-side (AES-256-GCM + HKDF-SHA256 + optional Argon2id). The server never sees plaintext.

## Repository layout

```
secrt/
├── Cargo.toml                  # workspace root
├── crates/
│   ├── secrt-core/             # shared: crypto, envelope types, TTL, URL, API traits
│   │   └── src/
│   │       ├── lib.rs          # re-exports
│   │       ├── api.rs          # CreateRequest/Response, ClaimRequest/Response, SecretApi trait
│   │       ├── apikey.rs       # API key v2 derivation and validation
│   │       ├── crypto.rs       # seal(), open(), HKDF, Argon2id, AES-GCM
│   │       ├── payload.rs      # sealed payload frame encoding/decoding
│   │       ├── server.rs       # server-shared logic
│   │       ├── ttl.rs          # parse_ttl()
│   │       ├── types.rs        # Envelope, EncBlock, HkdfBlock, KDF types, errors
│   │       └── url.rs          # parse_share_url(), format_share_link()
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
        ├── envelope.vectors.json   # crypto test vectors (5 vectors)
        └── cli.vectors.json    # TTL test vectors (17 valid + 18 invalid)
```

## Security non-negotiables

- **Zero-knowledge by default.** The server stores and serves ciphertext only. It must never require or have access to decryption keys.
- **Never log secrets.** No request bodies, plaintext, passphrases, PINs, or URL fragments. Assume logs are retained and searchable.
- **Atomic claim+delete.** The read path must return ciphertext at most once and delete it in the same atomic operation/transaction.
- **Minimize crypto dependencies.** Use `ring` for Rust, WebCrypto in the browser. Never roll your own crypto.
- **No credentials in plaintext files.** Production credentials use systemd `EnvironmentFile=` with root-owned `0600` permissions. Never commit credentials to git.

## Specification

The spec at `spec/v1/` is the normative contract for all implementations. **Read the spec before making changes to crypto, API, or CLI behavior.**

- `envelope.md` — client-side crypto workflow (AES-256-GCM, HKDF, Argon2id, envelope JSON shape)
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

### Local Postgres-backed tests

Server runtime and Postgres integration tests use `TEST_DATABASE_URL` when present.

```sh
# Known local option (default system user + local `secrt` DB)
TEST_DATABASE_URL='postgresql://jdlien@localhost/secrt?sslmode=disable' cargo test -p secrt-server postgres_integration -- --nocapture

# Include DB-backed paths in coverage runs
TEST_DATABASE_URL='postgresql://jdlien@localhost/secrt?sslmode=disable' cargo llvm-cov --workspace --summary-only
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

There are **two separate release pipelines** — one for the CLI and one for the server. Both share the same workspace version, but each is triggered by its own tag prefix. **Always tag and push both** when releasing a new version.

1. Update `version` in the workspace `Cargo.toml`
2. Update `secrt-core` version in `crates/secrt-cli/Cargo.toml` and `crates/secrt-server/Cargo.toml` dependencies
3. Add changelog entries in `crates/secrt-cli/CHANGELOG.md` and `crates/secrt-server/CHANGELOG.md`
4. Commit: `chore: bump version to X.Y.Z`
5. Tag **both** releases: `git tag cli/vX.Y.Z && git tag server/vX.Y.Z`
6. Push: `git push origin main --tags`
7. After the release workflows finish, update both GitHub Releases with notes matching the CHANGELOG entries, and explicitly set release titles to match the exact tag names:
   ```sh
   gh release edit cli/vX.Y.Z --title "cli/vX.Y.Z" --notes "$(cat <<'EOF'
   ## What's Changed
   (Paste the CHANGELOG.md entry for this version here, formatted for GitHub markdown)
   EOF
   )"
   ```
   Repeat for `server/vX.Y.Z` with `--title "server/vX.Y.Z"`. Include all Added/Changed/Fixed/Removed sections from the changelog.
8. Verify both tags and releases resolve correctly:
   ```sh
   git ls-remote --tags origin cli/vX.Y.Z server/vX.Y.Z
   gh release view cli/vX.Y.Z --json tagName,name,publishedAt,url
   gh release view server/vX.Y.Z --json tagName,name,publishedAt,url
   ```
9. **Do not use** `releases/latest` for server artifact selection. GitHub "latest" is repo-wide and may point to a CLI release.
   - For server downloads, always use tag-pinned URLs (`/releases/download/server%2FvX.Y.Z/...`).
   - If automation needs "latest server tag", query and filter by tag prefix:
     ```sh
     gh api repos/getsecrt/secrt/releases \
       --jq '[.[] | select(.tag_name|startswith("server/v"))] | sort_by(.tag_name | sub("^server/v"; "") | split(".") | map(tonumber)) | last.tag_name'
     ```

**`cli/v*` tag** triggers the CLI release workflow (`.github/workflows/release-cli.yml`):
- Runs `cargo test --workspace` and `cargo clippy --workspace`
- Cross-compiles for 6 targets (macOS arm64/amd64, Linux amd64/arm64, Windows amd64/arm64)
- Creates a universal macOS binary via `lipo`
- Code-signs macOS binaries (Developer ID + notarization)
- Code-signs Windows binaries (Azure Trusted Signing)
- Generates SHA256 checksums
- Publishes a GitHub Release with all CLI artifacts

**`server/v*` tag** triggers the server release workflow (`.github/workflows/release-server.yml`):
- Runs `cargo test --workspace` and `cargo clippy --workspace`
- Builds the web frontend (`pnpm install --frozen-lockfile && pnpm run build`)
- Cross-compiles server + admin binaries for Linux amd64/arm64 (musl)
- Generates SHA256 checksums
- Publishes a GitHub Release with server and admin artifacts

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
