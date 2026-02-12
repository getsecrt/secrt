# secrt-cli — Rust CLI for secrt.ca

Rust reimplementation of the Go `secrt` CLI. One-time secret sharing with
zero-knowledge client-side encryption (AES-256-GCM + HKDF + optional PBKDF2).

## Canonical spec

The spec lives in a sibling repo: `../spec/v1/` (symlinked into this repo as `spec/`).
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
├── send.rs          # send command
├── get.rs           # get command
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

## Before committing

Always run before committing code changes:

```sh
cargo fmt      # auto-fix formatting
make check     # clippy + fmt check (will catch any remaining issues)
make test      # ensure tests pass
```

CI runs `cargo fmt --check` and `cargo clippy -- -D warnings` — commits that
fail formatting or linting will break the build.

## Project Task Tracking

For complex multi-step tasks that cannot be completed in a single step, use `.taskmaster/tasks/tasks.json` (compatible with [taskmaster-ai ](https://github.com/eyaltoledano/claude-task-master)) to plan and track progress:

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

### Guidelines
- Create when a project has 5+ distinct steps
- Query with: `jq '.master.tasks[] | select(.status=="pending")' .taskmaster/tasks/tasks.json`
- Archive completed tasks periodically to keep `.taskmaster/tasks/tasks.json` lightweight and focused on incomplete tasks.
- Init new project: `mkdir -p .taskmaster/tasks .taskmaster/docs`
