# secret.fullspec.ca (One-time Secret Sharing) — Agent Notes

This repo is a small, security-sensitive service for one-time secret sharing (similar to onetimesecret.com). v1.0 backend will be implemented in **Go**.

Toolchain:
- Target **Go 1.24+** (match `../my-ip` conventions unless there’s a reason to pick a different baseline).

## Non-negotiables (security)

- **Zero-knowledge by default**: the server stores/serves **ciphertext only** and must not require access to decryption keys.
- **Never log secrets**: no request bodies, no decrypted plaintext, no passphrases/PINs, no URL fragments. Assume logs are retained and searchable.
- **Atomic “claim+delete”**: the read path must return the ciphertext at most once, and delete it in the same atomic operation/transaction.
- **Minimize dependencies** (runtime + crypto): prefer Go stdlib on the server; in the browser prefer WebCrypto; avoid “roll-your-own crypto”.

## Go project conventions (suggested structure)

Keep packages small and testable. Prefer an explicit dependency graph.

```
cmd/secret-server/         # main package (wiring only)
internal/
  api/                     # HTTP handlers + request/response types
  storage/                 # persistence interface + implementations (sqlite/postgres/redis)
  secrets/                 # envelope validation, TTL rules, claim token checks
  auth/                    # API key auth + scopes + rate limit keys
  config/                  # env parsing, defaults
web/                       # static frontend (minimal JS)
docs/                      # design + security notes
```

## Testing expectations

- Prefer **table-driven tests**, `t.Parallel()` when safe, and `httptest` for HTTP handlers.
- Avoid flakiness: inject clocks/time where needed; keep tests deterministic.
- Add targeted tests for:
  - **claim atomicity** under concurrency (two clients racing to claim)
  - TTL expiry behavior
  - request validation and error mapping
  - storage-layer behavior (SQLite/Postgres) behind a common interface
- Coverage target: **90%+ for core packages** (`internal/secrets`, `internal/storage` claim paths). Handlers can be lighter if they’re thin.

## Linting / formatting / security scanning

Baseline command set (mirrors practices from `../my-ip`):

```bash
go test ./...
go test -race ./...
golangci-lint run
govulncheck ./...
```

Prefer adding a `Makefile` with `build`, `test`, `test-cover`, `test-race`, `lint`, `govulncheck`, and `check` targets.

Formatting:
- Always run `gofmt` and `goimports` on touched files.

Static analysis:
- Prefer `golangci-lint` with a conservative ruleset (errcheck/staticcheck/govet/goimports/bodyclose/noctx/sqlclosecheck/errorlint/copyloopvar).

Vuln scanning:
- Run `govulncheck` before releases.

## Dependency policy

- Prefer stdlib (`net/http`, `crypto/*`, `database/sql`, `log/slog`).
- If adding a dependency:
  - justify it in the PR/notes (what it replaces, why it’s worth it)
  - pin versions (Go modules) and avoid sprawling transitive graphs
  - avoid dependencies that pull in large frameworks unless there’s a strong reason

## Operational assumptions

- This service may be public. Design for abuse: rate limits, size limits, and safe error messages.
- Treat any plaintext handling as high-risk. If we ever add a “server-encrypt” API for convenience, it must be **explicitly opt-in** and documented as a different trust model.
