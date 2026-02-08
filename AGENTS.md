# secrt.ca (One-time Secret Sharing) — Agent Notes

This repo is a small, security-sensitive service for one-time secret sharing (similar to onetimesecret.com). v1.0 backend will be implemented in **Go**.

Toolchain:
- Target **Go 1.24+** (match `../my-ip` conventions unless there’s a reason to pick a different baseline).

## Non-negotiables (security)

- **Zero-knowledge by default**: the server stores/serves **ciphertext only** and must not require access to decryption keys.
- **Never log secrets**: no request bodies, no decrypted plaintext, no passphrases/PINs, no URL fragments. Assume logs are retained and searchable.
- **Atomic “claim+delete”**: the read path must return the ciphertext at most once, and delete it in the same atomic operation/transaction.
- **Minimize dependencies** (runtime + crypto): prefer Go stdlib on the server; in the browser prefer WebCrypto; avoid "roll-your-own crypto".
- **Production credentials must never be in plaintext `.env` files.** Use systemd `EnvironmentFile=` with root-owned, `0600`-permission files. Never commit credentials to git. See `docs/credentials-and-deployment.md` for the full policy and setup guide.

## Specifications (normative)

The `spec/v1/` directory contains the normative v1 specs. **Read these before making changes to crypto, API, or CLI behavior:**

- `spec/v1/envelope.md` — client-side crypto workflow (AES-256-GCM, HKDF, PBKDF2, envelope JSON shape)
- `spec/v1/api.md` — HTTP API contract (endpoints, auth, error semantics, policy tiers)
- `spec/v1/server.md` — server runtime behavior (middleware, storage, atomic claim, reaper, rate limits)
- `spec/v1/cli.md` — CLI UX contract (commands, flags, TTL grammar, output discipline, completions)

**Test vectors are mandatory:**

- `spec/v1/envelope.vectors.json` — crypto interop vectors; both CLI and browser implementations MUST pass these
- `spec/v1/cli.vectors.json` — TTL parsing vectors
- `spec/v1/envelope_vectors_test.go` — verification test proving vectors are self-consistent
- `cmd/gen-vectors/` — regenerate vectors if the envelope spec changes

When spec and code disagree, fix code to match spec (or update spec first with rationale, then update code in the same changeset per server.md §16).

## Go project conventions (suggested structure)

Keep packages small and testable. Prefer an explicit dependency graph.

```
cmd/secrt-server/          # main package (wiring only)
cmd/secrt/                 # CLI client (create/claim/burn)
cmd/secretctl/             # admin CLI (API key management)
cmd/gen-vectors/           # test vector generator
internal/
  api/                     # HTTP handlers + request/response types
  storage/                 # persistence interface + implementations (postgres)
  secrets/                 # envelope validation, TTL rules, claim token checks
  auth/                    # API key auth + scopes + rate limit keys
  config/                  # env parsing, defaults
spec/v1/                   # normative specs + test vectors
web/                       # static frontend (minimal JS)
docs/                      # design + security notes
```

## Testing expectations

- **TDD-first for behavior changes:** when fixing bugs or adding features, write tests that capture the expected behavior **before** implementing the code change.
- **Bug fixes:** add a regression test that fails against current behavior, then implement the fix and verify the test passes.
- **New features:** add/extend contract tests first (unit + handler/integration as appropriate), then implement until tests pass.
- If a test cannot be written first (for example, missing harness or external constraint), document why in notes/PR and add the test in the same change set as soon as feasible.
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

## Git Commits

Git commits should be done 'atomically' when possible: One commit per logical change to the codebase. This makes it easy to trace back and figure out what change may have broken something or affected some aspect of the application.

Use the "Conventional Commits" style:

type: subject

Types:

- feat: new feature
- fix: bug fix
- test: edits to tests
- refactor: improvements to code quality
- docs: documentation
- style: style/whitespace/formatting
- perf: improved performance
- chore: configuration, dependencies, updates
- ci: CD/CD pipeline changes
- build: build system changes
- revert: revert a prior commit

Subject:

- Concise description (< 52 characters)
- Start with lowercase letter (except when using a proper noun or term that's normally capitalized)
- NO period at end

When non-trivial, add a few lines in the body in bullet point explaining the key changes made, and when non-obvious, what the rationale was.

Important: When planning big new features or preparing to make large refactors, commit any uncommitted files, _especially_ if they are likely to be touched in the impending changes. That way if everything goes wrong, it's relatively easy to revert the changes.


## Dependency policy

- Prefer stdlib (`net/http`, `crypto/*`, `database/sql`, `log/slog`).
- If adding a dependency:
  - justify it in the PR/notes (what it replaces, why it’s worth it)
  - pin versions (Go modules) and avoid sprawling transitive graphs
  - avoid dependencies that pull in large frameworks unless there’s a strong reason

## Operational assumptions

- This service may be public. Design for abuse: rate limits, size limits, and safe error messages.
- Treat any plaintext handling as high-risk. If we ever add a “server-encrypt” API for convenience, it must be **explicitly opt-in** and documented as a different trust model.
