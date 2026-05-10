# Next-session handoff — post-0.16.2 follow-ups

**Created:** 2026-04-26 (replaces the prior handoff which covered Tasks A/B/C — all shipped in `cli/v0.16.2`/`server/v0.16.2`).
**For:** the next agent picking up the secrt repo at `/Users/jdlien/code/getsecrt/secrt`.

This file is the literal opening prompt to paste into a fresh session.
Self-contained — read this and the files it references, no prior
conversation needed.

---

You're picking up the secrt repo. Most of the urgent work landed in
`cli/v0.16.2` + `server/v0.16.2` (released and deployed to both
production hosts on 2026-04-26). Four loose threads remain. They are
**independent** — pick whichever fits your time box.

## What NOT to redo

These all landed in commits up to `a9b7305` (`chore: bump version to 0.16.2`):

- Task A — frontend CI gap closed (new `Frontend (ubuntu-latest)` job in `.github/workflows/ci.yml`)
- Task B — release-cli notarization parallelization (validated in production on the cli/v0.16.2 release run — succeeded)
- Task C — `cargo clippy --workspace --exclude secrt-desktop --all-targets -- -D warnings` is now clean and required by CI + Makefile
- pnpm/action-setup v4 → v6 (Node.js 24)
- Task #55 — `secrt update` permission-denied message branches: `sudo secrt update` for system paths (`/usr/local/bin`, etc.), `--install-dir ~/.local/bin` for user-space paths

Durable design records live in `.taskmaster/docs/`:
- `task-a-frontend-ci.md`, `task-b-notarize-parallel.md`, `task-c-clippy-all-targets.md`
- `test-cycle-perf.md` — measured baselines

## Context that's already true

- Repo is at workspace version `0.16.2` (Cargo.toml + crate dep refs).
- Both production hosts (`secrt.is`, `jdlien.com` which serves `secrt.ca`) are on `0.16.2`. `curl https://secrt.ca/api/v1/info` should return `latest_cli_version: "0.16.2"`.
- The `frontend` CI job runs `pnpm install --frozen-lockfile && pnpm check && pnpm test`. It does NOT run `pnpm format:check` (deliberate; see #4 below).
- Toolchain pinned at `1.95.0` via `rust-toolchain.toml`.
- `make test-rust` (nextest) → green; `make lint-rust` (clippy --all-targets + fmt-check) → clean.
- A separate agent is working on **task #56** (expose `server_version` on `/api/v1/info` + `X-Secrt-Server-Version` response header). **Do NOT touch task #56.** Check `tasks.json` and `git log` first if unsure.

---

## Loose threads (independent — pick any)

### Thread 1 — Builder rename in `crates/secrt-cli/tests/helpers.rs`

*Mechanical refactor; medium scope; touches ~88 call sites.*

`tests/helpers.rs:236-256` defines three builder setters that consume
`self`:

```rust
#[allow(clippy::wrong_self_convention)]
pub fn is_tty(mut self, v: bool) -> Self { ... }

#[allow(dead_code)]
#[allow(clippy::wrong_self_convention)]
pub fn is_stdout_tty(mut self, v: bool) -> Self { ... }

#[allow(dead_code)]
#[allow(clippy::wrong_self_convention)]
pub fn is_stderr_tty(mut self, v: bool) -> Self { ... }
```

There's a `// TODO: rename to drop the `is_` prefix — these are builder
setters, not predicates. Rename touches ~88 call sites across test
files; deferred to a focused refactor PR.` comment in place. **This is
that focused refactor PR.**

**Plan:**

1. Rename methods: `is_tty` → `tty`, `is_stdout_tty` → `stdout_tty`,
   `is_stderr_tty` → `stderr_tty`. The fields keep their names
   (`self.is_tty`, etc.) — only the builder methods change.
2. Drop the three `#[allow(clippy::wrong_self_convention)]` attributes
   and the TODO comment.
3. Update call sites. They're all in `crates/secrt-cli/tests/`. The
   pattern `\.is_(tty|stdout_tty|stderr_tty)\(` should be safe to
   replace with `.\1(` (or just sed). **Watch:** field-style accesses
   like `self.is_tty = v;` MUST NOT change.

```sh
# Audit before changing
grep -rn '\.is_tty(\|\.is_stdout_tty(\|\.is_stderr_tty(' crates/secrt-cli/tests/ | wc -l   # ~88
grep -rn '\.is_tty\b\|\.is_stdout_tty\b\|\.is_stderr_tty\b' crates/secrt-cli/tests/ | wc -l # should be same — confirms no field-style uses

# Apply (verify the diff before committing)
find crates/secrt-cli/tests -name '*.rs' -exec sed -i '' \
  -e 's/\.is_tty(/.tty(/g' \
  -e 's/\.is_stdout_tty(/.stdout_tty(/g' \
  -e 's/\.is_stderr_tty(/.stderr_tty(/g' {} \;
```

**Verify:** `make test-cli && make lint-rust` clean.

**Risk:** very low — pure mechanical, type system enforces correctness.
Field references (`self.is_tty`) are unchanged because the regex matches
only method-call form `(`.

**Commit message:** `refactor(test): rename is_tty builder methods to drop is_ prefix`

---

### Thread 2 — `softprops/action-gh-release@v2` → `v3` (Node.js 24)

*Tiny CI hygiene; ~5 LOC.*

The cli/v0.16.2 + server/v0.16.2 release runs surfaced a Node.js 20
deprecation warning for this action. Upstream `v3.0.0` (released
2026-04-12) is "a major release that moves the action runtime from
Node 20 to Node 24" — the action's input/output API is unchanged, so
it's a drop-in bump.

**Files:**
- `.github/workflows/release-cli.yml:355` (look for `softprops/action-gh-release@v2`)
- `.github/workflows/release-server.yml:109` (same)

Change `@v2` → `@v3`. Sanity-check the file with
`python3 -c "import yaml; yaml.safe_load(open('<file>'))"` after.

**Won't fire until you cut a real release tag**, so verification is
"the next 0.16.x or 0.17.0 release run is green and no longer prints
the Node 20 warning." Or stage as a draft and ride along the next
real release.

**Commit message:** `ci: bump softprops/action-gh-release v2 → v3 (Node.js 24)`

---

### Thread 3 — Unify `actions/checkout` versions across workflows

*Cosmetic; ~3 LOC; do alongside Thread 2 if you're touching workflows
anyway.*

Audit:
```sh
grep -n actions/checkout .github/workflows/*.yml
```

Current state:
- `ci.yml` uses `@v5` (twice)
- `release-cli.yml` uses `@v6`
- `release-server.yml` uses `@v6`

`v6` is the latest stable. Bump `ci.yml` to `@v6` for consistency, or
pin everything at `@v5` if `v6` introduces breakage in the rust-cache
path you don't want to debug right now. (Last known: `v6` is fine for
all three; the mismatch is just historical.)

**Commit message:** `ci: unify actions/checkout at v6 across workflows`

Combine with Thread 2 in one PR if you like — both are pure CI hygiene.

---

### Thread 4 — Add `pnpm format:check` to the frontend CI job (when ready)

*Deliberately deferred. Don't ship this without a trigger.*

The `frontend` job in `.github/workflows/ci.yml` runs `pnpm check` +
`pnpm test` but **not** `pnpm format:check`. That was a deliberate
choice while the project is solo-dev: drift in prettier formatting
isn't a correctness issue, and gating PRs on whitespace would just
annoy the developer who forgets to run `pnpm format` locally.

**Trigger this when:** the project picks up a regular collaborator (or
when CI starts seeing repeated whitespace-only diffs from a contributor
who doesn't have an editor-on-save formatter configured).

**Implementation:** one new step in the `frontend` job:

```yaml
- name: Prettier check
  working-directory: web
  run: pnpm format:check
```

Place it between `TypeScript check` and `Vitest`, or after both — order
doesn't matter (they're all gates).

**Commit message:** `ci: gate frontend on pnpm format:check`

---

## Workflow notes

- `make test-rust` for the iteration loop; `make test-rust-fallback`
  if nextest isn't installed.
- The `Makefile` is the day-to-day entry point — read it for scoped
  targets (`test-cli`, `test-server`, `test-core`, `test-web`).
- Toolchain pinned to `1.95.0` via `rust-toolchain.toml` — don't touch.
- The user reviews plans by **diffing every claim against the current
  worktree**. If you cite a file or function in a plan, verify it
  exists *now*. Memory note at
  `~/.claude/projects/-Users-jdlien-code-getsecrt/memory/feedback_plan_review.md`
  captures the review style.
- The user also pushes back on UX hedges in task specs — see
  `feedback_question_design_hedges.md`. If a plan describes "show A AND
  B" with contradictory implications, propose the cleaner branched
  shape before implementing the hedge.
- Today is **2026-04-26** (or later by the time you read this — convert
  any relative dates to absolute when saving memory).

## Branch / push policy

The user works directly on `main` (no PRs, solo-dev). Pushing is fine
as long as no parallel agent is mid-flight. Check `git fetch && git log
HEAD..origin/main` before push; if origin advanced, rebase your work
on top.
