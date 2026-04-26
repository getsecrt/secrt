# Next-session handoff — 0.16.x follow-ups

**Created:** 2026-04-26
**Source session:** the one that shipped the test-cycle perf push +
tasks #15/#16/#18/#19 fixes.
**For:** the next agent picking up the secrt repo.

This file is the literal opening prompt to paste into a fresh session.
It is self-contained — the new agent does not need to read the prior
conversation, only the files this references.

---

You're picking up the secrt repo at `/Users/jdlien/code/getsecrt/secrt`.

## Context from prior session

The prior session shipped commits that fixed tasks #15, #16, #18, #19
(test cycle perf, temp-dir races, `update --check` version validation,
Windows `classify_install`). Repo is now on `main` at ~`22fd56a` plus
whatever the parallel session adds for the 0.16.1 release bundle (server
cross-instance share-link fix + the two CLI fixes above).

**Do NOT re-investigate the test cycle work** — the durable record is
[`test-cycle-perf.md`](test-cycle-perf.md). Read it first so you know
what's done, what's deferred, and what was deliberately left alone.

## Your job

**PLAN three follow-up tasks.** Implementation comes after the user
approves each plan. Do not bundle them — they're independent and have
very different risk profiles.

---

### Task A — Frontend CI gap

*Probably the most actionable item; medium scope.*

The `web/` directory has 510 vitest tests that pass locally in ~7.6s but
**never run in CI**. Worse: `pnpm check` (TypeScript) currently fails
with 3 pre-existing errors and `pnpm format:check` fails with 23
prettier-drift files. `make lint-web` is broken locally as a result.
CI doesn't notice because there are zero `pnpm` invocations in any
workflow file.

Three sub-fixes, **in this order**, in one PR:

1. **Fix the 3 TS errors:**
   - `web/src/crypto/amk.test.ts` — `path` and `__dirname` undefined
     (likely missing `@types/node` or a vitest config issue)
   - `web/src/lib/clipboard.test.ts` — `Window & typeof globalThis →
     Record<string, unknown>` conversion error (line ~109)
2. **Run `pnpm format`** to clean the 23 prettier-drift files.
3. **Add a `frontend` job to `.github/workflows/ci.yml`** that runs:
   ```sh
   pnpm install --frozen-lockfile
   pnpm check       # TypeScript
   pnpm test        # vitest
   ```
   Use the existing `pnpm/setup-node` v24 / pnpm v4 pattern from
   `release-server.yml` as a reference.

**Verify:** `make lint-web && make test-web` clean locally; CI green
on first push. Watch for: vitest may need extra time on Windows. Matrix
decision — probably ubuntu-only is fine since web behaviour is
platform-agnostic.

---

### Task B — Release-CLI notarization parallelization

*Smallest scope; release-only impact.*

`.github/workflows/release-cli.yml` `universal-macos` job currently does:

```
codesign universal binary
notarize macOS binaries (--wait, ~3-5 min, SEQUENTIAL)
import Installer cert
build + sign 3 .pkg files
notarize 3 .pkg in parallel via & + wait (~3-5 min)
staple 3 .pkg
```

The two notarize calls have **no ordering dependency** on each other
(different certs, different inputs, independent Apple notary
submissions). Restructure to:

```
codesign universal binary
import Installer cert       ← move up (fast)
build + sign 3 .pkg files   ← move up (fast)
notarize binaries zip + 3 .pkg ALL IN PARALLEL  ← one step, & + wait
staple 3 .pkg
```

Saves **~3-5 min per macOS release** (Apple queue time bounds it).
Implementation is a YAML restructure of about 30 lines. Risk: low —
extends an existing parallel pattern (the `.pkg` loop already uses
`&` + `wait`). Verify the binaries-zip submission can coexist with
`.pkg` submissions in flight from the same Apple ID (it can — the same
account already does 3 parallel pkg submissions today, and 4 is no
different from Apple's perspective).

Won't fire until you cut a real `cli/v*` tag, so verification is "tag
a test-only rc and watch the timing." Or stage as a draft PR and merge
when ready to bake under the next real release.

---

### Task C — Adopt `cargo clippy --all-targets` in CI

*Cleanup; low priority.*

Today CI runs `cargo clippy --workspace --exclude secrt-app -- -D warnings`
(without `--all-targets`), which means **test code is never linted.**
Running with `--all-targets` surfaces ~32 pre-existing lint errors,
mostly in `crates/secrt-cli/tests/helpers.rs` and downstream test files.

**Categories observed during the prior session:**
- `manual_default` (`TestDepsBuilder` + `SharedBuf` could derive `Default`)
- `useless_conversion` / `to_string` for `Display` types
- `field_reassign_with_default` (multiple call sites in `cli_dispatch.rs` etc.)
- methods named `is_*` taking ownership instead of `&self`
- very-complex-type warnings in some `Box<dyn Fn>` aliases

**Concrete first step before planning:** rerun
```sh
cargo clippy --workspace --exclude secrt-app --all-targets -- -D warnings
```
and capture the **full** list (the prior session only saw the head).
Then group by lint category and decide:
- (a) fix all (most are auto-fixable with `cargo clippy --fix`), or
- (b) suppress with `#[allow(...)]` at module level for the
  genuinely-test-only quirks.

**Prefer (a).** After lints are clean, change `Makefile` and `ci.yml` to
use `--all-targets`.

---

## Workflow requirements

- For each task, follow the standard plan workflow: **explore → propose
  plan via the plan file → ExitPlanMode → user approval → implement.**
- The user reviews plans by **diffing every claim against the current
  worktree** (test names, line numbers, helper visibility, version
  flow). If a plan cites a file or function, verify it exists. If it
  cites a workflow pattern, verify against `.github/workflows/` as it
  stands.
- **Do NOT re-do work covered** in commits `4e5c836` / `63f20d1` /
  `22fd56a` / `3ff746f` / `4b56f84` / `c877ac8` / `ff142a4` — those
  landed in the prior session.
- The `Makefile` is the day-to-day entry point:
  - `make test-rust` (nextest, excludes secrt-app)
  - `make test-cli` / `test-server` / `test-core` (scoped)
  - `make lint-rust`
  - `make test-rust-fallback` (cargo test, for libtest-thread coverage)
- Toolchain pinned to **1.95.0** via `rust-toolchain.toml` — don't touch.
- Memory file
  `~/.claude/projects/-Users-jdlien-code-getsecrt/memory/MEMORY.md`
  references `feedback_plan_review.md` which captures the user's
  plan-review style. **Read it before exiting plan mode.**
- Today is **2026-04-26** (or later by the time you read this — convert
  any relative dates to absolute when saving memory).

**Start with Task A** unless the user picks differently — it's the
highest user-facing leverage and uncovers what state the web stack
is actually in.
