# Test & Lint Cycle Performance — Investigation Log

**Status:** Phase 1 (measurement) complete; Phase 2 (recommendations) below.
**Owner:** jdlien (with Claude)
**Started:** 2026-04-26
**Goal:** Iteration cycles (`cargo test`, `cargo clippy`, full `make lint`) felt like
they were eating 15–20 min of wall time per round during a long working day. Make
the test system fast enough that fix-iterate loops feel cheap, while still
protecting against regression.

This file is the durable record across sessions. Update measurements & decisions
inline as we go; old measurements stay so we can see drift over time.

## Constraints / non-goals

- Must keep covering the same code paths the current suite covers — no skipping
  a test purely because it's slow.
- macOS is the primary dev environment (Apple Silicon). Linux is CI; Windows is
  CI-only. Optimizations should target macOS-local first, CI second.
- This work is scoped to test/lint cycle hygiene only. PR6/PR7 (install.sh
  trust-root, Sigstore signing) resume after.

## Repository facts (snapshot 2026-04-26)

- Workspace: 4 published crates — `secrt-core`, `secrt-cli`, `secrt-server`,
  `secrt-desktop`. CI excludes `secrt-desktop` (Tauri).
- ~46k LOC of test code across `crates/*/tests/`.
- `crates/secrt-cli/tests/` — **18 integration test files** (each = its own
  test binary, separately linked). Largest: `cli_dispatch.rs` (1158 lines).
  12 of them `mod helpers;` a 436-line shared helper.
- `crates/secrt-server/tests/` — **16 integration test files**. Largest:
  `api_amk.rs` (1246), `postgres_integration.rs` (1070).
- No `rust-toolchain.toml` pin → local 1.95.0, CI uses
  `dtolnay/rust-toolchain@stable` (drift hit us once already this week).
- `cargo-nextest` was not installed; installed during this investigation.
- `make test-rust` → `cargo test --workspace` (no `--exclude secrt-desktop`, so
  local Tauri builds too — significant local cost, see [J] below).
- `make lint-rust` → `cargo clippy --workspace -- -D warnings` + `cargo fmt --all -- --check`.

## Measurements (2026-04-26, Apple M2 Max, 12 cores, rustc 1.95.0)

Raw logs: `/tmp/secrt-perf/cold.log` and `/tmp/secrt-perf/incremental.log`
(throwaway local paths — these tables are the durable record).

### Headline numbers

| # | Scenario | Command | Wall | CPU (×) | Notes |
|---|---|---|---|---|---|
| A | Cold build tests (no secrt-desktop) | `cargo test -W --exclude secrt-desktop --no-run` | **29.8s** | 5.8× | the canonical CI test build |
| J | Cold build tests **with** secrt-desktop | `cargo test --workspace --no-run` | **57.3s** | 5.9× | what `make test-rust` does locally |
| B | No-op rebuild tests | (same, no source changes) | 0.4s | 0.6× | cargo bookkeeping only |
| C | Touch one src file, rebuild tests | (touch `secrt-cli/src/lib.rs`) | **2.5s** | 4.4× | very cheap |
| D | Touch shared helpers, rebuild | (touch `secrt-cli/tests/helpers.rs`) | **1.6s** | 5.0× | smaller, no downstream lib re-link |
| E | Test exec via `cargo test` | `cargo test -W --exclude secrt-desktop` (warm) | **25.7s** | 0.83× | sequential across binaries |
| F | Test exec via `cargo nextest` | `cargo nextest run -W --exclude secrt-desktop` | **7.3s** | 4.7× | **3.5× faster** (1092 tests in 6.2s) |
| G | Touch src, incremental clippy | `cargo clippy ... -D warnings` | 12.0s | 4.6× | rebuilds downstream cli |
| H | No-op clippy | (same, no changes) | 0.3s | trivial | — |
| I | Cold clippy | (after `cargo clean`) | **17.3s** | 3.9× | matches CI command exactly |

Target dir size: **293 MB** (excl. secrt-desktop) → **3.5 GB** (incl. secrt-desktop).
That's a 12× explosion when local devs run `make test-rust` because Tauri
pulls webkit/wry/etc.

### Key inferences

1. **Test execution is the single biggest local win.** `cargo nextest` is
   3.5× faster than `cargo test` for the exact same suite (26 s → 7 s) with
   zero code changes. `cargo test` runs binaries one-at-a-time; nextest runs
   them in parallel. CPU saturation tells the story: 0.83× vs 4.7×.
2. **Cold build is fine — when secrt-desktop is excluded.** 30 s for ~36 test
   binaries on M2 Max is not the killer. Aligning local `make test-rust` with
   CI (`--exclude secrt-desktop`) almost halves cold build time and shrinks the
   target dir 12×.
3. **Incremental builds are already fast.** 1.6–2.5 s after touching one file.
   The "umbrella binary" refactor (collapsing `tests/cli_*.rs` into one bin)
   would help cold builds but **wouldn't move the needle on day-to-day
   iteration** — defer indefinitely unless cold builds become a hot spot.
4. **CI clippy doesn't lint test code** — running `clippy --all-targets`
   surfaces ~32 lint errors in `crates/secrt-cli/tests/helpers.rs` and
   downstream test files. Pre-existing tech debt; not in scope tonight, but
   worth a follow-up task. (See "Known issues — not in scope" below.)
5. **Where is "15–20 min" actually coming from?** Single full local cycle
   measures ~73 s (excl. secrt-desktop) or ~120 s (incl. secrt-desktop). The pain is
   almost certainly:
     - `make test-rust` building secrt-desktop locally (~2× cost + huge cache)
     - `cargo test` 3.5× slower than necessary (no nextest)
     - CI round-trip per push (~5–8 min × 3-4 iterations = 20+ min waiting)
     - rust-analyzer or branch-switching invalidating incremental cache and
       forcing the 30-second cold path repeatedly
     - 1.93 vs 1.95 toolchain drift causing a re-run after fixing wrong-version
       lints

## CI redundancy & shape

`.github/workflows/ci.yml` (push to main, PRs):
- `check` job: `cargo fmt --check` + `cargo clippy --workspace --exclude secrt-desktop -- -D warnings` (ubuntu)
- `test` job: `cargo test --workspace --exclude secrt-desktop` on **ubuntu, macos, windows** matrix

`.github/workflows/release-cli.yml` (`cli/v*` tag push):
- `test` job: `cargo test --workspace --exclude secrt-desktop` + `cargo clippy --workspace --exclude secrt-desktop -- -D warnings` (ubuntu only) **— REDUNDANT**: same checks ran on the merge commit in ci.yml.
- `build` job: 5-platform matrix (darwin amd64+arm64, linux musl amd64+arm64, windows amd64) with `fail-fast: true` **— RISKY**: any one platform's flake aborts the rest, forcing a re-tag.

`.github/workflows/release-server.yml` (`server/v*` tag push):
- `test` job: same redundant pattern.
- `build` job: **ubuntu-only** matrix (linux musl amd64+arm64). No macOS / Windows server build. Probably intentional (server is deployed as a Linux container) — confirm with jdlien before assuming.

## Recommendations (in priority order)

### Priority 1 — adopt nextest + fix `make test-rust` (do tonight)

Both are zero-risk and high-impact for daily local iteration.

- [ ] Add `cargo-nextest` install instructions to `CONTRIBUTING.md` (one
      `cargo install --locked cargo-nextest` line).
- [ ] In `Makefile`, change `test-rust` to:
      ```
      cargo nextest run --workspace --exclude secrt-desktop
      ```
      Add a separate `test-rust-app` target for the rare times someone needs
      to test the desktop app locally. (Keep `cargo test` doctests covered:
      nextest doesn't run them — add `make test-doc` or fold into `make test`.)
- [ ] Document the choice: nextest is the default; raw `cargo test` still
      works for anyone who wants it.

**Expected payoff:** ~50 s → ~10 s for a local "run all tests" cycle (5×).

### Priority 2 — pin the toolchain (do tonight)

- [ ] Add `rust-toolchain.toml` at repo root pinning to `1.95.0` (stable as
      of 2026-04-14, what we're shipping today). Eliminates the local-vs-CI
      drift class entirely. Bump intentionally on a known schedule.

### Priority 3 — trim CI redundancy (small PR, do tonight or next session)

- [ ] Remove the `test` job from `release-cli.yml` and `release-server.yml`.
      The merge commit already passed it in `ci.yml`; tag push should trust
      it. Saves ~30–60 s of CI per release.
- [ ] Set `fail-fast: false` on the `release-cli.yml` build matrix so one
      platform's flake doesn't waste a tag. (Consequence: more total minutes
      consumed when a real bug hits multiple platforms; net win because re-tags
      cost more than parallel build minutes.)
- [ ] Confirm with jdlien: is `release-server.yml` ubuntu-only intentional?
      If yes, document the reason in a comment in the workflow file.

### Priority 4 — investigate-only (don't act unless P1–P3 don't move the needle)

- [ ] Try `mold` linker on Linux CI (drop-in `RUSTFLAGS=-Clink-arg=-fuse-ld=mold`).
      Likely 30–50 % cold build time. Measure first.
- [ ] Try `lld` linker on macOS local (`-Clink-arg=-fuse-ld=lld`). Less
      universally a win on macOS than mold on Linux.
- [ ] Consider `sccache` for cross-machine cache (adds setup; only worth it
      if cold cache is the killer for fresh CI runners — `Swatinem/rust-cache@v2`
      already provides per-job cache). **Probably not worth it** given the
      Swatinem cache already exists.
- [ ] **Defer the umbrella-binary refactor.** It would consolidate
      `tests/cli_*.rs` into one binary and save ~5–15 s on cold builds, but at
      the cost of restructuring 12 test files and breaking `cargo test
      --test cli_send`-style filtering. The cold-build phase is not the
      bottleneck — re-evaluate only if it becomes one.

## Known issues — not in scope tonight

- **CI clippy ignores test code.** `cargo clippy --all-targets` surfaces ~32
  lint errors in test helpers (mostly `manual_default`, `useless_conversion`,
  `field_reassign_with_default`, `to_string_in_display`). Adopting
  `--all-targets` in CI would require fixing these first. Track as separate
  task; not a perf issue.
- **`#[ignore]`-gated e2e tests** in `crates/secrt-cli/tests/e2e.rs` are
  correctly excluded from default runs. Good.
- **`postgres_integration.rs` correctly skips when `TEST_DATABASE_URL` is
  unset.** Good.

## Decisions

| Date | Decision | Rationale |
|---|---|---|
| 2026-04-26 | Adopt cargo-nextest as the default local test runner | Measured 3.5× speedup with zero code changes |
| 2026-04-26 | Align `make test-rust` with CI (`--exclude secrt-desktop`) | secrt-desktop inflates cold build 2× and target dir 12× |
| 2026-04-26 | Pin toolchain via `rust-toolchain.toml = "1.95.0"` | Drift between local 1.95 and CI's "stable" caused a real failure this week |
| 2026-04-26 | Drop redundant test/clippy job from `release-cli.yml` and `release-server.yml` | Same checks already passed in ci.yml on the merge commit; toolchain pin closes the drift gap |
| 2026-04-26 | Set `fail-fast: false` on release build matrix | One platform's transient flake should not waste the rest, forcing a re-tag |
| 2026-04-26 | Add scoped `make test-cli` / `test-server` / `test-core` targets | When iterating on one crate, no point in rebuilding the other two |
| 2026-04-26 | Add `concurrency: cancel-in-progress` to ci.yml (PRs only, not main) | Pushing a new commit cancels the now-stale CI run for the previous one |
| 2026-04-26 | Fold `check` (lint) job into `test` job, ubuntu-only steps | Saves one runner's setup overhead per push; lint is platform-agnostic |
| 2026-04-26 | Reject Linux-first build gating (Phase 4 original plan) | mac/Windows tests catch genuine platform-specific bugs (see #19); gating would surface them late |

## Phase 2/3/4 implementation results (measured 2026-04-26)

| Cycle | Before | After | Win |
|---|---|---|---|
| `make test-rust` warm | ~25 s (cargo test full workspace incl. secrt-desktop) | **8.8 s** (nextest, --exclude secrt-desktop, doctests) | ~3× |
| `make test-rust` cold | ~57 s (incl. secrt-desktop) | **30 s** (excl. secrt-desktop) | ~2× + 3.5 GB → 293 MB target |
| `make test-cli` warm (new) | n/a — had to run full workspace | **22.6 s** total wall (~5 s test exec) | scope = much smaller rebuild graph |
| `make lint-rust` warm | ~21 s | ~21 s | unchanged (same command) |
| CI per-push | 1× lint runner + 3× test runners | 3× test runners (ubuntu does lint+test inline) | ~30–40 s saved per push |
| CI on rapid pushes | each push burns full matrix | stale runs cancelled mid-flight | minutes saved per iteration burst |
| Release tag → build start | ~30–60 s test job first | starts immediately | ~30–60 s saved per release |

## New finding (2026-04-26): frontend has zero CI coverage

While measuring `pnpm test` and `pnpm check` for the frontend cycle, I
discovered:

- `web/` has **510 vitest tests** that pass locally in 7.6 s — and **CI runs
  none of them**. There are no `pnpm` invocations in any workflow file.
- `pnpm check` (TypeScript) **currently fails** with 3 pre-existing errors
  in `src/crypto/amk.test.ts` and `src/lib/clipboard.test.ts`. Because
  CI doesn't run it, nobody noticed.
- `pnpm format:check` **currently fails** — 23 files have unfixed prettier
  drift.
- `make lint-web` is therefore broken locally as a result.

This is a separate problem from test cycle performance, but it's a real
regression-risk gap. **Suggested follow-up task** (not done tonight):

1. Fix the 3 TS errors and run `pnpm format` to clean prettier drift.
2. Add a `frontend` job to `ci.yml` that runs `pnpm install --frozen-lockfile && pnpm check && pnpm test` on ubuntu.
3. Make `make lint-web` pass cleanly so future regressions are caught locally.

## Phase 5 — investigate-only (deferred)

Tonight's wins should make iteration cycles bearable. Re-evaluate these
only if they don't:

- `mold` linker on Linux CI (drop-in `RUSTFLAGS=-Clink-arg=-fuse-ld=mold`).
  Speculative ~30–50 % cold build time on Linux. Measure first.
- `lld` linker on macOS local. Less universally a win on macOS.
- `[profile.dev]` tuning (e.g., `debug = "line-tables-only"`,
  `codegen-units = 256`). Speculative 10–30 % cold build time.
- `sccache` for cross-machine cache. `Swatinem/rust-cache@v2` already
  provides per-job cache; sccache is only worth the setup if cold runners
  become a bottleneck.
- Verify Swatinem cache hit rate on a recent CI run — easy and informative.
- The umbrella-binary refactor for `tests/cli_*.rs`. Cold-build phase is
  not the bottleneck; defer indefinitely.

## Reverted / didn't help

(empty — populate when an experiment doesn't pan out so we don't re-litigate it)
