# Task C — Adopt `cargo clippy --all-targets` in CI (plan)

**Created:** 2026-04-26
**Source:** `.taskmaster/docs/next-session-handoff.md` (Task C)
**Risk:** medium — touches production code, but mostly mechanical.

## Verified state (2026-04-26)

Ran `cargo clippy --workspace --exclude secrt-app --all-targets -- -D warnings`
on commit `70141a1`. **57 lint errors total.**

### Discrepancies vs. handoff

| Handoff claim | Reality | Implication |
|---|---|---|
| "~32 pre-existing lint errors" | **57 total** lint errors | Handoff number was for the cli lib-test only. Plan reflects 57. |
| "mostly in `tests/helpers.rs` and downstream test files" | **Mostly in production code** (passphrase.rs:25, http/mod.rs:5, runtime.rs:3, cli.rs:5, update_check.rs:2, release_poller.rs:2, postgres.rs:1 = 43 in `src/`; helpers.rs:8, tests/api_*.rs:2, tests/helpers/mod.rs:2 = 12 in `tests/`; rest in `#[cfg(test)]` mods under src/) | Risk profile higher than implied — touching production. |
| Categories: `manual_default`, `useless_conversion`, `field_reassign_with_default`, `is_*` self-convention, `Box<dyn Fn>` complexity | Actual top-5 categories: `field_reassign_with_default` (26), `io_other_error` (6), `await_holding_lock` (5), `sort_by_key` (4), `ptr_arg` (3) | `manual_default` and `useless_conversion` aren't in the count; `await_holding_lock` is the one I'd flag separately as not purely cosmetic. |

### Full breakdown by lint category

| Lint | Count | Where |
|---|---|---|
| `field_reassign_with_default` | 26 | passphrase.rs (23 in `#[cfg(test)]`), cli.rs (3 in `#[cfg(test)]`) |
| `io_other_error` (use `Error::other(_)`) | 6 | passphrase.rs (2), cli.rs (2), helpers.rs (2) |
| `await_holding_lock` | 5 | runtime.rs `#[cfg(test)]` (3), api_passkey_mgmt.rs (2) |
| `sort_by_key` | 4 | http/mod.rs (2), tests/helpers/mod.rs (2) |
| `ptr_arg` (`&PathBuf` → `&Path`) | 3 | update_check.rs (2 in `#[cfg(test)]`), 1 elsewhere |
| `wrong_self_convention` (is_*) | 3 | tests/helpers.rs builder methods |
| `unnecessary_get_then_check` | 2 | release_poller.rs |
| `needless_borrow` | 2 | http/mod.rs |
| `type_complexity` | 1 | tests/helpers.rs |
| `inherent_to_string` | 1 | tests/helpers.rs `SharedBuf` |
| `derivable_impls` | 1 | tests/helpers.rs `MockApiResponses` |
| `comparison_to_empty` (len == 0) | 1 | http/mod.rs |
| `assert_eq` w/ bool literal | 1 | helpers.rs |
| `items_after_test_module` | 1 | postgres.rs (cfg(test) at L427, more `impl`s at L450-1298) |

### Notable: `await_holding_lock` is not purely cosmetic

It flags real correctness risks. I checked all 5 sites:

- **`runtime.rs:660,679,695` (3)** — `let _lock = env_lock();` followed by
  awaits. The lock is a global `std::sync::Mutex` that serializes tests
  which mutate process-wide env vars. The lock *must* be held across
  the async test body because the contention is on env vars (process
  state), not the Mutex itself. Switching to `tokio::sync::Mutex`
  doesn't help — env vars are still process-global.
  **Decision: `#[allow(clippy::await_holding_lock)]` with comment
  explaining why.**

- **`api_passkey_mgmt.rs:492,645` (2)** — `let passkeys = store.passkeys.lock()...; ... drop(passkeys);` followed by an await.
  The explicit `drop()` *should* release before the await but clippy is
  conservative about this pattern. **Decision: refactor to a `let x = { let g = store.lock(); g.foo() };` block-scope which clippy
  recognizes cleanly.** This is a real readability win and matches the
  intent of the code.

### Notable: `wrong_self_convention` on `is_*` builder methods

`tests/helpers.rs:237/243/249` — `pub fn is_tty(mut self, v: bool) -> Self { ... }` etc. These are builder-pattern setters that
consume `self`, but their names imply predicates. Renaming them
(`tty(bool)`, `stdout_tty(bool)`) would be the right fix but means
chasing call sites across ~12 test files.

**Decision: rename.** It's mechanical (find/replace) and surfaces a real
naming bug; deferring would mean carrying `#[allow]` forever. If call
sites turn out to be more sprawling than expected, fall back to
`#[allow(clippy::wrong_self_convention)]` on the impl block with a
TODO comment, but try the rename first.

## Plan — five commits, one PR (don't push until 0.16.1 lands)

### Commit 1 — auto-fixable lints via `cargo clippy --fix`

Run:
```sh
cargo clippy --workspace --exclude secrt-app --all-targets --fix \
  --allow-dirty --allow-staged
```

Expected to handle (from clippy's docs): `field_reassign_with_default`
(when struct literal fits), `sort_by_key`, `ptr_arg`, `io_other_error`,
`needless_borrow`, `unnecessary_get_then_check`, `comparison_to_empty`,
`derivable_impls`. Most of the 57 should fall here.

After --fix, re-run lint and inspect the residual list. Run
`cargo fmt` and `make test-rust` to confirm no behavior regressions.

Risks:
- Auto-fix may rewrite a `field_reassign_with_default` block in a way
  that breaks if the field count is large (struct literal becomes
  unreadable). If a specific site looks worse after auto-fix, hand-
  rewrite or revert that one hunk.
- `ptr_arg` rewrite of `&PathBuf` → `&Path` is *load-bearing* if any
  callsite passes `&pathbuf_var` — `&PathBuf` derefs to `&Path` so
  callers don't need to change, but verify by running tests.

Commit message: `refactor: apply mechanical clippy fixes (--all-targets)`

### Commit 2 — manual fixes for what `--fix` didn't catch

Likely residual:
- `assert_eq!(x, true)` → `assert!(x)` (one site in helpers.rs)
- `inherent_to_string` on `SharedBuf` → `impl Display for SharedBuf` (Display gives a free `to_string()` so all callers keep working).
- `type_complexity` on `Box<dyn Fn(&str) -> Result<(), String>>` → introduce `type CopyFn = Box<dyn Fn(&str) -> Result<(), String>>;` at module scope and use it.

Verify after each: `make test-rust` green.

Commit message: `refactor(test): clean up helpers.rs to satisfy clippy`

### Commit 3 — `await_holding_lock` real fixes

- **`tests/api_passkey_mgmt.rs:492-498` and `:645-...`** — wrap the lock
  region in a block expression so the guard drops at block end:
  ```rust
  let alice_pk_id = {
      let passkeys = store.passkeys.lock().expect("lock");
      passkeys.values()
          .find(|p| p.credential_id == "cred-xuser-a")
          .expect("alice pk")
          .id
  };
  ```
  Removes the explicit `drop(passkeys)` and silences clippy.

Commit message: `refactor(test): scope mutex guards to silence await_holding_lock`

### Commit 4 — justified `#[allow]` and structural reorder

- **`runtime.rs` `#[cfg(test)] mod tests`** — add at the top of the
  test module:
  ```rust
  #![allow(clippy::await_holding_lock)]
  // env_lock() serializes tests that mutate process-global env vars.
  // The lock contention is on the env, not the mutex; an async-aware
  // mutex would not help.
  ```
- **`tests/helpers.rs` builder block** — rename `is_tty`/`is_stdout_tty`/
  `is_stderr_tty` to `tty`/`stdout_tty`/`stderr_tty`. Then grep and
  update all call sites. Run `make test-rust` to verify.
  - **Fallback:** if rename surfaces too many surprises (>5 files
    needing non-trivial changes), revert and instead add
    `#[allow(clippy::wrong_self_convention)]` on the impl block with a
    `// TODO: rename to drop is_ prefix; clippy is right about the
    name implying a predicate.` comment.
- **`postgres.rs`** — move the `#[cfg(test)] mod tests { ... }` from
  line 427 to the end of the file, after the last `impl` (currently
  line 1298+). Run `make test-server` to confirm tests still find
  visible items.

Commit message: `refactor: silence remaining clippy lints with rationale`

### Commit 5 — adopt `--all-targets` in CI and Makefile

- **`Makefile`** — change `lint-rust`:
  ```make
  lint-rust:
  	cargo clippy --workspace --exclude secrt-app --all-targets -- -D warnings
  	cargo fmt --all -- --check
  ```
- **`.github/workflows/ci.yml`** — change clippy step:
  ```yaml
  - name: Clippy (ubuntu only)
    if: matrix.os == 'ubuntu-latest'
    run: cargo clippy --workspace --exclude secrt-app --all-targets -- -D warnings
  ```

Verify locally: `make lint-rust` exits 0.

Commit message: `ci: lint test code via cargo clippy --all-targets`

## Verification

After the full chain:
1. `cargo clippy --workspace --exclude secrt-app --all-targets -- -D warnings` → exit 0
2. `make lint-rust` → exit 0
3. `make test-rust` → all pass
4. `make test-cli`, `make test-server`, `make test-core` → green
5. Inspect `git log` — 5 commits, atomic, readable.

## Scope-out / explicit non-goals

- Not running clippy on `secrt-app` (Tauri excluded everywhere; not in scope).
- Not adopting `--all-features` (out of scope; we use default features).
- Not bumping clippy lint set (still default + `-D warnings`).
- Not gating frontend lints (Task A territory).
- Not adopting `cargo machete` or unused-dep checks (separate cleanup).

## Risks & rollback

- **Risk:** auto-fix touches ~50+ locations and accidentally breaks a
  test. Mitigation: run `make test-rust` after every commit; if a
  commit fails, drop it and hand-fix the relevant lints in a smaller
  atomic commit.
- **Risk:** `Display` impl for `SharedBuf` differs subtly from the
  current `to_string()` if the caller relied on something Display
  doesn't give. The current implementation calls
  `String::from_utf8_lossy(&buf).to_string()`, which is
  identical to `write!(f, "{}", String::from_utf8_lossy(&buf))`. Safe.
- **Rollback:** every commit is independently revertible; final
  Makefile/ci.yml change is a one-line revert.

## Open questions for the user

1. Are you OK with the renames in commit 4 (`is_tty` → `tty` etc.)?
   They're builder methods used across the test suite. I'll fall back
   to `#[allow]` if it's too sprawling.
2. Bundle into one PR or split? (Handoff is silent; I default to one
   PR with 5 atomic commits since they're all "lint hygiene" themed and
   the partial state — `--all-targets` in CI without all fixes done —
   is broken.)
3. OK to land these on `main` directly (per your no-PR-needed
   workflow) once 0.16.1 CI clears?
