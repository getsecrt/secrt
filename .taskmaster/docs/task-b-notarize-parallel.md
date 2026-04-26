# Task B — Release-CLI notarization parallelization (record)

**Created:** 2026-04-26
**Source:** `.taskmaster/docs/next-session-handoff.md` (Task B)
**Status:** implemented; verification deferred to next real release.

## What changed

`.github/workflows/release-cli.yml` `universal-macos` job step ordering.

**Before:**
1. Codesign universal binary
2. Notarize macOS binaries (zip submission, sequential `--wait` ~3-5 min)
3. Import Installer certificate
4. Build + sign 3 .pkg files
5. Notarize 3 .pkg files (parallel via `&` + `wait`, ~3-5 min)
6. Staple .pkg files

**After:**
1. Codesign universal binary
2. **Import Installer certificate** ← moved up (fast, no async)
3. **Build + sign 3 .pkg files** ← moved up (fast, no async)
4. **Notarize binaries-zip + 3 .pkg files** all in parallel via `&` +
   `wait` (single step; ~3-5 min total bounded by Apple's queue)
5. Staple .pkg files

## Expected payoff

~3-5 min saved per macOS release (Apple notary queue time bound).

## Why it's safe

- **Apple notary handles concurrent submissions from a single Apple ID.**
  The prior workflow already submitted 3 `.pkg` files in parallel; adding
  the binaries-zip is one more concurrent submission from the same
  `apple-id` and `team-id`. From Apple's notary's perspective there is
  no functional difference between 3 and 4 concurrent submissions.
- **No ordering dependency between the two notarizations.** The
  binaries-zip contains raw Mach-O binaries (independent inputs), the
  `.pkg` files are independently signed by `productsign`. Neither
  consumes the other's output. The handoff also calls this out
  explicitly.
- **Stapler still runs after all notarizations complete** because `wait`
  blocks until every backgrounded submission returns. No race window
  between notarization and stapling.

## Implementation notes

- Single bash loop over a `submissions` array. The array starts with
  `secrt-notarize.zip` and conditionally appends the 3 `.pkg` files
  when `HAS_INSTALLER_CERT == 'true'` (matching the existing guards on
  the now-merged-away `Notarize installer packages` step).
- Used job-level env propagation for `HAS_INSTALLER_CERT` rather than
  redeclaring it at the step. Job-level env vars are exposed as shell
  env vars to all steps in the job.
- Kept the existing `Staple installer packages` step verbatim — it's
  still gated on `HAS_APPLE_ID == 'true' && HAS_INSTALLER_CERT ==
  'true'` and runs unchanged.

## Verification status

**Not yet verified end-to-end.** The release-cli.yml workflow only
fires on `cli/v*` tag push. Tonight's commit lands on `main` directly;
the next real release tag (likely `cli/v0.16.2` or `cli/v0.17.0` per
the parallel agent's bundling note) will be the first run that
exercises this path.

If the new step fails due to an Apple-side concurrency limit not
documented today, the rollback is a one-line revert (separate the
binaries-zip submission back into its own pre-step). The existing
parallel-pkg pattern still works as a fallback shape.

## What's not in scope

- No change to `release-server.yml` (no notarization there).
- No change to the per-platform `build` matrix (line 19+) which signs
  raw binaries on each runner.
- No change to the `Staple installer packages` step.
- No change to the `Upload macOS release archives` step.
- No verification of Apple's per-account submission ceiling — relying on
  the precedent of 3 successful parallel submissions from this same
  Apple ID over many prior releases.
