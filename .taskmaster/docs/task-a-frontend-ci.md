# Task A — Frontend CI gap (plan)

**Created:** 2026-04-26
**Source:** `.taskmaster/docs/next-session-handoff.md` (Task A)
**Risk:** medium. Three coupled fixes in one PR; no production code touched.

## Verified state (2026-04-26)

I diffed every handoff claim against the worktree before writing this plan.
Discrepancies vs. handoff text below — flagging because plan accuracy matters.

| Claim in handoff | Reality | Implication |
|---|---|---|
| `pnpm test` = 510 tests, 7.6 s | **547 tests, 3.55 s** locally | Count grew; perf better. No plan change. |
| `pnpm check` fails with **3** TS errors | **4** errors | I list all 4 below. |
| `pnpm format:check` = **23** drift files | **20** files | Drift partially fixed since handoff written. `pnpm format` covers any count. |
| Pattern: "`pnpm/setup-node v24` / pnpm v4" | Real pattern: `pnpm/action-setup@v4` + `actions/setup-node@v5` (Node 24) | Plan uses the real pattern. |
| No `pnpm` invocations in CI | Confirmed: only `release-server.yml` has them | Confirmed gap. |
| `make lint-web` is broken locally | Confirmed: `pnpm check && pnpm format:check` both fail | True. |

### Exact TS errors (verbatim from `pnpm check`)

```
src/crypto/amk.test.ts(2,30):  error TS2591: Cannot find name 'fs'.
src/crypto/amk.test.ts(3,25):  error TS2591: Cannot find name 'path'.
src/crypto/amk.test.ts(23,29): error TS2304: Cannot find name '__dirname'.
src/lib/clipboard.test.ts(109,26): error TS2352: Conversion of type 'Window & typeof globalThis' to type 'Record<string, unknown>' may be a mistake...
```

The first three trace to `import { readFileSync } from 'fs'`,
`import { resolve } from 'path'`, and `__dirname` in lines 2/3/23 of
`amk.test.ts`.

### Why tsc doesn't already know about these

`web/tsconfig.json` declares `"types": ["vite/client", "@testing-library/jest-dom/vitest"]`.
Explicit `types` array suppresses automatic `@types/*` discovery, so even
though `@types/node@25.6.0` is hoisted into `node_modules/.pnpm/` (transitive
via vite/vitest), tsc never loads it.

`vite.config.ts` uses `node:fs`, `__dirname`, `process.cwd()` too — but
it's outside `tsconfig.json`'s `include: ["src"]`, so tsc doesn't check
it. Production code in `src/` is browser-only and should *stay* browser-only.

## Approach: keep node types out of `src/` type-surface

Two ways to fix `amk.test.ts`:

**Option 1 — add `@types/node` to `types` array.** One-line fix, but exposes
`process`, `Buffer`, `fs`, etc. to every browser-only file under `src/`.
Someone could write `process.env.SECRET` in a component and tsc would
greenlight it. No eslint to catch it. Reject.

**Option 2 — drop the node imports entirely from `amk.test.ts`.** Vitest
already supports JSON imports via Vite's resolver (and `resolveJsonModule:
true` is set), so we replace:
```ts
import { readFileSync } from 'fs';
import { resolve } from 'path';
const vectorsPath = resolve(__dirname, '../../../spec/v1/amk.vectors.json');
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf-8'));
```
with one line:
```ts
import vectors from '../../../spec/v1/amk.vectors.json';
```
TS picks it up because `resolveJsonModule: true` is already set. Path
resolves at build time via Vite. No node types needed. **This is the
chosen fix.**

For `clipboard.test.ts:109`, the cast
`window as Record<string, unknown>` fails because `Window & typeof
globalThis` lacks an index signature. The TS error message tells us the
sanctioned fix: cast through `unknown` first.
```ts
const originalWindow = window as unknown as Record<string, unknown>;
```

## Plan — three commits, one PR

### Commit 1 — fix the 4 TS errors

- **`web/src/crypto/amk.test.ts`** (lines 2-3, 22-24)
  - Remove `import { readFileSync } from 'fs';`
  - Remove `import { resolve } from 'path';`
  - Replace the `vectorsPath`/`JSON.parse(readFileSync(...))` block with
    a single `import vectors from '../../../spec/v1/amk.vectors.json';` at
    the top of the file (alongside the other imports).
- **`web/src/lib/clipboard.test.ts`** (line 109)
  - Change `window as Record<string, unknown>` → `window as unknown as Record<string, unknown>`.
- **Verify:** `cd web && pnpm check` exits 0; `cd web && pnpm test` still
  passes all 547 tests (no behavior change — test still loads the same JSON).

Commit message: `fix(web): resolve TypeScript errors in test files`

### Commit 2 — run `pnpm format` to clear prettier drift

- `cd web && pnpm format` (auto-fixes the 20 drift files).
- **Verify:** `cd web && pnpm format:check` exits 0.
- **Verify:** `cd web && pnpm test` still passes all tests (formatting is
  whitespace-only).
- Inspect the diff before committing — should be pure whitespace/quoting.
  If anything semantic changed, stop and reassess.

Commit message: `style(web): apply prettier auto-format`

### Commit 3 — wire frontend into CI

Add a new `frontend` job to `.github/workflows/ci.yml` (separate from
the existing `test` matrix; ubuntu-only; doesn't need rust toolchain):

```yaml
frontend:
  name: Frontend (ubuntu-latest)
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v5

    - uses: pnpm/action-setup@v4
      with:
        package_json_file: web/package.json

    - uses: actions/setup-node@v5
      with:
        node-version: 24
        cache: pnpm
        cache-dependency-path: web/pnpm-lock.yaml

    - name: Install dependencies
      working-directory: web
      run: pnpm install --frozen-lockfile

    - name: TypeScript check
      working-directory: web
      run: pnpm check

    - name: Vitest
      working-directory: web
      run: pnpm test
```

Notes on choices that don't match the handoff verbatim:

- **Separate job, not a matrix step.** Frontend behaviour is platform-
  agnostic (browser code, node-pinned tooling); running it on
  ubuntu/macos/windows triples cost for no signal. Aligns with the
  precedent set by the existing comment in `ci.yml` lines 43-45 where
  fmt+clippy are gated to ubuntu-only "to avoid wasting minutes".
- **Action versions match the existing repo style:** `actions/checkout@v5`
  (matches `ci.yml` line 29; `release-server.yml` uses `@v6` but I'm
  staying consistent with the file I'm editing — separate decision to
  unify those across the repo, not in scope here).
- **No `pnpm format:check` step in CI.** Format drift is annoying but
  not a correctness failure; tests + tsc are the gate. Adding format:check
  to CI is a separate decision and would block PRs that don't run
  `pnpm format` locally; raise it as a follow-up if desired.
- **No coverage upload.** Existing CI doesn't upload Rust coverage either;
  adding vitest coverage upload is a separate task.

Commit message: `ci: add frontend job (TypeScript + vitest)`

## Verification (full local run, before pushing)

1. `cd web && pnpm install --frozen-lockfile`  → clean install
2. `cd web && pnpm check`                       → exit 0
3. `cd web && pnpm format:check`                → exit 0
4. `cd web && pnpm test`                        → 547/547 pass
5. `make lint-web && make test-web` from repo root → both green
6. `make test-rust` (sanity — should be unaffected) → green
7. Push as a feature branch, watch CI: new `frontend` job appears, all
   green on first push.

## What I'm not doing (scoped out)

- Not adding `format:check` to CI (deliberate; see above).
- Not bumping `actions/checkout` versions across files (unification job).
- Not adding vitest coverage CI step.
- Not adding `windows`/`macos` to the frontend matrix (not platform-
  sensitive; would triple cost for ~no signal).
- Not adding eslint (pre-existing absence; out of scope).
- Not touching `release-server.yml` or any non-web CI.

## Risks & rollback

- **Risk:** vitest hangs or runs slowly on GitHub-hosted ubuntu runners.
  Local wall is 3.55 s; GHA ubuntu-latest is comparable or slightly
  slower. If vitest exceeds 60 s I'll add `--no-coverage` (already off)
  and investigate before merging.
- **Risk:** `pnpm install --frozen-lockfile` fails on CI because the
  lockfile is somehow stale relative to package.json. Local `pnpm
  install` succeeded recently, so this is unlikely; verified locally as
  step 1 above.
- **Rollback:** revert the merge commit; no production runtime touched.

## Open questions for the user

1. OK to keep `pnpm format:check` out of CI for now?
2. OK that this PR consolidates all three sub-fixes? (Per the handoff
   it's already prescribed as "in this order, in one PR", so I'm taking
   that as a yes unless you push back.)
