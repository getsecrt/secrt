# Test Coverage Report

## Current State

**132 tests passing, 4 E2E tests ignored (gated by env var)**

| File | Lines | Missed | Coverage |
|------|------:|-------:|---------:|
| `cli.rs` | 417 | 4 | 99.0% |
| `color.rs` | 15 | 0 | 100% |
| `envelope/crypto.rs` | 660 | 18 | 97.3% |
| `envelope/ttl.rs` | 49 | 3 | 93.9% |
| `envelope/types.rs` | 10 | 0 | 100% |
| `envelope/url.rs` | 121 | 2 | 98.3% |
| `passphrase.rs` | 255 | 13 | 94.9% |
| `create.rs` | 103 | 30 | 70.9% |
| `claim.rs` | 76 | 39 | 48.7% |
| `burn.rs` | 60 | 19 | 68.3% |
| `client.rs` | 98 | 45 | 54.1% |
| `main.rs` | 34 | 34 | 0% |
| **TOTAL** | **1898** | **207** | **89.1%** |

Excluding `main.rs` and `client.rs` (untestable I/O wiring and HTTP glue): **92.7%**.

## What's Covered

- **Crypto**: All `seal()`/`open()` paths, RNG failure injection at each call site, every `validate_envelope()` check, every `parse_kdf()` branch, claim token derivation, base64 error handling, Display impl for all error variants.
- **URL parsing**: Full URL, bare ID, port, missing fragment, wrong version, bad base64, wrong key length, empty ID, format/parse roundtrip.
- **TTL parsing**: All valid/invalid vectors from the spec (34 vectors).
- **CLI parsing**: Every flag (value + missing-value), positional args, `--help`/`-h`, unknown flags, mixed args. `resolve_globals()` with env vars, flag overrides, and defaults.
- **Passphrase**: All three sources (env/file/prompt), mutual exclusivity, empty values, file trimming, create confirmation match/mismatch, `write_error()` in JSON and plain modes.
- **CLI dispatch**: All commands, version/help flags, completion scripts (bash/zsh/fish), unknown command/shell errors.
- **Command handlers**: Flag parsing errors, input validation (empty stdin, multiple sources, invalid TTL, missing required args), passphrase resolution through the CLI, crypto through to the API call boundary.

## What's Not Covered (207 lines)

### 1. `main.rs` -- 34 lines, 0%

The real entry point that wires `io::stdin()`, `io::stdout()`, `SystemRandom`, `rpassword`, etc. into `Deps`. Tests use `cli::run()` with injected deps instead.

**To reach 100%:** Not possible with unit/integration tests. This is pure I/O wiring with no logic. The only way to cover it would be a binary-level test (`Command::new("./target/debug/secrt")`) but that doesn't help `cargo llvm-cov` instrument it.

### 2. `client.rs` -- 45 lines, 54%

All HTTP methods (`create`, `claim`, `burn`), response parsing, and error handling. The covered lines are just struct definitions and the `agent()` constructor. Everything that actually sends a request or reads a response is uncovered.

**To reach 100%:** Two options:
- **Mock HTTP**: Add a trait for the API client and inject a mock in tests. This requires refactoring `ApiClient` into a trait with `create`/`claim`/`burn` methods, then passing `Box<dyn ApiClientTrait>` into command handlers. Moderate refactor (~50 lines changed across create/claim/burn/client).
- **HTTP test server**: Spin up a lightweight HTTP server in tests (e.g., `tiny_http` or `hyper`) that returns canned responses. No refactoring needed but adds a dev-dependency and ~100 lines of server setup.

The mock trait approach is cleaner and also unlocks coverage for the post-API paths in create/claim/burn.

### 3. `create.rs` -- 30 lines, 71%

Uncovered lines fall into three groups:

| Lines | What | Why |
|-------|------|-----|
| L16-18 | `parse_flags` returning `CliError::Error` | The `parse_flags` error inside `run_create` is only reachable if `parse_flags` returns an error that isn't `ShowHelp`. Currently covered by the `--help` test. To hit this: pass an unknown flag through `run` (e.g., `secrt create --bogus`). **Easy fix.** |
| L35 | `parse_ttl` success path producing `Some(ttl)` | TTL is parsed but the result flows into the API call. Currently the TTL test uses an *invalid* TTL. A test with a valid TTL already hits L33-34 but L35 (`Ok(ttl) => Some(ttl)`) is only hit when the API call succeeds. **Requires mock API or E2E.** |
| L86-108 | Successful API response: share link formatting, JSON/plain output | Everything after `client.create()` returns `Ok(r)`. **Requires mock API or E2E.** |
| L131 | Empty file error in `read_plaintext` | **Easy fix:** Add a test with `--file` pointing to an empty file. |

### 4. `claim.rs` -- 39 lines, 49%

| Lines | What | Why |
|-------|------|-----|
| L15-17 | `parse_flags` error inside `run_claim` | Same as create. **Easy fix.** |
| L51-57 | Base URL fallback paths | URL without a path separator, non-URL input. Partially hit but some branches missed. **Could add a bare-ID-format test.** |
| L66-72 | `derive_claim_token` error | Only triggers with invalid url_key length, but `parse_share_url` already validates this. Effectively dead code. |
| L83-126 | Everything after `client.claim()` | Passphrase resolution, decryption, JSON/plain output. **Requires mock API or E2E.** |

### 5. `burn.rs` -- 19 lines, 68%

| Lines | What | Why |
|-------|------|-----|
| L15-17 | `parse_flags` error inside `run_burn` | Same pattern. **Easy fix.** |
| L58-60 | Invalid URL parse error in burn | Only reached when the input looks like a URL (`/` or `#`) but fails to parse. Currently the `burn_share_url` test uses a valid URL. **Easy fix:** Add a test with a malformed URL-like input. |
| L75-85 | Successful burn: JSON/plain output | Everything after `client.burn()` returns `Ok(())`. **Requires mock API or E2E.** |

### 6. `passphrase.rs` -- 13 lines, 95%

| Lines | What | Why |
|-------|------|-----|
| L73-79 | Duplicate mutual-exclusivity check in `resolve_passphrase_for_create` | The function has its own `count > 1` check before delegating to `resolve_passphrase`. The test for `multiple_flags_error` hits the one in `resolve_passphrase` but not this one because `passphrase_prompt` is false in that test. **Easy fix:** Add a test with `passphrase_prompt=true` plus another flag through `resolve_passphrase_for_create`. |
| L133, L137 | Error/empty branches in test helper closures | These are inside the test `make_deps` helper, not production code. Doesn't matter. |

### 7. `envelope/ttl.rs` -- 3 lines, 94%

| Lines | What |
|-------|------|
| L20 | Single-char TTL with invalid unit (e.g., `"x"`) |
| L35 | Empty TTL after `last()` returns None -- unreachable since L11 checks for empty |
| L61 | `unreachable!()` arm in unit match |

L35 and L61 are genuinely unreachable. L20 could be covered by adding `"x"` to the invalid TTL tests. **Easy fix.**

### 8. `envelope/url.rs` -- 2 lines, 98%

| Lines | What |
|-------|------|
| L25 | URL with `://` but no path after host (e.g., `https://example.com#v1.key`) |
| L28 | Fallback empty path string |

**Easy fix:** Add a test for `https://example.com#v1.<key>` (no path at all).

### 9. `cli.rs` -- 4 lines, 99%

Two lines inside a test helper closure (`make_deps_for_globals`). Not production code.

### 10. `envelope/crypto.rs` -- 18 lines, 97%

These are all inside ring library error branches (`UnboundKey::new` failure, `Nonce::try_assume_unique_for_key` failure, HKDF expand/fill failure). Ring won't actually fail on valid-length inputs, so these are defensive error paths that can't be triggered in practice.

## Path to 100%

### Easy wins (no refactoring, ~10 lines of new tests)

1. **`passphrase.rs` L73-79**: Test `resolve_passphrase_for_create` with `prompt + env` together.
2. **`create.rs` L16-18, `claim.rs` L15-17, `burn.rs` L15-17**: Pass an unknown flag through the full `run` path (e.g., `secrt create --bogus`).
3. **`create.rs` L131**: Test `--file` with an empty file.
4. **`burn.rs` L58-60**: Test burn with a malformed URL-like input (e.g., `bad/url#v1.short`).
5. **`envelope/url.rs` L25,28**: Test a URL with no path.
6. **`envelope/ttl.rs` L20**: Test single-char invalid TTL.

These would bring coverage to **~91%**.

### Medium effort: Mock API client (~100 lines of refactoring)

Extract `ApiClient` into a trait:

```rust
pub trait SecretApi {
    fn create(&self, req: CreateRequest) -> Result<CreateResponse, String>;
    fn claim(&self, id: &str, token: &[u8]) -> Result<ClaimResponse, String>;
    fn burn(&self, id: &str) -> Result<(), String>;
}
```

Add `api: Box<dyn SecretApi>` to `Deps`, inject a mock in tests that returns canned responses. This unlocks:

- `create.rs` L86-108: Successful create output (JSON + plain)
- `claim.rs` L83-126: Successful claim with passphrase resolution + decryption + output
- `burn.rs` L75-85: Successful burn output (JSON + plain)
- `client.rs` all methods: via mock, or keep real tests gated behind E2E

This would bring coverage to **~96%**.

### Unreachable / not worth covering

| Lines | Why |
|-------|-----|
| `main.rs` (34) | I/O wiring, no logic |
| `client.rs` HTTP internals (32) | Real HTTP, needs E2E |
| `crypto.rs` ring error paths (18) | Defensive; ring won't fail on valid inputs |
| `ttl.rs` L35,61 (2) | Genuinely unreachable code paths |
| `cli.rs` test helper (2) | Test code, not production |

These 88 lines represent the theoretical ceiling: **~95.4%** is the maximum achievable coverage without E2E tests and without somehow triggering ring internal failures.

## E2E Tests

The 4 ignored E2E tests cover the full create/claim roundtrip against a real server, including the post-API success paths that unit tests can't reach:

```sh
SECRET_E2E_BASE_URL=https://secrt.ca cargo test e2e -- --ignored
```

When run, these would cover most of the remaining `create.rs`, `claim.rs`, and `client.rs` gaps.
