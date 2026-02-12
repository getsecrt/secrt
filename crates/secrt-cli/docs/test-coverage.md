# Test Coverage Report

## Current State

**257 tests passing, 6 E2E tests ignored (gated by env var)**

| Suite | Tests | Description |
|-------|------:|-------------|
| Unit (secrt) | 134 | Flag parsing, globals, crypto, URL, TTL, config, passphrase |
| cli_burn | 15 | Burn command integration tests |
| cli_claim | 30 | Claim command integration tests |
| cli_create | 41 | Create command integration tests |
| cli_dispatch | 27 | Top-level dispatch, help, version, completion |
| envelope_vectors | 6 | Spec crypto test vectors |
| ttl_vectors | 2 | Spec TTL test vectors (17 valid + 17 invalid) |
| E2E (ignored) | 6 | Full roundtrip against live server |

## Architecture: Mock API Testing

The codebase uses a `SecretApi` trait to abstract the HTTP layer:

```rust
pub trait SecretApi {
    fn create(&self, req: CreateRequest) -> Result<CreateResponse, String>;
    fn claim(&self, secret_id: &str, claim_token: &[u8]) -> Result<ClaimResponse, String>;
    fn burn(&self, secret_id: &str) -> Result<(), String>;
}
```

`Deps` includes a `make_api: Box<dyn Fn(&str, &str) -> Box<dyn SecretApi>>` factory. In production (`main.rs`), this creates a real `ApiClient`. In tests, `TestDepsBuilder` supports `.mock_create()`, `.mock_claim()`, and `.mock_burn()` to inject canned responses via `MockApi`, enabling full success-path testing without network calls.

## What's Covered

- **Crypto**: All `seal()`/`open()` paths, `requires_passphrase()`, RNG failure injection at each call site, every `validate_envelope()` check, every `parse_kdf()` branch, claim token derivation, base64 error handling, Display impl for all error variants.
- **URL parsing**: Full URL, bare ID, port, missing fragment, wrong version, bad base64, wrong key length, empty ID, no-path URL, format/parse roundtrip.
- **TTL parsing**: All valid/invalid vectors from the spec (34 vectors), single-char invalid input.
- **CLI parsing**: Every flag (value + missing-value), positional args, `--help`/`-h`, unknown flags, mixed args, `-p`/`-s`/`-m` short forms. `resolve_globals()` with env vars, config file, flag overrides, and defaults.
- **Config**: TOML loading, partial configs, invalid TOML warnings, permission-based secret filtering, missing file fallback, `show_input` option.
- **Passphrase**: All three sources (env/file/prompt), config default fallback, mutual exclusivity (in both `resolve_passphrase` and `resolve_passphrase_for_create`), empty values, file trimming, create confirmation match/mismatch, `write_error()` in JSON and plain modes.
- **CLI dispatch**: All commands, version/help flags, completion scripts (bash/zsh/fish), unknown command/shell errors, config subcommands.
- **Command handlers (create)**: Unknown flags, input validation (empty stdin/file, multiple sources, invalid TTL), passphrase via env, conflicting passphrase flags, success paths (plain + JSON + TTL + TTY stdout), API error handling (TTY + silent), `--show`/`--hidden`/`--silent`/`--trim` modes.
- **Command handlers (claim)**: Unknown flags, missing URL, invalid URL, base-URL override, success paths (plain + JSON + passphrase), JSON with unicode/emoji, JSON with binary data (lossy UTF-8), decryption error, API error handling, auto-prompt on TTY (success + empty input + read error), non-TTY passphrase error, passphrase retry (single + many attempts), no retry with env/file flags, retry with explicit `-p` flag, conflicting flags, JSON non-TTY error, `--silent` hides notice.
- **Command handlers (burn)**: Unknown flags, missing ID, missing API key, bare ID, share URL, malformed URL, success paths (plain + JSON + via share URL + TTY checkmark), API error handling, env API key, `--silent` suppresses message.

## What's Not Covered

### 1. `main.rs` — 37 lines, 0%

Pure I/O wiring: `io::stdin()`, `io::stdout()`, `SystemRandom`, `rpassword`, config loading. Tests use `cli::run()` with injected deps instead. Not coverable with unit/integration tests.

### 2. `client.rs` — ~45 lines uncovered, ~86%

All HTTP methods (`create`, `claim`, `burn`), response parsing, and error handling. The mock API trait bypasses this code entirely. Only coverable via E2E tests against a real server.

### 3. `claim.rs` — ~10 lines uncovered

| Lines | What | Why |
|-------|------|-----|
| Base URL derivation | Edge cases in URL parsing fallback | Some branches unreachable after `parse_share_url` validates |
| `derive_claim_token` error | Only triggers with invalid url_key length | `parse_share_url` already validates key length |

### 4. `create.rs` — ~8 lines uncovered

| Lines | What | Why |
|-------|------|-----|
| Seal envelope error | Ring won't fail with valid inputs | Defensive code |
| `fs::read` / `stdin.read_to_end` error closures | I/O errors can't be injected through `Deps` | Would need OS-level fault injection |

### 5. `envelope/crypto.rs` — ~18 lines uncovered

All inside ring library error branches (`UnboundKey::new`, `Nonce::try_assume_unique_for_key`, HKDF expand/fill). Ring won't fail on valid-length inputs. Defensive code.

### 6. `config.rs` — ~13 lines uncovered

The top-level `load_config()` function (config path resolution, permission checking, file loading orchestration). The internal functions (`load_config_from_path`, `load_config_filtered`) are fully tested. `load_config()` itself is only called from `main.rs`.

### 7. `passphrase.rs` — ~10 lines uncovered

Uncovered lines are inside test helper closures (`make_deps`), not production code.

### 8. `cli.rs` — ~15 lines uncovered

Test helper closures and config-related globals wiring in test helpers. Not production code.

### 9. `envelope/ttl.rs` — 3 lines uncovered

L35 and L61 are genuinely unreachable (empty check at L11 prevents L35; L61 is `unreachable!()` after exhaustive match).

## Theoretical Coverage Ceiling

| Category | Lines | Notes |
|----------|------:|-------|
| `main.rs` I/O wiring | 37 | Not testable |
| `client.rs` HTTP | ~45 | Only via E2E |
| `crypto.rs` ring errors | ~18 | Can't trigger with valid inputs |
| `config.rs` `load_config()` | ~13 | Only called from `main.rs` |
| `ttl.rs` unreachable | 2 | Dead code |
| Test helper closures | ~10 | Not production code |
| **Total uncoverable** | **~125** | |

Maximum achievable without E2E: approximately 97% of coverable production code.

## E2E Tests

6 E2E tests cover the full create/claim/burn roundtrip against a real server:

```sh
# Basic (public endpoints only):
SECRET_E2E_BASE_URL=https://secrt.ca cargo test e2e -- --ignored

# Full (including burn and API key create, requires API key):
SECRET_E2E_BASE_URL=https://secrt.ca SECRET_E2E_API_KEY=sk_... cargo test e2e -- --ignored
```

When run, these cover `client.rs` HTTP paths (~45 lines), pushing total coverage towards ~98%.
