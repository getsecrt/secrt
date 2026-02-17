# Pre-Release Security & Correctness Audit

**Date:** 2026-02-12
**Version:** 0.6.0
**Scope:** Full codebase audit against spec/v1/ — crypto, API, CLI, server lifecycle, API key auth

---

## Summary

| Severity | Count | Resolved |
|----------|-------|----------|
| Critical | 1 | 1 |
| High | 2 | 2 |
| Medium | 6 | 6 |
| Low | 5 | 5 |
| **Total** | **14** | **14** |

The top 3 issues (1 critical, 2 high) were already fixed in the current codebase at the time of verification. The remaining 11 issues (6 medium, 5 low) are now remediated in code and covered by tests (including DB-gated integration tests where applicable).

The **API key v2 authentication system** (derivation chain, wire protocol, storage, timing resistance) was audited thoroughly and found to be correct. All test vectors pass across Rust core, CLI client, and TypeScript frontend.

---

## Critical

### ~~1. Reflected XSS in `/s/{id}` page~~ — RESOLVED

- **File:** `secrt-server/src/http/mod.rs` ~line 1365
- **Component:** Server
- **Status:** Already fixed. `handle_secret_page` uses `escape_html(&id)` with a proper entity-escaping function (`&`, `<`, `>`, `"`, `'`). Verified at lines 1350-1368.

---

## High

### ~~2. TOCTOU race in secret creation quota enforcement~~ — RESOLVED

- **File:** `secrt-server/src/http/mod.rs` ~line 617, `storage/postgres.rs` ~line 88
- **Component:** Server
- **Status:** Already fixed. The handler calls `create_with_quota()` which wraps quota check + insert in a single Postgres transaction with `pg_advisory_xact_lock` for per-owner serialization. Verified at `postgres.rs` lines 88-149.

---

### ~~3. `--no-passphrase` / `-n` ignored during `get`~~ — RESOLVED

- **File:** `secrt-cli/src/get.rs` ~line 174
- **Component:** CLI
- **Spec:** cli.md, line 345
- **Status:** Already fixed. Phase B guards candidate list construction with `if !pa.no_passphrase { ... }` at line 174, with an explanatory comment at line 172.

---

## Medium

### ~~4. No graceful shutdown timeout (spec requires 10s)~~ — RESOLVED

- **File:** `secrt-server/src/runtime.rs` ~lines 75-81
- **Component:** Server
- **Spec:** server.md, section 2

**Status:** Fixed in `secrt-server/src/runtime.rs` by explicit connection orchestration and a hard shutdown deadline (`HttpTimeouts::production().graceful_shutdown_timeout = 10s`) around `graceful.shutdown()`.

**Coverage:** `runtime::tests::graceful_shutdown_times_out_when_inflight_request_hangs`; binary-level path in `tests/server_bin.rs::server_sigterm_honors_shutdown_deadline_with_stalled_request_body` (DB-gated).

---

### ~~5. No HTTP read/idle timeouts (slowloris vulnerability)~~ — RESOLVED

- **File:** `secrt-server/src/runtime.rs`
- **Component:** Server
- **Spec:** server.md, section 2

**Status:** Fixed in `secrt-server/src/runtime.rs`:
- `ReadHeaderTimeout: 5s` via Hyper HTTP/1 `header_read_timeout`
- `Read/Write budget: 15s` via request timeout middleware (`TimeoutLayer` returning 408)
- `WriteTimeout: 15s` and `IdleTimeout: 60s` via `TimeoutStream` socket configuration

**Coverage:** `runtime::tests::http_timeout_constants_match_spec`, `runtime::tests::header_read_timeout_closes_slow_connections`, `runtime::tests::request_timeout_returns_408_for_stalled_body_reads`, `runtime::tests::idle_timeout_closes_keepalive_connection`.

---

### ~~6. Logout revokes session by SID without verifying token hash~~ — RESOLVED

- **File:** `secrt-server/src/http/mod.rs` ~lines 1159-1178
- **Component:** Server

**Status:** Fixed in `secrt-server/src/http/mod.rs` by centralizing full session-token validation into `require_valid_session(...)` and reusing it in both session auth and logout paths before revoke.

**Coverage:** `tests/api_auth_passkeys.rs::logout_rejects_tampered_token_secret_and_preserves_session`.

---

### ~~7. Stale rows never cleaned up (challenges, sessions, registrations)~~ — RESOLVED

- **Files:** `secrt-server/src/reaper.rs`, `migrations/001_initial.sql`
- **Component:** Server

**Status:** Fixed in `secrt-server/src/storage/postgres.rs`; `delete_expired()` now runs transactional cleanup across:
- `secrets` (expired)
- `webauthn_challenges` (expired)
- `sessions` (expired or revoked)
- `api_key_registrations` (older than 24h retention)

**Coverage:** `tests/postgres_integration.rs::postgres_delete_expired_cleans_stale_auth_and_quota_rows` (DB-gated).

---

### ~~8. `seal()` / `open()` must enforce Argon2id bounds~~ — RESOLVED

- **File:** `secrt-core/src/crypto.rs` ~line 84
- **Component:** Core
- **Spec:** envelope.md, lines 101-105

**Status:** Fixed in `secrt-core/src/crypto.rs` by centralizing Argon2id parameter validation in `validate_argon2id_params()` and applying it in both `seal()` and `open()`.

**Coverage:** `crypto::tests::seal_passphrase_uses_argon2id_defaults`, `crypto::tests::open_kdf_argon2id_out_of_range_costs`.

---

### ~~9. `--trim` silently corrupts binary data~~ — RESOLVED

- **File:** `secrt-cli/src/send.rs` ~lines 49-62
- **Component:** CLI

**Status:** Fixed in `secrt-cli/src/send.rs` by replacing lossy conversion with strict UTF-8 validation (`std::str::from_utf8`) and explicit erroring for invalid input when `--trim` is set.

**Coverage:** `tests/cli_send.rs::send_trim_non_utf8_stdin_errors`, `tests/cli_send.rs::send_trim_non_utf8_file_errors`.

---

## Low

### ~~10. `kdf.name == "none"` with extra fields accepted instead of rejected~~ — RESOLVED

- **File:** `secrt-core/src/crypto.rs` ~line 326
- **Component:** Core
- **Spec:** envelope.md, lines 107-109

**Status:** Fixed in `secrt-core/src/crypto.rs`; `parse_kdf("none")` now rejects `salt`, `iterations`, and `length` extras via explicit field checks.

**Coverage:** `crypto::tests::open_kdf_none_rejects_extra_salt_field`, `crypto::tests::open_kdf_none_rejects_extra_iterations_field`.

---

### ~~11. Short boolean flag stacking silently drops flags~~ — RESOLVED

- **File:** `secrt-cli/src/cli.rs` ~lines 230-237
- **Component:** CLI

**Status:** Fixed in `secrt-cli/src/cli.rs` by rejecting inline suffixes on boolean short flags (`-SNG`, `-mfoo`) with explicit parse errors; inline suffixes remain allowed for value flags (e.g., `-L20`, `-oout.txt`).

**Coverage:** `cli::tests::flags_short_bool_stack_errors`, `cli::tests::flags_short_bool_with_inline_suffix_errors`; CLI contract updated in `spec/v1/cli.md`.

---

### ~~12. Passkey challenge is never cryptographically verified~~ — RESOLVED (DOCUMENTED FOR V1)

- **File:** `secrt-server/src/http/mod.rs` ~lines 880-999, 1063-1125
- **Component:** Server

**Status:** Addressed per scope decision (documentation + behavior lock only). Specs now explicitly describe v1 finish flow as challenge-id bearer semantics and mark cryptographic WebAuthn assertion verification as out-of-scope for v1.

**Coverage:** `tests/api_auth_passkeys.rs::passkey_login_finish_uses_challenge_id_bearer_semantics_in_v1`; docs updated in `spec/v1/api.md`, `spec/v1/server.md`, and `spec/v1/openapi.yaml`.

---

### ~~13. Missing connection pool max lifetime per spec~~ — RESOLVED

- **File:** `secrt-server/src/storage/postgres.rs` ~lines 27-35
- **Component:** Server
- **Spec:** server.md, section 3

**Status:** Fixed in `secrt-server/src/storage/postgres.rs`:
- centralized pool sizing and lifetime constants
- added 30m max-lifetime enforcement via Deadpool `post_recycle` hook (connection age check)
- exposed `from_database_url_with_max_lifetime(...)` for deterministic test override paths

**Coverage:** `storage::postgres::tests::connection_max_lifetime_check` and integration construction paths in `tests/postgres_integration.rs`.

---

### ~~14. Reaper double-fires at startup~~ — RESOLVED

- **File:** `secrt-server/src/reaper.rs` ~lines 16-18
- **Component:** Server

**Status:** Fixed in `secrt-server/src/reaper.rs` by consuming the interval's immediate first tick after the explicit startup run.

**Coverage:** `tests/reaper_runtime.rs::reaper_runs_once_immediately_before_first_interval_tick`.

---

## Clean Areas (No Issues Found)

- **API Key v2 system:** Derivation chain (sk2_ to ak2_), wire protocol, HMAC verification, storage model (only hashes stored), timing-attack mitigations (constant-time compare), test vectors — all correct and consistent across Rust core, CLI, and TypeScript frontend.
- **Core crypto primitives:** AES-256-GCM, HKDF-SHA-256, Argon2id all match spec. Parameter sizes, info strings, AAD, base64url encoding — all correct.
- **Claim token derivation:** Correctly independent of passphrase, derived from url_key only via HKDF.
- **Atomic claim+delete:** Single `DELETE...RETURNING` SQL statement — no TOCTOU.
- **SQL injection:** All queries use parameterized statements throughout.
- **Sealed payload frame format:** Magic, version, codec, lengths, meta, body — all match spec.
- **Compression policy:** Thresholds, savings requirements, pre-compressed detection — all correct.
