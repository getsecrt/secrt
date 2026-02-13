# Pre-Release Security & Correctness Audit

**Date:** 2026-02-12
**Version:** 0.6.0
**Scope:** Full codebase audit against spec/v1/ — crypto, API, CLI, server lifecycle, API key auth

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 2 |
| Medium | 6 |
| Low | 5 |
| **Total** | **14** |

The **API key v2 authentication system** (derivation chain, wire protocol, storage, timing resistance) was audited thoroughly and found to be correct. All test vectors pass across Rust core, CLI client, and TypeScript frontend.

---

## Critical

### 1. Reflected XSS in `/s/{id}` page

- **File:** `secrt-server/src/http/mod.rs` ~line 1347
- **Component:** Server

The `id` path parameter is interpolated directly into HTML without any escaping:

```rust
let body = format!(
    "<!doctype html>...Secret {id}</title>...<h1>Secret {id}</h1>..."
);
```

A crafted URL like `/s/<script>alert(1)</script>` produces a valid XSS payload. The response Content-Type is `text/html`, so the script executes in all browsers. This is a textbook reflected XSS vulnerability on a security-focused application.

**Fix:** HTML-escape `id` before interpolation, or validate it against the expected base64url alphabet (`[A-Za-z0-9_-]`) and reject anything that doesn't match.

---

## High

### 2. TOCTOU race in secret creation quota enforcement

- **File:** `secrt-server/src/http/mod.rs` ~lines 594-632
- **Component:** Server

The quota check (`get_usage`) and the secret insert (`create`) are two separate, non-transactional operations:

```rust
// Step 1: Check quota (separate query)
let usage = state.secrets.get_usage(&owner_key).await;
if usage.secret_count >= max_secrets { return 429; }

// Step 2: Insert secret (separate query, possibly later)
state.secrets.create(rec).await;
```

Concurrent requests from the same owner can all pass the quota check before any insert commits. For the public tier (`max_secrets = 10`), this is trivially exploitable with ~10 parallel requests. Note that the API key registration flow correctly wraps quota check + insert in a single transaction — the secret creation flow should do the same.

**Fix:** Wrap the quota check and insert in a single database transaction.

---

### 3. `--no-passphrase` / `-n` ignored during `get`

- **File:** `secrt-cli/src/get.rs` ~lines 104-231
- **Component:** CLI
- **Spec:** cli.md, line 345

The spec says `-n`/`--no-passphrase` skips the configured `decryption_passphrases` list and proceeds directly to interactive prompt (or error if non-TTY).

In `get.rs`, Phase B unconditionally builds and tries the candidate list from `pa.passphrase_default` and `pa.decryption_passphrases` without any guard for `pa.no_passphrase`. The flag is effectively a no-op during `get`.

For comparison, `send` correctly handles this via `resolve_passphrase_for_send` in `passphrase.rs` line 34:
```rust
if !args.no_passphrase && !args.passphrase_default.is_empty() { ... }
```

A user running `secrt get <url> -n` expecting to bypass configured passphrases and enter one interactively will instead have the CLI silently try all configured passphrases first. If one matches, the secret decrypts without prompting — contrary to user intent.

**Fix:** In `get.rs` Phase B, guard with `if !pa.no_passphrase { ... }` to skip the configured candidate list when the flag is set.

---

## Medium

### 4. No graceful shutdown timeout (spec requires 10s)

- **File:** `secrt-server/src/runtime.rs` ~lines 75-81
- **Component:** Server
- **Spec:** server.md, section 2

`axum::serve(...).with_graceful_shutdown(shutdown)` waits indefinitely for in-flight connections to drain. There is no 10-second deadline as required by the spec. If a client holds a connection open, the server hangs forever on shutdown.

**Fix:** Wrap the server future in `tokio::time::timeout(Duration::from_secs(10), server)` or use `tokio::select!` with a sleep after the shutdown signal fires.

---

### 5. No HTTP read/idle timeouts (slowloris vulnerability)

- **File:** `secrt-server/src/runtime.rs`
- **Component:** Server
- **Spec:** server.md, section 2

The spec requires:
- ReadHeaderTimeout: 5s
- ReadTimeout: 15s
- WriteTimeout: 15s
- IdleTimeout: 60s

None are configured. Axum's `serve()` does not set any by default. Without read/idle timeouts, a slowloris-style attacker can exhaust the server's connection limit by opening connections and sending data slowly.

**Fix:** Configure timeouts via `tower-http` middleware or Hyper's server builder.

---

### 6. Logout revokes session by SID without verifying token hash

- **File:** `secrt-server/src/http/mod.rs` ~lines 1159-1178
- **Component:** Server

The logout handler extracts the SID from the session token and revokes by SID alone, without verifying the token hash:

```rust
let parsed = session_token_from_headers(req.headers());
state.auth_store.revoke_session_by_sid(&parsed.sid).await;
```

Compare with `require_session_user` (~line 832-860), which correctly computes and verifies the token hash before granting access. An attacker who knows only the SID (but not the full secret) could revoke someone else's session. The SID is 12 random bytes (16 base64url chars), so brute-forcing is impractical, but the design violates defense-in-depth — possession of the full token should be required for any session mutation.

**Fix:** Verify the token hash against the stored hash before revoking, consistent with `require_session_user`.

---

### 7. Stale rows never cleaned up (challenges, sessions, registrations)

- **Files:** `secrt-server/src/reaper.rs`, `migrations/001_initial.sql`
- **Component:** Server

The reaper only cleans expired rows in the `secrets` table. Three other tables accumulate rows indefinitely:

| Table | Issue |
|-------|-------|
| `webauthn_challenges` | Has `expires_at` column; expired challenges never deleted |
| `sessions` | Expired and revoked sessions never deleted |
| `api_key_registrations` | Only used for 1h/24h quota windows; old rows never purged |

Over time these tables grow unbounded, degrading query performance.

**Fix:** Extend the reaper to clean expired rows from all three tables.

---

### 8. `seal()` doesn't enforce minimum PBKDF2 iteration count

- **File:** `secrt-core/src/crypto.rs` ~line 84
- **Component:** Core
- **Spec:** envelope.md, lines 101-105

The spec requires `kdf.iterations >= 300,000`. When `seal()` is called with a passphrase and a nonzero `iterations` value below `MIN_PBKDF2_ITERATIONS`, it uses that value directly:

```rust
let iterations = if p.iterations == 0 {
    DEFAULT_PBKDF2_ITERATIONS  // 600,000
} else {
    p.iterations  // no minimum check
};
```

This allows producing envelopes with dangerously weak KDF parameters (e.g., 1 iteration). The `open()` path correctly validates `>= 300,000`.

**Fix:** Add `if p.iterations > 0 && p.iterations < MIN_PBKDF2_ITERATIONS { return Err(...); }` before using the value.

---

### 9. `--trim` silently corrupts binary data

- **File:** `secrt-cli/src/send.rs` ~lines 49-62
- **Component:** CLI

```rust
if pa.trim {
    let trimmed = String::from_utf8_lossy(&plaintext);
    let trimmed = trimmed.trim();
    plaintext = trimmed.as_bytes().to_vec();
}
```

`String::from_utf8_lossy` replaces every invalid UTF-8 byte with U+FFFD (the 3-byte sequence `EF BF BD`). If binary data is piped through stdin with `--trim`, the plaintext is silently corrupted before encryption. The user won't notice until decryption, by which point the original data is lost.

**Fix:** Use `std::str::from_utf8()` and return an error if the input is not valid UTF-8 when `--trim` is set.

---

## Low

### 10. `kdf.name == "none"` with extra fields accepted instead of rejected

- **File:** `secrt-core/src/crypto.rs` ~line 326
- **Component:** Core
- **Spec:** envelope.md, lines 107-109

The spec says: for `kdf.name == "none"`, `kdf` MUST NOT include `salt`, `iterations`, or `length`. The `parse_kdf` function ignores extra fields silently when `name` is `"none"`. An envelope with `{"name":"none","salt":"AAAA","iterations":600000}` is accepted without error.

**Fix:** Reject envelopes where `kdf.name == "none"` but extra fields are present.

---

### 11. Short boolean flag stacking silently drops flags

- **File:** `secrt-cli/src/cli.rs` ~lines 230-237
- **Component:** CLI

The arg parser handles short flags with inline values: `-X<value>` splits into flag `-X` with value `<value>`. For boolean flags (e.g., `-S`, `-N`, `-G`), the inline value is silently discarded.

This means `-SNG` parses as `-S` with unused inline value `"NG"` — only `--no-symbols` is set. Users expecting `tar`-style flag stacking (common Unix convention) will get wrong password generation results with no warning.

**Fix:** For boolean flags that receive an unexpected inline value, either emit an error or support flag clustering for boolean-only short flags.

---

### 12. Passkey challenge is never cryptographically verified

- **File:** `secrt-server/src/http/mod.rs` ~lines 880-999, 1063-1125
- **Component:** Server

In the passkey register/login flows, the server generates a random `challenge` and sends it to the client. In the finish step, the server only checks that the `challenge_id` exists and hasn't expired — it never verifies any cryptographic signature over the challenge. The `challenge` value itself is unused in the finish step.

This is a challenge-ID-based bearer-token flow, not WebAuthn. The protocol is sound if `challenge_id` stays secret (32 random bytes), but it is misleadingly named and will need rework if real WebAuthn verification is expected.

**Fix:** Document this as intentional or implement actual WebAuthn signature verification.

---

### 13. Missing connection pool max lifetime per spec

- **File:** `secrt-server/src/storage/postgres.rs` ~lines 27-35
- **Component:** Server
- **Spec:** server.md, section 3

The spec calls for `conn max lifetime: 30m`. The pool configuration only sets `max_size: 10` and leaves everything else at defaults. `deadpool-postgres` does not impose a max connection lifetime by default. Long-lived connections can accumulate server-side state and fail to pick up Postgres configuration changes or failovers.

**Fix:** Configure `manager.recycling_method` or add a connection age check.

---

### 14. Reaper double-fires at startup

- **File:** `secrt-server/src/reaper.rs` ~lines 16-18
- **Component:** Server

The reaper calls `run_expiry_reaper_once` explicitly, then creates `tokio::time::interval` whose first tick fires immediately (documented Tokio behavior). This causes two back-to-back reaper runs at startup. Harmless (idempotent) but wasteful.

**Fix:** Remove the explicit first call, or consume the initial tick with `ticker.tick().await` before entering the loop.

---

## Clean Areas (No Issues Found)

- **API Key v2 system:** Derivation chain (sk2_ to ak2_), wire protocol, HMAC verification, storage model (only hashes stored), timing-attack mitigations (constant-time compare), test vectors — all correct and consistent across Rust core, CLI, and TypeScript frontend.
- **Core crypto primitives:** AES-256-GCM, HKDF-SHA-256, PBKDF2-HMAC-SHA-256 all match spec. Parameter sizes, info strings, AAD, base64url encoding — all correct.
- **Claim token derivation:** Correctly independent of passphrase, derived from url_key only via HKDF.
- **Atomic claim+delete:** Single `DELETE...RETURNING` SQL statement — no TOCTOU.
- **SQL injection:** All queries use parameterized statements throughout.
- **Sealed payload frame format:** Magic, version, codec, lengths, meta, body — all match spec.
- **Compression policy:** Thresholds, savings requirements, pre-compressed detection — all correct.
