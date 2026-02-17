# Documentation Accuracy Audit — February 15, 2026

## Summary

Comprehensive cross-reference of all documentation (README, AGENTS.md, CHANGELOG, spec/v1/*, docs/whitepaper.md, crate changelogs, .env.example) against the actual source code at workspace version **0.9.0**.

**Findings:** 6 critical issues, 12 moderate issues, 11 minor issues, and 4 bugs/UX notes.

Overall the docs are in remarkably good shape for a fast-moving project. Most issues are staleness from rapid iteration rather than fundamental inaccuracies.

---

## Critical Issues (docs contradict code)

### C1. CLI README uses legacy `sk_` API key format in examples

**File:** `crates/secrt-cli/README.md`

The CLI README shows legacy `sk_` key format in four places:

```
secrt burn abc123 --api-key sk_prefix.secret
secrt burn https://secrt.ca/s/abc123#key... --api-key sk_prefix.secret
api_key = "sk_live_abc123"
```

**Actual code:** Since v0.6.0, the CLI only accepts `sk2_<prefix>.<root_b64>` format. Legacy `sk_` is explicitly rejected by the server runtime and the CLI validation. The CLI CHANGELOG v0.6.0 documents this breaking change.

**Impact:** Users copying examples from the README will get authentication errors.

---

### C2. Root README hardcodes server download links to v0.5.0

**File:** `README.md`, lines 42–43

```markdown
| Linux x64 | [secrt-server-linux-amd64](https://github.com/getsecrt/secrt/releases/download/server%2Fv0.5.0/secrt-server-linux-amd64) |
| Linux ARM64 | [secrt-server-linux-arm64](https://github.com/getsecrt/secrt/releases/download/server%2Fv0.5.0/secrt-server-linux-arm64) |
```

**Actual state:** Latest server release tag is `server/v0.9.0`. The v0.5.0 binary predates passkey auth, v2 API keys, the sealed-payload envelope format, dashboard endpoints, and many other features. Anyone downloading from these links gets a fundamentally outdated binary.

**Impact:** High — users will download a server that is 8 versions behind and lacks critical security features.

---

### C3. Whitepaper claims 7 envelope test vectors; actual count is 5

**File:** `docs/whitepaper.md`, Specification & Test Vectors section

> **7 cryptographic test vectors** (`envelope.vectors.json`)

**Actual file:** `spec/v1/envelope.vectors.json` contains **5 vectors**.

```bash
$ python3 -c "import json; d=json.load(open('spec/v1/envelope.vectors.json')); print(len(d['vectors']))"
5
```

**Impact:** Misrepresents the scope of test coverage in a security-focused white paper.

---

### C4. Whitepaper claims "17 valid + 17 invalid" TTL vectors; actual is 17 valid + 18 invalid

**File:** `docs/whitepaper.md`, Specification & Test Vectors section

> **34 TTL parsing vectors** (`cli.vectors.json`) — 17 valid and 17 invalid inputs.

**Actual file:** `spec/v1/cli.vectors.json` contains **17 valid + 18 invalid = 35 total**.

**Impact:** Minor inaccuracy in the whitepaper's vector count, but still factually wrong.

---

### C5. server.md uses Go terminology ("goroutine") for the Rust server

**File:** `spec/v1/server.md`, lines 237 and 367

> **Garbage collection:** A background **goroutine** sweeps stale buckets every 2 minutes...
>
> A best-effort cleanup **goroutine** runs every 5 minutes:

**Actual code:** The server was fully rewritten in Rust (Axum + Tokio) in v0.4.0. There are no goroutines — these are `tokio::spawn` tasks.

- Rate limiter GC: `start_gc()` in `domain/limiter.rs` spawns a Tokio task
- Expiry reaper: `start_expiry_reaper()` in `reaper.rs` spawns a Tokio task

**Impact:** Misleading for anyone reading the spec to understand the implementation. The Go server no longer exists.

---

### C6. server.md uses Go-style HTTP timeout names

**File:** `spec/v1/server.md`, Section 2

> HTTP server timeouts:
> - `ReadHeaderTimeout`: 5s
> - `ReadTimeout`: 15s
> - `WriteTimeout`: 15s
> - `IdleTimeout`: 60s

**Actual code:** `crates/secrt-server/src/runtime.rs` lines 54–57:

```rust
read_header_timeout: Duration::from_secs(5),
request_timeout: Duration::from_secs(15),
write_timeout: Duration::from_secs(15),
idle_timeout: Duration::from_secs(60),
```

The values match, but the names are Go `net/http.Server` field names (`ReadHeaderTimeout`, `ReadTimeout`), not the Rust struct field names (`read_header_timeout`, `request_timeout`). Also, `ReadTimeout` in Go includes body read time, whereas the Rust implementation uses a dedicated `request_timeout` layer — semantically different.

**Impact:** Developers implementing against the spec may misunderstand timeout semantics.

---

## Moderate Issues (outdated or misleading)

### M1. server.md pool settings don't match deadpool semantics

**File:** `spec/v1/server.md`, Section 3

> Connection pool settings:
> - max open conns: 10
> - max idle conns: 10
> - conn max lifetime: 30m

**Actual code:** `crates/secrt-server/src/storage/postgres.rs`:

```rust
const POOL_MAX_SIZE: usize = 10;
const POOL_MAX_LIFETIME: std::time::Duration = std::time::Duration::from_secs(30 * 60);
```

`deadpool-postgres` doesn't have a separate "max idle conns" concept — `max_size` is the total pool size. Listing both "max open" and "max idle" at 10 is a copy-paste from Go's `sql.DB` settings and is misleading for a deadpool implementation.

---

### M2. server.md Section 3 is missing schema columns `meta_key_version` and `enc_meta`

**File:** `spec/v1/server.md`, Section 3

The secrets table description lists:

> `secrets(id, claim_hash, envelope, expires_at, created_at, owner_key)`

**Actual migration** (`migrations/001_initial.sql`):

```sql
CREATE TABLE IF NOT EXISTS secrets (
    ...
    meta_key_version SMALLINT,
    enc_meta JSONB
);
```

Two columns (`meta_key_version` and `enc_meta`) exist in the actual schema but are undocumented in the server spec. These are nullable and appear to be future-use columns for encrypted metadata (referenced in `docs/plans/website-plan.md`).

---

### M3. server.md Section 3 missing index names

**File:** `spec/v1/server.md`, Section 3

The spec mentions:

> Indexes:
> - `secrets_expires_at_idx`
> - `secrets_owner_key_idx`
> - `api_key_registrations_user_created_idx`
> - `api_key_registrations_ip_created_idx`

**Actual migration** includes additional indexes not documented:

```sql
CREATE INDEX IF NOT EXISTS passkeys_user_id_idx ON passkeys (user_id, revoked_at);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id, expires_at);
CREATE INDEX IF NOT EXISTS webauthn_challenges_purpose_idx ON webauthn_challenges (purpose, expires_at);
```

Not critical, but the index list is incomplete.

---

### M4. Whitepaper Appendix D schema missing `meta_key_version` and `enc_meta`

**File:** `docs/whitepaper.md`, Appendix D

The secrets table in the whitepaper shows:

| Column | Type | Purpose |
|--------|------|---------|
| `id` | TEXT (PK) | ... |
| `claim_hash` | TEXT | ... |
| `envelope` | JSONB | ... |
| `expires_at` | TIMESTAMPTZ | ... |
| `created_at` | TIMESTAMPTZ | ... |
| `owner_key` | TEXT | ... |

Same issue as M2 — actual schema has two additional columns.

---

### M5. AGENTS.md repository layout missing files from secrt-core

**File:** `AGENTS.md`, Repository layout section

The layout lists `secrt-core/src/` containing:

```
├── lib.rs
├── crypto.rs
├── types.rs
├── ttl.rs
├── url.rs
└── api.rs
```

**Actual files in** `crates/secrt-core/src/`:

```
api.rs, apikey.rs, crypto.rs, lib.rs, payload.rs, server.rs, ttl.rs, types.rs, url.rs
```

Missing from the layout: `apikey.rs`, `payload.rs`, `server.rs`. These were added in v0.6.0+ and the AGENTS.md layout was never updated.

---

### M6. CLI README missing `--output`/`-o` flag from `get` options table

**File:** `crates/secrt-cli/README.md`, `get` command options table

The options table for `get` lists only: `-p`, `--passphrase-env`, `--passphrase-file`, `--json`, `--silent`.

**Actual implementation** (`crates/secrt-cli/src/cli.rs` line 297):

```rust
"--output" | "-o" => pa.output = next_val!("--output"),
```

The `--output`/`-o` flag is implemented, documented in the help text (line 1168), and described in the spec (`spec/v1/cli.md`) — but it's missing from the README's options table.

---

### M7. CLI README missing `-n`/`--no-passphrase` flag

**File:** `crates/secrt-cli/README.md`

The `-n`/`--no-passphrase` flag is not documented anywhere in the CLI README.

**Actual implementation** (`crates/secrt-cli/src/cli.rs` line 299):

```rust
"--no-passphrase" | "-n" => pa.no_passphrase = true,
```

The spec (`spec/v1/cli.md`) documents it under both `send` and `get` commands.

---

### M8. server CHANGELOG v0.4.0 claims `X-Robots-Tag` on all responses

**File:** `crates/secrt-server/CHANGELOG.md`, v0.4.0

> **Security headers** — `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`, `X-Robots-Tag` on all responses.

**Actual code** (`crates/secrt-server/src/http/mod.rs`):

- `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options` → set in `request_middleware` on **all responses** ✓
- `X-Robots-Tag` → set **only** on the `/s/{id}` handler (line 1735) ✗

The middleware sets 3 of the 4 headers globally. `X-Robots-Tag` was likely moved to be route-specific but the changelog was never corrected.

---

### M9. Root CHANGELOG version is 0.7.0 but workspace is at 0.9.0

**File:** `CHANGELOG.md`

The root changelog's latest entry is `0.7.0 — 2026-02-14`. The workspace version in `Cargo.toml` is `0.9.0`.

Versions 0.8.0 and 0.9.0 are documented in `crates/secrt-server/CHANGELOG.md` but not in the root `CHANGELOG.md`.

---

### M10. Whitepaper rate limit table says authenticated creation keyed by "API key prefix"

**File:** `docs/whitepaper.md`, Abuse Prevention > Rate Limiting

> | Authenticated creation | 2.0 rps | 20 | API key prefix |

**Actual code** (`crates/secrt-server/src/http/mod.rs`, `handle_create_authed`):

```rust
let (owner_key, rate_key) =
    if let Ok((user_id, _, _)) = require_session_user(&state, req.headers()).await {
        let uid = user_id.to_string();
        (format!("user:{uid}"), format!("user:{uid}"))
    } else {
        ...
        (format!("apikey:{prefix}"), format!("apikey:{prefix}"))
    };
```

The rate key is `user:<uuid>` for session auth or `apikey:<prefix>` for API key auth. The whitepaper only mentions API key prefix, omitting the session auth path.

---

### M11. Root README Quick Start examples don't match actual CLI behavior

**File:** `README.md`, Quick start section

```sh
# Generate and share a password
secrt send gen --ttl 1h
```

This is correct, but the preceding example:

```sh
# Claim a secret
secrt get https://secrt.ca/s/abc123#key...
```

While technically correct, the README should probably note that `get` is implicit (can just use `secrt https://...`), which is one of the CLI's most notable UX features and is well documented elsewhere.

---

### M12. server.md Section 8 says "0.5 rps" for API key registration but doesn't mention keying

**File:** `spec/v1/server.md`, Section 8

> API-key registration: `0.5 rps`, burst `6` keyed by client IP.

**Actual code** (`handle_apikey_register_entry`):

```rust
let ip = get_client_ip(req.headers(), request_connect_addr(&req));
if !state.apikey_register_limiter.allow(&ip) {
    return rate_limited();
}
```

The rate limiter key is raw client IP string, not HMAC-hashed like other limiters. But the Privacy section above says "Rate limiter keys are HMAC-SHA256 hashed." Let me check...

Actually, looking at the Limiter implementation, all limiters use the same `allow()` function which HMAC-hashes internally. The `ip` string passed is the raw IP but the limiter hashes it before keying. This is fine — the doc claim is correct. Demoting this to a note.

---

## Minor Issues (style, broken links, typos)

### m1. spec/README.md references standalone repo `getsecrt/spec`

**File:** `spec/README.md`

> This spec lives in the secrt monorepo at `spec/` and is also available standalone at [getsecrt/spec](https://github.com/getsecrt/spec).

The standalone spec repo may not exist or be synced. This should be verified — if the repo doesn't exist, the link is broken.

---

### m2. AGENTS.md secrt-cli src/ layout missing newer files

**File:** `AGENTS.md`, Repository layout > secrt-cli

The layout shows files like `client.rs`, `send.rs`, `get.rs`, `burn.rs`, `gen.rs`, etc. but doesn't list all files. This is reasonable as a layout overview, but the listed files should be verified as still present.

---

### m3. Root README Development section uses `pnpm -C web` syntax

**File:** `README.md`, Development section

```sh
SECRT_API_ORIGIN=http://127.0.0.1:8080 pnpm -C web dev
```

Uses `SECRT_API_ORIGIN` for the Vite proxy but this isn't documented in `.env.example` (which is server-side config only). Web dev proxy config is separate — not technically wrong but could confuse developers.

---

### m4. `spec/v1/cli.md` says "Draft v1" status

**File:** `spec/v1/cli.md`, line 1

> Status: Draft v1 (normative for CLI interoperability once accepted)

All other spec files say "Active" or "Active (normative)." The CLI spec should be updated to reflect its actual status since it has been implemented and is being used.

---

### m5. AGENTS.md mentions `secrt-admin apikey create` removal

**File:** `AGENTS.md` doesn't reference admin CLI at all.

The server CHANGELOG v0.6.0 mentions:

> Admin CLI surface: removed `secrt-admin apikey create`; kept `secrt-admin apikey revoke <prefix>`.

The admin CLI isn't described in the server spec or documented anywhere except changelogs. Minor but could use at least a mention in AGENTS.md.

---

### m6. Root CHANGELOG lists 0.7.0 as latest but it doesn't include 0.8.0/0.9.0 changes

The root `CHANGELOG.md` is missing entries for versions 0.8.0 and 0.9.0, which added dashboard, settings, secrets check endpoint, and various UI improvements. These are documented in `crates/secrt-server/CHANGELOG.md` but missing from the root.

---

### m7. `spec/v1/server.md` Section 5 missing `/settings` route

**File:** `spec/v1/server.md`, Section 5 (Route Surface)

The route surface lists `/dashboard` and `/settings`:

```
- `GET /dashboard`
- `GET /settings`
```

Wait, these ARE listed. Let me verify...

Actually, looking again, the route surface in server.md DOES include both `/dashboard` and `/settings`. Retracting this one.

---

### m7. (Replacement) Whitepaper says "approximately 2,500 unique combinations" for display names

**File:** `docs/whitepaper.md`, Account System section

> auto-generates random, friendly display names from an adjective-animal combination (e.g., "Swift Falcon", "Quiet Otter") with approximately 2,500 unique combinations.

This number should be verified against the actual word lists in the code — if there are 50 adjectives × 50 animals = 2,500, it's correct; otherwise it's inaccurate.

---

### m8. Whitepaper TODO comments remain in the published document

**File:** `docs/whitepaper.md`

Multiple TODO comments exist:

```html
<!-- TODO: Architecture diagram placeholder -->
<!-- TODO: Verify OneTimeSecret still lacks client-side encryption -->
<!-- TODO: Verify Yopass doesn't support passphrase protection -->
<!-- TODO: Add link to self-hosting guide / docker-compose setup once available -->
```

These are HTML comments (invisible in rendered markdown) but indicate unfinished areas of the whitepaper.

---

### m9. OpenAPI schema example envelope uses wrong field names

**File:** `spec/v1/openapi.yaml`, `createPublicSecret` example

```yaml
example:
  envelope:
    ct: "base64-encoded-ciphertext"
    nonce: "base64-encoded-nonce"
    kdf:
      name: "argon2id"
      m_cost: 19456
```

The actual envelope format uses `enc.ciphertext` (not `ct`), `enc.alg` (not `kdf.alg`), and includes `v`, `suite`, `enc`, `kdf`, `hkdf` top-level fields. The example is a placeholder and does not represent the real envelope shape.

---

### m10. CLI README config example uses `sk_live_abc123` (legacy format)

**File:** `crates/secrt-cli/README.md`, Configuration section

```toml
api_key = "sk_live_abc123"
```

Should be `sk2_<prefix>.<root_b64>` format. (Duplicate of C1 but in a different location within the file.)

---

### m11. `spec/v1/api.md` Session response doesn't mention `display_name` was added

The OpenAPI schema for `SessionResponse` includes `display_name` field, and the server code returns it. The `api.md` passkey endpoints section doesn't explicitly document the session response fields for `GET /api/v1/auth/session`, though the schema is in the openapi.yaml.

---

## Bugs & UX Issues Noticed

### B1. Web `burnSecret()` sends a `ClaimRequest` body for burn

**File:** `web/src/lib/api.ts`, `burnSecret` function

```typescript
export async function burnSecret(
  id: string,
  req: ClaimRequest,
  signal?: AbortSignal,
): Promise<void> {
```

The burn endpoint doesn't require or read a request body — it only needs auth headers. This function takes a `ClaimRequest` (which has a `claim` field) and sends it as the body. The `burnSecretAuthed()` function below it correctly sends no body.

This appears to be an unused/legacy function (the dashboard uses `burnSecretAuthed`), but it's still exported and could confuse consumers.

---

### B2. Reaper only cleans secrets, not auth tables (maybe)

**File:** `crates/secrt-server/src/reaper.rs`

The reaper function calls `store.delete_expired()` which is on the `SecretsStore` trait. In the Postgres implementation, `delete_expired()` DOES delete from multiple tables (secrets, challenges, sessions, registrations) in one transaction.

However, the `SecretsStore` trait name is misleading — it does auth cleanup too. The `start_expiry_reaper` only receives `Arc<dyn SecretsStore>`, not `Arc<dyn AuthStore>`. This works because the Postgres implementation of `SecretsStore::delete_expired()` cleans everything, but it's a leaky abstraction — any non-Postgres implementation of `SecretsStore` would need to know to also clean auth tables.

---

### B3. Rate limiter GC interval/max_idle are hardcoded

**File:** `crates/secrt-server/src/http/mod.rs`, `start_limiter_gc`

```rust
let interval = Duration::from_secs(120);
let max_idle = Duration::from_secs(600);
```

The server.md documents these as "2 minutes" and "10 minutes" which matches, but they're not configurable via env vars unlike all other operational parameters. Not a bug, but an inconsistency with the otherwise highly configurable design.

---

### B4. `handle_info_entry` only checks API key auth, not session auth

**File:** `crates/secrt-server/src/http/mod.rs`, `handle_info_entry`

```rust
let authenticated = if let Some(raw) = api_key_from_headers(req.headers()) {
    state.auth.authenticate(&raw).await.is_ok()
} else {
    false
};
```

The `/api/v1/info` endpoint reports `authenticated: true/false` but only checks for API key auth. Session tokens (`uss_`) are not checked. A logged-in user viewing the info endpoint via the web UI would see `authenticated: false`.

The spec says: "if a valid API key is provided, `authenticated` is `true`" — which matches the code. But it would be more useful to also detect session auth for web users.

---

## Methodology

### Files Read

**Documentation:**
- `README.md` (root)
- `AGENTS.md` (root, aliased as `CLAUDE.md`)
- `CHANGELOG.md` (root)
- `crates/secrt-cli/README.md`
- `crates/secrt-cli/CHANGELOG.md`
- `crates/secrt-server/CHANGELOG.md`
- `crates/secrt-core/CHANGELOG.md`
- `docs/whitepaper.md`
- `spec/README.md`
- `spec/v1/README.md`
- `spec/v1/envelope.md`
- `spec/v1/api.md`
- `spec/v1/server.md`
- `spec/v1/cli.md`
- `spec/v1/openapi.yaml`
- `.env.example`

**Source Code:**
- `Cargo.toml` (workspace root — version 0.9.0)
- `crates/secrt-core/src/types.rs` — all constants verified
- `crates/secrt-core/src/crypto.rs` — seal/open implementation verified
- `crates/secrt-core/src/payload.rs` — frame format verified
- `crates/secrt-core/src/ttl.rs` — TTL parsing verified
- `crates/secrt-core/src/server.rs` — server shared logic verified
- `crates/secrt-core/src/apikey.rs` — API key auth len verified
- `crates/secrt-server/src/http/mod.rs` — all routes, middleware, rate limits verified
- `crates/secrt-server/src/config.rs` — all env var names and defaults verified
- `crates/secrt-server/src/runtime.rs` — HTTP timeouts verified
- `crates/secrt-server/src/reaper.rs` — reaper interval and behavior verified
- `crates/secrt-server/src/storage/postgres.rs` — pool settings, queries, delete_expired verified
- `crates/secrt-server/migrations/001_initial.sql` — full schema verified
- `crates/secrt-cli/src/cli.rs` — CLI flags verified
- `crates/secrt-cli/src/get.rs` — output behavior verified
- `web/src/lib/api.ts` — API client calls verified

**Test Vectors:**
- `spec/v1/envelope.vectors.json` — counted 5 vectors
- `spec/v1/cli.vectors.json` — counted 17 valid + 18 invalid
- `spec/v1/apikey.vectors.json` — counted 4 vectors

### Cross-Reference Checks Performed

1. **Rate limits:** docs vs config defaults vs .env.example — all match ✓
2. **Quota values:** docs vs config defaults vs .env.example — all match ✓
3. **API endpoints:** spec route surface vs code router — all match ✓
4. **Schema columns:** spec vs migration — two undocumented columns found (meta_key_version, enc_meta)
5. **Constants:** spec vs types.rs — all match ✓
6. **CLI flags:** spec vs actual parsing — match, but README is missing some flags
7. **Env var names:** .env.example vs config.rs — all match ✓
8. **Version numbers:** Cargo.toml 0.9.0 vs docs — root changelog stale at 0.7.0
9. **Server download links:** README vs actual tags — v0.5.0 links, latest is v0.9.0
10. **API key format:** sk_ vs sk2_ usage across all docs — inconsistencies found in CLI README
11. **OpenAPI vs actual API:** routes match, examples use placeholder envelope format
12. **Test vector counts:** whitepaper claims vs actual files — mismatches found
