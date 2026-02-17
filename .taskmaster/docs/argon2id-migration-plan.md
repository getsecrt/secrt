# Argon2id KDF Migration Plan

**Branch:** `feat/argon2id`
**Status:** Implemented (manual cross-device validation pending)
**Decision:** Clean break — replace PBKDF2 with Argon2id. No dual-KDF, no backward compat. Pre-launch, zero public users.

---

## Implementation Status (2026-02-17)

- Phases 1-4 are complete across `secrt-core`, `secrt-cli`, `secrt-server/web`, spec, vectors, docs, and changelogs.
- Phase 5 is partially complete:
  - ✅ Vectors regenerated from Rust and synchronized to CLI fixtures
  - ✅ Cross-implementation vector tests passing (Rust/CLI/web)
  - ✅ Workspace Rust tests/lints passing, web unit/build/E2E passing, CLI live E2E against `https://secrt.ca` passing
  - ⏳ Remaining: manual browser/device performance checks on older mobile hardware

---

## Motivation

PBKDF2-SHA-256 is trivially parallelizable on GPUs. At 600,000 iterations it provides ~200–400ms of delay on CPUs but is orders of magnitude cheaper to brute-force on GPU clusters. Argon2id is memory-hard and GPU-resistant by design — it's the OWASP-recommended KDF for new systems and won the Password Hashing Competition.

Switching now (pre-launch) avoids carrying a legacy codepath forever.

## Scope

This is a breaking spec change affecting all three implementations:

| Component    | Language   | Current KDF       | Files                                                    |
| ------------ | ---------- | ----------------- | -------------------------------------------------------- |
| `secrt-core` | Rust       | `ring::pbkdf2`    | `crates/secrt-core/src/crypto.rs`, `types.rs`            |
| `secrt-cli`  | Rust       | via secrt-core    | inherits from core                                       |
| `web`        | TypeScript | Web Crypto PBKDF2 | `web/src/crypto/envelope.ts`, `constants.ts`, `types.ts` |
| `spec`       | Markdown   | PBKDF2-SHA256     | `spec/v1/envelope.md`                                    |
| `docs`       | Markdown   | References PBKDF2 | `docs/whitepaper.md`, `SECURITY.md`, `README.md`         |

## Argon2id Parameters

**Proposed defaults** (OWASP "first recommended" for argon2id):

| Parameter              | Value              | Notes                                    |
| ---------------------- | ------------------ | ---------------------------------------- |
| `m_cost` (memory)      | 19456 KiB (19 MiB) | OWASP minimum; memory-hard               |
| `t_cost` (iterations)  | 2                  | Sufficient with 19 MiB memory            |
| `p_cost` (parallelism) | 1                  | Single-threaded; simplest, most portable |
| `output_length`        | 32 bytes           | Same as current PASS_KEY_LEN             |
| `salt_length`          | 16 bytes           | Same as current KDF_SALT_LEN             |

**Expected timings:**

| Platform                | Estimated |
| ----------------------- | --------- |
| Modern desktop (native) | 50–100ms  |
| Modern desktop (WASM)   | 100–200ms |
| Mid-range phone (WASM)  | 200–400ms |
| Budget phone (WASM)     | 400–800ms |

These are comparable to current PBKDF2 timings — users won't notice a difference.

## Implementation Libraries

### Rust (`secrt-core`)

**Crate:** [`argon2`](https://crates.io/crates/argon2) (RustCrypto)

- Pure Rust, no C dependencies, well-audited
- Already uses `ring` for everything else — `argon2` crate is a clean addition
- Drop `ring::pbkdf2` usage entirely

```toml
[dependencies]
argon2 = "0.5"
```

### Web (`web/`)

**Package:** [`hash-wasm`](https://www.npmjs.com/package/hash-wasm) (argon2id only)

- WASM-based, tree-shakes to ~32 KB min / ~12 KB gzipped
- WASM binary embedded as base64 (no separate file to serve)
- Well-maintained, 500K+ weekly downloads
- Could lazy-import so no-passphrase secrets pay zero bundle cost

```bash
pnpm add hash-wasm
```

**Alternative considered:** `argon2-browser` — less maintained, similar approach. `hash-wasm` is the better choice.

## Spec Changes

### Envelope format (`spec/v1/envelope.md`)

**Suite string change:**

```
OLD: "v1-pbkdf2-hkdf-aes256gcm-sealed-payload"
NEW: "v1-argon2id-hkdf-aes256gcm-sealed-payload"
```

**KDF block when passphrase is used:**

```json
{
  "name": "argon2id",
  "salt": "<base64url 16+ bytes>",
  "m_cost": 19456,
  "t_cost": 2,
  "p_cost": 1,
  "length": 32
}
```

**KDF block when no passphrase:** unchanged (`{ "name": "none" }`).

**Validation rules for `kdf.name == "argon2id"`:**

- `kdf.salt` MUST decode to at least 16 bytes
- `kdf.m_cost` MUST be >= 19456 (19 MiB)
- `kdf.t_cost` MUST be >= 2
- `kdf.p_cost` MUST be >= 1
- `kdf.length` MUST equal 32

**Remove:** All references to `PBKDF2-SHA256`, `iterations`, `MIN_PBKDF2_ITERATIONS`.

### Constants changes

| Constant                    | Old                                       | New                                         |
| --------------------------- | ----------------------------------------- | ------------------------------------------- |
| `SUITE`                     | `v1-pbkdf2-hkdf-aes256gcm-sealed-payload` | `v1-argon2id-hkdf-aes256gcm-sealed-payload` |
| `DEFAULT_PBKDF2_ITERATIONS` | 600,000                                   | **remove**                                  |
| `MIN_PBKDF2_ITERATIONS`     | 300,000                                   | **remove**                                  |
| `ARGON2_M_COST`             | —                                         | 19,456                                      |
| `ARGON2_T_COST`             | —                                         | 2                                           |
| `ARGON2_P_COST`             | —                                         | 1                                           |

### IKM derivation (unchanged pattern)

The IKM derivation stays the same structurally:

```
pass_key = argon2id(passphrase, kdf.salt, m_cost, t_cost, p_cost, 32)
ikm = SHA-256(url_key || pass_key)
```

Everything downstream (HKDF, AES-GCM, claim token, framing) is unchanged.

## Implementation Plan

### Phase 1: Spec + Core (`secrt-core`)

1. **Update `spec/v1/envelope.md`** — new suite string, argon2id KDF block, validation rules, remove PBKDF2 references
2. **Update `crates/secrt-core/Cargo.toml`** — add `argon2 = "0.5"`, remove `ring::pbkdf2` usage
3. **Update `crates/secrt-core/src/types.rs`** — new constants, new `KdfArgon2id` struct, remove PBKDF2 types
4. **Update `crates/secrt-core/src/crypto.rs`** — replace `pbkdf2::derive` with `argon2::Argon2::hash_password_into`, update validation
5. **Update test vectors** — regenerate `spec/v1/envelope.vectors.json`
6. **Run `cargo test`** — all tests pass with new KDF

### Phase 2: CLI (`secrt-cli`)

7. **Update any CLI-specific passphrase handling** (likely minimal — inherits from core)
8. **Update CLI `--iterations` flag** → replace with `--m-cost`, `--t-cost`, `--p-cost` (or just remove custom tuning and use defaults)
9. **Integration tests** — seal/open round-trip with passphrase

### Phase 3: Web (`web/`)

10. **`pnpm add hash-wasm`** in `web/`
11. **Update `web/src/crypto/constants.ts`** — new suite, argon2 params, remove PBKDF2 constants
12. **Update `web/src/types.ts`** — `KdfArgon2id` interface, update `EnvelopeJson` union
13. **Update `web/src/crypto/envelope.ts`** — replace `pbkdf2Derive()` with `argon2id()` from hash-wasm (lazy import)
14. **Update tests** — `envelope.test.ts`, `api.test.ts`, etc.
15. **Build + verify bundle size** — confirm ~12 KB gzip delta

### Phase 4: Docs + Cleanup

16. **Update `SECURITY.md`** — document argon2id choice and parameters
17. **Update `docs/whitepaper.md`** — argon2id references
18. **Update `README.md`** — "How It Works" section
19. **Update website copy** (if the "How It Works" page is in the web app)
20. **Update `CHANGELOG.md`** for all crates
21. **Tag as breaking change** in changelogs

### Phase 5: Cross-implementation verification

22. **Generate new test vectors** from Rust implementation
23. **Verify web decrypts Rust-sealed envelopes** and vice versa
24. **Verify CLI decrypts web-sealed envelopes** and vice versa
25. **Test on real devices** — phone browsers, older hardware

## Bundle Size Impact

| Asset                | Before      | After (est.) | Delta            |
| -------------------- | ----------- | ------------ | ---------------- |
| JS (gzipped)         | ~39 KB      | ~51 KB       | +12 KB           |
| WASM (zstd, gzipped) | 80 KB       | 80 KB        | unchanged        |
| CSS                  | 8 KB        | 8 KB         | unchanged        |
| **Total gzipped**    | **~127 KB** | **~139 KB**  | **+12 KB (+9%)** |

With lazy loading (only import hash-wasm when passphrase is entered), the no-passphrase path has zero overhead.

## Risk Assessment

| Risk                    | Likelihood | Mitigation                                                     |
| ----------------------- | ---------- | -------------------------------------------------------------- |
| WASM slow on old phones | Low        | Params chosen for ~400ms worst case; can tune down             |
| hash-wasm maintenance   | Low        | WASM is stable, algorithm won't change; could vendor if needed |
| Spec regression         | Low        | Cross-impl test vectors catch mismatches                       |
| `argon2` crate breaking | Very low   | RustCrypto is well-maintained; pin version                     |

## Open Questions

1. **CLI param flags:** Resolved as defaults-only (no user-exposed Argon2 tuning flags yet).
2. **Minimum m_cost validation:** Resolved as strict bounded validation (`m_cost >= 19456` and full bounds/work-cap enforcement).
3. **Lazy loading strategy:** Resolved as dynamic `import('hash-wasm')` for passphrase paths.
