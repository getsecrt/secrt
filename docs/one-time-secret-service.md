# One-time Secret Sharing Service (secret.fullspec.ca)

Date: 2026-02-04  
Goal: a self-hosted, “view once then delete” service for sharing text secrets (passwords, recovery codes, small notes) safely over the internet, with an optional out-of-band PIN and an authenticated API for automation.

This report answers:
1) How to architect it to be maximally safe  
2) How to provide “proof” it’s safe / not doing anything untoward  
3) Existing projects to build on  
4) Missing features / sharp edges to plan for

---

## 0) Executive Summary (recommended approach)

If “unobtainable except by the intended recipient” is a hard requirement, the safest practical architecture is **zero-knowledge / client-side encryption**:

- The browser (or a CLI) **encrypts the secret before upload**.
- The server stores **only ciphertext + minimal metadata** (expiry time, KDF salt/params, etc.).
- The decryption key is carried **in the URL fragment (`#...`)** and therefore is **not sent to the server** by normal HTTP requests. (The fragment is client-side only.)  
  See MDN’s reference on URL fragments.  
- An optional PIN/passphrase is combined with the URL key so that **intercepting the URL alone is insufficient**.
- “One-time” behavior is implemented as an **atomic claim+delete** on the ciphertext record.

This is the same *style* of security model used by projects like **PrivateBin** (explicitly “server never has access to the data”) and **Yopass** (encrypt/decrypt locally, no decryption key sent to server).  
Password Pusher is a strong alternative foundation when you value a mature UI + API and can accept server-side visibility (“encrypted at rest” but still decryptable by the service).

---

## 1) Threat Model (what we’re defending against)

You cannot design this well without being explicit about attackers and what “secure” means.

### Primary threats

1. **URL interception** (email compromise, forwarding, mailbox rules, “view in browser” links, etc.).  
   - Mitigation: optional PIN/passphrase *not shared in the same channel*, and ideally zero-knowledge design.

2. **Server compromise / database exfiltration** (attacker steals DB, backups, snapshots).  
   - Mitigation: ciphertext-only storage + no keys on server; short TTL; strict ops hygiene.

3. **“Accidental view” / link scanners** (Slack/Teams/email security scanners follow URLs and can consume a one-time link).  
   - Mitigation: “click-to-reveal” step; do not burn on GET; consider a claim token.

4. **Malicious or modified client code** (a web page can exfiltrate plaintext before encryption).  
   - Mitigation: provide a CLI mode; keep client small/auditable; strong CSP; optional “offline decrypt” tooling.

5. **Abuse** (spam, API key theft, resource exhaustion, enumeration).  
   - Mitigation: rate limiting, quotas, key scoping, monitoring, IP throttling, and careful identifier design.

### Non-goals (be honest)

- You cannot guarantee “no traces” in a literal sense on general-purpose storage (DB pages, backups, snapshots, OS-level caching).  
  What you *can* do is ensure leftovers are **cryptographically useless** (ciphertext without keys) and operationally reduce retention.

---

## 2) Secure Architecture (maximally safe design)

### 2.1 System components

- **Frontend**: static HTML/JS served from `secret.fullspec.ca` (no third-party scripts).
- **Backend API**: small service that accepts ciphertext, enforces TTL, serves ciphertext once, and deletes records.
- **Storage**: Redis or Postgres.
  - Redis (with TTL) is common and fast for one-time semantics.
  - Postgres works fine too; you’ll add a cleanup job for expirations.
  - Optional “Cryptgeon-style” mode: store ciphertext **in memory only** (e.g., in-process store or Redis with persistence disabled).
    - Upside: avoids durable DB artifacts/backups containing ciphertext and better matches “data minimization”.
    - Downside: secrets are lost on process/host restart; harder to run multi-instance; requires strict memory/DoS controls.

### 2.2 Data flow (recommended “zero-knowledge” mode)

#### Create

1. User enters secret in the client (web UI or CLI).
2. Client generates random material:
   - `secret_id` (public identifier)
   - `k_url` (random key material that will be placed in URL **fragment**)
3. Optional: user enters `PIN`.
4. Client derives keys:
   - `k_pin = Argon2id(PIN, salt, params)` (OWASP recommends Argon2id for password hashing/KDF use-cases.)
     - In browsers, Argon2id typically requires a WASM/JS implementation (e.g., libsodium). If you can’t support that, PBKDF2 via WebCrypto is the common fallback (but less resistant to GPU attacks than Argon2/scrypt).
     - Usability + security sweet spot: use a **short word-based passphrase** (e.g., 3–4 random words) rather than a 4–6 digit numeric PIN. It’s easier to type/remember *and* dramatically higher entropy.
     - Dependency-minimizing option: if the passphrase is already high-entropy (randomly generated), the KDF choice matters much less and you can stick to built-in WebCrypto primitives.
   - `k_master = HKDF(k_url || k_pin)` (or another well-reviewed key schedule)
   - `k_enc = HKDF(k_master, info="enc")`
   - `k_claim = HKDF(k_master, info="claim")`  *(used only to authorize the one-time claim; not reversible to k_enc)*
5. Client encrypts secret:
   - Use an **AEAD** mode (authenticated encryption) such as AES-GCM (WebCrypto) or XChaCha20-Poly1305 (libsodium).
   - OWASP recommends authenticated encryption modes such as GCM/CCM.
6. Client uploads to server:
   - `secret_id`, `ciphertext`, `nonce`, `kdf_salt`, `kdf_params`, `expires_at`, and `claim_hash = H(k_claim)` (hash only).
7. Client outputs a shareable URL:
   - `https://secret.fullspec.ca/s/<secret_id>#<k_url>`
8. If PIN is used: user shares **URL** and **PIN via separate channel**.

#### View (one-time retrieval)

1. Recipient opens the URL (the browser sends `/s/<secret_id>` to server; fragment is not sent).
2. UI asks for PIN (if required/expected) and shows a “Reveal” button.
3. On “Reveal”, client derives `k_claim` and sends it to the API:
   - `POST /api/v1/secrets/<secret_id>/claim` with `k_claim` (or better: `H(k_claim)`), over TLS.
4. Backend:
   - performs an **atomic** “check claim token + delete record + return ciphertext” transaction.
   - returns ciphertext once; record is deleted and cannot be re-fetched.
5. Client decrypts locally using `k_enc`.

This yields the property you asked for: the plaintext is not obtainable from the DB/server unless the attacker also has the URL fragment key and (optionally) the PIN.

### 2.3 One-time deletion semantics (correctness details)

To ensure “view once then gone” even under concurrency:

- Use a single atomic operation:
  - in SQL: `DELETE ... RETURNING ciphertext,...` guarded by claim token verification
  - or in Redis: `GETDEL` (Redis 6.2+) plus claim token checks and TTL.
- Treat “viewed” as “successfully claimed” (server has no perfect way to know decryption succeeded).

#### Database-agnostic persistence (migrations + atomic claim)

You can keep the application *database-agnostic* while preserving an atomic “return-and-delete” claim by:

- Defining a small storage interface (e.g., `create_secret`, `claim_secret`, `burn_secret`, `purge_expired`) and providing separate implementations for SQLite/Postgres.
- Using a migration system that runs **versioned schema changes** at deploy time (e.g., `migrations/001_init.sql`, `002_add_api_keys.sql`, etc.). Keep the schema as portable as possible (e.g., store timestamps as integer epoch seconds; use `TEXT`/`BLOB`/`INTEGER` types).
- Implementing `claim_secret` with the most atomic primitive available per database, even if the rest is ORM-driven:
  - **Postgres**: `DELETE FROM secrets WHERE id=$1 AND claim_hash=$2 AND expires_at_epoch>$3 RETURNING ciphertext, nonce, ...;`
  - **SQLite (>= 3.35)**: `DELETE FROM secrets WHERE id=? AND claim_hash=? AND expires_at_epoch>? RETURNING ciphertext, nonce, ...;`
  - **Fallback (no `RETURNING`)**: run `SELECT ...` then `DELETE ...` in a single transaction with appropriate locking (e.g., `SELECT ... FOR UPDATE` in databases that support it; `BEGIN IMMEDIATE` in SQLite to serialize claims).

The key is that **the claim path is intentionally database-aware** to maintain one-time semantics, while the rest of the app can remain portable.

Important tradeoff: if the client claims but disconnects before receiving ciphertext, the secret is gone.  
If you want fewer false burns, you can add an optional “two-phase” reveal:
- Phase 1: lock/claim (short lease), return ciphertext
- Phase 2: client ACKs burn after successful decrypt

But two-phase designs are more complex and (by definition) keep secrets around longer.

### 2.4 Storage, backups, and “no traces”

Even if you delete a DB row, remnants can persist in:
- DB pages / WAL
- snapshots / backups
- log aggregation

Mitigations:
- **Ciphertext-only storage + no server-side keys** is the strongest baseline: backups contain only ciphertext.
- Consider **excluding the secrets store from long-term backups**, or using very short retention.
- Add strict log hygiene: never log request bodies; avoid logging identifiers at high verbosity.
- If you want to go further, you can avoid durable persistence entirely by using an **in-memory-only ciphertext store** (Cryptgeon-style). Be careful not to overclaim “no traces”:
  - processes can crash and produce core dumps; hosts can be snapshotted; and OS swap can write memory to disk unless disabled.
  - on Linux, operational hardening typically includes disabling swap, disabling core dumps, and keeping secrets isolated from general-purpose logs/metrics.

### 2.5 API design for automation (with API keys)

You requested an API that other applications can use to create secrets, protected by an API key.

Recommended patterns:

- API keys are **random high-entropy tokens** with a visible prefix (for identification) + secret part.
- Store only a **hash** of the secret part server-side (e.g., HMAC-SHA256 with a server-side pepper), not the raw key.
- Scope keys (e.g., `secrets:create`, `secrets:burn`) and support rotation.
- Rate limit by key + IP; protect against “unrestricted resource consumption” and auth failures (OWASP API Security Top 10).

Suggested endpoints:

- `POST /api/v1/secrets`  
  - Mode A (zero-knowledge): accept ciphertext payload + `claim_hash`, return share URL template.
  - Mode B (server-encrypt): accept plaintext (only if you explicitly choose to allow it), encrypt server-side, return URL.
  - Accept a `ttl_seconds` (or `expires_in`) parameter, but enforce a server-side allowlist/cap (e.g., max 7–30 days) regardless of what the client requests.

- `POST /api/v1/secrets/<id>/burn` (sender-initiated invalidation)
- `GET /api/v1/secrets/<id>/status` (exists? expires_at?) *without revealing*

If you implement Mode B (server-encrypt), be explicit: it does **not** meet the “unobtainable except recipient” bar in the strongest sense because the service can see plaintext at creation time.

### 2.6 Web security hardening checklist

Transport & headers:
- TLS everywhere, HSTS, disable HTTP.  
  OWASP Secure Headers Project lists common protective headers.
- `Cache-Control: no-store` on all secret-related pages/responses.
- `X-Robots-Tag: noindex` on secret pages (and a conservative `robots.txt`) to reduce accidental indexing.
- Strict CSP (no inline script if possible; no third-party origins).
- `Referrer-Policy: no-referrer` to avoid URL leakage.

App security:
- Strong input validation; limit secret sizes.
- CSRF protection for any cookie-auth endpoints.
- XSS prevention is critical: XSS defeats client-side encryption by stealing plaintext before encryption.
- Abuse controls: IP throttles, WAF rules, optional CAPTCHA for anonymous web creation.

Logging:
- Follow OWASP Logging guidance: avoid secrets, PINs, and request bodies in logs.

---

## 3) “Proof” it’s safe (and you’re not doing anything untoward)

There is no single silver bullet, but you can combine technical and process controls to make the system meaningfully verifiable.

### 3.1 Strongest technical lever: zero-knowledge design

If the server never receives the decryption key (fragment-based) and stores only ciphertext, then:
- a DB leak does not reveal plaintext
- an operator cannot decrypt from storage alone

This is not a complete “proof” because a malicious server could still serve modified JS to exfiltrate plaintext at creation time. Which leads to the next items.

### 3.2 Make the client verifiable

- Keep client code small, open source, and easy to audit.
- Provide a **CLI** that can:
  - encrypt locally and upload ciphertext (no plaintext ever touches the server)
  - download ciphertext and decrypt locally
- Optionally sign releases (and publish hashes) for the CLI.

### 3.3 Transparency & assurance practices

- Publish a clear **threat model** (what you protect, what you don’t).
- Publish a **security policy** (contact, response timelines) + `/.well-known/security.txt`.
- Commission periodic **third-party security review** (even a small one is valuable).
- Add a **bug bounty** (can be private/invite-only initially).
- Provide minimal, privacy-preserving operational telemetry (availability, not user content).

### 3.4 Supply-chain & deployment integrity (what you can prove)

It helps to distinguish what you can prove to **yourself** (as operator) vs what you can prove to **anonymous web users**.

Operator-verifiable controls (high value, practical):
- **Signed source**: sign Git tags/releases (GPG or Sigstore) and publish release notes.
- **Reproducible builds (where possible)**: deterministic front-end bundle + pinned dependencies.
- **Build provenance**: generate SLSA-style provenance in CI so you can show *how* artifacts were built.
- **Signed artifacts**: sign container images/artifacts (e.g., Sigstore Cosign) and deploy by immutable digest, not by mutable tags.
- **SBOM**: publish a software bill of materials and keep dependency updates auditable.
- **Minimize crypto deps**: prefer browser **WebCrypto** for AES-GCM/HKDF/PBKDF2 over “roll-your-own” JS crypto. If you need Argon2, consider a single well-known WASM dependency and vendor/pin it (no CDN), with immutable asset hashes.

User-verifiable options (helpful, but not a complete “proof” for the web UI):
- Provide a **CLI** that verifies its own signature/provenance and performs encrypt/decrypt locally; users can choose it when the web threat model isn’t acceptable.
- Publish the current deployed build’s **Git commit + artifact digest** so third parties can audit your deployments over time.

Hard truth: if the server can serve arbitrary HTML/JS, it can also serve a targeted malicious build to a specific visitor. The only strong cryptographic mitigations are out-of-band trust anchors (signed CLI/extension) or hardware-backed remote attestation (complex; provider-dependent).

---

## 4) Existing projects to use as a foundation (self-host)

Below are strong candidates. Pick based on whether “server can’t decrypt” is mandatory.

### Quick comparison

| Project             | Self-host | Client-side encryption (“zero knowledge”) |          One-time / burn | Passphrase/PIN |                          API for automation |
|:--------------------|----------:|------------------------------------------:|-------------------------:|---------------:|--------------------------------------------:|
| Password Pusher     |        ✅ |          ❌ (typically server can decrypt) |                        ✅ |              ✅ |                                           ✅ |
| Yopass              |        ✅ |                                         ✅ |                        ✅ |              ✅ | ⚠️ (verify fit / may require customization) |
| PrivateBin          |        ✅ |                                         ✅ | ✅ (“burn after reading”) |              ✅ |               ⚠️ (not primarily API-driven) |
| OneTimeSecret (OSS) |        ✅ |        ⚠️ (verify exact deployment model) |                        ✅ |              ✅ |                                           ✅ |
| Cryptgeon           |        ✅ |            ⚠️ (verify exact crypto model) |                        ✅ |              ✅ |                                 ⚠️ (verify) |

### 4.1 Password Pusher (pwpush)

- Pros:
  - Mature, popular, easy to host.
  - Supports passphrases and expiry by views/days; includes a JSON API.
  - Documents real-world issues like link scanners consuming view counts and mitigation options.
- Cons:
  - Described as “encrypted at rest” — the service still handles plaintext in typical deployments.

Refs:
- GitHub: https://github.com/pglombardo/PasswordPusher
- FAQ (link scanners): https://docs.pwpush.com/docs/faq/

### 4.2 Yopass

- Pros:
  - Designed for one-time secrets.
  - Encrypts/decrypts locally; decryption key is not sent to the server.
- Cons:
  - You’ll need to evaluate API/auth needs (may require customization for API key workflows).

Ref:
- GitHub: https://github.com/jhaals/yopass

### 4.3 PrivateBin

- Pros:
  - Explicit client-side encryption; server never sees plaintext.
  - Has “burn after reading” and discussions support.
- Cons:
  - More “pastebin” than purpose-built secret sharer; API ergonomics vary.

Ref:
- https://privatebin.info/

### 4.4 OneTimeSecret (official/open source)

- Pros:
  - Mature UX pattern (secret link + optional passphrase; metadata/burn patterns).
  - Provides libraries and a well-known product model to emulate.
- Cons:
  - Verify whether the self-hosted implementation matches your desired trust model; some deployments may be server-decryptable.

Refs:
- How it works: https://onetimesecret.com/docs/how-it-works
- Open-source repo: https://github.com/onetimesecret/onetimesecret

### 4.5 Cryptgeon (candidate)

- Pros:
  - Modern, self-hostable one-time secret sharing.
- Cons:
  - Validate crypto model, API, and operational maturity for your needs.

Ref:
- https://github.com/cupcakearmy/cryptgeon

### Practical recommendation

- If you want **best security properties** (server cannot decrypt from storage): start with **Yopass** or **PrivateBin**, or implement the zero-knowledge architecture described above.
- If you want **best product completeness** and a clean API quickly: start with **Password Pusher**, then decide if you need to evolve toward zero-knowledge over time.

---

## 5) Features you’re likely missing (high-value additions)

### Product features

- **Sender metadata link** (“receipt”): see whether the secret still exists, and burn it without revealing.
- **Manual burn**: invalidate immediately.
- **Expiration**: time-based TTL + optional “max views” (usually 1; make it configurable).
  - Provide a simple TTL picker with safe defaults, e.g.: 10 minutes, 1 hour, 8 hours, 24 hours, 48 hours, 1 week, 1 month.
  - Default: **48 hours** is reasonable for usability; **shorter is safer**. Consider capping anonymous/public secrets to a shorter max (e.g., 7 days) and allowing longer TTLs only for authenticated users/API keys you control.
- **Passphrase generator**: one-click generate a 3–4 word passphrase and show a strength hint; allow users to set their own but discourage short numeric PINs.
- **No-JS / Tor support** (optional):
  - Browser-based zero-knowledge requires client-side code (JS/WASM) to encrypt/decrypt; without JS the web UI can’t provide that experience.
  - Provide a **signed CLI** (or small desktop app) that can create and reveal secrets while keeping the same zero-knowledge model.
  - For a “manual” no-JS flow, allow users to paste **already-encrypted ciphertext** into the web form and decrypt offline; document that the web UI can only display ciphertext.
- **Reveal step** to avoid premature burning by link previews/scanners.
- **Attachments** (optional): careful with size limits and AV scanning.
- **Notifications**: optionally notify sender when claimed (privacy tradeoff).

### Security/ops features

- **No third-party assets**; strong CSP; strict no-store caching.
- **API key management UI** (rotate, revoke, scope, rate limits).
- **Rate limiting / quotas** by IP and key.
- **Audit logs** *without sensitive payloads* (who created/burned, timestamps, key id).
- **Abuse monitoring** (spam use, scanning spikes).
- **Multi-tenant separation** (if you ever host for multiple orgs).

---

## 6) Suggested MVP build plan

1. Decide the trust model:
   - Zero-knowledge only (recommended), or
   - Mixed mode (plaintext API allowed for convenience).
2. Pick a foundation:
   - Fork Password Pusher for speed, or
   - Deploy Yopass/PrivateBin, or
   - Build a minimal Go/Node/Rails service with the architecture above.
3. Implement:
   - create secret (ciphertext upload) + claim+delete endpoint
   - optional PIN KDF params + storage
   - API key auth + rate limits
   - DB abstraction + migrations (keep “claim” as DB-specific SQL for atomicity)
4. Hardening:
   - security headers, CSP, no-store, logs hygiene, monitoring
5. Validate:
   - threat model review, basic penetration test, and operational runbooks

---

## 7) Standards & interoperability (what you can lean on)

There isn’t a widely adopted “open standard” for a **one-time secret service** end-to-end (URLs, burn semantics, claim flows, deletion guarantees). Interoperability usually comes from **publishing a small spec + reference clients**, not from a single canonical protocol.

That said, you *can* lean heavily on open standards for the cryptographic envelope and its building blocks:

- **JOSE / JWE** (JSON Web Encryption): a standard container format for encrypted payloads. It’s widely implemented across languages and maps well to web APIs.  
  Practical fit here: derive a content-encryption key in the client (from URL fragment key + optional PIN KDF) and use JWE with `alg=dir` (“direct” key) and an AEAD `enc` (e.g., AES-GCM).  
  Caveat: JWE’s standardized password-based options are PBKDF2-based (PBES2). If you want Argon2id you’ll either extend the headers or define your own envelope version.

- **OpenPGP / CMS (S/MIME)**: good standards when you have a recipient public key/cert. Less applicable for “share a link with anyone” flows unless you add user accounts / key exchange.

- **HPKE** (Hybrid Public Key Encryption): a modern standard for public-key encryption. Potentially useful if you later support “encrypt to a user’s public key” as an alternative to link-key sharing.

Recommended “pragmatic standardization” for this project:

1. Publish an **envelope spec** (versioned) that fixes: AEAD algorithm, key derivation, base64url encoding, and required metadata fields.
2. Publish **test vectors** (known inputs/outputs) so other clients can validate compatibility.
3. Publish an **OpenAPI** spec for the HTTP API.
4. Provide at least one **reference implementation** (browser JS + CLI) and treat those as the compatibility anchor.

Supply-chain note: using a standard doesn’t remove the “malicious JS served by the server” risk. Mitigate with a minimal client, strong CSP, no third-party assets, reproducible builds, and a CLI option for high-assurance workflows.

---

## 8) Implementation language (what makes sense)

The language choice matters less than the trust model:

- In the recommended **zero-knowledge** design, the server is mostly a small authenticated CRUD service for **ciphertext + TTL + atomic claim+delete**. The sensitive crypto runs in the browser/CLI, and the backend shouldn’t need to “share encryption code” with the frontend at all.
- If you intentionally support a **server-encrypt** mode (plaintext accepted by API), then backend crypto correctness and key management become a larger part of the system risk.

### If you’re building on an existing project

Pick the project first and accept its language/runtime:
- Password Pusher: Ruby/Rails
- Yopass: Go
- PrivateBin: PHP
- Cryptgeon: Rust
- OneTimeSecret (OSS): Ruby

### If you’re building new (greenfield)

**Node.js + TypeScript** is a reasonable choice if you value velocity and want a single-language ecosystem:
- Pros: same language for web UI tooling + API; great HTTP ecosystem; easy to publish a shared “envelope” package for browser + CLI.
- Cons: larger dependency surface area; long-lived services require runtime patching discipline.
- Note: Node’s benefit is mostly about sharing **types/envelope encoding** and (optionally) a CLI implementation. The browser should use WebCrypto; the backend doesn’t need to encrypt secrets in zero-knowledge mode.

**Go** is often the cleanest operational choice for a small public-facing service:
- Pros: single static binary, straightforward deployment, strong concurrency, typically fewer deps.
- Cons: frontend still JS/TS (separate stack), though that’s normal.

**Rust** is viable if you want high-assurance and are comfortable with the ecosystem:
- Pros: memory safety, performance.
- Cons: higher implementation complexity/time for most teams.

Recommendation for `~1,000/day` single-instance use:
- Choose **Node/TS** if you’re most productive there and can keep deps minimal.
- Choose **Go** if you want the simplest, most robust deployment story.

---

## 9) Backend framework options (keep it lightweight)

In a zero-knowledge design, the backend can be extremely small: validate inputs, enforce TTL, do atomic claim+delete, authenticate API keys, and serve static assets. The “best” framework is mostly the one that helps you do those things with **fewest dependencies** and **least magic**.

### Best lightweight options

**Go: `net/http` + small router**
- Typical stack: `net/http` + `chi` (or stdlib mux), `database/sql`, and a simple migration tool.
- Pros: very small runtime footprint, excellent concurrency, straightforward ops (one binary), dependency counts can stay low.

**Node.js/TypeScript: Fastify or Hono**
- Typical stack: Fastify (or Hono) + minimal validation + SQL driver.
- Pros: fast iteration, easy OpenAPI generation, easy to share envelope/types with a CLI.
- Cons: dependency/supply-chain surface tends to grow unless you keep discipline.

**PHP (if you want to stay close to Laravel): Slim or “thin Laravel”**
- If you want minimal: Slim (or Symfony HttpFoundation components) can be much lighter than full Laravel.
- Laravel can still work, but it’s “heavier than necessary” for this service; the main reason to pick it is team familiarity and speed.

### What to avoid (if “minimal deps” is the priority)

- Heavy ORMs and complex background job stacks for v1 (raw SQL is fine here, and the claim path should be DB-specific anyway).
- Large client frameworks for the crypto UI (a small static page + a tiny encryption module is easier to audit).

### Practical recommendation

If you want the simplest, most dependency-light public service: **Go + SQLite/Postgres + static frontend**.  
If you want fastest iteration and you’re comfortable keeping deps tight: **Node/TS + Fastify/Hono**.  
If you want to stick with your comfort zone: **Laravel is acceptable**, but consider using it as an API-only app and keep the surface area minimal.

---

## 10) Keeping browser + API clients consistent (without tying to backend language)

Even with a Go backend, you can keep clients consistent by treating crypto + API contracts as **versioned specs** with reference implementations:

- **Versioned envelope spec**: define `envelope_version` plus exact algorithms/encodings (AEAD, nonce format, base64url, KDF params). The server stores/returns the envelope as an opaque blob.
- **OpenAPI for the HTTP API**: publish `/openapi.json` and generate clients where convenient (e.g., TypeScript fetch client).
- **Shared “SDK” package (recommended)**:
  - a small TypeScript package that implements the envelope (encrypt/decrypt) and API calls
  - used by the browser UI *and* by any Node-based automation/CLI tooling
  - the backend language stays independent (Go just validates and persists the envelope)
- **Test vectors + contract tests**: publish known plaintext+keys → expected ciphertext/envelope outputs, and use them to keep multiple client implementations compatible (e.g., TS browser + optional Go CLI).

This approach gives you the “consistency” benefits you were looking for from Node, without requiring the backend to be Node.

## Appendix: Reference materials (quick links)

- URL fragments are client-side and not sent to servers (MDN): https://developer.mozilla.org/en-US/docs/Web/URI/Reference/Fragment
- OWASP Password Storage Cheat Sheet (Argon2id recommendation): https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- OWASP Cryptographic Storage Cheat Sheet (AEAD guidance): https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x11-t10/
