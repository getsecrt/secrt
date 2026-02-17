# Website Plan for secrt.ca

Status: Phase 1 complete — all core UI, coverage gate, trust content, and E2E tests done (2026-02-14)

This document defines how we move from the current placeholder pages to a full web product while preserving the zero-knowledge model and spec compatibility.

## 1. Context and Current State

Current status in repo:

- Rust server is live and stable for v1 API (`/api/v1/*`).
- Preact + TypeScript SPA in `web/` serves `/` and `/s/:id` via hash-based client-side routing.
- Server serves frontend assets from:
  - `SECRT_WEB_DIST_DIR` override, or
  - embedded `web/dist` assets (`rust-embed`).
- **Send page is functional** — text/file encryption, passphrase, TTL selection, share link generation all working.
- **Claim page is a placeholder** — shows secret ID but does not yet parse fragment, claim, or decrypt.
- Design system (Tailwind v4 tokens, dark mode, component classes) is established.
- WebCrypto envelope module (`seal`/`open`) passes all 28+ spec test vectors.

## 2. Product Goals

### Primary goals (must ship first)

1. Create secret flow in browser:
   - Paste/type plaintext in textarea.
   - Optional file drag-and-drop (with filename/mime hint metadata).
   - Optional passphrase.
   - Copyable share link output.
2. Claim flow in browser:
   - Parse `/s/{id}#<fragment>` links.
   - Claim once via API and decrypt client-side.
   - Safe reveal UX (masked by default, copy button, download option).
3. Protocol compatibility:
   - Full compatibility with `spec/v1/envelope.md` and `spec/v1/api.md`.
   - Do not diverge from CLI envelope/test vectors.
4. Product navigation:
   - Links to GitHub and binary downloads.
   - Position CLI/apps as preferred power-user path.

### Secondary goals (phase 2+)

1. Passwordless accounts (passkeys only, no email).
2. Passkey management:
   - add additional passkeys
   - revoke passkeys
3. API key lifecycle in web:
   - create API keys
   - revoke API keys
4. Secret dashboard:
   - list unclaimed/active owned secrets
   - sort by created/expiry
   - burn owned secrets
5. Optional encrypted metadata for notes/names (privacy-preserving).

### Nice-to-have goals

- Architecture whitepaper + FAQ links.
- ~~Public "how sharing works" page.~~ **Done** (`/how-it-works`)
- Secret naming UX backed by encrypted metadata.

## 3. Security and Privacy Invariants (Non-Negotiable)

1. Server never sees plaintext or URL fragment key material.
2. Server stores envelope + claim hash only (per existing v1 contract).
3. Claim remains atomic claim+delete server-side.
4. Browser app must never log plaintext, passphrases, claim tokens, or fragments.
5. Any analytics/telemetry must be opt-in and strictly metadata-only.
6. New account/dashboard features must not weaken zero-knowledge secret handling.

## 4. Tech Stack (established)

The following stack is implemented and in use:

- UI framework: `Preact 10` + TypeScript 5.8 (strict mode).
- Build tool: `Vite 7` with `@preact/preset-vite`.
- Crypto in browser: native `WebCrypto` APIs + lazy-loaded `hash-wasm` for Argon2id.
  - AES-256-GCM encryption/decryption
  - HKDF-SHA256 key derivation
  - Argon2id passphrase KDF (`v=19`, `m=19456`, `t=2`, `p=1`)
- Routing: custom hash-based client-side router (`router.ts`) for:
  - `/` (send/create flow)
  - `/s/:id` (claim flow)
  - `/test/theme` (design system reference)
  - future `/dashboard`, `/settings`
- State/data:
  - Preact hooks for local component state
  - typed API client module (`lib/api.ts`) with fetch wrapper
  - envelope size validation against server-reported limits
- Testing:
  - `Vitest 3` for unit/integration/vector tests (happy-dom environment)
  - `Playwright` for end-to-end browser coverage (Chromium + WebKit + mobile-chrome)
- Styling:
  - Tailwind CSS v4 with `@tailwindcss/vite` plugin
  - OKLch green palette, semantic color tokens, dark mode via `.dark` class
  - Component classes: `.btn`, `.input`, `.textarea`, `.card`, `.link`, `.code`
- Dependencies: `fzstd` for zstd decompression (envelope frame codec)

### Shared with CLI vs Separate

Decision (confirmed):

- Crypto implementations are separate:
  - CLI/core: Rust + `ring`
  - Web: native `WebCrypto`
- Protocol contracts and compatibility gates are shared:
  - `spec/v1/envelope.md`
  - `spec/v1/envelope.vectors.json` (28+ vectors, all passing in both implementations)
  - `spec/v1/api.md` and OpenAPI schema

## 5. Architecture Plan

### Frontend module layout (actual)

`web/src/`:

- `app.tsx` — main App component with route switch
- `router.ts` — hash-based client-side router with `pushState` support
- `main.tsx` — Vite entry point
- `types.ts` — shared TypeScript types (`ApiInfo`, `PayloadMeta`, `Envelope`, etc.)
- `styles.css` — Tailwind v4 config, theme tokens, component classes, dark mode
- `features/send/` — **complete**
  - `SendPage.tsx` — text/file mode, passphrase, TTL, encrypt+upload flow
  - `FileDropZone.tsx` — drag-and-drop and click-to-browse file input
  - `TtlSelector.tsx` — TTL preset buttons (5min → 30d)
  - `ShareResult.tsx` — success screen with copy button and expiry display
- `features/claim/` — **complete**
  - `ClaimPage.tsx` — full claim flow: fragment parsing, API claim, passphrase modal, text reveal/copy, file download, error states
  - `ClaimPage.test.tsx` — 16 tests covering all flows
- `features/test/`
  - `ThemePage.tsx` — design system reference page
  - `TestClaimPage.tsx` — claim flow test harness (dev-only)
- `features/trust/`
  - `HowItWorksPage.tsx` — full technical page at `/how-it-works` (encryption, passphrase, one-time retrieval, what server sees, open source)
- `crypto/`
  - `constants.ts` — protocol constants (algorithm names, iterations, info strings)
  - `encoding.ts` — base64url, hex, UTF-8 encode/decode
  - `frame.ts` — payload frame build/parse (magic header, zstd codec)
  - `envelope.ts` — `seal()`, `open()`, `deriveClaimToken()`, `deriveClaimHash()`
  - `envelope.test.ts` — 28+ spec vector tests
- `lib/`
  - `api.ts` — typed HTTP client (`fetchInfo`, `createSecret`, `claimSecret`, `burnSecret`)
  - `url.ts` — share URL parse/format helpers
  - `ttl.ts` — TTL presets, validation, expiry formatting
  - `envelope-size.ts` — envelope size check against server limits
  - `ttl.test.ts`, `envelope-size.test.ts` — unit tests
- `components/`
  - `Layout.tsx` — page wrapper with header (logo) and footer (links, theme toggle)
  - `Logo.tsx` — SVG logo with light/dark variants
  - `Icons.tsx` — 16 icon components (Clipboard, Upload, Lock, Eye, Clock, etc.)
  - `CopyButton.tsx` — clipboard copy with "Copied!" feedback
  - `ThemeToggle.tsx` — dark/light mode switch (persists to localStorage, `D` key shortcut)
  - `HowItWorks.tsx` — expandable `<details>` disclosure with zero-knowledge summary, links to `/how-it-works`

### Server/frontend integration

1. Server acts as same-origin API + static asset host.
2. SPA shell serves for `/` and `/s/{id}` (placeholder HTML replaced by app).
3. `no-store` and security headers preserved on secret routes.

## 6. Delivery Phases

### Phase 0: Foundation hardening — COMPLETE

1. ~~Route integration:~~
   - ~~Serve SPA shell for `/` and `/s/{id}`.~~ **Done** — hash-based router in `router.ts`.
2. ~~Add robust API client wrappers for:~~
   - ~~`GET /api/v1/info`~~ **Done**
   - ~~`POST /api/v1/public/secrets`~~ **Done**
   - ~~`POST /api/v1/secrets/{id}/claim`~~ **Done**
3. ~~Add shared binary/text utilities:~~
   - ~~UTF-8 detection~~ **Done** (`crypto/encoding.ts`)
   - ~~base64url encode/decode~~ **Done** (`crypto/encoding.ts`)
   - ~~safe filename handling for downloads~~ **Done** (implemented in ClaimPage)
4. ~~Add Vitest test harness and vector-driven crypto tests using `spec/v1/envelope.vectors.json`.~~ **Done** — 28+ vectors passing, 299 tests across 24 files.
5. ~~Add Playwright harness with baseline E2E flows for send/claim.~~ **Done** — 47 E2E tests across 6 spec files (Chromium + WebKit + mobile-chrome).

Exit criteria:

- ~~Browser crypto passes all spec vectors.~~ **Done**
- ~~Vitest coverage gate configured~~ **Done** — thresholds at 90/85/90/90 (statements/branches/functions/lines). Crypto and lib modules at ~100%; frontend components excluded from strict thresholds.
- ~~Playwright baseline E2E suite running~~ **Done** — 47 tests covering send/claim, file upload, error states, navigation, clipboard, and security.
- ~~Placeholder pages removed for `/` and `/s/{id}`.~~ **Done**

### Phase 1: MVP web experience (public) — COMPLETE

1. ~~Send page (`/`)~~ **COMPLETE**
   - ~~plaintext textarea~~ **Done**
   - ~~file drop/select~~ **Done** (drag-and-drop + click-to-browse)
   - ~~optional passphrase~~ **Done** (with show/hide toggle)
   - ~~TTL presets + custom seconds (validated to API bounds)~~ **Done** (5 presets: 5min/1h/24h/7d/30d)
   - ~~create secret + show share link + copy button~~ **Done** (ShareResult component)
2. ~~Claim page (`/s/:id`)~~ **COMPLETE**
   - ~~parse fragment key from URL~~ **Done**
   - ~~call claim API with derived claim_token~~ **Done**
   - ~~passphrase prompt only when envelope indicates KDF != none~~ **Done** (modal overlay with retry)
   - ~~masked reveal + copy button for text secrets~~ **Done** (eye toggle + CopyButton)
   - ~~download button for file secrets (with original filename/mime)~~ **Done**
   - ~~design follows send page patterns (card layout, icon labels, status flow, error alerts)~~ **Done**
   - 16 component tests covering all flows
3. ~~Content/marketing essentials~~ **COMPLETE**
   - ~~GitHub + Downloads links~~ **Done** (footer)
   - ~~Trust model explanation~~ **Done** — inline `<HowItWorks />` disclosure on send page + full `/how-it-works` technical page covering encryption, passphrase protection, one-time retrieval, what the server sees, and open source
   - ~~CLI/apps pointer~~ **Done** (footer "CLI & App Downloads" link)
4. ~~Error UX~~ **COMPLETE**
   - ~~generic unavailable message for 404 claim outcomes~~ **Done** (ClaimPage "no longer available" state)
   - ~~explicit guidance for bad fragment/malformed link/passphrase mismatch~~ **Done** (incomplete link, malformed key, wrong passphrase error states)
   - could still benefit from polish and a dedicated error illustration

Exit criteria:

- End-to-end create/claim works for text and file payloads.
- CLI-created secrets can be claimed/decrypted in browser and vice versa.

### Phase 2: Authenticated product surface (accounts + keys + dashboard)

Note: requires new backend/API work not in current v1 runtime.

1. Passkey-only account system
   - WebAuthn registration/authentication
   - display name only (no email)
   - generated default handle (e.g. adjective-animal)
2. Passkey management
   - list credentials
   - add credential
   - revoke credential
3. API key management UI
   - create API key
   - list/revoke keys
4. Secrets dashboard
   - list owned active secrets
   - sort/filter
   - burn action
   - optional pagination/cursoring.

Exit criteria:

- User can fully manage passkeys and API keys in browser.
- Dashboard reflects owned secrets without exposing any decryption material.

### Phase 3: Encrypted metadata and trust docs

1. Add encrypted notes/names for owned secrets.
2. Publish architecture whitepaper + FAQ.
3. Add sharing education page for safer secret handling.

## 7. Required API and Schema Additions for Phase 2+

Current v1 API is intentionally minimal. To support accounts/dashboard:

Versioning decision for alpha:

- Keep API routes under `/api/v1` for this phase.
- Do not introduce an `/api/v2` namespace yet.
- Treat any auth/key redesign as an internal contract change while the product is still pre-adoption.
- Backward compatibility with pre-alpha API key/auth credential formats is not required.

### Authentication model change (alpha)

Target: server must never see user root metadata keys.

1. Browser generates `api_key_root` locally (32 random bytes).
2. Browser derives:
   - `auth_token = HKDF(api_key_root, "secrt-auth")`
   - `meta_key = HKDF(api_key_root, "secrt-meta-encrypt")`
3. Browser sends only verifier/auth material derived from `auth_token` to server.
4. Server never receives `api_key_root` or `meta_key`.

### New API groups (proposed)

1. `auth/webauthn/*`
   - registration start/finish
   - authentication start/finish
2. `account/*`
   - profile (name/handle)
   - passkey list/add/revoke
3. `apikeys/*`
   - create/list/revoke using derived auth credentials (no root key on server)
4. metadata list endpoints for owned secrets:
   - `GET /api/v1/secrets` (owner scoped)
   - `GET /api/v1/secrets/{id}` (owner scoped metadata only)
   - `PUT /api/v1/secrets/{id}/meta` (owner scoped encrypted metadata upsert)

### API key issuance/auth flow (proposed)

Provisioning:

1. Client generates `api_key_root` locally.
2. Client derives `auth_token` and `meta_key`.
3. Client submits a key-registration request with derived verifier material.
4. Server stores verifier material and returns key identifier/prefix.
5. Client assembles local key string (example: `sk2_<prefix>.<root_b64>`) for export/backup.

Authenticated request flow:

1. Client parses local key string and derives `auth_token`.
2. Client sends auth credential derived from `auth_token` (bearer token format for alpha is acceptable).
3. Server verifies against stored verifier material.

Operational constraints:

1. Do not log auth credentials or verifier material.
2. Continue using `X-API-Key`/`Authorization` headers, but credential semantics/format may change.
3. Since this is pre-adoption, old key shapes may be dropped without migration support.

### Owner-scoped secrets list contract (dashboard)

Primary endpoint:

- `GET /api/v1/secrets?cursor=<cursor>&limit=<n>&sort=created_at|expires_at&state=active|expired|claimed`

Response shape (proposed):

```json
{
  "items": [
    {
      "id": "sec_...",
      "share_url": "https://secrt.ca/s/sec_...",
      "created_at": "2026-02-12T16:00:00Z",
      "expires_at": "2026-02-13T16:00:00Z",
      "state": "active",
      "meta_key_version": 1,
      "enc_meta": {
        "v": 1,
        "alg": "A256GCM",
        "nonce": "<base64url>",
        "ciphertext": "<base64url>"
      }
    }
  ],
  "next_cursor": "..."
}
```

Contract requirements:

1. Owner-scoped only; no cross-user visibility.
2. Metadata-only surface; no envelope plaintext output.
3. Never return URL fragment keys, claim tokens, or raw `claim_hash`.
4. Client decrypts `enc_meta` locally and performs keyword search locally (zero-knowledge preserved).
5. Server-side filtering is limited to non-sensitive fields (`state`, `created_at`, `expires_at`).

### Metadata search model (dashboard)

1. Server returns encrypted metadata blobs only (`enc_meta`).
2. Browser decrypts metadata in memory using locally derived `meta_key`.
3. Keyword search runs client-side over decrypted metadata.
4. Server-side search over secret titles/descriptions is intentionally out of scope to preserve zero-knowledge.

### Schema additions (proposed)

- `users`
- `passkeys` (credential id, public key, counter, transports, revoked_at)
- `sessions` (if using cookie-based auth)
- `api_keys` extension for user ownership
- `secrets` metadata extension (`meta_key_version`, `enc_meta`) or a dedicated `secret_meta` table for encrypted per-secret metadata blobs

### API client changes required

Affected components and required changes:

1. Web API client (`web/src/lib/api.ts`):
   - add authenticated methods for key management and dashboard metadata endpoints
   - add auth-header provider for derived auth credentials
   - add typed request/response models for `enc_meta`
2. Rust shared API types (`crates/secrt-core/src/api.rs`):
   - add request/response structs for list/detail/meta upsert/key management endpoints
   - extend API trait for new methods (or add a secondary trait if staged rollout is preferred)
3. CLI HTTP client (`crates/secrt-cli/src/client.rs`):
   - parse/support new API key credential format
   - derive auth credential before authenticated calls
   - optionally implement list/meta endpoints if dashboard or automation features are exposed in CLI
4. CLI test harness (`crates/secrt-cli/tests/helpers.rs` and related tests):
   - expand mock API surface for new methods
   - add tests for new auth credential format parsing and derived-auth requests

### Implementation impact map (codebase)

Server/API:

1. `crates/secrt-server/src/http/mod.rs`
   - add routes/handlers for key management and metadata endpoints
   - add auth parsing/verification path for derived-auth credentials
2. `crates/secrt-server/src/domain/auth.rs`
   - add new key-format parsing and derived-verifier validation
   - remove legacy key-format assumptions from parsing/verification paths
3. `crates/secrt-server/src/storage/mod.rs`
   - extend store traits for owner-scoped list/detail/meta upsert and API key management by account
4. `crates/secrt-server/src/storage/postgres.rs`
   - implement SQL for new store methods (pagination, sorting, meta upsert, key lifecycle)
5. `crates/secrt-server/migrations/*`
   - add schema changes for account/passkey/key metadata support
6. `crates/secrt-server/tests/*.rs`
   - add route/auth/storage behavior tests for new endpoints and credential scheme

Shared client contract:

1. `crates/secrt-core/src/api.rs`
   - add new API types and trait methods for dashboard + key endpoints

CLI client/tests:

1. `crates/secrt-cli/src/client.rs`
   - implement new request paths and auth derivation behavior
2. `crates/secrt-cli/tests/helpers.rs`
   - expand mock interface and canned responses for new methods
3. `crates/secrt-cli/tests/*`
   - add regression tests for auth format and new API operations as needed

Web client:

1. `web/src/lib/api.ts`
   - implement typed endpoint methods and auth header plumbing
2. `web/src/crypto/*` (new)
   - implement local root-key generation, derivation, and metadata decrypt helpers
3. `web/src/features/dashboard/*` (new)
   - implement list/decrypt/search/update metadata flows

## 8. Metadata Encryption Direction (for notes/names)

Preferred direction (Phase 2 baseline): HKDF-from-root-secret using API key material.

### API key as client-held root secret

Proposed derivation model:

```text
auth_token = HKDF(api_key_root, info="secrt-auth")
meta_key   = HKDF(api_key_root, info="secrt-meta-encrypt")
```

Rules:

1. `api_key_root` is generated client-side only and is never sent to the server.
2. Client sends only `auth_token` (or a verifier/signature derived from it) for API auth.
3. Server stores/verifies only hashed auth material; it never receives `meta_key`.
4. Client encrypts metadata (`title`, `description`, optional tags) with `meta_key` before upload.
5. Dashboard list endpoints return only ciphertext metadata blobs (`enc_meta`), which are decrypted in-browser.

Recovery and device-sync implications:

1. If users lose all copies of `api_key_root`, metadata becomes undecryptable.
2. Product must provide one of:
   - explicit user-managed key export/backup flow, or
   - passkey-assisted unwrap flow (where supported), plus fallback.
3. This tradeoff should be explicit in UX copy before enabling metadata encryption.

API key issuance/auth changes required:

1. Redefine API key issuance so raw root secret material is never present on the wire.
2. Update auth verification flow and storage schema to use derived auth credentials.
3. If needed, add an internal key-credential format marker for transition logic while keeping API endpoints on `/api/v1`.
4. Because API keys have not been used in production yet, this is a safe time for a one-time breaking redesign before broader adoption.

### Passkey-assisted future option

Passkeys may later act as an additional root/unwrap mechanism, but this should remain a follow-on design item after API-key-root flow is stable.

Important caveats:

- Standard WebAuthn signatures alone do not provide a stable symmetric root secret.
- If we rely on PRF extension support, we need compatibility fallback strategy for browsers/authenticators that do not implement it.
- Therefore passkey-root derivation should be gated behind a concrete cross-browser design doc.

## 9. Testing Strategy

### Test tooling (required)

- `Vitest`: unit + integration + vector tests.
- `Playwright`: browser E2E tests against real running app/server.

### Vitest coverage requirements

1. Coverage thresholds are mandatory and blocking:
   - statements: `90`
   - branches: `85`
   - functions: `90`
   - lines: `90`
2. Thresholds apply to app source under `web/src/**`.
3. Exclusions: `main.tsx`, `features/test/**`, `Icons.tsx`, `Logo.tsx`, `constants.ts`, `types.ts`, test files, `test-setup.ts`.
4. Crypto and lib modules maintain ~100% coverage; frontend component thresholds are relaxed to avoid testing pure markup.
4. Required Vitest suites:
   - URL parse/format
   - envelope validation
   - WebCrypto create/open and claim derivation
   - vector suite covering all `spec/v1/envelope.vectors.json` entries
   - API client behavior and error mapping
   - key UI state transitions using mocked API responses

### Playwright E2E requirements (comprehensive)

Comprehensive means covering all critical user workflows and security-sensitive error paths, not just smoke tests.

Minimum required E2E scenarios:

1. Send plaintext (no passphrase) -> share link generated.
2. Claim/decrypt plaintext from generated share link.
3. Send with passphrase -> wrong passphrase fails -> correct passphrase succeeds (same claimed envelope, no second API claim).
4. File upload send flow -> claim -> download with expected filename/mime behavior.
5. Invalid/missing fragment handling on `/s/:id`.
6. Claimed/expired/invalid-claim-token generic unavailable UX (`404` path).
7. Copy-to-clipboard actions for share link and revealed secret.
8. Responsive sanity checks for mobile and desktop breakpoints.
9. Navigation and route boot correctness for `/` and `/s/:id`.
10. Basic no-regression checks for security-sensitive UI messaging (no leakage of claim-token semantics).
11. Browser matrix execution in CI (at minimum Chromium + WebKit; add Firefox when stable in pipeline).

### Cross-client compatibility tests

1. Browser-created secret claimable via CLI.
2. CLI-created secret claimable via browser.
3. File hint metadata interop (`filename`, `mime`, `type`).

## 10. Operational and Release Plan

1. CI adds web checks:
   - `pnpm -C web check`
   - `pnpm -C web build`
   - `pnpm -C web test:unit --coverage` (Vitest with enforced 100% gate)
   - `pnpm -C web test:e2e` (Playwright)
2. Coverage and E2E failures are release-blocking.
3. Server release pipeline continues embedding `web/dist`.
4. Rollout:
   - canary on `secrt.ca`
   - monitor claim success/error rates and frontend JS error budget
   - full cutover after stability window.

## 11. Risks and Mitigations

1. Crypto drift between CLI and web.
   - Mitigation: vectors as release gate.
2. Browser crypto API inconsistencies.
   - Mitigation: strict compatibility matrix and fallback messaging.
3. Passkey UX complexity.
   - Mitigation: keep accounts out of MVP; ship core send/get first.
4. Over-scoping before real usage data.
   - Mitigation: phase-gated execution with explicit exit criteria.

## 12. Immediate Next Steps

Phase 0 + 1 completed:
- ~~A: route integration (`/` and `/s/:id` app shell)~~ **Done**
- ~~B: WebCrypto envelope module + vector tests~~ **Done**
- ~~C: send UI + create flow~~ **Done**
- ~~D: claim UI + decrypt/reveal/download flow~~ **Done** (passphrase modal, file download, text reveal/copy, error states)
- ~~E: error UX for claim failures~~ **Done** (404, bad fragment, wrong passphrase, network errors)
- ~~F: component test coverage~~ **Done** (299 tests across 24 files)
- ~~G: Vitest coverage gate~~ **Done** (90/85/90/90 thresholds with v8 provider)
- ~~H: Playwright E2E harness~~ **Done** (47 tests: send/claim, file upload, error states, navigation, clipboard, security across Chromium + WebKit + mobile-chrome)
- ~~I: Trust content~~ **Done** (inline HowItWorks disclosure + full `/how-it-works` technical page)

Current priority (ship MVP + prep for Phase 2):
1. **J: CI integration** — add web test jobs to CI pipeline (`pnpm -C web test:coverage`, `pnpm -C web test:e2e`). Requires PostgreSQL service in CI.
2. **K: Cross-client compatibility tests** — verify CLI-created secrets claimable in browser and vice versa. File hint metadata interop (`filename`, `mime`, `type`).
3. **L: Production deploy** — build + embed `web/dist` in server, canary on `secrt.ca`, monitor claim success/error rates.
4. **M: UX polish** — error illustrations, loading skeletons, accessibility audit, SEO meta tags.

After MVP ships:
- Begin Phase 2 backend work (passkey accounts, API key management, secrets dashboard).
