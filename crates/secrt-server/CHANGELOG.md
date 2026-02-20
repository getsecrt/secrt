# Changelog

## 0.14.1 — 2026-02-20

### Added

- **`secrt-admin` env-file auto-loading:** `secrt-admin` now automatically loads environment variables from `/etc/secrt-server/env` (the standard systemd `EnvironmentFile` path), so it works out of the box on deployed hosts without needing to manually export `DATABASE_URL`. A new `--env-file <path>` flag allows overriding the default path for non-standard setups. Existing environment variables are never overwritten.

## 0.14.0 — 2026-02-20

### Added

- **Passkey management endpoints:** `GET /api/v1/auth/passkeys` (list), `POST /api/v1/auth/passkeys/add/start` and `add/finish` (add new passkey), `POST /api/v1/auth/passkeys/{id}/revoke` (revoke), `GET /api/v1/auth/passkeys/{id}` (get/rename). All require session auth.
- **Passkey labels:** passkeys now have a `label` column (migration 004) for user-friendly names. Rename via `PATCH /api/v1/auth/passkeys/{id}`.
- **Display name update:** `PATCH /api/v1/auth/account` updates the user's display name (session auth required).
- **Admin stats and management commands:** `secrt-admin` now supports `stats` (dashboard overview), `secrets stats` (expiry buckets, passphrase breakdown, size stats), `users list` (with resource counts), `users show <id>` (detail view with keys, secrets, passkeys, AMK status), `apikeys list` (optionally filtered by user), and `top-users` (rank users by secrets, bytes, or keys). Both `apikey` and `apikeys` are accepted as top-level commands for backward compatibility. Output is TTY-aware with color.
- **`POST /api/v1/amk/commit` endpoint:** eagerly commits an AMK hash at registration time so other devices can detect that a Notes Key already exists. Uses first-writer-wins semantics — returns 409 if a different AMK hash is already committed, preventing accidental key divergence across browsers.
- **Second-browser AMK conflict detection (web):** the Send page now checks whether the server already has a committed AMK before showing the private-note field. If another device registered the key but this browser hasn't synced it yet, a "Sync your Notes Key" message appears instead of silently generating a conflicting key.
- **Coarse last-active tracking:** new `last_active_at DATE` column on users table (migration 003) records the month of each user's most recent login, rounded to the 1st of the month. Enables stale-account cleanup without compromising privacy.
- **Database migration 004:** adds `label TEXT` column to `passkeys` table.

### Changed

- **Settings page redesign (web):** passkey rename now uses a modal dialog (consistent with other modals in the app). Adding a new passkey prompts for a name immediately. Display name editing is a persistent input instead of an inline toggle. Unnamed passkeys display as "Default".
- **Dashboard polish (web):** date column now shows date and time separately, size column always visible, ID column width responsive, burn confirmation button text simplified.
- **Privacy page, How It Works page, and whitepaper** updated to disclose coarse activity-date tracking.

## 0.13.3 — 2026-02-19

### Added

- **"Share Link" button:** the share result screen now shows a native share button (using the Web Share API) alongside "Copy Link" on supported browsers (mobile Safari, Chrome Android, etc.).
- **Page-specific document titles:** each route now sets a descriptive `<title>` (e.g., "Claim Secret — secrt") so browser tabs, history, and screen readers reflect the current page.
- **Open Graph image for secret pages:** `/s/{id}` pages now include a custom OG image for richer social previews.

### Fixed

- **Web accessibility (WCAG 2.1 AA):** added ARIA menu attributes to Nav dropdowns, `aria-modal` and `aria-label` to modals, `aria-label` to FileDropZone, `aria-checked` to ThemeToggle switch, `aria-live` to CopyButton, `aria-busy` and `aria-describedby` to form submit buttons, `role=radiogroup`/`role=radio` to TTL selector, `aria-hidden` to decorative icons, `role=status` to loading spinners. Added skip-to-content link, semantic `<header>` landmark, and `id` on `<main>`. Restored keyboard access to passphrase visibility toggles.
- **AMK sync to wrong account:** opening a "Sync Notes Key" link while authenticated as a different user silently imported the key into the wrong account. The sender's user ID is now embedded in the encrypted payload metadata and checked on the receiving side. Old sync links without the field remain backward-compatible.
- **OG meta tag copy:** removed trailing exclamation marks from secret page titles and descriptions for a cleaner tone.

## 0.13.2 — 2026-02-19

### Fixed

- **Infinite spinner on auth-gated pages:** direct navigation to `/sync/{id}` or `/device` showed a spinner forever when unauthenticated. A Preact effect ordering race condition caused the login redirect's `PopStateEvent` to fire before the parent route listener was attached. Fixed by deferring the navigation.

## 0.13.1 — 2026-02-19

### Fixed

- **`/sync/{id}` route returns 404:** the SPA route for AMK sync links was defined in the frontend router but missing from the server's Axum router, causing a white screen when scanning sync QR codes on mobile.

### Changed

- **Upgraded web dependencies:** Tailwind CSS 4.2.0, Vitest 4.0, happy-dom 20, Preact 10.28.4.

## 0.13.0 — 2026-02-19

### Added

- **Zero-knowledge encrypted notes:** new `enc_meta` JSONB column on secrets table for client-encrypted note blobs. Server validates structure (version, base64url fields, size limits) but never sees plaintext.
- **AMK wrapper endpoints:** `PUT /api/v1/amk/wrapper` (upsert), `GET /api/v1/amk/wrapper` (retrieve by key prefix), `GET /api/v1/amk/wrappers` (list all for user), `GET /api/v1/amk/exists` (existence check).
- **AMK commitment protocol:** `amk_accounts` table with first-writer-wins semantics (`INSERT ... ON CONFLICT DO NOTHING`) and blinded commitment hash. Returns 409 on commitment mismatch.
- **Per-secret metadata endpoint:** `GET /api/v1/secrets/:id` returns metadata for a single owned secret.
- **Secret metadata update:** `PUT /api/v1/secrets/:id/meta` attaches encrypted metadata to an owned, unexpired secret. Validates `enc_meta.v == 1`, base64url encoding, field lengths (nonce: 12 bytes, salt: 32 bytes, ciphertext: max 8 KiB).
- **Database migration 002:** `amk_accounts` and `amk_wrappers` tables with cascading foreign keys.
- **Feature flag:** `ENCRYPTED_NOTES_ENABLED` env var (default: `true`) gates all AMK/enc_meta endpoints via `require_encrypted_notes()` middleware.
- **Server info features:** `/api/v1/info` response now includes `features.encrypted_notes` boolean.
- **`AmkStore` trait:** storage abstraction for AMK operations with `PgStore` and `MemStore` implementations.

### Changed

- **Quota calculations:** `enc_meta` size now counted alongside envelope size in per-owner byte quota enforcement.
- **`SecretSummary`:** now includes optional `enc_meta` field in list and single-secret responses.
- **`/sync/:id` route:** new SPA route served by the frontend for AMK sync links.

### Fixed

- **Device auth approval flow:** browser approval now shows a confirmation screen before sending the device approval, preventing accidental approvals.

## 0.12.2 — 2026-02-19

### Changed

- **Release pipeline:** server releases no longer claim GitHub's repo-wide "latest" tag (`make_latest: false`), ensuring `/releases/latest/download/` URLs always resolve to CLI assets.
- **Download links:** web frontend download menu updated to point to new archive filenames (`.zip`/`.tar.gz`).

## 0.12.1 — 2026-02-18

### Changed

- **Nav bar "More Information" menu:** grouped How it Works, Privacy Policy, Security Policy, and GitHub Repo into a dropdown; reorganized mobile menu with grouped sections and moved login link to the top.
- **iPhone PWA safe area insets:** added `viewport-fit=cover`, nav top padding, and footer bottom padding so content clears the Dynamic Island and home indicator in standalone mode.
- **Footer layout:** reordered to show navigation links first, then GitHub icon and copyright. Footer links use new `link-subtle` style.
- **Privacy page polish:** title-cased headings, punctuated list items, simplified "Home" back-link.
- **How it Works subtitle:** simplified to "An overview of our zero-knowledge architecture."
- **SECURITY.md:** formatting cleanup; removed redundant "Supported Versions" table.
- **Login/register redirect:** login and register pages now preserve a `?redirect=` query parameter, returning the user to their original destination (e.g., `/device`) after authentication.

### Fixed

- **API key owner key resolution:** list, checksum, and burn endpoints now resolve the full owner key set (`user:{id}` + all `apikey:{prefix}`) when an API key is linked to a user account, matching session auth behavior. Secrets created via web UI are now visible from CLI and vice versa.
- **CLI-created secret ownership:** secrets created via API key linked to a user are now owned under `user:{id}` for consistency with session-created secrets.
- **QR code spacing:** added top margin to the QR code on the share result page.
- **PWA meta tag:** corrected `apple-mobile-web-app-capable` to the standard `mobile-web-app-capable`.
- **PWA e2e test:** updated selector to match the corrected meta tag name.

## 0.12.0 — 2026-02-18

### Added

- **QR code on share result:** after sending a secret, the web frontend now displays a scannable QR code of the share URL using [`uqr`](https://github.com/unjs/uqr) (~8 kB gzipped, zero dependencies). Adapts to light and dark mode. Only bundled on the sender path.
- **Privacy policy page:** `/privacy` SPA route serving the privacy policy; server routes `/privacy` to the SPA `index.html`.
- **`/.well-known/security.txt`:** security contact endpoint per [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) — includes `Contact`, `Expires`, `Canonical`, and `Policy` fields. Cached for 24 hours.
- **Device authorization endpoints:** three new endpoints for CLI device-auth flow:
  - `POST /api/v1/auth/device/start` — generates device code + user code, stores challenge (10-min expiry, IP rate-limited).
  - `POST /api/v1/auth/device/poll` — checks challenge status; returns `complete` with API key prefix on approval.
  - `POST /api/v1/auth/device/approve` — session-authenticated endpoint that creates an API key and marks the challenge as approved.
- **Device approval page:** `/device?code=XXXX-XXXX` SPA route with user code confirmation, approve/cancel buttons, and success/error states. Requires authenticated session (redirects to login if needed).
- **Storage trait extensions:** `get_challenge`, `update_challenge_json`, and `find_device_challenge_by_user_code` methods on `AuthStore` for non-destructive challenge reads and user-code lookup.

## 0.11.0 — 2026-02-17

### Changed

- **Web passphrase crypto:** embedded frontend now uses Argon2id for passphrase KDF in the v1 envelope flow.
- **Lazy-loading behavior:** Argon2id (`hash-wasm`) is loaded only when passphrase handling is needed (input interaction or passphrase-required claim path).
- **Passphrase UX hardening:** passphrase claim flow now surfaces explicit Argon2 module load failures instead of silent retries.
- **Docs copy updates:** trust/how-it-works and related web-facing docs now reflect Argon2id-based passphrase protection.

## 0.10.3 — 2026-02-16

### Added

- **PWA support:** service worker (`sw.js`) with network-only fetch strategy for installability without offline caching; web app manifest with maskable icon; `registerServiceWorker()` helper that registers in production only.
- **PWA meta tags:** `<meta name="theme-color">` with light/dark media queries, `apple-mobile-web-app-capable`, and `apple-mobile-web-app-status-bar-style` for iOS standalone mode.
- **Service worker routing:** dedicated `/sw.js` route with `Service-Worker-Allowed: /` header and `no-store` cache control; `site.webmanifest` also served with `no-store`.
- **PWA tests:** vitest unit tests for service worker registration (4 tests covering all branches); Playwright e2e tests for manifest validation, icon reachability, meta tags, and service worker presence.

### Changed

- **Code formatting:** applied Prettier across all web source files for consistent style.

## 0.10.2 — 2026-02-16

### Added

- **Shared Modal component:** replaced hand-rolled modal markup with a native `<dialog>`-based `Modal` component with focus trap, backdrop click dismiss, and optional form mode.
- **Modal open/close animations:** backdrop fades in first, then card scales up with a staggered delay; reverse on close using CSS `@starting-style` and `transition-behavior: allow-discrete`.
- **Modal shadow theme token:** added `--shadow-modal` with dark-mode-aware values, applied via `var()` to ensure runtime theme switching.
- **CardHeading component:** reusable card heading with optional icon, subtitle (supports `\n`), underline, and custom class props.

### Changed

- **Claim page modal consolidation:** collapsed three separate modals (spinner, confirm, passphrase) into a single modal that switches content based on claim state; "View Secret" button now shows inline loading state instead of a spinner overlay.
- **Modal centering:** fixed horizontal centering (`w-full h-full` to override native `<dialog>` `fit-content`) and switched to upper-biased vertical positioning with `clamp()` padding.
- **Passphrase retry UX:** input is now auto-focused and text selected on wrong passphrase, so the user can immediately retype.
- **CopyButton styling:** updated default button style to primary with uppercase tracking.
- **Page heading consistency:** send page, settings page, and password generator modal now use `CardHeading` for consistent heading style.
- **How-it-Works page refresh:** updated layout, headings, and copy.

### Fixed

- **HMR double-mount:** `main.tsx` now clears the root element before rendering to prevent duplicate component trees during Vite hot-reload.
- **iOS Safari auto-zoom:** dropped explicit text size from password preview input to prevent unwanted zoom.

## 0.10.1 — 2026-02-16

### Changed

- **How-it-Works page simplification:** moved FAQ content into the page and rendered the technical overview/FAQ/whitepaper as static sections.
- **Send page disclosure polish:** replaced the old disclosure block with a simplified bottom "How secrt Works →" link and refreshed send form heading copy.
- **UI polish adjustments:** refined login/settings/trust-page styling to align spacing, typography, and control placement.

### Fixed

- **E2E navigation maintenance:** updated Playwright navigation assertions to match current How-it-Works and send-page link labels.

## 0.10.0 — 2026-02-16

### Added

- **Homepage password generator:** send form now supports one-click password generation and copy-to-clipboard.
- **Configurable generator modal:** users can tune password length and grouped generation, preview results, and edit them before sending.
- **Persistent generator preferences:** password length and grouping preferences now persist in browser localStorage across reloads.
- **Frontend regression coverage:** expanded send-page tests for generator settings, persistence, modal controls, and sync behavior.

### Changed

- **Responsive generate label:** send page now shows “Generate” on very narrow widths and “Generate a Password” from the new `xs` breakpoint (`440px`) upward.
- **Generator modal controls:** close interactions now support top-right X, background click, escape key, and footer close action.

## 0.9.1 — 2026-02-15

### Added

- **Claim confirmation screen:** visitors now see a "Someone Sent You a Secret" dialog and must click "View Secret" before the secret is claimed and destroyed, preventing accidental one-time secret consumption.
- **Auto-sizing secret textarea:** decrypted text is displayed in a readonly textarea that auto-sizes to content (with a 256 px max), replacing the fixed-height display.

### Changed

- **Frontend layout and styling refresh:** polished card layouts, spacing, and typography across the web UI.
- **GitHub link moved to CLI Downloads menu:** consolidated external links into the downloads popover.

### Fixed

- **SPA scroll-to-top on navigation:** clicking links no longer leaves you at the previous scroll position; pages scroll to top on every navigation.
- **Semantic HTML for navigation links:** dashboard "Send a New Secret" and "API Keys & Account Settings" are now proper `<a>` elements instead of buttons styled as links, improving accessibility and right-click behavior.
- **Send page copy:** simplified the intro text for clarity.
- **E2E test maintenance:** updated stale disclosure text and added claim confirmation step to dashboard burn test.

## 0.9.0 — 2026-02-14

### Added

- **Secrets check endpoint:** `GET /api/v1/secrets/check` returns count + opaque checksum for lightweight dashboard polling without refetching full metadata.
- **Dashboard live polling:** dashboard polls the check endpoint every 4 seconds and auto-refreshes on changes.

### Changed

- **Settings page redesign:** centered headings, clearer API key creation success state, destructive-subtle button style for revoke, polished delete-account confirmation flow.
- **Dashboard page size:** increased from 5 to 10 secrets per page.
- **Popover positioning:** user menu and burn confirmation popovers now use `useLayoutEffect` to prevent position flash on mount.
- **Shared UI components:** added `btn-destructive-subtle` and `code` utility classes.
- **v1 spec updates:** documented session auth, list/check endpoints, API key list/revoke, account deletion, and owner key types.

## 0.8.0 — 2026-02-14

### Added

- **Dashboard page:** authenticated users can view their secrets with status, expiry, and burn controls.
- **Settings page:** account management with display name editing and account deletion.
- **Open Graph and Twitter Card meta tags** for rich link previews when sharing secrt.ca URLs.

### Changed

- **Nav bar overhaul:** popover user menu with avatar, display name, dashboard/settings links, and logout.
- **Session token auth for secret creation:** authenticated web users can now create secrets using their session token (not just API keys).

### Fixed

- **Friendly passkey login errors:** "unknown credential" server errors now show a user-friendly explanation instead of the raw error string.
- **OG tags in fallback HTML:** secret pages now include proper Open Graph meta tags even when no SPA frontend is built, fixing CI test failures and ensuring social previews work in all configurations.

## 0.7.0 — 2026-02-14

### Added

- **Technical whitepaper** documenting cryptographic architecture, zero-knowledge design, abuse prevention, and FAQ.
- **Font Awesome icons** across nav and auth UI.
- **Passkey icon** SVG asset for auth pages.

### Changed

- **User identity storage hardening:** user IDs are now server-generated UUIDv7 values, and all auth-linked `user_id` foreign keys are UUID-typed.
- **Auth/session response privacy:** `user_id` is no longer returned by passkey `register/finish`, `login/finish`, or `GET /api/v1/auth/session` responses.
- **Registration page overhaul:** auto-generated privacy-friendly display names, polished passkey flow.
- **Nav and login UI polish:** updated styling, icon integration, responsive improvements.
- **Spec updates:** API and server spec amendments for UUID user IDs and session privacy.

### Fixed

- **SPA serving:** `/`, `/s/{id}`, `/login`, `/register`, and `/how-it-works` now serve the Preact SPA `index.html` instead of the old placeholder page. Falls back to the placeholder when no frontend is built.

## 0.6.1 — 2026-02-13

### Fixed

- **Static web bundle routing:** frontend bundles now load from `/static/assets/*` (instead of root `/assets/*`), aligning Vite output with server static routing.
- **No-side-effects CLI flags:** `secrt-server --version` and `secrt-server --help` now exit before config, DB connection, and migration startup paths.

## 0.6.0 — 2026-02-13

### Added

- **Passkey auth/session endpoints:** `register/start`, `register/finish`, `login/start`, `login/finish`, `auth/session`, and `auth/logout` with 24h bearer sessions (`uss_<sid>.<secret>`).
- **API-key registration endpoint:** `POST /api/v1/apikeys/register` requiring session auth.
- **Registration controls:** configurable account/IP quotas (`5/hour`, `20/day` defaults) and registration limiter settings.
- **Auth schema expansion:** new DB tables for users, passkeys, sessions, challenges, and API-key registration events.

### Changed

- **Breaking API-key auth format:** authenticated routes now accept only `ak2_<prefix>.<auth_b64>`; legacy `sk_` auth is removed.
- **Verifier contract update:** API key hashes now use structured v2 verifier input (`"secrt-apikey-v2-verifier" || u16be(prefix_len) || prefix || auth_token_bytes`).
- **Atomic registration write path:** quota checks + API-key insert + registration event insert execute in one transaction.
- **Admin CLI surface:** removed `secrt-admin apikey create`; kept `secrt-admin apikey revoke <prefix>`.
- **Envelope privacy contract alignment:** runtime/spec now explicitly treat all metadata as encrypted payload content; plaintext metadata fields are not part of the accepted envelope contract.
- **Legacy envelope compatibility policy:** 0.6.0 documents a hard-cut expectation for sealed-payload envelopes; compatibility with prior envelope internals is intentionally out of scope.
- **Compression policy visibility:** docs now reflect client-side compression defaults (`threshold=2048`, `min_savings=64`, `min_savings_ratio=10%`, `zstd level=3`, decode cap `100 MiB`).
- **OpenAPI/API text alignment:** server-facing contract docs now explicitly describe envelope JSON as opaque ciphertext metadata, with advisory metadata accessible only client-side after decrypt.

## 0.5.2 — 2026-02-12

### Added

- **Branded landing page:** Homepage now shows the secrt logo with light/dark mode support, explains zero-knowledge encryption, and links to CLI downloads. HTML moved from inline Rust to a `templates/index.html` file loaded via `include_str!`.

## 0.5.1 — 2026-02-12

### Fixed

- **Database error logging:** Storage errors now include the full error source chain instead of a truncated "db error" message. Root causes like connection failures, auth errors, and missing tables are now visible in logs.

## 0.5.0 — 2026-02-12

### Added

- **Embedded web assets:** Frontend is compiled into the server binary via `rust-embed`. No filesystem dependency for static files in production.
- **Static file fallback chain:** `SECRT_WEB_DIST_DIR` env var (dev override) → embedded assets (production) → filesystem `web/dist` (fallback).
- **Release workflow:** GitHub Actions workflow triggered by `server/v*` tags. Builds web frontend, cross-compiles Linux amd64/arm64 musl binaries, and publishes GitHub Release with checksums.

## 0.4.0 — 2026-02-11

### Added

- **Full Rust rewrite** of the legacy Go server, achieving complete feature and test parity.
- **Axum HTTP server** with structured JSON logging via `tracing`.
- **Postgres storage** with `deadpool-postgres` connection pooling and atomic claim-and-delete.
- **API key authentication** with HMAC-SHA256 hashing and pepper.
- **Per-IP and per-key rate limiting** with configurable rates and bursts.
- **Per-owner storage quotas** — max secrets and max total bytes per owner tier (public/authenticated).
- **Secret reaper** — background task that deletes expired secrets on a configurable interval.
- **Admin CLI** (`secrt-admin`) — API key management (create, revoke, list).
- **Privacy-aware logging** — `X-Privacy-Log` header check, IP hashing for owner keys, truncated IP support.
- **Security headers** — `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options` on all responses; `X-Robots-Tag` on `/s/{id}` route.
- **Request middleware** — request ID generation, timing, cache-control defaults.
- **Placeholder HTML pages** for `/` and `/s/{id}` routes.
- **`/healthz` endpoint** for health checks.
- **`/robots.txt`** returning `Disallow: /`.
- **CI coverage gate** at 90% line coverage with legacy parity checks.
