# Changelog

## Unreleased

## 0.17.7 — 2026-05-09

### Security

- **Layered defense against malicious / API-compatible secrt forks (web + Tauri side).**

  No server runtime behavior changed in this release; the work below is a coordinated frontend / desktop / spec contribution to the same defense. The CLI side is documented in detail in `crates/secrt-cli/CHANGELOG.md` for the same release.

  - **Web SPA — Get-Secret unknown-host warning strengthened.** The inline error that fires when a user pastes a share / sync URL for an unknown host now names the threat (logged secrets, stolen secrets, page tampering exfiltrating the URL key) instead of the prior meek "open it directly if you trust it." Files: `web/src/features/send/SendPage.tsx`.

  - **Web SPA — Subresource Integrity on the production bundle.** A hand-rolled Vite plugin (`web/vite-plugins/sri.ts`) injects `integrity="sha384-…"` and `crossorigin="anonymous"` on every external `<script src>` and `<link rel="stylesheet"|"modulepreload">` in `dist/index.html`. Defends against asset tampering when the HTML itself is trusted: CDN compromise, partial server compromise where `dist/assets/*.js` is overwritten but `index.html` isn't, or a compromised proxy modifying JS in flight. *Not* a rogue-instance defense — a malicious server controls `index.html` and could strip `integrity=`.

  - **Tauri CSP widened to all official instances.** `crates/secrt-desktop/tauri.conf.json` `connect-src` now lists every origin in `secrt_core::KNOWN_INSTANCES` (was hardcoded to `https://secrt.ca` only). A drift test in `crates/secrt-desktop/tests/csp_drift.rs` parses the config and fails if a new instance is added to the spec without widening the desktop CSP. Self-host Tauri support (runtime base-URL config, dynamic CSP) is intentionally deferred.

  - **`secrt_core::instance` module + spec contract.** New `KNOWN_INSTANCES` constant and `TrustDecision` enum (`Official` / `TrustedCustom` / `DevLocal` / `Untrusted`), shared between Rust and TypeScript. Spec: `spec/v1/instances.md` and `spec/v1/instances.json` (machine-readable apex / origin / hosting / security_contact for `secrt.ca` and `secrt.is`). Both Rust and TS test suites pin their lists to the JSON so they can't drift.

  - **Token-replace survival test.** `crates/secrt-server/tests/sri_survives_token_replace.rs` asserts that the server's `__PUBLIC_BASE_URL__` substitution (`assets.rs::spa_index_html_with_base`) and the secret-page meta-tag rewrite chain (`http/mod.rs::handle_secret_page`) preserve `integrity=` attributes on bundled `<script>` and `<link>` tags. Synthetic fixture, so it doesn't depend on `web/dist` being populated in CI.

  CI: `.github/workflows/ci.yml` `frontend` job now runs `pnpm build` and a gated `pnpm test:sri` after the regular vitest pass, so the integrity values in `dist/index.html` are verified against the actual on-disk asset bytes on every CI run.

## 0.17.5 — 2026-05-02

### Added

- **Client-side diagnostic logging for AMK / PRF flows in the web client.**

  Replaces the silent `} catch {}` blocks in passkey registration, login, settings add-passkey, and the PRF unwrap / upgrade / fallback-ceremony paths with structured `[secrt:<label>]` console traces. Disabled by default in production; opt-in via DevTools.

  - **Gating:** dev builds always log (`import.meta.env.DEV`); prod builds only when `localStorage.setItem('secrt:debug', '1')` is set. No data leaves the device — no telemetry, no remote collection.
  - **What's logged:** decision branches (which `if` arm fired), 8-byte SHA-256 fingerprints of PRF outputs and AMK material (sufficient for cross-device determinism checks; not invertible), WebAuthn `authenticatorAttachment` (`'platform'` vs `'cross-platform'`).
  - **Labels:** `webauthn-create`, `webauthn-get`, `prf-register-wrap`, `prf-unwrap`, `prf-upgrade`, `prf-settings-wrap`, `prf-fallback-ceremony`, `amk-store`, `amk-transfer-tauri`.

  Direct payoff: the 2026-05-01 spike captured the first concrete confirmation that **macOS Safari** (not just iOS) re-wraps `hmac-secret` for external authenticators — different PRF output for the same YubiKey credential on the same Mac depending on browser.

  See `crates/secrt-server/docs/prf-cross-device-testing.md` and `prf-amk-wrapping.md` §11.

## 0.17.4 — 2026-04-28

### Added

- **Structured info logs on the three passkey `/finish` paths.**

  `passkey_registered`, `passkey_added`, and `passkey_login` events now carry `user_id`, an 8-char `cred_id_prefix`, and PRF state (`prf=on/off`, `prf_wrapper=true/false`, `prf_upgrade=true/false`).

  Lets you correlate a request with its `passkeys` table row without grepping HTTP logs for the follow-up `/prf-wrapper` PUT. The `credential_id` is a public WebAuthn handle, not sensitive — only the prefix is logged to keep lines short.

## 0.17.3 — 2026-04-28

### Fixed

- **iCloud Keychain (and other counter-less authenticators) no longer 401 after the first sign-in.**

  The verifier rejected any assertion whose `signCount` was less than or equal to the stored value — a strict reading of W3C WebAuthn §6.1.1, but synced-passkey providers (Apple iCloud Keychain, several FIDO2 keys) emit `signCount = 0` on every assertion and are effectively counter-less. Once the stored count went positive, every subsequent iCloud login on the same credential was rejected as a cloned-authenticator signal.

  The verifier now treats `signCount = 0` as "no counter available": it accepts the assertion, persists `max(stored, new)`, and only fires `SignCountRegressed` when both stored and incoming counts are positive and the incoming value has stalled or gone backwards.

  New spec vector `login_sign_count_zero_synced_passkey` locks the behaviour in.

  Spec: `spec/v1/server.md` §6.2 (login finish step 6).

## 0.17.2 — 2026-04-28

### Added

- **Per-IP rate limiter on the unauthenticated passkey ceremony /start endpoints.**

  `/api/v1/auth/passkeys/register/start` and `/api/v1/auth/passkeys/login/start` now share a `passkey_ceremony_limiter` (defaults: 0.5 rps, burst 6 — `PASSKEY_CEREMONY_RATE` / `PASSKEY_CEREMONY_BURST`).

  Each call inserts a `webauthn_challenges` row with a 10-minute TTL; without this gate, an attacker could spam-fill the table even if no challenge ever progressed to /finish.

  Tests: `crates/secrt-server/tests/api_auth_passkeys.rs::passkey_{login,register}_start_is_rate_limited`.

## 0.17.1 — 2026-04-28

### Changed

- **Single-prompt passkey login.**

  `POST /api/v1/auth/passkeys/login/start` now accepts an empty body — `credential_id` is an optional advisory hint, no longer required. The web frontend uses this discoverable-credential flow to do a single `navigator.credentials.get()` against the server's challenge instead of two (one for the picker, one bound to the server challenge).

  The previous two-call flow forced iCloud Passwords users through the macOS account-password prompt twice on every login. The credential binding is now established solely by the assertion's signature in `/login/finish`.

  Spec: `spec/v1/server.md` §6.2 (login start), `spec/v1/api.md`.

## 0.17.0 — 2026-04-28

A coherent passkey-verification cutover. Wire format breaks for passkeys; existing passkey rows must be wiped via `secrt-admin reset` before deploying. See `Removed` notes below.

### Changed

- **WebAuthn assertion verification now enforced on all passkey `/finish` endpoints.**

  Register, add-passkey, and login finish handlers reject any assertion whose ECDSA signature, `rpIdHash`, `clientDataJSON.{type,challenge,origin}`, UP flag, or sign-count monotonicity does not check out. Failures map to opaque `401 unauthorized` (the discriminator is logged server-side, never returned).

  Implementation: pure-function verifier in `crates/secrt-server/src/domain/webauthn.rs`, exercised against `spec/v1/webauthn.vectors.json`. Fixtures generated by an independent Python reference (`scripts/generate_webauthn_vectors.py`), so passing the vectors is the actual correctness signal — not ring-against-ring self-consistency.

  Spec: `spec/v1/server.md` §6.2 (new), `spec/v1/api.md` "Passkey Registration and Login".

- **Passkey `/finish` wire shape replaces `public_key: String` with `authenticator_data` and `client_data_json` (and `signature` for login).**

  All three endpoints take base64url-encoded WebAuthn fields the browser already produces. Greenfield wire-format change — no `MIN_SUPPORTED_CLI_VERSION` bump because the CLI does not exercise passkey endpoints.

  Existing passkey rows in any pre-0.17 database carry placeholder `public_key` values and will not parse. Wipe them with `secrt-admin reset` before deploying.

### Added

- **ES256 / EC2-P256 only at MVP.**

  `kty=2`, `alg=-7`, `crv=1` is the only accepted COSE_Key shape. RS256 and other curves are rejected with `UnsupportedCoseAlgorithm`. Covers Apple, Google, Windows Hello (when configured for ES256), 1Password, and Bitwarden authenticators. Adding RS256 is mechanical and gated on a real-user request.

- **`secrt-admin reset` subcommand.**

  Destructive interactive command that `TRUNCATE … RESTART IDENTITY CASCADE`s every data table (passkeys, sessions, users, secrets, AMK + PRF wrappers, API keys, challenges).

  Operator must type `RESET <apex>` where `<apex>` is the host derived from `public_base_url` — a wrong-host wipe is blocked by the typed-confirmation check. No skip flag; intentionally interactive. Intended for the v0.17.0 cutover so old passkey rows don't survive into the verification regime.

## 0.16.9 — 2026-04-27

### Added

- **PRF upgrade path for pre-PRF credentials.**

  `POST /api/v1/auth/passkeys/login/finish` now accepts an optional `prf` field describing the assertion's PRF capability. When the assertion reports PRF support and the credential row predates PRF (`cred_salt = NULL`), the server stamps the row with a fresh 32-byte salt and returns it as `prf_cred_salt` so the client can wrap+PUT on this very login.

  When the row is already PRF-capable but has no wrapper, the existing salt is returned without overwriting. Pre-PRF credentials registered before 0.16.8 are now retrofitted transparently on the next sign-in from a PRF-capable browser.

  Spec: `spec/v1/api.md` §"Transport D — Upgrade path for pre-PRF credentials".

- **Add-passkey PRF wiring.**

  `POST /api/v1/auth/passkeys/add/finish` now accepts the same `prf` field and returns `prf_cred_salt` when supported, mirroring register-finish. Credentials added from Settings are PRF-enabled at create time without needing an upgrade round-trip.

- **`prf_supported` on `PasskeyItem` list responses.**

  Surfaces in the Settings UI as a "Sign-in only" warning badge for credentials that don't support one-tap notes-key unlock on new devices.

### Fixed

- **CSP integration test no longer asserts on a build artifact.**

  `html_responses_carry_csp_and_no_store` previously required `web/dist` to exist (so `csp_value()` could compute hashes from inline scripts in the served `index.html`). Without `web/dist` the embedded fallback template has zero inline scripts, no `'sha256-…'` source emitted, and the assertion failed.

  The same property is unit-tested in `crates/secrt-server/src/http/security.rs` against fixture HTML, so the integration assertion was duplicated coverage that happened to be the only thing in CI requiring a frontend build. Drops the duplicate; CI is green again on all three OSes without paying ~30s × 3 to build the frontend before Rust tests.

## 0.16.8 — 2026-04-27

Beta release of WebAuthn PRF AMK wrapping. Not all PRF-capable providers forward the extension yet — Bitwarden and 1Password silently drop it as of April 2026, and those users continue to use the existing sync-link flow on new devices. Passkey `/finish` endpoints still ride on the existing `challenge_id` bearer flow; full WebAuthn signature verification is tracked as a follow-up. The CLI does not yet exercise PRF; this round is browser-only.

### Added

- **WebAuthn PRF AMK wrapping (Transport D, beta).**

  Browsers whose passkey provider forwards the WebAuthn PRF extension (Apple Passwords / iCloud, Google Password Manager, Windows Hello, Firefox 148+) can now derive an AES wrap key from the authenticator and unwrap their AMK in one tap on a fresh device, replacing the sync-link round-trip.

  - Register-finish accepts an optional `prf` field describing the assertion's PRF state and returns a server-generated `prf_cred_salt` when supported.
  - Login-finish returns a `prf_wrapper` inline when one exists for that credential.
  - New `PUT/DELETE /api/v1/auth/passkeys/{cred_id}/prf-wrapper` endpoints store and revoke wrappers. Wrappers cascade-delete on `revoke_passkey`.
  - AAD slot generalized via `binding_id` (formerly `key_prefix`) so the same wrap-AAD shape works for Transport A (passphrase), C (recovery), and D (PRF).

- **Migration `005_prf_amk_wrappers.sql`.**

  New `prf_amk_wrappers` table (one row per credential, FK to `passkeys`); new `prf_supported`, `prf_cred_salt`, `prf_first_seen_at` columns on `passkeys`. Added to the `MIGRATIONS` array so it runs on startup.

## 0.16.7 — 2026-04-27

### Fixed

- **`Cache-Control: immutable` no longer applied to non-content-hashed static assets.**

  `crates/secrt-server/src/assets.rs` previously sent `public, max-age=31536000, immutable` for *every* file under `/static/*`, including stable-URL files like `favicon.svg`, `apple-touch-icon.png`, `og-image.png`, and the maskable manifest icon. `immutable` is only safe for filenames whose URL changes when content changes (Vite's content-hashed bundles in `assets/`); applying it to stable-URL files locks browsers to whatever they fetched first, so any future favicon/og-image update is undeployable until each user clears cache.

  Now: `assets/*` keeps the immutable forever-cache, everything else gets `public, max-age=86400` (1 day).

- **Renamed `favicon.svg` → `favicon-light.svg` to bust the iOS-cached old version.**

  The 0.16.5 → 0.16.6 patch removed an inline `<style>` block from `favicon.svg`, but the broken cache-control sent by 0.16.4 / 0.16.5 had already locked iOS Safari into "year-immutable" caching of the *old* bytes — which still triggered a `style-src` CSP violation each page load even after the server-side fix was deployed.

  Cache invalidation by URL change. Future favicon tweaks deploy cleanly thanks to the cache-control fix above.

### Changed

- **Mobile nav logo is now a link to the homepage when the user isn't already on `/`.**

  On the home route the logo renders as plain decoration so the click is suppressed (avoids a no-op router round-trip). Universal-pattern UX expectation; previously the small-breakpoint logo was non-interactive.

## 0.16.6 — 2026-04-27

### Fixed

- **Favicon CSP violation on iOS Safari.**

  `web/public/favicon.svg` contained an inline `<style>` block that swapped path fills under `prefers-color-scheme: dark`. iOS Safari subjects SVG-internal styles loaded via `<link rel="icon">` to the parent document's `style-src`, so the strict CSP shipped in 0.16.5 blocked the inline style and Safari fell back to rendering `apple-touch-icon.png` (the white-rounded-rect treatment) instead of the SVG.

  Drop the inline style and replace with two static SVG variants.

### Changed

- **Responsive favicon now uses two static SVG files via `media` queries on `<link rel="icon">`** instead of an inline SVG `<style>`.

  `web/public/favicon.svg` is now the light variant; `web/public/favicon-dark.svg` is new and contains the same paths with the two `fill` colours swapped. `web/index.html` references both with `media="(prefers-color-scheme: dark)"` and `media="(prefers-color-scheme: light)"`.

  Browser-specific behaviour:

  - **Chrome / Edge** honour the `media` query and swap correctly.
  - **Firefox** doesn't honour `media` on `<link rel="icon">` (longstanding open bug) and falls back to the last `<link rel="icon">` in source order. The dark variant is listed first and the light variant last so Firefox users always see the higher-contrast light variant.
  - **Safari** behaviour for `media` on `<link rel="icon">` is empirically uncertain and is the open question this release is meant to test.

### Performance

- **`touch-action: manipulation` on the mobile hamburger button.**

  Tells iOS Safari the element is for tap only, skipping the gesture-recognition wait that can otherwise add up to 300ms before the click event fires. Defensive change — small, free win on every mobile interaction.

## 0.16.5 — 2026-04-27

### Security

- **CSP flipped from Report-Only to enforcing.**

  After a clean cross-browser soak (Chrome / Safari / Firefox / iOS Safari) of the strict policy shipped in 0.16.4 as `Content-Security-Policy-Report-Only`, the policy now ships as the enforcing `Content-Security-Policy` header. Browsers will block, not just report, any future violation.

  Same directives as the 0.16.4 Report-Only policy plus `upgrade-insecure-requests` folded back in:

  ```
  default-src 'none'; script-src 'self' 'wasm-unsafe-eval' 'sha256-…';
  style-src 'self'; img-src 'self' data: blob:; font-src 'self';
  connect-src 'self'; manifest-src 'self'; worker-src 'self';
  form-action 'none'; base-uri 'none'; frame-ancestors 'none';
  object-src 'none'; upgrade-insecure-requests
  ```

- **`upgrade-insecure-requests` folded back into the main CSP**, dropping the previously-separate enforcing header. Single CSP header per HTML response now.

### Changed

- **Web SPA refactored to drop all CSSOM `el.style.x = y` writes.**

  iOS Safari was reporting CSSOM mutations as `style-src` violations under the strict policy. Six call sites refactored to native CSS:

  - Legacy `execCommand('copy')` clipboard fallback removed entirely (Clipboard API has been universal since 2018-2020).
  - ClaimPage textarea Safari-fallback effect removed in favour of native `field-sizing: content` (Safari 17.4+).
  - QR canvas display sizing moved to the `size-48` Tailwind class.
  - `BurnPopover` and three Nav menus (`UserMenu`, `DownloadsMenu`, `MoreInfoMenu`) now position via CSS Anchor Positioning (`anchor-name` / `position-anchor` / `anchor()` / `anchor-size()` / `position-try-fallbacks: flip-block`), eliminating ~20 inline-style writes and the associated `getBoundingClientRect` measurements.

  Net diff: ~−145 lines across the web SPA.

### Fixed

- **`navigator.clipboard.writeText()` from a form inside a `Modal`.**

  Removing `method="dialog"` from the Modal component's inner form. The dialog-submit semantics consumed the user-gesture activation flag at submit-event dispatch time, even when `e.preventDefault()` was called — so the await chain to `writeText` saw no active activation and silently rejected.

  Most visible victim: the password-generator modal's "Generate & copy" button on Safari desktop and iOS. All three `asForm` Modal callers (`SendPage`, `SettingsPage`, `ClaimPage`) already call `preventDefault` in their submit handlers, so the implicit dialog-close was never load-bearing.

## 0.16.4 — 2026-04-26

Strict CSP shipped in Report-Only mode (will enforce in 0.16.5), plus a sweep of always-on hardening headers.

### Added

- **"About secrt" entry in the More Information menu.**

  The `/about` page existed but had no nav entry point, making it functionally invisible. Now appears in both the desktop dropdown and the mobile menu group, between "Privacy Policy" and the external links. Uses a new `CircleInfoIcon`. The menu trigger now also highlights when on `/about`.

### Security

- **Strict Content-Security-Policy on HTML responses, shipped as Report-Only.**

  A new `crates/secrt-server/src/http/security.rs` module computes the policy once at server startup by SHA-256-hashing every inline `<script>` in the embedded `index.html` and emitting the hashes as `'sha256-…'` sources in `script-src` — so the CSP is strict (no `'unsafe-inline'`) without any build-time hash bookkeeping.

  Initial policy:

  ```
  default-src 'none'; script-src 'self' 'wasm-unsafe-eval' 'sha256-…';
  style-src 'self'; img-src 'self' data: blob:; font-src 'self';
  connect-src 'self'; manifest-src 'self'; worker-src 'self';
  form-action 'none'; base-uri 'none'; frame-ancestors 'none';
  object-src 'none'
  ```

  Ships as `Content-Security-Policy-Report-Only` for one release so any unanticipated violations surface in the browser console without breaking flows; will flip to enforcing in a follow-up patch. `'wasm-unsafe-eval'` is the CSP3-narrow source needed by Argon2's WebAssembly module — it allows WASM compilation but not JS `eval()`/`Function()`/`setTimeout(string)`.

- **`Content-Security-Policy: upgrade-insecure-requests` (enforcing) on HTML responses.**

  Transforming directive that has no Report-Only semantics (browsers warn and ignore it there), so it ships as its own enforcing header. Rewrites `http://` subresource URLs to `https://`; localhost is exempt per spec.

- **`Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, and `Permissions-Policy` lockdown.**

  The `Permissions-Policy` denies camera, geolocation, microphone, payment, USB, sensors, and `interest-cohort`. Always-on browser-hardening headers that close cross-origin window/document attack surface and deny access to sensor/payment APIs the app never uses. Defense-in-depth — small attack-surface reduction at zero runtime cost.

- **`Cache-Control: no-store` on every HTML response.**

  Prevents the browser/disk cache from resurrecting the SPA shell (and especially the claim page) after navigation. Content-hashed JS/CSS bundles still cache forever via existing `assets.rs` rules; only the HTML doc is no-stored.

- **Drift-guard test (`embedded_index_csp_covers_every_inline_script`)** in `http/security.rs` re-extracts every inline `<script>` from the served `index.html`, recomputes its hash, and asserts each appears in the live `csp_value()`. If anyone adds a new inline script, the test fails until the CSP regenerates (which it does automatically on next server start).

### Changed

- **`web/src/main.tsx` uses `replaceChildren()` instead of `innerHTML = ''` for HMR pre-mount cleanup.**

  Functionally identical — both clear all children — but the explicit DOM call removes the only `innerHTML` write in the codebase, prepping for a future `require-trusted-types-for 'script'` directive.

## 0.16.3 — 2026-04-26

### Added

- **`server_version` field on `/api/v1/info`.**

  Returns the server's own `CARGO_PKG_VERSION` at build time. Always present (no cold-cache window like the GitHub-poller fields). Lets operators verify deploys without SSH and lets clients record which server version a response came from.

- **`X-Secrt-Server-Version` advisory response header.**

  Emitted on every response (authenticated and public, including `/healthz`) by the existing CLI-version-headers middleware. Same `env!("CARGO_PKG_VERSION")` source as the `/api/v1/info` body field.

- **`secrt-core::InfoResponse::server_version: Option<String>`.**

  New `#[serde(default)]` field so older CLIs continue to deserialize new responses cleanly (mirrors the `latest_cli_version` field shape from 0.16.0).

### Spec

- **`spec/v1/api.md` and `spec/v1/openapi.yaml`** document the new `server_version` body field and `X-Secrt-Server-Version` header alongside the existing CLI-version trio.

## 0.16.2 — 2026-04-26

_No server-side functional changes. Workspace version bump in lockstep with `cli/v0.16.2`._

## 0.16.1 — 2026-04-26

### Fixed

- **Cross-instance share-link handling in the embedded SPA.**

  Pasting a `secrt.is` link into the secrt.ca Get-Secret form (or vice versa) used to silently navigate to the current origin and surface a confusing "secret unavailable" 404. The form now recognizes known sibling instances (`secrt.ca`, `secrt.is`, including wildcard subdomains via label-boundary suffix matching) and shows a confirm Modal before crossing origins.

  - **Web** does a sanitized cross-origin redirect.
  - **Tauri** hands the link to the OS default browser via `@tauri-apps/plugin-shell` instead of silently switching its API endpoint.
  - **Unknown hosts** get a high-friction inline error with no offer to navigate.

  Redirect URLs are rebuilt via `new URL()` from validated parts (drops userinfo, ports, scheme oddities), and `parseShareUrl` now rejects non-HTTPS in production builds (with a localhost dev exemption).

## 0.16.0 — 2026-04-26

Server-driven CLI update guidance. Operators get a `latest_cli_version` and `min_supported_cli_version` they can advertise to CLI clients without those clients hitting GitHub directly.

### Added

- **GitHub Releases version cache.**

  A new background task in `release_poller.rs` polls `https://api.github.com/repos/<repo>/releases` every 60 minutes (configurable via `GITHUB_POLL_INTERVAL_SECONDS`; set to `0` to disable polling entirely on air-gapped deployments).

  - Uses `If-None-Match` / ETag to avoid burning rate limit on unchanged data.
  - Fails soft on 403 / 429 / 5xx / timeout / parse errors (last-known-good is preserved).
  - Filters tags to `cli/v\d+\.\d+\.\d+` (drafts and prereleases skipped); picks the highest semver.
  - Optional `GITHUB_TOKEN` lifts the unauthenticated rate limit. Configurable repo via `GITHUB_REPO` (default `getsecrt/secrt`).

- **Three new `/api/v1/info` body fields.**

  `latest_cli_version` and `latest_cli_version_checked_at` (omitted while the cache is cold), and `min_supported_cli_version` (always present, sourced from the new `MIN_SUPPORTED_CLI_VERSION` constant in `secrt_server`).

- **Three new advisory response headers** added on every response (authenticated and public, including `/healthz`): `X-Secrt-Latest-Cli-Version`, `X-Secrt-Latest-Cli-Version-Checked-At`, `X-Secrt-Min-Cli-Version`. Mirror the body fields so CLI clients can refresh their update-check cache opportunistically.

- **`MIN_SUPPORTED_CLI_VERSION` constant** in `crates/secrt-server/src/lib.rs`. Bump when a server release contains a wire-format change that breaks older CLIs (the v0.15.0 AAD format break is the canonical example). Documented in the release-process section of `secrt/AGENTS.md`.

### Dependencies

- Added `reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }` for the GitHub poller. JSON is parsed with the existing `serde_json` workspace dep; the `json` reqwest feature is intentionally not enabled.

## 0.15.0 — 2026-04-25

_No server runtime changes — the server stores AMK wrappers as opaque blobs and is unaffected by the client-side AAD format change in `secrt-core` 0.15.0. Pre-launch deployments must `TRUNCATE amk_wrappers, amk_accounts;` once before serving the new client builds, since existing wrappers were generated under the prior AAD format and will fail to unwrap._

## 0.14.9 — 2026-04-22

### Changed

- **Privacy page Infrastructure section is host-aware:** "hosted on DigitalOcean in Canada" no longer baked into the bundle. A new `getInfrastructure()` helper returns provider/country per host (`secrt.is` → 1984.hosting / Iceland, `secrt.ca` → DigitalOcean / Canada). New deployments add a row.

## 0.14.8 — 2026-04-22

### Changed

- **Footer + Privacy contact email derive from current host:** `Layout.tsx` (footer) and `PrivacyPage.tsx` ("Contact Us" section) now compute the security email at runtime via `getSecurityEmail()`, which reads `window.location.host`. So `secrt.is` renders `security@secrt.is`, `secrt.ca` renders `security@secrt.ca`. Tauri builds and SSR-less environments fall back to `security@secrt.ca`.

## 0.14.7 — 2026-02-22

### Added

- **In-app registration via browser flow:** clicking "Register a New Account" in the Tauri desktop app now opens the system browser directly to the registration page with the app-login URL as a redirect. After registering, the user lands on the approval page to authorize the app — a single browser trip instead of two.

### Changed

- **Tauri register page simplified:** the Tauri WebView register page now redirects to the login page where both "Log in via Browser" and "Register a New Account" options are available, replacing the previous dead-end "Open Browser to Register" screen.
- **AppLoginPage intent fallback:** the `/app-login` page now reads an optional `intent=register` URL parameter and redirects unauthenticated users to `/register` instead of `/login` when present.
- **Public URLs derive from `PUBLIC_BASE_URL` at runtime:** Open Graph / Twitter card meta tags in the SPA, the `/robots.txt` body, and `/.well-known/security.txt` (including the security contact email — derived from the configured host) no longer hardcode `secrt.ca`. A new `__PUBLIC_BASE_URL__` placeholder in the SPA `index.html` is substituted at request time. Lets a single binary serve any deployment (e.g. `secrt.is`) cleanly.

## 0.14.6 — 2026-02-22

### Added

- **CORS support for Tauri desktop app:** the server now handles CORS preflight and response headers for Tauri webview origins (`tauri://localhost` on macOS, `https://tauri.localhost` on Windows/Linux). Allows the production Tauri app to make authenticated cross-origin requests to the API. Credentials are permitted so session-based auth works from the webview.
- **CORS integration tests:** 8 tests covering preflight responses, allowed/rejected origins, method and header validation, and normal request behavior.

### Fixed

- **Tauri app login fails in production builds:** production Tauri webview (`tauri://localhost`) was blocked by missing CORS headers on all API requests, causing "Load failed" on every fetch. The CorsLayer now intercepts OPTIONS preflight before route dispatch.

### Changed

- **Tauri app credential storage:** file-based fallback for OS keychain storage when macOS Tahoe keychain is broken (set succeeds but get returns `errSecItemNotFound`). Credentials stored in `~/Library/Application Support/ca.secrt.desktop/credentials.json`. Auto-detected via probe on startup.
- **Tauri app devtools:** WebInspector now auto-opens in debug builds for easier development.

## 0.14.5 — 2026-02-22

### Added

- **ECDH-based AMK transfer in app login flow:** the browser can now encrypt the user's Account Master Key (AMK) and hand it to the Tauri desktop app during login approval. The `/app/start` endpoint accepts an optional `ecdh_public_key`, embeds it in the `verification_url` as `&ek=`, and the `/app/approve` endpoint accepts an `amk_transfer` blob (`ct`, `nonce`, `ecdh_public_key`) which is stored on the challenge and returned by `/app/poll`.
- **OS keychain storage in Tauri app:** session tokens, cached profiles, and AMK are now stored in the OS keychain (`keyring` crate, service `ca.secrt.desktop`) instead of renderer-accessible storage. Tauri IPC commands (`keyring_set`, `keyring_get`, `keyring_delete`) enforce a Rust-side key allowlist.
- **Verification URL safety guard (web):** `isAllowedVerificationUrl()` validates that verification URLs are HTTPS and match the expected API origin before opening the system browser, preventing open-redirect and protocol-hijack attacks.
- **Spec documentation:** app login endpoints fully documented in `api.md`, `server.md`, and `openapi.yaml`.
- **Tauri native crypto test vectors:** all 5 spec envelope vectors verified through the Tauri IPC command layer with deterministic RNG injection.

### Changed

- **Session tokens minted at poll time:** tokens are now created fresh when the desktop app polls (after atomically consuming the challenge), rather than being stored in challenge JSON at approve time. Eliminates raw bearer tokens from the database.
- **ECDH and AMK transfer input validation:** both app-login and device-auth endpoints now validate ECDH public key length (65 bytes, uncompressed P-256) and AMK transfer field lengths (nonce 12 bytes, ct 48 bytes) at the API boundary.
- **Async session storage (web):** `getSessionToken()`, `setSessionToken()`, `clearSessionToken()`, `getCachedProfile()`, and `setCachedProfile()` are now async to support Tauri keychain reads. Synchronous fast-paths (`getSessionTokenSync`, `getCachedProfileSync`) available for browser-only initial render.
- **Dual-backend AMK persistence (web):** AMK storage routes to OS keychain in Tauri mode, IndexedDB in the browser.

### Fixed

- **Maskable icon colors:** SVG fill colors corrected for proper color assignment.
- **Async test assertions:** redirect tests in `AuthGuard`, `DashboardPage`, and `SettingsPage` now use `waitFor` to account for Preact's asynchronous `useEffect` ordering.

## 0.14.4 — 2026-02-22

### Added

- **App login endpoints (desktop app auth):** three new endpoints for an OAuth-style desktop app login flow that bypasses WebAuthn RP ID mismatch in Tauri's webview:
  - `POST /api/v1/auth/app/start` — unauthenticated; generates `app_code` + `user_code`, stores challenge with `purpose = "app-login"` and 10-minute expiry. Returns `verification_url` pointing to `/app-login?code=...`.
  - `POST /api/v1/auth/app/poll` — unauthenticated; polls by `app_code`. Returns `authorization_pending` while waiting, `complete` with `session_token`, `user_id`, and `display_name` on approval. Challenge consumed atomically on completion.
  - `POST /api/v1/auth/app/approve` — session auth required; looks up challenge by `user_code` with constant-time comparison, issues a session token for the authenticated user, and marks the challenge as approved.
- **`/app-login` SPA route:** serves the frontend approval page for desktop app authorization.
- **App login approval page (web):** browser-side approval page at `/app-login?code=XXXX-XXXX` — shows the authorization code, requires authenticated session, single-click approve.

### Changed

- **Generalized `find_challenge_by_user_code`:** renamed from `find_device_challenge_by_user_code` with an added `purpose` parameter, allowing both device-auth and app-login flows to share the same challenge lookup infrastructure.

## 0.14.3 — 2026-02-21

### Changed

- **Mobile UI:** Tightened padding/spacing, added logo to mobile header.
- **Theme toggle:** Moved inset shadow to vanilla CSS to fix Tailwind 4.2 dark-mode override regression. Polished knob hover effect.

## 0.14.2 — 2026-02-20

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
