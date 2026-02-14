# Manual Go/No-Go Checklist (v0.6.0)

Use this checklist before promoting staging to production.

## 0. Build Artifacts (Required)

- [x] Rebuild the current CLI from source before testing (`cargo build --release -p secrt-cli`).
- [x] Rebuild the current server from source before testing (`cargo build --release -p secrt-server`).
- [x] Confirm local binaries report expected version (`secrt --version`, `secrt-server --version`).
- [x] Confirm staging host is using freshly deployed binaries (not prior local/system package versions).

## 1. Environment and Startup

- [ ] Server binary is the expected build/version (`secrt-server --version`).
- [ ] `ENV=production` is set.
- [ ] `PUBLIC_BASE_URL` matches the public host.
- [ ] `API_KEY_PEPPER` is set and non-empty.
- [ ] `SESSION_TOKEN_PEPPER` is set and non-empty.
- [ ] DB connectivity is healthy with current credentials.
- [ ] `secrt` systemd unit starts successfully.
- [ ] Startup logs show migrations run cleanly (or already applied).
- [ ] `/healthz` returns `200`.

## 2. Database and Migration State

- [ ] Database contains expected tables: `secrets`, `api_keys`, `users`, `passkeys`, `sessions`, `webauthn_challenges`, `api_key_registrations`, `migrations`.
- [ ] `migrations` table includes `001_initial.sql`.
- [ ] No legacy migration drift remains from pre-squash state.
- [ ] Indexes exist for API-key registration quota windows.

## 3. Passkey Auth Flow

- [ ] `POST /api/v1/auth/passkeys/register/start` succeeds.
- [ ] `POST /api/v1/auth/passkeys/register/finish` succeeds.
- [ ] `POST /api/v1/auth/passkeys/login/start` succeeds.
- [ ] `POST /api/v1/auth/passkeys/login/finish` returns session bearer token (`uss_...`).
- [ ] `GET /api/v1/auth/session` returns authenticated session state.
- [ ] `POST /api/v1/auth/logout` invalidates the session.
- [ ] Expired or revoked session tokens are rejected.

## 4. API Key Registration (Passkey-Gated)

- [ ] `POST /api/v1/apikeys/register` fails without session bearer token.
- [ ] `POST /api/v1/apikeys/register` succeeds with valid session and valid `auth_token`.
- [ ] Malformed `auth_token` (bad base64url or wrong decoded length) is rejected.
- [ ] Registered key prefix is returned and stored.
- [ ] Stored verifier uses `auth_hash` (no plaintext auth token at rest).
- [ ] Account hourly limit blocks the 6th request in 1 hour.
- [ ] Account daily limit blocks the 21st request in 24 hours.
- [ ] IP hourly limit blocks the 6th request in 1 hour.
- [ ] IP daily limit blocks the 21st request in 24 hours.

## 5. API Key Auth Cutover

- [ ] Authenticated routes accept `ak2_<prefix>.<auth_b64>`.
- [ ] Legacy `sk_...` credentials are rejected.
- [ ] Invalid or revoked `ak2_...` credentials return unauthorized.
- [ ] `GET /api/v1/info` reports `authenticated=true` only for valid `ak2_`.

## 6. Secret Lifecycle Behavior

- [ ] Public create works (`POST /api/v1/public/secrets`).
- [ ] Authenticated create works (`POST /api/v1/secrets`) with valid `ak2_`.
- [ ] Claim works exactly once (`POST /api/v1/secrets/{id}/claim`).
- [ ] Re-claim after success returns not found.
- [ ] Burn works for owner key (`POST /api/v1/secrets/{id}/burn`).
- [ ] Burn fails for non-owner key.
- [ ] TTL expiry prevents claim of expired secret.

## 7. Envelope Privacy + Compression (Hard-Cut)

- [ ] Stored envelope JSON has no plaintext metadata keys (`hint`, `filename`, `mime`, `type`) at top-level.
- [ ] `send --file ...` + `get --json` returns file metadata from decrypted payload (`type=file`, `filename`, `mime`).
- [ ] Create two payloads >= 2 KiB (one highly compressible, one random/incompressible) and verify compressible one produces materially smaller stored envelope bytes.
- [ ] Round-trip compressed secret bytes match original bytes exactly (e.g., `cmp` on original vs retrieved file).
- [ ] Sub-threshold payload (`< 2048` bytes) does not show compression behavior.
- [ ] Already-compressed input (e.g., PNG/ZIP) does not show compression wins relative to similar-size compressible text.
- [ ] Legacy pre-sealed envelope payloads are treated as incompatible (expected hard cut, no backward compatibility).

## 8. Policy and Limits

- [ ] Public and authenticated envelope size limits enforce as configured.
- [ ] Public and authenticated active secret-count quotas enforce as configured.
- [ ] Public and authenticated active total-bytes quotas enforce as configured.
- [ ] Public create limiter enforces configured rate/burst.
- [ ] Claim limiter enforces configured rate/burst.
- [ ] Authenticated create limiter enforces configured rate/burst.
- [ ] API key registration limiter enforces configured rate/burst.

## 9. CLI Compatibility (sk2)

- [ ] CLI accepts local `sk2_<prefix>.<root_b64>` input.
- [ ] CLI derives and sends `ak2_<prefix>.<auth_b64>` on wire auth.
- [ ] `secrt send --api-key sk2_...` succeeds on authenticated path.
- [ ] `secrt burn --api-key sk2_...` works on owned secrets.
- [ ] `secrt info` with `sk2_...` shows authenticated true.
- [ ] Malformed `sk2_...` fails with clear user-facing error.

## 10. Web UI Operability (Minimal Auth UI)

- [ ] Browser passkey register/login flow works end-to-end.
- [ ] Session check in UI reflects real auth state.
- [ ] API key registration via UI path succeeds.
- [ ] UI handles unauthorized and validation errors clearly.

## 11. Security and Observability

- [ ] No logs include root keys, auth tokens, enc keys, session secrets, passphrases, or plaintext.
- [ ] Request logging includes metadata only (method/path/status/duration/request_id).
- [ ] Security headers are present on responses.
- [ ] `X-Privacy-Log` advisory behavior is visible in logs behind proxy.

## 12. Operations and Recovery

- [ ] Service restarts cleanly and remains healthy.
- [ ] Existing sessions behave as expected across restart boundaries.
- [ ] Backup/restore procedure for database has been tested once.
- [ ] Rollback plan is documented for staging and production.

## 13. Final Go/No-Go Gate

- [ ] `cargo fmt --all` passes.
- [ ] `cargo clippy --workspace -- -D warnings` passes.
- [ ] `cargo test --workspace` passes.
- [ ] Manual checks above are complete with no open P0/P1 issues.
- [ ] Decision logged: `GO` or `NO-GO`, with owner and timestamp.

## 14. Audit Remediation Spot Checks (2026-02-13)

- [ ] `secrt send --trim` rejects non-UTF-8 stdin/file input with clear error (exit code `2`).
- [ ] Short boolean flag suffixes are rejected (for example `secrt gen -SNG`, `secrt send -mfoo`).
- [ ] Valid short flags with inline values still work (for example `secrt gen -L20`, `secrt get -oout.txt`).
- [ ] Tampered session token secret is rejected on logout (`POST /api/v1/auth/logout` -> `401`) and does not revoke valid session.
- [ ] Passkey `/finish` rejects unknown/expired `challenge_id` and accepts valid `challenge_id` + credential linkage.
- [ ] Slow header connection is closed around 5s (`ReadHeaderTimeout` behavior).
- [ ] Stalled request body receives `408 Request Timeout` around 15s budget.
- [ ] Idle keepalive connection is closed around 60s of inactivity.
- [ ] Server shutdown completes under held in-flight connection and does not hang past ~10s graceful deadline.
- [ ] Reaper performs one immediate startup cleanup run (no duplicate immediate second run).
- [ ] `delete_expired()` cleanup removes stale `webauthn_challenges`, expired/revoked `sessions`, and `api_key_registrations` older than 24h.
