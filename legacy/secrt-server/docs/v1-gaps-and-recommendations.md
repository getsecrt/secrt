# v1 Gaps and Recommendations

*Review conducted: 2026-02-07 by Rachel (OpenClaw agent)*

This document captures gaps, open questions, and recommendations identified during a review of the v1 specification files.

---

## High Priority (Blocking Interoperability)

### 1. Test Vectors (`spec/v1/envelope.vectors.json`)

**Status:** Planned but not created

**Why it matters:** Test vectors are the only way to prove that CLI and browser implementations produce identical crypto output. Without them, you can't verify interoperability between clients.

**Recommendation:** Create vectors before finalizing v1. Each vector should include:
- URL key bytes (hex or base64)
- Passphrase (if any)
- KDF params
- HKDF salt
- Nonce
- Plaintext
- Expected envelope JSON
- Expected claim token and claim hash

### 2. OpenAPI Specification (`spec/v1/openapi.yaml`)

**Status:** Planned but not created

**Why it matters:** OpenAPI enables auto-generated API docs, client SDKs, and integration testing. It's also the industry standard for describing REST APIs.

**Recommendation:** Generate from the existing `api.md` spec. Can be done after core implementation is stable.

### 3. JSON Schema (`spec/v1/envelope.schema.json`)

**Status:** Planned but not created

**Why it matters:** Enables server-side envelope validation without custom parsing logic. Also useful for client-side validation in browsers.

**Recommendation:** Create alongside test vectors. The schema and vectors should validate each other.

---

## Medium Priority (Feature Gaps)

### 4. Web UI Specification

**Status:** Not started

**Why it matters:** The `web/` directory exists and browser UI is mentioned as "future," but there's no spec for:
- Fragment parsing and URL handling
- Passphrase prompt UX
- Error state display
- Copy-to-clipboard behavior
- Mobile responsiveness requirements

**Recommendation:** Draft a lightweight `spec/v1/web-ui.md` before building the frontend. Doesn't need to be as detailed as the crypto spec, but should cover key UX flows.

### 5. Binary vs Text Handling

**Status:** Ambiguous

**Current state:** The CLI spec mentions `--file <path>` as an input option, but doesn't specify:
- Are binary files supported, or text only?
- What's the effective size limit? (Envelope limits are tiered and ciphertext overhead reduces usable plaintext size)
- How should `claim` output binary content without corrupting the terminal?

**Options:**
1. **Keep it simple for v1:** Explicitly limit to UTF-8 text, max ~48KB plaintext. Document this clearly.
2. **Support binary:** Add `--output <path>` flag to `claim` for binary-safe output. Detect binary content and warn if outputting to terminal.

**Recommendation:** Option 1 for v1 (explicit text-only scope), option 2 for v1.1 if there's demand.

### 6. CLI Configuration File

**Status:** Not specified

**Why it matters:** Power users and automation scripts benefit from persistent config rather than passing `--base-url` and `--api-key` on every invocation.

**Recommendation:** Support optional config file at `~/.config/secrt/config.toml` or similar:
```toml
base_url = "https://secrt.ca"
api_key = "sk_xxx.yyy"
```

Precedence: CLI flag > environment variable > config file > built-in default.

Can be deferred to v1.1.

### 7. Optional Envelope Metadata Hints (`hint.mime`, `hint.filename`)

**Status:** Mentioned in v2 ideas, not formalized in v1 envelope spec

**Why it matters:** Zero-knowledge file sharing works without MIME metadata, but download UX is better when clients can preserve content type and optional filename.

**Recommendation:** Add an explicitly optional advisory `hint` object in `spec/v1/envelope.md`, for example:

```json
{
  "hint": {
    "type": "file",
    "mime": "application/pdf",
    "filename": "incident-report.pdf"
  }
}
```

Rules:
- `hint` MUST be optional and never required for decryption.
- `hint` MUST NOT affect key derivation, claim tokens, or cryptographic checks.
- Server stores/returns `hint` opaquely; do not trust it for authorization/security decisions.
- If `hint.mime` is absent, clients should default file downloads to `application/octet-stream`.

---

## Lower Priority (Operational Polish)

### 8. Distributed Rate Limiting

**Status:** Acknowledged as limitation in `server.md`

**Current state:** Rate limiter is in-memory, per-process. Multi-instance deployments don't share state.

**Options:**
- Redis-backed rate limiter
- Sticky sessions at load balancer
- Accept that limits are per-instance (fine for small scale)

**Recommendation:** Document the limitation clearly. Defer implementation until there's actual multi-instance deployment need.

### 9. Metrics and Observability

**Status:** Not specified

**Why it matters:** Production services need visibility into request rates, error rates, latency percentiles, and business metrics (secrets created/claimed/expired).

**Recommendation:** Add optional Prometheus metrics endpoint (`/metrics`) exposing:
- `http_requests_total{method, path, status}`
- `http_request_duration_seconds` (histogram)
- `secrets_created_total`
- `secrets_claimed_total`
- `secrets_expired_total`
- `secrets_active_count` (gauge)

Can be deferred to v1.1. Use `promhttp` from the Prometheus Go client.

### 10. Shell Completions

**Status:** Not mentioned

**Why it matters:** Tab completion significantly improves CLI UX.

**Recommendation:** Hand-roll completion scripts rather than adding a CLI framework dependency like Cobra. Shell completion scripts are just structured text with well-documented formats — tedious for humans to write by hand, but trivial for AI coding assistants (Claude Code, Codex, etc.) to generate in seconds.

Generate scripts for:
- **Bash** — `_secrt` function with `complete -F`
- **Zsh** — `_secrt` compdef with `_arguments`
- **Fish** — `complete -c secrt` commands
- **PowerShell** — `Register-ArgumentCompleter` block

Store in `completions/` directory. Users install with one line in their shell config.

This approach keeps the dependency count minimal (important for a security-focused tool) while still providing the UX benefit.

---

## Open Questions

### Q1: Size Limits and Large Secrets

**Question:** What happens when someone tries to share a 50MB file?

**Current state:** `MaxEnvelopeBytes` is 64KB. API rejects larger payloads with 400.

**Recommendation:** This is probably fine. Document the limit clearly in user-facing docs. If larger secrets are needed, that's a different product (file sharing, not secret sharing).

### Q2: Abuse Prevention

**Question:** Should v1 include captcha or proof-of-work on public create?

**Current state:** Rate limits only (0.2 rps, burst 4 per IP).

**Analysis:** Rate limits are probably sufficient for launch. Captcha adds friction and complexity. Monitor abuse patterns post-launch and add captcha if needed.

**Recommendation:** Ship without captcha. Add monitoring/alerting for unusual create patterns. Revisit if abuse becomes a problem.

### Q3: API Keys for v1

**Question:** Is API key auth needed for v1?

**Current state:** Spec includes both public and authenticated endpoints. Server implementation has API key infrastructure.

**Analysis:** Public endpoint is sufficient for human users. API keys matter for:
- Automation/CI pipelines
- Higher rate limits
- Audit trail
- Future billing/quotas

**Recommendation:** Can ship v1 with public endpoint only. API key support is already specced and partially implemented — low effort to enable when needed.

---

## Suggested Prioritization

**Before v1 launch:**
1. Test vectors (critical for interoperability)
2. Clarify text-only scope in CLI spec
3. Define optional envelope `hint` metadata for file UX

**v1.0 polish (can ship without):**
4. OpenAPI spec
5. JSON Schema
6. Shell completions

**v1.1 roadmap:**
7. Web UI
8. Prometheus metrics
9. CLI config file
10. Binary file support (if demand exists)

**Defer until needed:**
11. Distributed rate limiting
12. Captcha/proof-of-work
