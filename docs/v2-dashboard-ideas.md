# Dashboard Ideas (v2+)

*Brainstormed: 2026-02-08*

This document captures ideas for an authenticated user dashboard. This is explicitly **out of scope for v1** — the current design is anonymous-only with API keys for automation.

---

## Zero-Knowledge Constraints

The server operates in a zero-knowledge model. Dashboard can only show metadata the server already has access to:

**What the server CAN know:**
- Envelope size (ciphertext bytes)
- Created timestamp
- Expiry timestamp
- Status (active / claimed / expired)
- Claimed timestamp (if claimed)
- Whether passphrase was used (`kdf.name != "none"`)
- Owner (if authenticated when created)

**What the server CANNOT know:**
- Plaintext content
- Whether it's "a file" vs "text" (unless client adds optional hint)
- Passphrase value
- URL key

---

## Summary Cards

| Metric | Example Value |
|--------|---------------|
| Total secrets created | 142 |
| Active (unclaimed) | 8 |
| Claimed | 127 |
| Expired unclaimed | 7 |
| Storage used | 2.3 MB / 50 MB |

---

## Secrets Table

| Column | Description |
|--------|-------------|
| ID | Truncated secret ID (e.g., `a7f3...`) |
| Created | Timestamp when secret was created |
| Expires | Expiry timestamp |
| Size | Envelope size in human-readable format (e.g., "1.2 KB") |
| Protected | 🔒 icon if passphrase was used |
| Status | Active / Claimed / Expired |
| Claimed | Timestamp when claimed (if applicable) |

**Example rows:**

| ID | Created | Expires | Size | Protected | Status | Claimed |
|----|---------|---------|------|-----------|--------|---------|
| `a7f3...` | Feb 7, 20:15 | Feb 8, 20:15 | 1.2 KB | 🔒 | Active | — |
| `b2e1...` | Feb 7, 18:00 | Feb 8, 18:00 | 48 KB | — | Claimed | Feb 7, 18:05 |
| `c9d4...` | Feb 6, 10:00 | Feb 7, 10:00 | 256 B | 🔒 | Expired | — |

---

## Optional Content Hints

If we want to show "file vs text" or filenames, the client can include an optional hint in the envelope:

```json
{
  "v": 1,
  "suite": "...",
  "hint": {
    "type": "file",
    "filename": "credentials.txt",
    "mime": "text/plain"
  },
  ...
}
```

Server stores this opaquely with the envelope and displays it if present. Client-provided, unverified, purely for UX.

---

## Quota Ideas

Potential quota dimensions for tiered accounts:

| Quota | Free | Pro |
|-------|------|-----|
| Secrets per month | 50 | Unlimited |
| Max secret size | 64 KB | 10 MB |
| Max TTL | 7 days | 1 year |
| Storage limit | 10 MB | 1 GB |
| API key access | ❌ | ✅ |
| Dashboard history | 7 days | 90 days |

---

## Authentication Model

For authenticated accounts, the recommendation is **passkey-only** (no passwords):

**Rationale:**
- 99% of users don't need accounts (anonymous works fine)
- Power users who need accounts are developers/technical — can handle passkeys
- Passkey-only eliminates password storage, reset flows, and phishing risks
- Strong trust signal for a security-focused product

**Tiers:**

| Tier | Auth | Features |
|------|------|----------|
| Anonymous | None | Create/claim secrets, rate limited |
| API key | Token | Higher limits, automation, burn endpoint |
| Account | Passkey only | Dashboard, history, quotas, team features |

---

## Actions

Potential dashboard actions for owned secrets:

- **Burn** — Delete an unclaimed secret early
- **Copy link** — Re-copy the share URL (requires storing URL key server-side, breaks zero-knowledge — probably don't do this)
- **Extend TTL** — Push expiry out (if within quota limits)

---

## Notes

- All of this is v2+ scope
- v1 ships anonymous-only with API keys for automation
- Consider adding this incrementally based on actual user demand
