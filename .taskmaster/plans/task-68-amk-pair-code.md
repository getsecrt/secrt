# Task 68 — Browser-to-Browser AMK Transfer via Pairing Rendezvous (Typed Code + Bidirectional QR)

**Status:** Plan
**Date:** 2026-05-02
**Origin:** JD's phone→Windows-PC AMK transfer pain (had to email himself a sync link)
**Supersedes:** the `device-pair listener/inbox` framing in the original task-68 description

---

## TL;DR

A "TV-style" typed pair code already exists in this codebase — it's how `device-auth` (CLI) and `app-login` (Tauri) onboard new clients. The work is **not** building a new device-pairing system. It's:

1. **Surfacing the existing primitive as a web-to-web AMK transfer flow.**
2. **Generalizing the rendezvous channel** so the same pairing slot can be joined via either a typed `XXXX-XXXX` code *or* a scanned QR — and so QR can flow in either direction (sender→receiver or receiver→sender) instead of today's one-directional payload-baked QR.
3. **Consolidating the AMK-transfer primitives** (sync link, payload-QR, typed code, rendezvous-QR) into a coherent UX with sensible defaults, not three competing buttons.

Estimated effort: **~3 focused days**, of which ~70% is UX/web client and ~10% is backend tweaks. The rest is testing, docs, and an addition to `spec/v1/server.md`.

---

## Problem Statement

Today, transferring an AMK from one logged-in device to another browser involves:

- **Sync link**: generate a `/sync/{id}#<key>` URL, email/message it to yourself, click on the destination. Works async, works cold-start, but feels janky.
- **QR code (current)**: encodes the *sync link itself* — i.e. the encrypted AMK payload baked into the URL fragment. Fast when destination is a phone with a camera. Two limitations: (a) one-directional only, because the payload is prepared by the sender before the QR exists, and (b) useless when the destination has no camera (typical desktop PC, work-issued Windows machines).

Neither is great for the most common real-world case JD just hit: **phone has AMK, PC needs AMK, PC has no camera or the camera is awkward.**

The fix has two halves:
1. A **typed `XXXX-XXXX` pair code** as the universally-applicable rendezvous (works without a camera, the same primitive that already handles CLI device-auth and Tauri app-login).
2. A **rendezvous-QR** (encoding a slot identifier, not a payload) that works in either direction — the phone scans the laptop, regardless of which side has the AMK, because the QR carries a session not a secret.

These aren't separate features. They're the same backend slot rendered through two different rendezvous channels.

---

## Existing Infrastructure Audit

(Confirmed 2026-05-02 against the codebase.)

### Backend — already shipping

| Capability | Location | Reuse |
|---|---|---|
| Challenge table (`webauthn_challenges`) | `crates/secrt-server/src/http/mod.rs` | 100% — add purpose value |
| 8-char `XXXX-XXXX` code generator | `mod.rs` | 100% |
| Constant-time code comparison | `mod.rs` | 100% |
| 10-min expiry + atomic-consume-on-poll | `mod.rs` | 100% |
| IP rate limiting on `/start` | `mod.rs` | 100% |
| Session-authenticated approve endpoint | `mod.rs` lines 2813–3116 | 100% |
| ECDH P-256 + HKDF-SHA256 + AES-256-GCM | `web/src/crypto/amk.ts` lines 350–395 | 100% |
| `amk_transfer` schema validation (65/12/48 byte fields) | `mod.rs` lines 485–490 | 100% |

### Frontend — partial

| Capability | Location | Reuse |
|---|---|---|
| ECDH key generation in browser | `web/src/crypto/amk.ts` | 100% |
| AMK encryption to peer's pubkey | `web/src/crypto/amk.ts` | 100% |
| Approval UI (code display, approve/cancel) | `web/src/features/device/DevicePage.tsx` | ~80% — minor copy changes |
| **Code entry UI for unauthenticated browser** | — | ❌ greenfield |
| **"Receive AMK from another device" entry point on login page** | — | ❌ greenfield |
| **UX consolidation across sync-link / QR / typed-code** | spread across pages | ❌ design decision |

### Spec — already documented

`spec/v1/server.md` lines 268–335 covers `device-auth` and `app-login` flows in full, including the `amk_transfer` field semantics. The web-to-web use case needs a small addition; no new schema.

---

## The Rendezvous Primitive

A **pairing slot** is a short-lived server-side object (already implemented as a row in `webauthn_challenges`) that two devices coordinate through. It holds:

- A short user-visible code (`XXXX-XXXX`) — for typed entry.
- A role — `send` (the displaying device has the AMK) or `receive` (the displaying device needs the AMK).
- The displaying device's ECDH public key, when applicable.
- The encrypted AMK blob, once one side has uploaded it.
- An expiry timestamp, attempt counter, and rate-limit state.

A slot can be **joined** via two interchangeable channels:

| Channel | How |
|---|---|
| **Typed code** | User reads `K7MQ-3F2A` from one screen, types it on the other. Universal. No camera required. |
| **QR code** | The slot's URL is rendered as a QR. The other device scans it. Camera required on the scanner. |

Both channels resolve to the same slot ID server-side. The protocol from there is identical.

### URL scheme

```
secrt://pair/{slot_id}?role={send|receive}&pk={base64url_pubkey}
```

- `slot_id`: the server-side slot identifier (typically the same value derived from the user code, or a separate opaque token).
- `role`: declared by the displaying device.
  - `role=send` → displaying device has AMK; scanner is the receiver and posts its ECDH pubkey to the slot.
  - `role=receive` → displaying device needs AMK; QR includes the displaying device's ECDH pubkey, and the scanner (sender) encrypts AMK to it.
- `pk`: present only when `role=receive`. Receiver's ephemeral ECDH P-256 public key.

The same scheme also handles a deep-link entry from the QR (e.g. mobile browsers can register the URL scheme so a scanned link opens the secrt web app directly into the right flow).

---

## Proposed Flow

**Sender:** the device that already has the AMK.
**Receiver:** the device that needs the AMK.

Either side can be the one that "displays" (shows the QR + typed code). The displaying device's role is encoded in the slot.

### Happy path A — receiver displays (the original phone→PC case)

1. **On the receiver** (new browser, post-passkey but pre-AMK):
   - User clicks **"Receive AMK from another device"**.
   - Browser generates ephemeral ECDH P-256 key pair, calls `POST /api/v1/auth/device/start` with role `receive` and its public key.
   - Server returns slot ID + 8-char user code.
   - Browser displays both: a QR encoding `secrt://pair/{id}?role=receive&pk=…` *and* the typed code.
   - Browser polls `POST /api/v1/auth/device/poll` every ~2s.

2. **On the sender** (logged in, AMK present):
   - User opens **"Send AMK to another device"** in dashboard/settings.
   - One screen, two equivalent inputs: scan QR with camera, or paste/type the code.
   - Either input resolves to the same slot ID. Browser calls `GET /api/v1/auth/device/challenge?slot_id=…` (or `?user_code=…`) and retrieves the receiver's ECDH pubkey.
   - Browser performs ECDH, derives transfer key via HKDF-SHA256, encrypts AMK with AES-256-GCM.
   - Browser calls `POST /api/v1/auth/device/approve` with the `amk_transfer` blob.

3. **Back on the receiver:**
   - Next poll returns `amk_transfer`. Browser decrypts with its ECDH private key, stores AMK in IndexedDB via existing `storeAmk(userId, amkBytes)`.
   - Done.

### Happy path B — sender displays (laptop has AMK, phone is new)

1. **On the sender:** user clicks "Show pairing code". Browser calls `/device/start` with role `send`. No ECDH pubkey on the slot yet (the receiver will post one). Server returns slot ID + code.
2. **On the receiver:** scans QR or types code. Browser generates ECDH keypair, posts pubkey to the slot via a `claim` call.
3. **On the sender:** poll detects pubkey arrival. Browser performs ECDH, encrypts AMK, posts via `approve`.
4. **On the receiver:** poll returns blob, decrypts, stores. Done.

The two paths use slightly different endpoint orderings (which side posts the pubkey first) but the same primitives. The role flag in the slot tells both sides which order applies.

### Threat model (mostly unchanged; rendezvous-QR adds a small upgrade)

- **Server compromise:** server only sees the encrypted blob and public keys; cannot derive shared secret or decrypt AMK. Unchanged.
- **Code shoulder-surf:** sender must also be authenticated as the same user before approving — passkey is the second factor. Unchanged.
- **Brute force:** 32-char no-confusion alphabet × 8 chars = ~10¹² combos, 10-min TTL, single-use, attempt-locked. Implausible. Unchanged.
- **MITM:** ECDH public key is bound to the slot before the sender approves. Server can't swap keys without the receiver detecting via decrypt failure. Unchanged.
- **Phishing the receiver into typing a code into a fake site:** the receiver enters their *own* code; doesn't disclose anything sensitive. Lowest-risk error mode. Unchanged.
- **NEW — leaked rendezvous QR vs leaked payload QR:** today's payload-QR (sync link rendered as QR) leaks the AMK if intercepted (it carries the encrypted blob + the URL-fragment key). The new rendezvous-QR carries only a slot ID + maybe an ephemeral pubkey. An attacker who screenshot-leaks a rendezvous QR can attempt to join the slot but cannot decrypt anything — they'd need the legitimate user's authenticated session on the other side to actually move the AMK. **This is a security upgrade**, not just a UX one.

---

## UX Consolidation — The Real Hard Part

JD called this out explicitly: showing every primitive flat is bad UX. The reframe: **QR and typed code are two channels into the same slot**, not two competing options. Show them as paired siblings on the displaying device — whichever the other device finds easier, it can use. The sync link stays available but explicitly framed as the *async* path.

### On the displaying device (whichever side is showing the slot — could be sender or receiver)

```
┌─────────────────────────────────────────────────┐
│ Pair another device                             │
│                                                 │
│       ┌──────────────────┐                      │
│       │ ▒▒▒▒▒▒▒▒  QR     │  ← scan with phone   │
│       │ ▒▒▒▒▒▒▒▒         │                      │
│       └──────────────────┘                      │
│                                                 │
│       Or type this code:                        │
│       ┌────────────────┐                        │
│       │   K7MQ-3F2A    │  ← if no camera        │
│       └────────────────┘                        │
│                                                 │
│  Waiting for other device... ◌                  │
│                                                 │
│  ▸ Need to send to a device not present?        │  ← collapsible
│    Generate a sync link instead.                │
└─────────────────────────────────────────────────┘
```

### On the joining device (whichever side is scanning/typing)

```
┌─────────────────────────────────────────────────┐
│ Join paired device                              │
│                                                 │
│ [📷 Scan QR from other device]                  │  ← primary if camera
│                                                 │
│ [⌨️  Enter code instead]                        │  ← always shown
│  ┌──────────────────┐                           │
│  │  XXXX-XXXX       │                           │
│  └──────────────────┘                           │
└─────────────────────────────────────────────────┘
```

The displaying-device UI is **role-aware via the slot's role flag**, but visually identical regardless of direction. Behind the scenes, `role=send` waits for the joiner's pubkey; `role=receive` includes the displayer's pubkey in the QR. The user doesn't see this complexity.

### What about the sync link?

**Keep it, demote it.** The sync link's genuine niche is **async transfer**: the destination device isn't in front of you right now (you're setting up tomorrow's laptop). Both QR and typed code require simultaneous presence.

Demote to a "More options" disclosure on the displaying-device page. Don't surface it as a peer of QR/code in the primary UI.

### Decision matrix

| Situation | Best path |
|---|---|
| Both devices present, joiner has camera | → scan QR (any direction) |
| Both devices present, joiner has no camera | → typed code |
| Both devices present, both have cameras | → either, user's choice |
| Destination device not present / async setup | → sync link |
| User unsure | → display QR + typed code together; let the other device choose |

---

## Implementation Plan

### Phase 1 — Backend (≤ 0.5 day)

- [ ] Verify `device-auth` endpoints accept the web-to-web case end-to-end. Likely already works.
- [ ] Confirm the slot record can carry a `role` field (`send` / `receive`). If `webauthn_challenges.challenge_json` already permits arbitrary fields, just add it there. Otherwise small migration.
- [ ] If we want a separate `purpose` value (e.g. `web-pair`) for clearer logging/metrics, add it. Probably *not* worth the breakage; reuse `device-auth`.
- [ ] Add a `claim` endpoint variant for the `role=send` case where the joiner posts its ECDH pubkey *after* the slot is created (current flow assumes pubkey is set at start time). Possibly already supported via the existing approve path; needs verification.
- [ ] Confirm rate limits on `/device/start` are appropriate for the web-initiator case (web can initiate more frequently than CLI; may want session-cookie rate limit on top of IP).
- [ ] Add explicit unit tests for both directions: "receiver displays" and "sender displays" web-to-web AMK transfer.

### Phase 2 — Rendezvous URL scheme + QR rendering (~ 0.5 day)

- [ ] Define the `secrt://pair/{slot_id}?role=…&pk=…` URL scheme. Document in `spec/v1/server.md`.
- [ ] Helpers to encode a slot to URL and decode a URL back to slot info (TS in `web/`, mirror in Rust if any server-side rendering needed).
- [ ] QR rendering helper using existing QR library (likely `qrcode` npm or whatever the sync-link QR is using today).
- [ ] QR scanner integration — likely `getUserMedia` + `jsQR` or `BarcodeDetector` API where supported. Confirm what's in the bundle today; reuse if possible.

### Phase 3 — Displaying-device UI (~ 1 day)

- [ ] New route: `/pair` (or tabs under existing dashboard "Devices" page).
- [ ] Component: `PairDisplayPage.tsx`. Takes a `direction` prop (`send` or `receive`). On mount: generate ECDH keypair if `receive`, call `/device/start`, render QR + typed code, start polling.
- [ ] Wire the receive path to existing `storeAmk()` on success.
- [ ] Wire the send path to existing AMK-encryption-and-approve flow on pubkey arrival.
- [ ] Error states: code expired, max attempts exceeded, polling timeout, ECDH decrypt failure (suggests MITM — surface explicitly).
- [ ] Copy: role-aware. "Show this on your other device to receive AMK" vs "…to send AMK."

### Phase 4 — Joining-device UI (~ 0.5 day)

- [ ] Component: `PairJoinPage.tsx`. Two inputs: `[Scan QR]` (opens camera modal) and a text input `[XXXX-XXXX]`.
- [ ] Both inputs resolve to a slot ID. Branch on the slot's `role`:
  - `role=receive` → joiner is sender; perform ECDH against the displayer's pubkey, encrypt AMK, post via `approve`.
  - `role=send` → joiner is receiver; post own ECDH pubkey via `claim`, then poll for blob.
- [ ] Reuse the existing approval-screen pattern from `DevicePage.tsx` for the confirmation UX.
- [ ] Optional sanity-check display: receiver's IP + UA (for the sender to confirm "yes, that's my Windows PC").

### Phase 5 — Consolidation + cleanup (~ 0.5 day)

- [ ] Update existing sync-link UI: demote to "More options" / async-transfer-only framing. Don't break the `/sync/{id}` route — many existing links still in flight.
- [ ] Update existing payload-QR rendering (the QR-as-sync-link variant): either retire it in favor of rendezvous-QR, or keep it labeled as the "async link as QR" path for the niche use case. Preferred: retire payload-QR; rendezvous-QR is strictly better.
- [ ] Final UX pass: verify the user can always find at least one working path regardless of device camera situation.

### Phase 6 — Spec + docs (~ 0.5 day)

- [ ] Add a section to `spec/v1/server.md` documenting:
  - The web-to-web AMK transfer use case
  - The `secrt://pair/{slot_id}?role=…&pk=…` URL scheme
  - The role-aware slot semantics (when each side posts pubkey/blob)
  - The security upgrade: rendezvous-QR is opaque to interceptors in a way payload-QR is not
- [ ] Update `spec/v1/api.md` if any new endpoints or response fields land.
- [ ] Update `web/` docs / README with the rendezvous-channel UX model.
- [ ] No new test vectors needed — ECDH/AEAD primitives unchanged.

### Phase 7 — Decommission decision

- [ ] **Do not remove the sync link.** Async transfer is a real use case it uniquely covers.
- [ ] **Do** retire the payload-QR (today's QR-as-sync-link). Rendezvous-QR is strictly better in security and supports both directions.
- [ ] **Do** measure: instrument all three remaining channels (rendezvous-QR, typed code, sync link) for ~30 days post-launch. If sync link drops below ~5% of transfers, revisit removing it.

---

## Open Questions

1. **Should the receiver flow be accessible pre-login or post-login?** Today, `/device` requires the *approver* to be logged in but the *initiator* can be anonymous. For web-to-web transfer, the receiver needs to be logged in *as the same user* on the other device — but on the new device, the user has presumably just passkey-authenticated (tier-1) and is missing only AMK (tier-2). So receiver UI lives in the post-passkey, pre-AMK state. Worth confirming the routing exists for that intermediate state.

2. **Should we add a `purpose = "web-pair"` value?** Pro: cleaner metrics, easier to rate-limit independently. Con: more code, more tests, more surface area. Default: reuse `device-auth` unless metrics argue otherwise.

3. **Should the typed code be visually distinguishable from the existing CLI/app codes?** Probably not — same primitive, same length, same alphabet. Consistency wins.

4. **Out-of-band code verification (the SAS comparison from the original task-68 spec)?** Existing flows don't use it. Adding it would mean the user reads a 6-digit number on both screens and confirms they match. Pro: defense against ECDH key swap by a compromised server. Con: extra friction, the existing flows have decided this isn't worth the UX cost. Default: skip, document the residual risk in the spec.

---

## What This Plan Does NOT Include

- The "listening browser / inbox / SSE" architecture from the original task-68 description. Killed in the 2026-05-02 reconsideration; the typed-code primitive removes the need for it.
- Auto-send (zero-click). Killed for security reasons (turns logged-in browsers into AMK dispensers; loses the explicit-consent trail).
- Bluetooth. Killed because Web Bluetooth doesn't work cross-OS (Safari doesn't ship it).
- A native mobile app. Out of scope.

---

## Effort Summary

| Phase | Estimate |
|---|---|
| Backend tweaks + role field + tests | 0.5 day |
| Rendezvous URL scheme + QR render/scan helpers | 0.5 day |
| Displaying-device UI (`PairDisplayPage`) | 1 day |
| Joining-device UI (`PairJoinPage`) | 0.5 day |
| UX consolidation + payload-QR retirement | 0.5 day |
| Spec + docs | 0.5 day |
| **Total** | **~3.5 days** |

Slightly more than the typed-code-only version because of the QR scheme/rendering/scanning work — but bidirectional QR replaces the current one-directional payload-QR rather than adding to it, so net surface area shrinks.
