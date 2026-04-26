# Instance Trust Model — Design Notes

*Status: pre-design. Memo, not a plan. Written 2026-04-25 by JD + Rachel after a conversation about whether the secrt project should publish a "master list of trusted instances."*

## TL;DR

There are two questions hiding in "should we maintain a list of trusted instances," and conflating them produces bad answers:

1. **A UX-routing question.** When a user pastes a link from instance B into instance A's "Get Secret" form, should A auto-redirect them to B? A small hardcoded allowlist of known sibling instances handles this fine. This is what task #54 covers. It is not a trust system; it is a typo/phishing guardrail on a convenience feature.

2. **A trust question.** When a user retrieves a secret from instance B, what evidence do they have that B's JS bundle is honest — i.e. that it actually runs the published, audited secrt code rather than a fork that exfiltrates plaintext after decryption? This is the real, hard question, and **the redirect logic does not change its answer.** The decryption JS that handles the plaintext is whoever hosts the link; routing the user there from another origin doesn't make the destination more or less trustworthy.

This doc is about question 2, with a brief note at the end on how it interacts with question 1.

## The threat we're talking about

A secrt instance — and *anyone* can run one, since the server and web bundle are open source — sits in the privileged position of both:

- holding the ciphertext envelope and the (one-time) ability to release it on a valid claim, and
- serving the JavaScript that decrypts it in the user's browser.

The server-side power is bounded by the zero-knowledge protocol: a misbehaving server can refuse to release the envelope, can lie about whether a secret was claimed, can collect metadata, and can *attempt* offline brute force against passphrase-protected envelopes if it wants to. It cannot read plaintext. That's the architectural promise.

The client-side power is not bounded by the protocol. It is bounded only by the integrity of the JS bundle. A hostile fork can ship a web bundle that decrypts the secret, displays it to the user as expected, *and* POSTs the plaintext to an attacker. The user has no way to know. The encryption is end-to-end *between the sender's browser and the receiver's browser* — but "the receiver's browser" is running whatever JS the receiving instance served, and that JS can do whatever it wants once it has the plaintext in memory.

This is not a hypothetical problem with secrt specifically — it is the structural weakness of every "encrypted in your browser" web app. PrivateBin, Bitwarden Web Vault, ProtonMail's web client, all of them inherit this property: the cryptographic strength of the design is bounded by your trust in the JS the operator served you on this page load. There's no escape inside a browser context. (Which is why ProtonMail pushes hard on the desktop apps and why password managers prefer native binaries.)

So when we ask "is instance X trustworthy," we are really asking: do I trust the operator of X to run the published code, on the day I am using X, served via a TLS connection that hasn't been MITMed by a CDN or a compromised origin? That is a question about a person and an operational practice, not about a domain name.

## Why a hardcoded allowlist isn't a trust system

The proposal in #54 is to ship something like:

```ts
const KNOWN_INSTANCES = ['secrt.ca', 'secrt.is'];
```

This is fine for what it is — a list of "instances we will auto-redirect to without making the user click confirm." It says nothing about whether secrt.is is currently running honest code today. It says only that *we, the project maintainers, at the time we cut this release, considered secrt.is part of the official family.* The list is a snapshot of identity, not a real-time attestation of behaviour.

Things a hardcoded allowlist does **not** give you:

- **No revocation on a fast clock.** If secrt.is gets compromised on a Tuesday, the only way to remove it from the allowlist is to ship a web release. Users on stale tabs keep getting redirected.
- **No attestation of bundle integrity.** Being on the list doesn't mean the bundle being served is the published one. An operator can be "official" and still ship a tampered bundle, deliberately or via supply-chain compromise.
- **No coverage for community instances.** Anyone who self-hosts is invisible. Their users either get rejected, or get a "we don't know this instance" warning that doesn't help them decide.
- **No transparency.** A user can't verify *why* `secrt.is` is on the list. They have to trust the maintainers' judgment without any underlying signal.

A hardcoded allowlist is honest about being small and maintainer-curated, which is actually its main virtue — it's the right tool for the routing problem and an obviously inadequate tool for the trust problem.

## Mechanisms worth considering for the trust problem

Listed roughly from cheap-and-shallow to expensive-and-real. None of these are *commitments*. They are options worth weighing.

### 1. Signed instance manifest

Project publishes a JSON file at e.g. `https://secrt.dev/instances.json`, signed with a project key (or a key in a `.well-known` minisign/age setup). The file lists canonical instances along with metadata:

```json
{
  "instances": [
    {
      "host": "secrt.ca",
      "operator": "secrt project",
      "jurisdiction": "CA",
      "added": "2025-09-12",
      "notes": "Primary deployment"
    },
    {
      "host": "secrt.is",
      "operator": "secrt project",
      "jurisdiction": "IS",
      "added": "2026-04-15"
    }
  ],
  "issued_at": "2026-04-25T00:00:00Z",
  "valid_until": "2026-05-25T00:00:00Z"
}
```

Apps fetch on startup, cache, fall back to embedded copy if fetch fails. A signed expiring manifest gives you fast revocation (drop an instance, ship a new manifest) without requiring a binary release.

What this gets us: a real-time-ish identity statement. What it does *not* get us: any guarantee that `secrt.is` is actually running honest JS right now. It's still about *who is on the list*, not *what they are running*.

### 2. Bundle attestation in the manifest

Extension of (1). Each instance in the manifest pledges to serve a web bundle whose hash is also listed:

```json
{
  "host": "secrt.is",
  "expected_bundle_sha256": "ab12cd34..."
}
```

Combined with Subresource Integrity (SRI) on the served HTML's `<script>` tags, a third-party verifier (or the Tauri desktop app, or a power-user browser extension) can fetch the bundle and check it against the pledged hash.

What this gets us: a *checkable* attestation. If secrt.is silently swaps in malicious JS, the hash doesn't match, and external watchers can detect it. The casual web user still doesn't have great defenses — they'd need a browser extension that verifies, which most users won't have. But it dramatically raises the cost of attack: a hostile operator now has to either also forge the manifest (signed, hard) or accept that any monitor will catch them within minutes.

What it does not get us: defense against the operator updating the manifest *honestly* with a new bundle hash that just happens to be malicious. The signing key holder is the trust anchor, full stop.

### 3. Reproducible builds + public transparency log

Every official release of the web bundle gets its hash appended to an append-only log (à la Certificate Transparency). The log is independently mirrored. Anyone can verify that "the bundle hash my browser just got" appears in the log.

What this gets us: structural defense against targeted attacks. An attacker who compromises an operator and serves a malicious bundle to a specific user *cannot* keep that bundle out of the log without colluding with the log operators. So the attack becomes globally visible. CT-style transparency is a real upgrade in security posture and used in practice for very high-value systems.

What it costs: actual, real engineering. Reproducible builds in particular are a significant investment. Worth it only if secrt grows into something where the threat model justifies it — e.g. used by journalists in hostile jurisdictions, used by enterprises with regulatory exposure.

### 4. The desktop app as the trust anchor

This is the framing I keep coming back to and I think it's the most important one.

The Tauri desktop app ships JS *inside the signed binary*. It does not load JS from the server it talks to. It can connect to `secrt.ca`, `secrt.is`, your team's self-hosted `secrt.acme.corp`, or a pirate fork at `evil.tld`, and the encryption/decryption code running in the app is the *same code every time* — the one we shipped, signed with our key. The server only ever sees ciphertext, claim tokens, and commitments. There is no "the operator served bad JS" attack surface, because the operator does not get to serve JS.

This means:

- **The desktop app's trust is per-binary**, which is something we control.
- **The web app's trust is per-origin**, which is a property of who hosts the origin, and is mostly outside our control.

So the natural product framing is:

- **Web = convenience tier.** "We make a best effort. The trust unit here is the operator of whatever origin you're on. If you care, use the app."
- **Desktop = trust tier.** "One signed binary, encryption never leaves the binary, talks to whatever server you point it at."
- **Self-hosting = your own trust circle.** "You compiled it (or pulled the released image and verified the hash), you trust your ops team, your team's apps point at your server, you don't need anyone else's permission."

Lean into this and a "master list of trusted instances" becomes less load-bearing. The list is no longer a trust gate — it's a discovery aid for casual users picking a public instance to send a one-off secret. The serious users are on the desktop app, and for them the question "is this server honest" reduces to "does the protocol still hold," which the desktop binary already verifies as much as is verifiable.

## How the redirect interaction shakes out

Returning to question 1 (the UX one) now that question 2 is on paper:

If the trust model lives mostly in the desktop binary, then on the web, the redirect is just a routing decision and a hardcoded allowlist is the right tool. The threat to defend against is "user pasted a link to a typosquat," not "user pasted a link to a hostile server." The latter is *unsolvable on the web*, so trying to solve it via redirect logic is a category error.

In the desktop app, the redirect is *not* a trust event — clicking through to secrt.is in a browser would trade the trusted binary for the web app's per-origin trust, which is a downgrade. So the desktop should *not* auto-redirect; it should warn, or, once #49 lands, offer to switch the active instance internally so the trusted binary handles the claim against the new server. That keeps the user inside the strong tier rather than punting them to the weak tier.

That gives us the current task split:

- **#54 (cross-instance redirect):** ship the hardcoded allowlist. Don't pretend it's a trust system. Document the limitation in the release notes ("the web app trusts whatever origin you're on; for stronger guarantees, use the desktop app").
- **#45 (jurisdiction picker UX) and #49 (custom host config):** these *are* the surfaces where the trust framing lives. The picker is where users learn that "Iceland or Canada" is a *jurisdictional* choice, not a *cryptographic* one. The custom-host config is where the desktop app demonstrates "we work with any compliant server, your choice of trust."
- **This doc / a future design task:** decide if and when we invest in (1)–(3) above. Probably (1) is the next step if the project grows enough to need third-party verifiability. (3) is interesting if we ever serve a high-stakes user base.

## Open questions

- **Who holds the project signing key, and how is it rotated?** Any of the manifest schemes assumes a project key. Today there is no such key. Setting one up is a governance question as much as a technical one — solo project vs. multi-maintainer changes the answer.

- **Does the web bundle leak its identity to the server?** If we ever want server-side attestation (e.g. the receiving server checks the requesting bundle is on the allowlist), we'd need bundle identity in the request. Worth thinking about whether we ever want this — there's a tradeoff against client privacy.

- **What's the right UX for "you're using a fork we don't recognize"?** Today: nothing happens, it works. Future: probably a one-time "you're using `secrt.acme.corp` — is this your team's instance?" confirmation, dismissable, remembered. Soft signal, not a hard block. Self-hosters should not have to fight the UX.

- **Does a transparency log even make sense for a project this size?** CT works because there are many independent log operators with adversarial incentives. A secrt log would have to be operated by us, which means we'd be both the publisher and the witness. Maybe we lean on existing infrastructure (sigstore's Rekor?) rather than rolling our own.

- **What's the security claim we want on the marketing site?** Right now the home page implies a strong end-to-end story. As soon as multi-instance is real, the claim needs to be honest about the per-origin trust property of the web app. "Zero-knowledge server, but the JS is whoever served it" is a more honest framing — and frankly, leaning into it differentiates us from competitors who handwave the same problem.

## Status / next step

Park this. Revisit if/when:
- A third instance shows up (community-run, self-hosted public), forcing us to decide what to do with non-project hosts.
- Someone asks for verifiable evidence that a specific instance is running honest code (security-conscious user, or a B2B prospect doing due diligence).
- We're staffing more than just JD on the project and the governance question gets real.

Until then, ship #54 as described, treat the allowlist as the routing tool it is, and let the trust question wait for a load-bearing reason to answer it.
