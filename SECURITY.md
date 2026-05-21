# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in secrt, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email **security@secrt.ca** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional)

You should receive an acknowledgment within 48 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Disclosure Timeline

Once a report is received we aim to:

- **Acknowledge** the report within 48 hours.
- **Triage** and assign severity within 7 days.
- **Fix** critical issues within 30 days, high-severity within 90 days, and lower-severity issues within 180 days.
- **Publish** an advisory once a fix is released — as a GitHub Security Advisory and a `Security` entry in the relevant CHANGELOG.

We ask reporters to allow up to **90 days** between the initial report and any public disclosure, extended by mutual agreement if the fix legitimately takes longer. Reporters acting in good faith will be publicly credited in the advisory unless they prefer to remain anonymous.

## Safe Harbor

We will not pursue legal action against security researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, or service disruption.
- Only access data necessary to demonstrate the vulnerability.
- Give us reasonable time to investigate and address the issue before any public disclosure.
- Do not exploit a vulnerability beyond what is necessary for a proof of concept.

This applies to research conducted against secrt's official deployments (`secrt.is`, `secrt.ca`) and the source code in this repository. Activities clearly outside good-faith research — accessing other users' secrets, denial-of-service attacks, social engineering of operators, or attempts to access non-public infrastructure — are not covered.

## Scope

The following are in scope for security reports:

- **Cryptographic issues:** weaknesses in the AES-256-GCM, HKDF-SHA256, or Argon2id implementation
- **Server-side data leaks:** any path where the server could access or log plaintext, decryption keys, or passphrases
- **Claim atomicity failures:** scenarios where a secret could be read more than once
- **Authentication bypass:** unauthorized access to API-key-protected endpoints
- **Rate limiter bypass:** circumventing per-IP or per-key rate limits
- **Injection attacks:** SQL injection, command injection, or header injection

## Design Principles

secrt is built on a zero-knowledge architecture:

- All encryption and decryption happens client-side
- The server only stores and serves ciphertext
- Decryption keys are never sent to the server (they live in the URL fragment)
- Secrets are atomically claimed and deleted — read-once by design
- No plaintext, passphrases, PINs, or URL fragments are ever logged
