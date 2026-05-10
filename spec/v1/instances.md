# Official Instances (v1)

Status: Active (normative for trust-policy interoperability)

This document defines which secrt instances are **official** — that is,
operated by the secrt project itself and held to the security guarantees
of this repository. Conforming clients (CLI, web SPA, desktop app) use
this list to decide when to warn users that they are interacting with a
server the project does not vouch for.

The machine-readable companion is `spec/v1/instances.json`. Both
documents MUST be updated together; tests in Rust and TypeScript pin
each implementation's in-code constant to the JSON list and will fail
on drift.

## Normative Language

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used as
defined in RFC 2119.

## Official Instances

The following hosts are official secrt instances:

- `secrt.ca` — primary deployment (DigitalOcean, Canada)
- `secrt.is`  — Iceland deployment (1984.hosting, Iceland)

A host is *official* iff:

1. Its source code is built from the `getsecrt/secrt` repository at a
   tagged release commit.
2. Its CLI / desktop binaries are signed by the project's Developer ID
   (Apple) and Trusted Signing (Windows) credentials.
3. Its web SPA bundle is identical to the bundle produced from the same
   tagged commit (subject to reproducible-build limitations; cross-host
   bundle attestation is a future work item — see Non-Goals).
4. Its security contact is `security@<host>` (e.g.
   `security@secrt.ca`).
5. Its hosting provider and country are disclosed in
   `instances.json` and surfaced in the SPA's privacy page.

## Wildcard-Trust Invariant

Every host under an official apex (e.g. `my.secrt.is`,
`team.secrt.ca`, `foo.bar.secrt.ca`) MUST serve the same backend, the
same storage, and the same SPA bundle as its apex. Conforming clients
MAY collapse any subdomain of an official apex to the apex for trust
decisions.

If the project ever introduces per-tenant subdomains, custom user
subdomains, or any other split-trust model under an official apex,
this invariant — and this document — MUST be updated in the same
release.

## Trust Verdicts

Conforming clients SHOULD classify any base URL into one of four
verdicts:

- **Official** — the URL's normalized origin matches an entry in the
  official list, with `https` scheme and default port.
- **TrustedCustom** — the URL's host appears in a user-managed
  trust list (e.g. the CLI's `trusted_servers` config key). Self-hosters
  use this verdict to silence the off-list warning for their own
  deployment.
- **DevLocal** — the host is `localhost`, `127.0.0.0/8`, an IPv6
  loopback, or `*.local`. Used for development and integration testing;
  no warning emitted.
- **Untrusted** — none of the above. Conforming clients MUST emit a
  loud warning before any send/get/sync/auth operation against an
  Untrusted host. Conforming clients MUST refuse to send API keys to
  an Untrusted URL-derived host that does not match the user's
  configured base URL (see `cli.md § Instance trust`).

A non-default port on an official apex (e.g. `https://secrt.ca:8443`)
is **not** Official. Operators running on a non-default port are
considered self-hosters and MUST be added to the user's
`trusted_servers` list to silence warnings.

## Adding or Removing an Instance

A change to the official-instance set is a coordinated, reviewed
release:

1. The PR MUST update `spec/v1/instances.md` and
   `spec/v1/instances.json` in the same commit.
2. The PR MUST update the `KNOWN_INSTANCES` constant in
   `crates/secrt-core/src/instance.rs` and the corresponding
   TypeScript constant in `web/src/lib/config.ts`.
3. The PR MUST update `getInfrastructure()` in `web/src/lib/config.ts`
   and the equivalent Rust facts to match the new JSON.
4. The PR description MUST state the operational facts (provider,
   country, security contact, deployment date).
5. Removing an instance requires a deprecation notice in the changelog
   for at least one release before the removal lands; conforming
   clients SHOULD continue to recognize the deprecated apex as
   Official until the removal release.

## Non-Goals

This specification does **not** establish:

- A reproducible-build attestation that the SPA bundle is byte-identical
  across official instances. That guarantee requires signed bundle
  manifests published out-of-band, which is a separate work item.
- A trust-on-first-use scheme for self-hosters. The
  `TrustedCustom` verdict is configured locally; the project does not
  maintain a federated registry of community instances.
- A mechanism for users to verify that the binary they are running
  matches a published hash of an official release. Binary signing
  (Apple Developer ID, Windows Trusted Signing) is the current trust
  anchor; an independent verification pathway is future work.

## Self-Hoster Notice

Operators running their own secrt deployments:

- MUST NOT describe their deployment as "official", "primary", or
  imply project endorsement.
- MUST publish their own security contact and hosting facts.
- SHOULD configure their CLI users with the appropriate
  `trusted_servers` entry rather than encouraging users to disable
  warnings globally.
