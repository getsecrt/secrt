# Third-Party Security Audit — Roadmap Notes

A reference for when, why, and how secrt would commission an independent security audit. Not a commitment; revisit as the project's scale and surface stabilize.

## Why an audit will eventually matter

secrt belongs to a small category of products whose pitch is "trust the operator with your secrets." The relevant peers — password managers (Bitwarden, 1Password), encrypted messaging (Signal), VPNs (Proton, Mullvad), encrypted mail (Proton, Tuta) — have all either commissioned independent audits or been audited by external researchers and can point to the reports.

The reason is structural: the user is asked to take a cryptographic claim ("the server cannot read your plaintext") on faith. Three ways exist to verify it: (1) read the source and audit the deployment, which effectively nobody does; (2) trust the operator's word, sufficient for individuals but not for businesses or non-trivial threat models; or (3) trust an independent auditor's word. At hobbyist scale, (2) is enough. For paid or B2B usage, (3) becomes table stakes.

A second benefit is at least as important: **the prep work for an audit captures most of the value.** Writing a complete threat model, documenting the deployment topology, making builds reproducible, and articulating non-goals are the activities that catch the bugs. The audit firm finds the rest.

## What an audit covers

Engagements typically combine some or all of three workstreams:

- **Cryptographic design review**
  - *What it examines:* protocol correctness, KDF parameters, key handling, side channels, randomness sources, envelope format.
  - *Typical artifact:* whitepaper-style writeup with findings.

- **Implementation audit**
  - *What it examines:* source code, lints, unsafe blocks, dependency graph, JS bundle integrity, supply chain.
  - *Typical artifact:* per-finding writeup with severity + reproduction.

- **Penetration testing**
  - *What it examines:* live system probing — auth bypass, injection, deployment misconfig, network exposure.
  - *Typical artifact:* pentest report with PoCs.

The highest-leverage scope for secrt would be a cryptographic design + implementation review of `secrt-core`, plus a light pentest of the live deployment.

## Timing

Audits are point-in-time: they assess a specific commit, and refactoring the crypto path afterward weakens the report's claims. They are also only as useful as the prep work, and they cost real money even when discounted.

The right trigger conditions are roughly:

- secrt.app has launched with paying users (or is near launch with confirmed buyers).
- The cryptographic core has been stable for ~3 months — no in-flight migrations.
- A public spec is canonical and a public threat model exists.
- Builds are reproducible.
- A documented story exists for how findings will be remediated.

A reasonable window is **6–18 months after secrt.app launches**, before any large public commitment that would benefit from the credibility.

## Audit options

Two tracks are relevant.

**Subsidized / FOSS ecosystem.** Several organizations fund or broker security audits for open-source privacy/security tools, and secrt fits the brief. The Open Technology Fund's Red Team Lab is the most natural first application — it funds independent audits for internet-freedom and privacy tools, brokered through OTF-vetted firms. OSTIF (Open Source Technology Improvement Fund) has coordinated audits of OpenSSL, OpenVPN, Tor, sigstore, and others. The NLnet Foundation (NGI0) and the Sovereign Tech Fund (Germany) are possible additional sources, particularly for projects with EU framing. Subsidized engagements typically have 3–6 months of lead time between application and audit.

**Full-fee firms.** Firms whose name on an audit carries weight in the FOSS privacy/security space include Cure53 (Bitwarden, Mullvad, Standard Notes, ProtonMail), Trail of Bits (crypto-heavy), NCC Group, Kudelski Security, Securitum (multiple Proton engagements), Doyensec (web-focused), and Radically Open Security (Dutch non-profit, FOSS-oriented). A scoped engagement — roughly 1–3 weeks of auditor time with a written report and retest of fixes — typically runs **USD $25K–$100K+** depending on firm and scope.

Default plan: apply to OTF Red Team Lab first; if rejected or timeline-incompatible, evaluate self-funding with a FOSS-aligned firm such as Cure53 or Radically Open Security.

## Compliance certifications (SOC 2, ISO 27001) — out of scope

SOC 2 and ISO 27001 are *operational-controls* certifications about company-level processes (access management, change management, onboarding/offboarding, incident response, vendor management). They do not assess product security and are largely vacuous for a project without employees — most of what they certify is process between people who do not exist.

They become relevant only when (a) secrt has employees whose access needs to be managed, or (b) a specific enterprise prospect demands one as a condition of a deal that justifies the ongoing cost (roughly $50K+/yr for SOC 2 Type II once compliance tooling like Vanta is included). Treat them as reactive — pursue only when a specific qualifying deal makes the math work. The code/cryptography audit, not SOC 2, is what addresses secrt's load-bearing trust claim.

## Prep work (start regardless of audit timing)

The following deliverables should exist before applying for OTF or paying a firm. Each has independent value:

1. **Public threat model.** Extend `docs/instance-trust-model.md` to cover server-side, network, and supply-chain adversaries — not just hostile-instance scenarios.
2. **Canonical spec at `spec/`.** Envelope format, KDF, protocol — documented to the point that a third party could implement a compatible client.
3. **Architecture overview.** Component diagram and data flow for the four main operations (create, retrieve, claim, expire).
4. **Public security overview page** linked from `secrt.app/security` and `secrt.ca`.
5. **Reproducible builds.** Anyone should be able to verify that the deployed `secrt.ca` JS bundle matches a checked-out commit. This is itself one of the highest-leverage trust signals.
6. **Remediation policy.** Disclosure window, fix SLA, where the report gets published.
7. **`SECURITY.md` at the repo root** with disclosure policy and contact.

## Next steps

Ordered by leverage; nothing here is urgent.

1. Extend `docs/instance-trust-model.md` into a full public threat model.
2. Harden `SECURITY.md` at the repo root.
3. Set up reproducible builds for the web bundle and verify deployed bundles match a checked-out commit.
4. Watch for an OTF Red Team Lab application window and apply when secrt.app is ~3 months from launch.
