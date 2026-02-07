# CLI Specification (v1)

Status: Draft v1 (normative for CLI interoperability once accepted)

This document defines a v1-compatible CLI for `secrt.ca`.

The CLI is a client of:

- `/Users/jdlien/code/secret/spec/v1/api.md` (HTTP API contract)
- `/Users/jdlien/code/secret/spec/v1/envelope.md` (client-side crypto + envelope format)

The API contract remains canonical on the wire. CLI ergonomics are defined here.

## Normative Language

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used as defined in RFC 2119.

## Security Invariants

A conforming CLI:

- MUST encrypt/decrypt locally using `/Users/jdlien/code/secret/spec/v1/envelope.md`.
- MUST NOT send plaintext, URL fragment keys, passphrases, or decrypted plaintext to the server.
- MUST NOT log plaintext, passphrases, claim tokens, or URL fragments to stderr/stdout logs.
- SHOULD avoid unsafe input methods that leak to shell history.

## Command Surface (v1)

Reference binary name in examples: `secrt`.

Required commands:

- `secrt secret create`
- `secrt secret claim <share-url>`

Optional command:

- `secrt secret burn <id-or-share-url>` (API-key authenticated)

Operational/admin API-key management commands are implementation-specific and out of scope for this client-interoperability spec.

## Global Options

All commands SHOULD support:

- `--base-url <url>`: base service URL (default from environment or implementation default).
- `--api-key <key>`: API key when using authenticated API endpoints.
- `--json`: machine-readable output mode.

Environment variable fallbacks are RECOMMENDED:

- `SECRET_BASE_URL`
- `SECRET_API_KEY`

Configuration precedence (RECOMMENDED):

1. Explicit CLI flag
2. Environment variable
3. Built-in default

## TTL Input Grammar

The CLI accepts human-friendly TTL input and converts it to API `ttl_seconds`.

Grammar:

- `<ttl> := <positive-integer> [unit]`
- `unit := s | m | d | w`

Semantics:

- No unit means seconds (`s`) by default.
- `m` = minutes (60s), `d` = days (86400s), `w` = weeks (604800s).
- TTL MUST be converted to integer `ttl_seconds` before API calls.
- Resulting `ttl_seconds` MUST satisfy API bounds (`1..31536000`).

Examples:

- `90` -> `90`
- `90s` -> `90`
- `5m` -> `300`
- `2d` -> `172800`
- `1w` -> `604800`

Rejection rules (MUST reject with a clear error):

- Ambiguous or unknown units (`h`, `month`, `minute`, `ms`, etc.)
- Prefix matching (for example interpreting `month` by first letter) MUST NOT be used.
- Zero/negative values, whitespace-separated values (`1 d`), decimals (`1.5m`)

Rationale: strict parsing avoids ambiguity and sharp edges in security-sensitive workflows.

## `secret create`

Creates a one-time secret by encrypting locally, then uploading ciphertext envelope.

Usage:

```bash
secrt secret create [--ttl <ttl>] [--api-key <key>] [--base-url <url>] [--json]
                         [--text <value> | --file <path>]
                         [--passphrase-prompt | --passphrase-env <name> | --passphrase-file <path>]
```

Behavior:

1. CLI selects plaintext input source:
   - Default: stdin.
   - Optional: `--text` or `--file`.
   - Exactly one source MUST be selected.
2. CLI performs envelope creation per `/Users/jdlien/code/secret/spec/v1/envelope.md`.
3. CLI computes `claim_hash = base64url(sha256(claim_token_bytes))`.
4. CLI sends create request:
   - Anonymous: `POST /api/v1/public/secrets`
   - Authenticated (`--api-key` set): `POST /api/v1/secrets`
5. CLI outputs a share link containing the URL fragment key:
   - `<share_url>#v1.<url_key_b64>`

Output:

- Default mode: print share link only.
- `--json` mode: include at minimum `id`, `share_url`, `share_link`, `expires_at`.

Passphrase handling:

- Implementations SHOULD support `--passphrase-prompt`.
- Implementations MAY support `--passphrase-env` and `--passphrase-file`.
- Implementations SHOULD NOT support passphrase values directly in command arguments (high leakage risk via shell history/process list).

## `secret claim`

Claims and decrypts a secret once.

Usage:

```bash
secrt secret claim <share-url> [--base-url <url>] [--json]
                        [--passphrase-prompt | --passphrase-env <name> | --passphrase-file <path>]
```

Behavior:

1. Parse `<id>` from `/s/<id>` and parse fragment `#v1.<url_key_b64>`.
2. Derive `claim_token_bytes` and `enc_key` per `/Users/jdlien/code/secret/spec/v1/envelope.md`.
3. Send `POST /api/v1/secrets/{id}/claim` with `{ "claim": base64url(claim_token_bytes) }`.
4. On `200`, decrypt locally and print plaintext.
5. On `404`, return a generic failure message (not found / expired / already claimed / invalid claim) and non-zero exit.

Output:

- Default mode: print plaintext to stdout only.
- `--json` mode: SHOULD avoid embedding plaintext unless explicitly requested by implementation, to reduce accidental logging exposure.

## `secret burn` (optional)

Deletes a secret without claiming it.

Usage:

```bash
secrt secret burn <id-or-share-url> --api-key <key> [--base-url <url>] [--json]
```

Behavior:

- Resolve `<id>` and call `POST /api/v1/secrets/{id}/burn`.
- Requires API key auth.

## Error and Exit Behavior

Recommended exit codes:

- `0`: success
- `2`: usage or argument parsing error
- `1`: operational failure (network, API error, decrypt failure, secret unavailable)

Error messages MUST NOT reveal secret material.

Recommended HTTP error mapping:

- Create `400`: invalid input (envelope, claim hash, ttl, JSON shape)
- Create/claim/burn `429`: rate limited
- Claim `404`: generic unavailable result (not found, expired, already claimed, invalid claim)
- Authenticated endpoints `401`/`403`: invalid or unauthorized API key

## Interoperability Requirements

To be considered v1-compatible, a CLI implementation MUST:

- Pass envelope test vectors once available (`/Users/jdlien/code/secret/spec/v1/envelope.vectors.json`).
- Map TTL values exactly as specified in this document.
- Produce API payloads that satisfy `/Users/jdlien/code/secret/spec/v1/api.md`.
