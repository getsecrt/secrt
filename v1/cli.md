# CLI Specification (v1)

Status: Draft v1 (normative for CLI interoperability once accepted)

This document defines a v1-compatible CLI for `secrt.ca`.

The CLI is a client of:

- `spec/v1/api.md` (HTTP API contract)
- `spec/v1/envelope.md` (client-side crypto + envelope format)

The API contract remains canonical on the wire. CLI ergonomics are defined here.

## Normative Language

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used as defined in RFC 2119.

## Security Invariants

A conforming CLI:

- MUST encrypt/decrypt locally using `spec/v1/envelope.md`.
- MUST NOT send plaintext, URL fragment keys, passphrases, or decrypted plaintext to the server.
- MUST NOT log plaintext, passphrases, claim tokens, or URL fragments to stderr/stdout logs.
- SHOULD avoid unsafe input methods that leak to shell history.

## Command Surface (v1)

Reference binary name in examples: `secrt`.

Required commands:

- `secrt create`
- `secrt claim <share-url>`

Optional command:

- `secrt burn <id-or-share-url>` (API-key authenticated)

Built-in commands:

- `secrt --version` or `secrt version`: print version string and exit.
- `secrt --help` or `secrt help`: print top-level usage and exit.
- `secrt <command> --help` or `secrt help <command>`: print command-specific usage and exit.
- `secrt completion <shell>`: emit shell completion script (see Shell Completions below).

Operational/admin API-key management commands are implementation-specific and out of scope for this client-interoperability spec.

## Global Options

All commands SHOULD support:

- `--base-url <url>`: base service URL (default: `https://secrt.ca`).
- `--api-key <key>`: API key when using authenticated API endpoints.
- `--json`: machine-readable output mode.
- `--help`, `-h`: print usage for current command and exit.
- `--version`, `-v`: print version string and exit (top-level only).

Environment variable fallbacks are RECOMMENDED:

- `SECRET_BASE_URL`
- `SECRET_API_KEY`

Configuration precedence (RECOMMENDED):

1. Explicit CLI flag (highest priority)
2. Environment variable
3. OS keychain (optional; see Configuration below)
4. Configuration file (see Configuration below)
5. Built-in default (lowest priority)

## Configuration

Implementations MAY support persistent configuration via a config file and/or OS keychain to reduce repetitive flag usage and avoid credentials appearing in shell history or process lists.

### Config File

Location: `$XDG_CONFIG_HOME/secrt/config.toml`, falling back to `~/.config/secrt/config.toml` if `XDG_CONFIG_HOME` is unset. TOML format is RECOMMENDED for cross-language compatibility.

Supported keys:

| Key | Type | Description |
|---|---|---|
| `api_key` | string | API key for authenticated endpoints |
| `base_url` | string | Base service URL |
| `passphrase` | string | Default passphrase for encryption/decryption |

Example:

```toml
api_key = "sk_live_abc123"
base_url = "https://my-server.example.com"
passphrase = "my-default-passphrase"
```

#### File Permission Requirements

On Unix systems, the config file MUST be checked for safe permissions before loading secrets:

- If the file is group-readable or world-readable (i.e., mode bits `0o077` are set), implementations MUST warn to stderr and MUST NOT load secret-bearing fields (`api_key`, `passphrase`) from the file.
- Non-secret fields (`base_url`) MAY still be loaded from a file with open permissions.
- The recommended file mode is `0600` (owner read/write only).
- Implementations SHOULD suggest a fix in the warning message (e.g., `chmod 600 <path>`).

If the config file does not exist, no error is produced and all values fall through to built-in defaults.

If the config file contains invalid TOML, implementations SHOULD warn to stderr and continue with defaults.

### OS Keychain (Optional)

Implementations MAY support reading credentials from the operating system's native credential store:

- **macOS:** Keychain (Security.framework)
- **Linux:** kernel keyutils or Secret Service (D-Bus)
- **Windows:** Credential Manager

Keychain support is OPTIONAL and MAY be gated behind a build-time feature flag (e.g., `--features keychain` in Rust, build tags in Go).

Supported credential keys:

| Key | Description |
|---|---|
| `api_key` | API key for authenticated endpoints |
| `passphrase` | Default passphrase for encryption/decryption |

Service name for keychain entries: `secrt`.

Keychain errors (missing credential, unavailable keychain) MUST be handled gracefully by falling through to the next tier in the precedence chain (config file, then built-in default). Keychain failures MUST NOT produce user-visible errors unless the user explicitly requested keychain storage.

### Passphrase from Configuration

When a passphrase is provided via config file or keychain (and no explicit `--passphrase-*` flag is set), the passphrase SHOULD be used silently without prompting for confirmation — it is a pre-configured default, not interactive input.

Explicit passphrase flags (`--passphrase-prompt`, `--passphrase-env`, `--passphrase-file`) always take precedence over a configured passphrase.

## Output Discipline

To support piping and composition:

- **stdout**: MUST contain only the primary output (share link for `create`, plaintext for `claim`, completion script for `completion`).
- **stderr**: all status messages, prompts, warnings, and errors.

This ensures patterns like `secrt create < secret.txt | pbcopy` work cleanly.

In `--json` mode, the JSON object is printed to stdout. Errors in `--json` mode SHOULD also be JSON on stderr when practical.

## Authenticated Mode

Supplying `--api-key` is RECOMMENDED for automation and high-volume usage.

Authenticated mode enables:

- Higher service limits than anonymous/public calls (rate + storage quotas).
- Ownership-bound management operations like `burn`.
- Future owner metadata APIs (for example listing active secrets) without changing trust model.

`claim` remains token-based and does not require an API key.

## TTL Input Grammar

The CLI accepts human-friendly TTL input and converts it to API `ttl_seconds`.

Grammar:

- `<ttl> := <positive-integer> [unit]`
- `unit := s | m | h | d | w`

Semantics:

- No unit means seconds (`s`) by default.
- `m` = minutes (60s), `h` = hours (3600s), `d` = days (86400s), `w` = weeks (604800s).
- TTL MUST be converted to integer `ttl_seconds` before API calls.
- Resulting `ttl_seconds` MUST satisfy API bounds (`1..31536000`).

Examples:

- `90` -> `90`
- `90s` -> `90`
- `5m` -> `300`
- `2h` -> `7200`
- `2d` -> `172800`
- `1w` -> `604800`

Rejection rules (MUST reject with a clear error):

- Ambiguous or unknown units (`month`, `minute`, `ms`, etc.)
- Prefix matching (for example interpreting `month` by first letter) MUST NOT be used.
- Zero/negative values, whitespace-separated values (`1 d`), decimals (`1.5m`)

Rationale: strict parsing avoids ambiguity and sharp edges in security-sensitive workflows.

## `create`

Creates a one-time secret by encrypting locally, then uploading ciphertext envelope.

Usage:

```bash
secrt create [--ttl <ttl>] [--api-key <key>] [--base-url <url>] [--json]
                         [--text <value> | --file <path>]
                         [--passphrase-prompt | --passphrase-env <name> | --passphrase-file <path>]
```

Behavior:

1. CLI selects plaintext input source:
   - Default: stdin.
   - Optional: `--text` or `--file`.
   - Exactly one source MUST be selected.
   - When reading from stdin with a TTY attached, the CLI SHOULD print a prompt to stderr (e.g., `"Enter secret (Ctrl+D to finish):"`) so the user knows input is expected.
   - Empty input MUST be rejected.
2. CLI performs envelope creation per `spec/v1/envelope.md`.
3. CLI computes `claim_hash = base64url(sha256(claim_token_bytes))`.
4. CLI sends create request:
   - Anonymous: `POST /api/v1/public/secrets`
   - Authenticated (`--api-key` set): `POST /api/v1/secrets`
5. CLI outputs a share link containing the URL fragment key:
   - `<share_url>#v1.<url_key_b64>`

Output:

- Default mode: print share link only.
- `--json` mode: include at minimum `id`, `share_url`, `share_link`, `expires_at`.

Input security note:

- `--text` passes secret content as a process argument, which is visible in shell history and `ps` output. Implementations SHOULD document this risk. Prefer stdin or `--file` for sensitive content.

Passphrase handling:

- Implementations SHOULD support `--passphrase-prompt`.
- Implementations MAY support `--passphrase-env` and `--passphrase-file`.
- Implementations SHOULD NOT support passphrase values directly in command arguments (high leakage risk via shell history/process list).
- When using `--passphrase-prompt` during `create`, implementations SHOULD prompt for confirmation (enter passphrase twice) to prevent typos that would make the secret unrecoverable.

## `claim`

Claims and decrypts a secret once.

Usage:

```bash
secrt claim <share-url> [--base-url <url>] [--json]
                        [--passphrase-prompt | --passphrase-env <name> | --passphrase-file <path>]
```

Behavior:

1. Parse `<id>` from `/s/<id>` and parse fragment `#v1.<url_key_b64>`.
2. Derive `claim_token_bytes` and `enc_key` per `spec/v1/envelope.md`.
3. Send `POST /api/v1/secrets/{id}/claim` with `{ "claim": base64url(claim_token_bytes) }`.
4. On `200`, decrypt locally and print plaintext.
5. On `404`, return a generic failure message (not found / expired / already claimed / invalid claim) and non-zero exit.

Output:

- Default mode: print plaintext to stdout only.
- `--json` mode: SHOULD avoid embedding plaintext unless explicitly requested by implementation, to reduce accidental logging exposure.

## `burn` (optional)

Deletes a secret without claiming it.

Usage:

```bash
secrt burn <id-or-share-url> --api-key <key> [--base-url <url>] [--json]
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

## Shell Completions

The CLI SHOULD provide a `completion` subcommand that emits shell completion scripts:

```bash
secrt completion bash
secrt completion zsh
secrt completion fish
```

Behavior:

- Print the completion script to stdout for the requested shell.
- Unknown shell names MUST produce a clear error listing supported shells.
- Users install completions via shell-standard mechanisms (e.g., `secrt completion bash > /etc/bash_completion.d/secrt`).

Implementation note: given the small command surface, completion scripts SHOULD be embedded as string constants (no external dependencies). Template substitution MAY be used if the binary name is configurable.

## HTTP Client Behavior

- Default request timeout: 30 seconds. Implementations MAY allow override via `--timeout` in a future version.
- The CLI SHOULD respect standard proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) via the runtime's default HTTP transport.
- TLS certificate verification MUST NOT be skippable. No `--insecure` flag — this is a security-sensitive tool.

## Interoperability Requirements

To be considered v1-compatible, a CLI implementation MUST:

- Pass envelope test vectors once available (`spec/v1/envelope.vectors.json`).
- Map TTL values exactly as specified in this document.
- Produce API payloads that satisfy `spec/v1/api.md`.
