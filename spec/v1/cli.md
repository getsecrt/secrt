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

- `secrt send`
- `secrt get <share-url>`

Optional commands:

- `secrt burn <id-or-share-url>` (API-key authenticated)
- `secrt gen` (password generation)

Built-in commands:

- `secrt --version` or `secrt version`: print version string and exit.
- `secrt --help` or `secrt help`: print top-level usage and exit.
- `secrt <command> --help` or `secrt help <command>`: print command-specific usage and exit.
- `secrt completion <shell>`: emit shell completion script (see Shell Completions below).
- `secrt config`: show effective settings (resolved from all sources).
- `secrt config init [--force]`: create a template config file.
- `secrt config path`: print the config file path.
- `secrt config set-passphrase`: store default passphrase in OS keychain.
- `secrt config delete-passphrase`: remove passphrase from OS keychain.

### Implicit `get` from Share URL

When the first positional argument is not a recognized command but contains a `#` followed by a base64url string of at least 22 characters (indicating a share URL or bare ID with fragment), the CLI MUST treat the invocation as `secrt get <arg> [remaining args...]`. This allows users to run:

```bash
secrt https://secrt.ca/s/abc123#key...
```

as shorthand for:

```bash
secrt get https://secrt.ca/s/abc123#key...
```

The detection MUST be based on the presence of `#` followed by a base64url string (characters `[A-Za-z0-9_-]`) of at least 22 characters. The 22-character threshold (16 bytes in base64url) prevents false positives on short fragments while remaining well below the actual 43-character key length. Full URL validation is deferred to the `get` command's normal parsing.

Operational/admin API-key management commands are implementation-specific and out of scope for this client-interoperability spec.

## Global Options

All commands SHOULD support:

- `--base-url <url>`: base service URL (default: `https://secrt.ca`).
- `--api-key <key>`: local API key (`sk2_<prefix>.<root_b64>`) for authenticated API endpoints.
- `--json`: machine-readable output mode.
- `--silent`: suppress non-essential stderr output (prompts, status, labels). Errors are never suppressed.
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
| `api_key` | string | local API key (`sk2_<prefix>.<root_b64>`) for authenticated endpoints |
| `base_url` | string | Base service URL |
| `default_ttl` | string | Default TTL for secrets (e.g., `5m`, `2h`, `1d`, `1w`) |
| `passphrase` | string | Default passphrase for encryption/decryption |
| `decryption_passphrases` | string[] | Additional passphrases to try when claiming (tried in order) |
| `show_input` | bool | Show secret input as typed (default: `false`) |
| `use_keychain` | bool | Enable OS keychain lookups for credentials (default: `false`) |

`default_ttl` precedence: `--ttl` flag > config `default_ttl` > none (server decides).

`default_ttl` is validated at create time using the TTL grammar defined below, not at config load time.

Example:

```toml
api_key = "sk2_abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
base_url = "https://my-server.example.com"
default_ttl = "24h"
passphrase = "my-default-passphrase"
decryption_passphrases = ["old-passphrase", "team-passphrase"]
show_input = false
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

### Passphrase Trial Order During Claim

When no explicit passphrase flag (`-p`, `--passphrase-env`, `--passphrase-file`) is set, implementations SHOULD try configured passphrases in this order:

1. `passphrase` from keychain/config (the existing default passphrase, tried first)
2. Each entry in `decryption_passphrases` (in order, deduplicated against #1)
3. Interactive prompt on TTY / error on non-TTY

When an explicit passphrase flag is set, the `decryption_passphrases` list is bypassed entirely — explicit flags represent deliberate user action.

Only `DecryptionFailed` errors should trigger the next candidate; other errors (e.g., `InvalidEnvelope`) should propagate immediately.

`decryption_passphrases` is a secret-bearing field and MUST be subject to the same file permission requirements as `api_key` and `passphrase`.

### Keychain Storage for Passphrase Lists

Implementations MAY support storing `decryption_passphrases` in the OS keychain as a JSON-encoded array string (e.g., `["p1","p2"]`). If JSON parsing fails, the raw string SHOULD be treated as a single-entry list (graceful fallback). Keychain entries are merged with config file entries, with keychain entries taking priority order (listed first), and duplicates removed.

| Key | Description |
|---|---|
| `decryption_passphrases` | JSON array of additional passphrases to try when claiming |

## Output Discipline

To support piping and composition:

- **stdout**: MUST contain only the primary output (share link for `send`, plaintext for `get`, completion script for `completion`).
- **stderr**: all status messages, prompts, warnings, and errors.

This ensures patterns like `secrt send < secret.txt | pbcopy` work cleanly.

### TTY Output Formatting

When stdout is a TTY (interactive terminal), implementations SHOULD append a trailing newline after output that does not already end with one. This prevents shell artifacts (e.g., zsh's `%` indicator) and keeps terminal display clean.

When stdout is piped or redirected, implementations MUST NOT modify the output bytes — the raw content MUST be preserved exactly for downstream consumers (e.g., `secrt get <url> | pbcopy`).

In `--json` mode, the JSON object is printed to stdout. Errors in `--json` mode SHOULD also be JSON on stderr when practical.

## Authenticated Mode

Supplying `--api-key` is RECOMMENDED for automation and high-volume usage.

Credential handling rules:

1. CLI accepts local keys in `sk2_<prefix>.<root_b64>` format.
2. For authenticated requests, CLI derives:
   - `ROOT_SALT = SHA256("secrt-apikey-v2-root-salt")`
   - `auth_token = HKDF-SHA256(root_key, ROOT_SALT, "secrt-auth", 32)`
3. CLI sends wire credentials as `ak2_<prefix>.<auth_b64>` in `X-API-Key` / bearer headers.
4. Malformed `sk2_` values MUST fail fast with a clear user-facing error.

Authenticated mode enables:

- Higher service limits than anonymous/public calls (rate + storage quotas).
- Ownership-bound management operations like `burn`.
- Future owner metadata APIs (for example listing active secrets) without changing trust model.

`get` remains token-based and does not require an API key.

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

## `send`

Encrypts and uploads a one-time secret.

Usage:

```bash
secrt send [--ttl <ttl>] [--api-key <key>] [--base-url <url>] [--json] [--silent]
           [--text <value> | --file <path>]
           [-m | --multi-line] [--trim]
           [-s | --show | --hidden]
           [-n | --no-passphrase]
           [-p | --passphrase-prompt | --passphrase-env <name> | --passphrase-file <path>]
```

Behavior:

1. CLI selects plaintext input source:
   - Default: stdin.
   - Optional: `--text` or `--file`.
   - Exactly one source MUST be selected.
   - When reading from stdin with a TTY attached:
     - Default (single-line): the CLI SHOULD use a password-style prompt with hidden input (no echo), reading until Enter. This is optimized for the common case of sharing passwords, API keys, and tokens. The prompt SHOULD indicate that input is hidden (e.g., `"Enter secret (input hidden):"`).
     - Multi-line mode (e.g., `--multi-line` / `-m`): implementations SHOULD support reading until EOF (Ctrl+D), preserving exact bytes. This is intended for pasting multi-line content like SSH keys, certificates, or config snippets.
   - `--trim` trims leading/trailing whitespace from input. Input that is empty after trimming MUST be rejected.
   - When stdin is piped or redirected (non-TTY), the CLI MUST read all bytes until EOF regardless of flags.
   - Empty input MUST be rejected.
2. CLI performs envelope creation per `spec/v1/envelope.md`.
   - When `--file` is used, implementations SHOULD populate encrypted payload metadata with `type: "file"`, `filename`, and `mime` (inside the sealed payload frame). No plaintext metadata fields are allowed in envelope JSON.
3. CLI computes `claim_hash = base64url(sha256(claim_token_bytes))`.
4. CLI sends create request:
   - Anonymous: `POST /api/v1/public/secrets`
   - Authenticated (`--api-key` set): `POST /api/v1/secrets`
5. CLI outputs a share link containing the URL fragment key:
   - `<share_url>#<url_key_b64>`

Output:

- Default mode: print share link only.
- `--json` mode: include at minimum `id`, `share_url`, `share_link`, `expires_at`.

Input security note:

- `--text` passes secret content as a process argument, which is visible in shell history and `ps` output. Implementations SHOULD document this risk. Prefer stdin or `--file` for sensitive content.

Passphrase handling:

- Implementations SHOULD support `-p`/`--passphrase-prompt`.
- Implementations MAY support `--passphrase-env` and `--passphrase-file`.
- Implementations SHOULD NOT support passphrase values directly in command arguments (high leakage risk via shell history/process list).
- When using `-p`/`--passphrase-prompt` during `send`, implementations SHOULD prompt for confirmation (enter passphrase twice) to prevent typos that would make the secret unrecoverable.
- `-n`/`--no-passphrase` explicitly skips any configured default passphrase, creating an unprotected secret.

## `get`

Retrieves and decrypts a secret once.

Usage:

```bash
secrt get <share-url> [--base-url <url>] [--json] [--silent]
          [--output <path> | -o <path>]
          [-n | --no-passphrase]
          [-p | --passphrase-prompt | --passphrase-env <name> | --passphrase-file <path>]
```

Behavior:

1. Parse `<id>` from `/s/<id>` and decode `url_key_b64` from the URL fragment.
2. Derive `claim_token_bytes` and `enc_key` per `spec/v1/envelope.md`.
3. Send `POST /api/v1/secrets/{id}/claim` with `{ "claim": base64url(claim_token_bytes) }`.
4. On `200`, decrypt locally and print plaintext.
5. On `404`, return a generic failure message (not found / expired / already claimed / invalid claim) and non-zero exit.

Passphrase auto-detection:

After claiming the envelope from the server, implementations SHOULD inspect the `kdf.name` field to determine if the secret is passphrase-protected (i.e., `kdf.name` is not `"none"`).

- If the secret requires a passphrase and a TTY is attached, the CLI SHOULD automatically prompt for the passphrase (without requiring `-p`). A notice (e.g., `⚷ This secret is passphrase-protected`) SHOULD be displayed before the prompt.
- If the secret requires a passphrase and no TTY is attached, the CLI MUST exit with an error message directing the user to `--passphrase-env` or `--passphrase-file`.
- Since the envelope is already claimed and held in memory, wrong passphrase retries do not require additional server round-trips. Implementations SHOULD allow unlimited retries when the passphrase was entered interactively.
- `--silent` suppresses the notice but not the passphrase prompt itself.
- `-n`/`--no-passphrase` skips the configured `decryption_passphrases` list and proceeds directly to interactive prompt (or error if non-TTY).

Output:

Output behavior follows a decision matrix based on flags, decrypted payload metadata, and terminal state:

1. `--json`: JSON output to stdout. When decrypted metadata indicates `type: "file"`, include `filename`, `mime`, and `type` fields. For non-UTF-8 binary data, use `plaintext_base64` (standard base64) instead of `plaintext`.
2. `--output -` (or `-o -`): write raw decrypted bytes to stdout with no label or framing.
3. `--output <path>` (or `-o <path>`): write decrypted bytes to the specified file path. Print a success message to stderr (e.g., `✓ Saved to <path> (mime, N bytes)`).
4. File metadata present + stdout is TTY: auto-save to `./<filename>` in the current directory. If the filename already exists, implementations SHOULD deconflict (e.g., `file (1).ext`). Print a success message to stderr. Implementations MUST sanitize decrypted filenames before use (strip path separators, control characters, leading dots; limit length).
5. No file metadata + stdout is TTY + plaintext is non-UTF-8 binary: auto-save to a default filename (e.g., `secret.bin`) and print a success message to stderr. Implementations MUST NOT dump raw binary bytes to a TTY, as the secret is already burned and cannot be re-claimed.
6. Stdout is piped or redirected: write raw decrypted bytes exactly as-is with no label or modification, to preserve secret integrity for binary secrets or downstream consumers.
7. No file metadata + stdout is TTY + plaintext is valid UTF-8: print a brief label (e.g., `"Secret:"`) to stderr, then print plaintext to stdout. If the plaintext does not end with a newline (`\n`), implementations SHOULD append a trailing newline for clean terminal display.

## `burn` (optional)

Deletes a secret without claiming it.

Usage:

```bash
secrt burn <id-or-share-url> --api-key <key> [--base-url <url>] [--json] [--silent]
```

Behavior:

- Resolve `<id>` and call `POST /api/v1/secrets/{id}/burn`.
- Requires API key auth.

## `gen` (optional)

Generates a random password. May be used standalone or combined with `send`.

Aliases: `gen`, `generate`

Usage:

```bash
secrt gen [--length <n>] [--no-symbols] [--no-numbers] [--no-caps] [--grouped] [--count <n>] [--json]
```

Options:

- `-L`, `--length <n>`: password length (default: 20)
- `-S`, `--no-symbols`: exclude symbol characters
- `-N`, `--no-numbers`: exclude digit characters
- `-C`, `--no-caps`: exclude uppercase letters
- `-G`, `--grouped`: group characters by type (all lowercase, then uppercase, then digits, then symbols)
- `--count <n>`: generate multiple passwords (default: 1)
- `--json`: output as JSON array

Character sets:

- Lowercase: `a-z` (always included)
- Uppercase: `A-Z` (unless `--no-caps`)
- Digits: `0-9` (unless `--no-numbers`)
- Symbols: `!@*^_+-=?` (unless `--no-symbols`)

When at least one character from each enabled class is required, implementations SHOULD ensure the generated password contains at least one character from each class, then fill remaining positions randomly from all enabled classes.

### Combined Mode (`send gen` / `gen send`)

Implementations SHOULD support combining `gen` with `send` to generate and immediately share a password:

```bash
secrt send gen [--length 32] [--ttl 1h] [--no-symbols]
secrt gen send [--length 32] [--ttl 1h]
```

Both orderings are equivalent. All `gen` options and all `send` options may be combined. The generated password is used as the secret content.

Output in combined mode:

- Default: print share link only (same as `send`)
- `--json`: include `password` field alongside `id`, `share_url`, `share_link`, `expires_at`

## Error and Exit Behavior

Recommended exit codes:

- `0`: success
- `2`: usage or argument parsing error
- `1`: operational failure (network, API error, decrypt failure, secret unavailable)

Error messages MUST NOT reveal secret material.

Recommended HTTP error mapping:

- `send` `400`: invalid input (envelope, claim hash, ttl, JSON shape)
- `send`/`get`/`burn` `429`: rate limited
- `get` `404`: generic unavailable result (not found, expired, already claimed, invalid claim)
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

## Input Visibility

When reading interactive single-line input on a TTY, implementations SHOULD default to hidden input (no-echo, like a password prompt).

- `-s`, `--show`: show input as typed.
- `--hidden`: force hidden input (default). Overrides `--show` if both are provided.
- Config key `show_input = true` changes the default to visible input. `--hidden` still overrides.

## Status Indicators

On TTY, implementations SHOULD display a status indicator during upload:

- **In-progress:** yellow circle (`○`) with message (e.g., `○ Encrypting and uploading...`)
- **Success:** green checkmark (`✓`) with message and expiry in DIM (e.g., `✓ Encrypted and uploaded.  Expires 2026-02-10 09:30`)

The success line SHOULD overwrite the in-progress line using carriage return (`\r`).

The expiry timestamp SHOULD be formatted as `Expires YYYY-MM-DD HH:MM` in DIM to provide immediate feedback about secret lifetime without cluttering the primary output.

`--silent` suppresses all status indicators. Errors are never suppressed.

## Color & Styling

Implementations SHOULD use semantic color tokens for TTY output. All color MUST be suppressed when output is not a TTY.

### Semantic Color Tokens

| Token | ANSI SGR | Usage |
|---|---|---|
| CMD | 36 (cyan) | Command names |
| OPT | 33 (yellow) | Flags/options |
| ARG | 2 (dim) | Argument placeholders |
| HEADING | 1 (bold) | Section headings |
| SUCCESS | 32 (green) | Success indicators |
| ERROR | 31 (red) | Error prefix |
| URL | 1;36 (bold cyan) | Share URLs |
| LABEL | 37 (white) | Prompt labels that request user input ("Secret:", "Passphrase:") |
| DIM | 2 (dim) | Status messages, hints, secondary info text |
| WARN | 33 (yellow) | Warnings, in-progress indicators |

### Styling Guidelines

**Visual hierarchy:**

- **LABEL** (white) for prompts requesting input — they need attention
- **DIM** for contextual info and status — secondary importance
- **SUCCESS/ERROR/WARN** for outcomes — clear visual feedback
- **URL** for copyable output — stands out, easy to select

**Output values** (share links, decrypted secrets) SHOULD be on their own line with no leading/trailing decoration, making clipboard selection clean.

**Progressive disclosure:**

- Default: essential output only
- `--silent`: suppress all status (errors never suppressed)
- `--json`: machine-readable, suitable for scripting

## Interoperability Requirements

To be considered v1-compatible, a CLI implementation MUST:

- Pass envelope test vectors once available (`spec/v1/envelope.vectors.json`).
- Map TTL values exactly as specified in this document.
- Produce API payloads that satisfy `spec/v1/api.md`.
