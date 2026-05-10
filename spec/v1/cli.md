# CLI Specification (v1)

Status: Active (normative for CLI interoperability)

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

## Instance Trust

Conforming CLIs classify the resolved `base_url` against
`spec/v1/instances.md` (Official / TrustedCustom / DevLocal / Untrusted)
and apply two layered checks:

- **Off-list warning.** Every command that talks to a server (`send`,
  `get`, `list`, `info`, `burn`, `sync`, `auth login`, `auth setup`,
  `auth status`) MUST emit a loud stderr warning when the verdict is
  `Untrusted`. The warning explains what an unofficial operator could
  do (log plaintext/ciphertext/credentials, ship a tampered SPA bundle,
  refuse atomic-claim semantics) and tells the user how to silence it
  via the `trusted_servers` config key.
- **Cross-instance credential-leak hard-block.** The credential-bearing
  commands (`sync`, `burn`, `info`) MUST refuse to run when a share or
  sync URL on argv silently overrode the configured `base_url` AND the
  derived host doesn't refer to the same logical instance. ("Same
  logical instance" collapses wildcard subdomains under an Official
  apex per `instances.md § Wildcard-Trust Invariant`; for non-Official
  hosts, identity requires equal lowercased hosts.) The block diagnoses
  with both URLs and points the user at `secrt auth login --base-url
  <derived>` if they really meant to switch instances. An explicit
  `--base-url` flag or `SECRET_BASE_URL` env var bypasses the block —
  the user has signaled intent.

`get` is unauthenticated and warn-only (URL-key auth alone, no API key
sent). When `get` is handed a sync URL it delegates to the sync handler,
at which point the hard-block applies.

`sync` additionally distinguishes two post-claim failure modes after
its `info()` precondition check: `authenticated == false` ("this API
key is not registered on `<derived>`") versus
`authenticated == true && user_id.is_none()` (the legacy unlinked-key
case, "API key may not be linked to a user"). The cross-instance block
above prevents the silent-host-override path from reaching this check
in the first place; what's left here is the user's `--base-url` opt-in
landing on a server their key isn't registered on.

## Command Surface (v1)

Reference binary name in examples: `secrt`.

Required commands:

- `secrt send`
- `secrt get <share-url>`

Optional commands:

- `secrt burn <id-or-share-url>` (API-key authenticated)
- `secrt list` (API-key authenticated, lists active secrets)
- `secrt info <id-or-share-url>` (API-key authenticated, show secret metadata)
- `secrt sync <url>` (API-key authenticated, import notes encryption key)
- `secrt gen` (password generation)

Authentication commands:

- `secrt auth login`: browser-based device authorization flow.
- `secrt auth setup`: interactively paste and store an API key.
- `secrt auth status`: show current authentication state.
- `secrt auth logout`: clear stored credentials.

Built-in commands:

- `secrt --version` or `secrt version`: print version string and exit.
- `secrt --help` or `secrt help`: print top-level usage and exit.
- `secrt <command> --help` or `secrt help <command>`: print command-specific usage and exit.
- `secrt completion <shell>`: emit shell completion script (see Shell Completions below).
- `secrt config` (no subcommand): print effective settings resolved across flag/env/keychain/config-file/built-in default. Secret-bearing values MUST be masked in the output (e.g., `sk2_abcdef.••••••••`).
- `secrt config init [--force]`: create a template config file.
- `secrt config path`: print the config file path.
- `secrt config set-passphrase`: store default passphrase in OS keychain.
- `secrt config delete-passphrase`: remove passphrase from OS keychain.
- `secrt update [--check] [--force] [--version <X.Y.Z>] [--install-dir <path>]`: in-place self-upgrade. See `Update Check and Self-Update` below.

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

This implicit routing also applies to sync URLs (e.g., `secrt https://secrt.ca/sync/abc123#key...`). The `get` command detects `/sync/` URLs and delegates to the `sync` handler automatically (see `sync` below).

Operational/admin API-key management commands are implementation-specific and out of scope for this client-interoperability spec.

## Global Options

All commands SHOULD support:

- `--base-url <url>`: base service URL (default: `https://secrt.ca`).
- `--api-key <key>`: local API key (`sk2_<prefix>.<root_b64>`) for authenticated API endpoints.
- `--json`: machine-readable output mode.
- `--silent`: suppress non-essential stderr output (prompts, status, labels). Errors are never suppressed.
- `--no-update-check`: suppress the implicit update-check banner for this invocation. Equivalent to setting `SECRET_NO_UPDATE_CHECK=1`. See `Update Check and Self-Update` below.
- `--help`, `-h`: print usage for current command and exit.
- `--version`, `-v`: print version string and exit (top-level only).

Short option parsing rules:

- Implementations MAY support short inline values for value-taking short flags (for example `-L20`, `-oout.txt`).
- Boolean short flags MUST NOT accept inline suffixes or clustering.
- Inputs like `-SNG` or `-mfoo` MUST return a usage error instead of silently dropping suffix characters.

Environment variable fallbacks are RECOMMENDED:

- `SECRET_BASE_URL`
- `SECRET_API_KEY`
- `SECRET_NO_UPDATE_CHECK` (`1` to suppress the implicit update-check banner)

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
| `auto_copy` | bool | Auto-copy share link to clipboard on `send` when stdout is a TTY (default: `true` if implementation supports it). `--no-copy` always overrides. |
| `update_check` | bool | Enable the implicit update-check banner (default: `true`). See `Update Check and Self-Update` below. |
| `update_channel` | string | **Reserved.** `"stable"` (default) or `"prerelease"`. The `"prerelease"` value MAY be parsed but MUST NOT change behavior in this revision; reserved for a future PR. |

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

1. CLI accepts local keys in `sk2_<prefix>.<root_b64>` format. The `<prefix>` MUST be at least 6 ASCII characters from the set `[A-Za-z0-9_-]`. The `<root_b64>` MUST decode as base64url (no padding) to exactly 32 bytes.
2. For authenticated requests, CLI derives:
   - `ROOT_SALT = SHA256("secrt-apikey-v2-root-salt")`
   - `auth_token = HKDF-SHA256(root_key, ROOT_SALT, "secrt-auth", 32)`
3. CLI sends wire credentials as `ak2_<prefix>.<auth_b64>` in `X-API-Key` / bearer headers, where `<auth_b64>` is the base64url (no padding) encoding of `auth_token`.
4. Malformed `sk2_` values (wrong prefix, invalid prefix charset/length, invalid base64url, or wrong decoded length) MUST fail fast with a clear user-facing error.

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
           [--note <text>]
           [-Q | --qr] [--no-copy]
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

Encrypted notes:

- `--note <text>` attaches an encrypted note to the secret after creation. Requires authentication (`--api-key` or stored key) and an established AMK.
- The note is encrypted client-side using a key derived from the AMK, then sent via `PUT /api/v1/secrets/{id}/meta`.
- If no AMK is available, `--note` MUST fail with a clear error directing the user to set up an AMK (e.g., via `secrt auth login`).

QR code output:

- `-Q` / `--qr` prints the share link as a Unicode block QR code on stderr after the share link itself. Implementations SHOULD only render the QR code when stderr is a TTY; for non-TTY stderr the flag SHOULD be a no-op (the share link still goes to stdout as normal).

Clipboard behavior:

- Implementations MAY auto-copy the share link to the system clipboard after a successful `send` when stdout is a TTY. When supported, this behavior SHOULD be on by default and disabled by `--no-copy`. The `auto_copy` config key (boolean) sets the default; `--no-copy` always overrides.
- When stdout is piped or redirected, implementations MUST NOT touch the clipboard (the user is composing a pipeline, not consuming the link interactively).

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

## `list` (optional)

Lists active secrets owned by the authenticated user.

Usage:

```bash
secrt list [--api-key <key>] [--base-url <url>] [--json] [--silent]
           [--limit <n>] [--offset <n>]
```

Behavior:

- Calls `GET /api/v1/secrets` with the authenticated key.
- Requires API key auth.

Output:

- Default: tabular output with columns for ID, expiry, size, and passphrase protection status.
- When any secret has attached `enc_meta`, a **Notes** column is shown — regardless of whether the AMK is available.
- If the AMK is available, the CLI decrypts notes client-side and displays the plaintext note text.
- If the AMK is unavailable and `enc_meta` is present, the Notes column displays `(encrypted)` in WARN color. A hint is printed to stderr: "Sync your notes key from another browser/device to view your notes (secrt sync)".
- `--json` mode: include `enc_meta` and decrypted `note` fields when available.

## `info` (optional)

Shows metadata for an active secret without claiming it.

Usage:

```bash
secrt info <id-or-share-url> [--api-key <key>] [--base-url <url>] [--json] [--silent]
```

Behavior:

- Resolve `<id>` from a full ID, share URL, or ID prefix.
- Call `GET /api/v1/secrets/{id}` (authenticated).
- Requires API key auth.

Prefix resolution: if the exact ID returns 404, the CLI SHOULD attempt prefix resolution by listing secrets and finding a unique match. If the prefix is ambiguous (matches multiple secrets), an error listing the matches SHOULD be returned.

Output:

- Default: display ID, share URL, created timestamp, expiry (absolute + relative), size, passphrase-protection status, and decrypted note (if AMK is available).
- When `enc_meta` is present but the AMK is unavailable, display `(encrypted)` for the note.
- `--json` mode: output the raw metadata JSON to stdout.

## `sync` (optional)

Imports the notes encryption key (AMK) from a sync link generated by the web UI.

Usage:

```bash
secrt sync <url> [--api-key <key>] [--base-url <url>] [--json] [--silent]
```

Behavior:

1. Parse the sync URL to extract `<id>` and `url_key` from the fragment.
   - The URL path component MUST be `/sync/<id>`. Bare ID format (`<id>#<key>`) is allowed and treated as a sync URL in this command.
   - A share URL with `/s/<id>` path MUST be rejected **before** calling claim. Claiming a share URL is destructive (the secret is burned on the single claim), so the CLI MUST NOT attempt it. Emit a clear error directing the user to use `secrt get` instead.
2. Require API key authentication. If no API key is resolved, fail with a clear error.
3. Derive `claim_token` and claim the sync secret from the server via `POST /api/v1/secrets/{id}/claim`.
4. Decrypt the envelope. The decrypted plaintext MUST be exactly 32 bytes (the AMK). Any other length is a protocol violation and MUST cause the CLI to fail without uploading.
5. Resolve the caller's `user_id` by calling `GET /api/v1/info` with the API key. If the response does not include a `user_id` (i.e., the API key is not linked to a user account), fail with a clear error; the wrapping step requires the UUID.
6. Wrap the AMK with a key derived from the local API key's `root_key`, using the AAD and byte layout defined in `spec/v1/api.md § AMK wrapping`.
7. Compute `amk_commit` per the same section.
8. Upload the wrapped blob via `PUT /api/v1/amk/wrapper`. A `409` response indicates the account already committed a different AMK — surface this as a distinct error and do not retry.

The base URL is derived from the sync URL when `--base-url` is not set and `SECRET_BASE_URL` is not present.

The `get` command auto-detects sync URLs (paths containing `/sync/`) and delegates to the sync handler, so `secrt https://secrt.ca/sync/abc#key` works without an explicit `sync` subcommand.

Output:

- Default: print a success message on stderr (`✓ Notes key synced successfully`).
- On error: print error to stderr and exit 1.

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

## `auth`

Authentication management. All subcommands are optional for v1-compatible CLIs.

### `auth login`

Browser-based device authorization flow.

Usage:

```bash
secrt auth login [--base-url <url>]
```

Behavior:

1. Generate `root_key` (32 random bytes) locally.
2. Derive `auth_token = HKDF-SHA256(root_key, ROOT_SALT, "secrt-auth", 32)`.
3. Generate an ephemeral ECDH P-256 key pair for AMK transfer.
4. POST `/api/v1/auth/device/start` with `{ "auth_token": "<base64url>", "ecdh_public_key": "<base64url>" }`.
5. Display `user_code` prominently on stderr.
6. If stderr is a TTY, render a QR code of `verification_url` for mobile scanning.
7. Open `verification_url` in default browser (fallback: print URL to stderr).
8. Poll `/api/v1/auth/device/poll` with `{ "device_code": "..." }` every 5 seconds.
9. On `"complete"` response, construct `sk2_<prefix>.<base64(root_key)>`.
10. If `amk_transfer` is present in the poll response, decrypt the AMK using the ECDH shared secret and store the unwrapped AMK wrapper locally via `PUT /api/v1/amk/wrapper`.
11. Store the key using the shared key storage logic (see below).
12. Print success with masked key preview.

When the poll response includes an `amk_transfer` blob, the CLI performs ECDH key agreement with the browser's ephemeral public key, derives a transfer key, decrypts the AMK, wraps it for the local API key, and uploads the wrapper via `PUT /api/v1/amk/wrapper`. This process is fully automatic and requires no user interaction. If any step fails, the transfer is skipped with a warning and the user can sync the AMK later via `secrt sync`. AMK transfer works in both interactive and non-interactive sessions.

Security invariant: the `root_key` never leaves the CLI process. Only the derived `auth_token` is sent to the server.

### `auth setup`

Interactive API key setup for users who already have a key.

Usage:

```bash
secrt auth setup [--base-url <url>]
```

Behavior:

1. Prompt: "Paste your API key (sk2_...):" with hidden input.
2. Validate format via `parse_local_api_key()`.
3. Optionally verify against server by deriving wire key and calling `GET /api/v1/info`.
4. Store the key using the shared key storage logic (see below).
5. Print success.

### `auth status`

Show current authentication state.

Usage:

```bash
secrt auth status [--base-url <url>] [--api-key <key>]
```

Behavior:

1. Resolve API key from all sources (flag → env → keychain → config).
2. If none: print "Not authenticated" and exit 0.
3. Print key info: `Key: sk2_<prefix>.***  (from: keychain|config|env|flag)`.
4. Derive wire key and call `GET /api/v1/info` to check server connectivity.
5. Print: `Server: <base_url> (connected)` or `(unreachable)`.
6. If the server is reachable, check notes key status via `GET /api/v1/amk/wrapper`:
   - If an AMK wrapper exists: print `Notes key: synced` in SUCCESS color.
   - If no wrapper: print `Notes key: not synced` in WARN color with a hint to sync.
   - Silently skip if the request fails (server may not support AMK endpoints).

### `auth logout`

Clear stored credentials.

Usage:

```bash
secrt auth logout
```

Behavior:

1. Delete `api_key` from OS keychain (if present).
2. Comment out `api_key` in config file (if present).
3. Print success.

### Key Storage Logic (shared by `auth login` and `auth setup`)

After obtaining a valid API key:

1. Load config to check `use_keychain` setting.
2. If `use_keychain = true`: store in keychain, done.
3. If `use_keychain` is not set and stdin is a TTY, prompt: "Store API key in OS keychain? (recommended for security) [y/N]:"
   - Yes: store in keychain + set `use_keychain = true` in config file.
   - No: store as `api_key = "sk2_..."` in config file.
4. If non-interactive (piped stdin): store in config file.

### Config Write-Back

`auth login`, `auth setup`, and `auth logout` write to the config file. Write-back rules:

- Creates file from template if missing.
- Preserves existing comments and formatting.
- Finds and updates (or uncomments) the target key line.
- `remove_config_key` comments out the key line (does not delete it).
- File permissions are enforced at `0600` on write.

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
- Every CLI HTTP request MUST set `User-Agent: secrt/<version>` (e.g., `User-Agent: secrt/0.16.0`). This applies to both API calls and update-check fetches. The version is the CLI's own `CARGO_PKG_VERSION`, not the server's.

## Update Check and Self-Update

Implementations SHOULD provide an update-check mechanism that informs users when a newer CLI version is available, and SHOULD provide a `secrt update` subcommand that performs an in-place self-upgrade.

### Sources of Truth

The CLI consumes two pieces of version information from `/api/v1/info`:

- **Latest available version** (advisory): the `latest_cli_version` field, populated by the server polling GitHub Releases on a cadence (see `spec/v1/server.md` §13.2). The accompanying `latest_cli_version_checked_at` field carries an RFC 3339 timestamp of the last successful poll. When `latest_cli_version` is absent or null (server has not yet polled, server is air-gapped, etc.), the CLI MAY fall back to querying the GitHub Releases API directly — but ONLY for explicit user actions (`secrt update --check`, `secrt update`), NEVER for the implicit banner.
- **Minimum supported version** (advisory hard floor): the `min_supported_cli_version` field. The server provides this as a constant baked into the server build; it is bumped only when a server release introduces a wire-format change that breaks older CLIs. The CLI SHOULD surface this to the user when running below the floor, but MUST NOT block on it: zero-knowledge claim flows must continue to work for users who received share URLs before they upgraded.

### Local Cache

The CLI SHOULD cache update-check results locally to avoid repeated network calls.

- Location: `$XDG_CACHE_HOME/secrt/update-check.json`, falling back to `~/.cache/secrt/update-check.json` if `XDG_CACHE_HOME` is unset.
- TTL: 24 hours. Older entries are treated as stale and re-fetched on next implicit check.
- Format (JSON):

  ```json
  {
    "checked_at": "2026-04-25T09:08:07Z",
    "latest": "0.16.0",
    "current": "0.15.0"
  }
  ```

- Cache writes are best-effort. If the cache file or its directory is not writable, the CLI MUST NOT fail — it simply skips caching for that invocation.
- Corrupted cache files (truncated JSON, missing fields, invalid timestamps) MUST be silently ignored and re-fetched.
- Clock-skew protection: a `checked_at` timestamp in the future relative to the local clock MUST be treated as stale and re-fetched.

### Implicit Banner

After every command's primary work completes, the CLI SHOULD perform an update check and emit a banner on stderr if a newer version is available.

- The banner is two lines: a header line announcing the new version, followed by an indented line carrying the upgrade command on its own so it is trivially copy-pasteable.
- Recommended wording:

  ```
  secrt 0.16.0 available (current: 0.15.0)
    secrt update
  ```

- The header line SHOULD be styled in DIM and the command line SHOULD be styled in **bold cyan** (matching the `URL` semantic-color token used elsewhere for copyable values). When stderr is not a TTY, the banner MUST be suppressed entirely (see suppression matrix below) — implementations MUST NOT emit a colorless plain-text variant in piped contexts, since a bare `secrt update` line in a deploy log is more confusing than helpful. Anyone needing the announcement in piped contexts can run `secrt update --check`.
- The banner MUST be emitted at most once per CLI invocation, even if the command made multiple `/api/v1/info` calls.
- **The implicit banner is cache-only.** It MUST NOT initiate a network request. The cache is opportunistically refreshed by:
  - Commands that already call `/api/v1/info` for their primary work (e.g., `secrt info`, `secrt sync`, `secrt list`, `secrt config`).
  - Advisory response headers (`X-Secrt-Latest-Cli-Version`, `X-Secrt-Latest-Cli-Version-Checked-At`, `X-Secrt-Min-Cli-Version`) on any server response — see § Advisory Response Headers below.
  - Explicit `secrt update --check` and `secrt update`, which then write back to the local cache.
- This rule keeps fully offline commands (`secrt --version`, `secrt help`, `secrt completion`, `secrt gen`) truly offline.

The banner MUST be suppressed when any of the following hold:

- `--silent` is set.
- `--no-update-check` is set.
- `update_check = false` is configured in the config file.
- `SECRET_NO_UPDATE_CHECK=1` is set in the environment.
- `--json` is set (machine-readable output mode).
- The current command is `secrt update` itself.
- Stdout is being used to emit binary data to a non-TTY pipe (e.g., `secrt get -o -` piped to a file or another process).
- **Stderr is not a TTY** (e.g., redirected to a file, captured by a CI logger, piped to another process). Anyone needing the banner in piped contexts can use `secrt update --check`.

When the running CLI is below the server's `min_supported_cli_version`, the banner MUST be replaced with a stronger message:

```
warning: secrt <current> may not be compatible with this server
  secrt update
```

The header line SHOULD be styled in WARN (yellow) instead of DIM; the command line stays bold cyan. This stronger message follows the same suppression rules as the regular banner.

### Advisory Response Headers

To let the CLI keep its update-check cache warm without dedicated round-trips, conforming servers SHOULD include three advisory headers on **every** response (authenticated and public, including `/healthz`, error responses, and binary payload responses):

- `X-Secrt-Latest-Cli-Version: <semver>` — omitted when the server has not yet completed a successful poll.
- `X-Secrt-Latest-Cli-Version-Checked-At: <RFC 3339>` — omitted when never polled successfully.
- `X-Secrt-Min-Cli-Version: <semver>` — always present.

The CLI's HTTP client SHOULD parse these headers from any successful response and update the local update-check cache when the values are newer than what is cached. The values are public; there is nothing sensitive about emitting them on unauthenticated responses.

### `secrt update` Subcommand

Usage:

```bash
secrt update [--check] [--force] [--version <X.Y.Z>] [--install-dir <path>] [--channel <stable|prerelease>]
```

Options:

- `--check`: print whether an update is available; do not download or install.
- `--force`: re-download and install even if already on the latest version. Always re-verifies the SHA-256 against the published checksum.
- `--version <X.Y.Z>`: install a specific version (useful for downgrades during incident response). With `--channel stable` (the default), MUST be a strict semver of the form `\d+\.\d+\.\d+`. With `--channel prerelease`, MAY also include a prerelease suffix matching `-(rc|beta|alpha)\.\d+`.
- `--install-dir <path>`: install to a directory other than the running binary's directory.
- `--channel <stable|prerelease>`: select which set of releases is eligible for installation. See **§ Update Channels** below.

Behavior:

1. Resolve the running binary path via `current_exe()` and canonicalize it (`fs::canonicalize`).
2. Detect managed installs and refuse with a manager-specific message. Pattern-match the canonical path in this order; the first match wins:

   | Pattern in canonical path | Manager | Refuse message |
   |---|---|---|
   | contains `/Cellar/` | Homebrew | `Run: brew upgrade secrt` |
   | contains `/.asdf/installs/` | asdf | `Run: asdf install secrt latest && asdf global secrt latest` |
   | contains `/.local/share/mise/installs/` | mise | `Run: mise upgrade secrt` |
   | contains `/nix/store/` | Nix | `Run: nix profile upgrade secrt (or update your flake)` |
   | parent directory is `~/.cargo/bin` | cargo | `Run: cargo install --force secrt-cli` (the package name is `secrt-cli`; binary name is `secrt`. If installed via `--git`, use the same `--git` invocation with `--force`.) |
   | canonical path differs from `current_exe()` (other symlink) | unknown | generic refuse-and-redirect |

   Refusal exits with code 3.
3. Determine the latest version: read `latest_cli_version` from `/api/v1/info`, falling back to `https://api.github.com/repos/getsecrt/secrt/releases?per_page=30` filtered to non-draft non-prerelease entries with tags matching `^cli/v\d+\.\d+\.\d+$`, picking the highest semver.
4. Determine the asset filename for the current OS and architecture. **`secrt update` fetches a raw per-platform binary, not an archive** — this avoids a class of archive-extraction vulnerabilities and keeps the CLI dep graph small. The release pipeline publishes both raw binaries (for self-update) and `.tar.gz` / `.zip` / `.pkg` archives (for `install.sh`, brew, and human downloads).

   | OS, arch | Self-update raw binary | Human-install archive |
   |---|---|---|
   | linux, x86_64 | `secrt-linux-amd64` | `secrt-linux-amd64.tar.gz` |
   | linux, aarch64 | `secrt-linux-arm64` | `secrt-linux-arm64.tar.gz` |
   | macos, x86_64 | `secrt-darwin-amd64` | `secrt-macos.pkg`, `secrt-macos-amd64.tar.gz` |
   | macos, aarch64 | `secrt-darwin-arm64` | `secrt-macos.pkg`, `secrt-macos-arm64.tar.gz` |
   | windows, x86_64 | `secrt-windows-amd64.exe` | `secrt-windows-amd64.zip` |
   | windows, aarch64 | `secrt-windows-arm64.exe` | `secrt-windows-arm64.zip` |

5. Fetch the published checksum file `secrt-checksums-sha256.txt` from the same release.
6. Fetch the raw binary, compute SHA-256, and compare against the published checksum. **A mismatch MUST halt the install loudly**: print both expected and actual hashes, exit with code 2, and do not write any binary.
7. Stage the new binary in the same directory as the install target with a deterministic temp name (e.g., `secrt.new` on Unix, `secrt.exe.new` on Windows). `chmod 0755` on Unix. `fsync` the staged file before atomic replace.
8. Atomic install:
   - **Unix**: `rename(2)` the new binary over the running binary. The kernel keeps the running process's inode alive after rename.
   - **Windows**: rename `secrt.exe` to `secrt.exe.old`, place the new binary at `secrt.exe`. On next launch, the new `secrt` cleans up `secrt.exe.old` silently (via a hidden `--cleanup` startup hook). If even the rename-self-aside step fails (antivirus has the file open), implementations MAY fall back to `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` and inform the user the upgrade lands on next reboot.

Implementations SHOULD acquire an exclusive lock (e.g., `flock(2)` on Unix, `LockFileEx` on Windows) on a small lockfile in the install directory before any write, so two concurrent `secrt update` invocations cannot interleave.

Exit codes:

- `0`: success, or `--check` ran successfully (whether or not an update is available).
- `1`: generic error (network, parse, etc.).
- `2`: SHA-256 verification failure.
- `3`: managed install detected; refused.
- `4`: permission denied writing to install dir.
- `5`: install lock contention (another `secrt update` is in progress).

Permission-denied error message branches on whether the failing install directory is a known system path (`/usr/local/bin`, `/usr/bin`, `/usr/local/sbin`, `/usr/sbin`, or `/opt/<segment>/bin`):

- **System path** — message MUST recommend `sudo secrt update` and MUST NOT suggest `--install-dir`. The user deliberately chose a system-wide install; suggesting `--install-dir ~/.local/bin` would create a parallel install in user-space while leaving the privileged binary in place at the original location, with `PATH` ordering determining which one runs (a real footgun in practice).
- **User-space path** — message MUST suggest `--install-dir ~/.local/bin` and MUST NOT mention `sudo` (privilege escalation is hostile to least-privilege practice and surprising on user-level installs).

On Windows the system-path branch is never taken (no `sudo` analog; Windows installs are typically per-user or via MSI). Manual download via the GitHub release URL is offered as a universal fallback in both branches.

### Opt-out

The opt-outs are layered to fit different audiences:

- `--no-update-check` flag: one-off, per-invocation.
- `update_check = false` config key: durable per-user.
- `SECRET_NO_UPDATE_CHECK=1` environment variable: scriptable for CI contexts.

These opt-outs suppress only the implicit banner and implicit check during other commands. The `secrt update` subcommand itself is unaffected.

### Trust Root and Supply-Chain Notes

The trust root for `secrt update` is whoever can push tags matching `cli/v*` to `github.com/getsecrt/secrt`. SHA-256 verification against the published checksum file protects against transport tampering and mirror corruption, but **not** against compromise of the GitHub release publishing pipeline — both the binary and the checksum are fetched from the same release. The planned mitigation is Sigstore/cosign keyless signing of release artifacts, tracked as a separate task; it is not in scope for this spec revision but should land before secrt has many users. Until then, this trust gap is acknowledged and documented in the `README.md`.

### Update Channels

Two channels are defined: `stable` (default) and `prerelease`.

- **`stable`**: only tags matching `^cli/v\d+\.\d+\.\d+$` are eligible. `--version` MUST match `\d+\.\d+\.\d+` exactly. Pre-release tags (e.g., `cli/v0.16.0-rc.1`) MUST be skipped by both the server poller and the CLI's GitHub-direct fallback. `--version` with a prerelease suffix MUST be rejected with a usage error pointing at `--channel prerelease`.
- **`prerelease`**: `--version` MAY match `\d+\.\d+\.\d+(-(rc|beta|alpha)\.\d+)?`. When `--channel prerelease` is set without `--version`, the CLI MUST query the GitHub Releases API and pick the highest tag matching `^cli/v\d+\.\d+\.\d+(-(rc|beta|alpha)\.\d+)?$` (skipping drafts and tags that don't match the pattern). Ordering uses `(major, minor, patch)` first; ties are broken by `(channel_rank, index)` where `alpha < beta < rc < stable`. A stable triplet still sorts above its own prerelease, so on a release set containing both `0.16.0` and `0.16.0-rc.1`, the resolver returns `0.16.0`.

Anything other than `stable` or `prerelease` MUST exit with a usage error.

The `update_channel` config key in `[update_check]` is **Reserved.** Its parsed value MUST NOT alter behavior in this revision; the resolver lands alongside auto-discovery in a future revision.

The implicit update-check banner is unaffected by `--channel`: it always considers stable releases only.

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
