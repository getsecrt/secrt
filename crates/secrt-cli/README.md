<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/secrt-logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/images/secrt-logo.svg">
    <img alt="secrt" src="docs/images/secrt-logo-sticker.svg" width="250">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/getsecrt/secrt-cli/actions/workflows/ci.yml"><img src="https://github.com/getsecrt/secrt-cli/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/MSRV-1.82-blue" alt="MSRV: 1.82">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

A fast, small CLI for [secrt.ca](https://secrt.ca) — one-time secret sharing with zero-knowledge client-side encryption.

Built in Rust. No async runtime, no framework overhead. AES-256-GCM + HKDF-SHA256 + optional PBKDF2 passphrase protection, powered by [ring](https://github.com/briansmith/ring).

**Download:** [macOS (Universal)](https://github.com/getsecrt/secrt-cli/releases/latest/download/secrt-darwin-universal) | [Linux (x86_64)](https://github.com/getsecrt/secrt-cli/releases/latest/download/secrt-linux-amd64) | [Windows (x86_64)](https://github.com/getsecrt/secrt-cli/releases/latest/download/secrt-windows-amd64.exe) | [Windows (ARM64)](https://github.com/getsecrt/secrt-cli/releases/latest/download/secrt-windows-arm64.exe)

> **Server project:** [getsecrt/secrt-server](https://github.com/getsecrt/secrt-server)

## Install

### From source

```sh
git clone https://github.com/getsecrt/secrt-cli.git
cd secrt-cli
make release
# Binary at target/release/secrt
```

To include OS keychain support (macOS Keychain, Linux keyutils, Windows Credential Manager):

```sh
cargo build --release --features keychain
```

### Shell completions

```sh
# Bash
secrt completion bash >> ~/.bashrc

# Zsh
secrt completion zsh >> ~/.zshrc

# Fish
secrt completion fish | source
```

## Quick start

```sh
# Share a secret (interactive, hidden input)
secrt send

# Share with visible input and a TTL
secrt send --show --ttl 5m

# Pipe in a secret
echo "s3cret-password" | secrt send

# Share with passphrase protection
echo "s3cret-password" | secrt send -p --ttl 5m

# Claim a secret (auto-prompts for passphrase if needed)
secrt get https://secrt.ca/s/abc123#key...

# Or just paste the URL directly (implicit get)
secrt https://secrt.ca/s/abc123#key...

# Generate a password
secrt gen

# Generate and share in one step
secrt send gen --ttl 1h

# Burn a secret (requires API key)
secrt burn abc123 --api-key sk_prefix.secret
```

## Commands

### `send` — Encrypt and upload a secret

```
secrt send [options]
```

Reads the secret interactively on a TTY, or from **stdin** when piped. Use `--text` or `--file` for alternatives (exactly one input source).

| Option                      | Description                                       |
| --------------------------- | ------------------------------------------------- |
| `--ttl <ttl>`               | Time-to-live (e.g. `30s`, `5m`, `2h`, `1d`, `1w`) |
| `--text <value>`            | Secret text inline (visible in shell history)     |
| `-f`, `--file <path>`       | Read secret from a file                           |
| `-m`, `--multi-line`        | Multi-line input (read until Ctrl+D)              |
| `--trim`                    | Trim leading/trailing whitespace from input       |
| `-s`, `--show`              | Show input as you type (default: hidden)          |
| `--hidden`                  | Hide input (default; overrides `--show`)          |
| `-p`, `--passphrase-prompt` | Interactively prompt for a passphrase             |
| `--passphrase-env <name>`   | Read passphrase from an environment variable      |
| `--passphrase-file <path>`  | Read passphrase from a file                       |
| `--json`                    | Output as JSON                                    |
| `--silent`                  | Suppress status output                            |

**Examples:**

```sh
# Interactive single-line (hidden input, like a password)
secrt send

# Interactive with visible input
secrt send --show

# Multi-line input (Ctrl+D to finish)
secrt send -m

# Pipe in a secret
echo "database-password" | secrt send

# From a file, expires in 1 hour
secrt send --file ./credentials.txt --ttl 1h

# With passphrase protection
cat key.pem | secrt send -p --ttl 30m

# JSON output for scripting
echo "token" | secrt send --json --ttl 5m
```

### `get` — Retrieve and decrypt a secret

```
secrt get <share-url> [options]
```

**Tip:** The `get` subcommand is optional — you can paste a share URL directly:

```sh
secrt https://secrt.ca/s/abc123#key...
```

If the secret is passphrase-protected and a TTY is attached, `get` automatically prompts for the passphrase with unlimited retries. For non-interactive use, provide the passphrase via `--passphrase-env` or `--passphrase-file`.

| Option                      | Description                                  |
| --------------------------- | -------------------------------------------- |
| `-p`, `--passphrase-prompt` | Prompt for the passphrase                    |
| `--passphrase-env <name>`   | Read passphrase from an environment variable |
| `--passphrase-file <path>`  | Read passphrase from a file                  |
| `--json`                    | Output as JSON                               |
| `--silent`                  | Suppress status output                       |

**Examples:**

```sh
# Claim a secret (auto-prompts for passphrase if needed)
secrt get https://secrt.ca/s/abc123#key...

# Explicitly prompt for passphrase
secrt get https://secrt.ca/s/abc123#key... -p

# Passphrase from env (non-interactive)
secrt get https://secrt.ca/s/abc123#key... --passphrase-env MY_PASS

# Pipe to a file
secrt get https://secrt.ca/s/abc123#key... > secret.txt
```

### `burn` — Destroy a secret

```
secrt burn <id-or-url> [options]
```

| Option            | Description            |
| ----------------- | ---------------------- |
| `--api-key <key>` | API key (required)     |
| `--json`          | Output as JSON         |
| `--silent`        | Suppress status output |

**Examples:**

```sh
# Burn by ID
secrt burn abc123 --api-key sk_prefix.secret

# Burn by share URL
secrt burn https://secrt.ca/s/abc123#key... --api-key sk_prefix.secret
```

### `gen` — Generate a random password

```
secrt gen [options]
```

Generates cryptographically secure passwords using unbiased rejection sampling.

| Option               | Description                   |
| -------------------- | ----------------------------- |
| `-L`, `--length <n>` | Password length (default: 20) |
| `-S`, `--no-symbols` | Exclude symbols               |
| `-N`, `--no-numbers` | Exclude digits                |
| `-C`, `--no-caps`    | Exclude uppercase letters     |
| `-G`, `--grouped`    | Group characters by type      |
| `--count <n>`        | Generate multiple passwords   |
| `--json`             | Output as JSON                |

**Character sets:**

- Lowercase: `a-z` (always included)
- Uppercase: `A-Z`
- Digits: `0-9`
- Symbols: `!@*^_+-=?`

**Examples:**

```sh
# 20-char password with all character classes
secrt gen

# 32-char password, no symbols
secrt gen -L 32 -S

# Generate 5 passwords
secrt gen --count 5

# Grouped by character type (e.g., lowercase block, then digits, etc.)
secrt gen -G

# JSON output
secrt gen --json
```

### `send gen` — Generate and share in one step

Combine password generation with secret sharing:

```sh
# Generate a password and share it
secrt send gen

# With TTL and passphrase protection
secrt send gen --ttl 1h -p

# 32-char, no symbols, expires in 5 minutes
secrt send gen -L 32 -S --ttl 5m
```

The generated password is printed to stderr (on TTY) or included as `"password"` in `--json` output, so you can see what was shared.

## Global options

| Option             | Description                              |
| ------------------ | ---------------------------------------- |
| `--base-url <url>` | Server URL (default: `https://secrt.ca`) |
| `--api-key <key>`  | API key for authenticated access         |
| `--json`           | Output as JSON                           |
| `--silent`         | Suppress status output                   |
| `-h`, `--help`     | Show help                                |
| `-v`, `--version`  | Show version                             |

## Environment variables

| Variable          | Description                          |
| ----------------- | ------------------------------------ |
| `SECRET_BASE_URL` | Override the default server URL      |
| `SECRET_API_KEY`  | API key (alternative to `--api-key`) |

## Configuration

Settings can be persisted in a TOML config file so you don't need to pass flags or set environment variables for every invocation.

### Config file

**Location:** `~/.config/secrt/config.toml` (or `$XDG_CONFIG_HOME/secrt/config.toml`)

```toml
# API key for authenticated access (send, burn)
api_key = "sk_live_abc123"

# Custom server URL (default: https://secrt.ca)
base_url = "https://my-secrt-server.example.com"

# Default TTL for secrets (e.g., 5m, 2h, 1d, 1w)
default_ttl = "24h"

# Default passphrase for encryption and decryption
passphrase = "my-default-passphrase"

# Additional passphrases to try when claiming (tried in order)
decryption_passphrases = ["old-passphrase", "team-passphrase"]

# Show secret input as typed (default: false)
show_input = true

# Read secrets from the OS credential store (default: false)
# use_keychain = false
```

The `decryption_passphrases` array is useful for teams rotating passphrases — when claiming a secret, secrt tries the default `passphrase` first, then each entry in `decryption_passphrases` in order, before falling back to an interactive prompt. This allows seamless decryption of secrets encrypted with older passphrases without manual intervention.

### Config subcommands

```sh
# Show effective settings (config file + env + keychain)
secrt config

# Create a template config file
secrt config init

# Overwrite an existing config file
secrt config init --force

# Print the config file path
secrt config path
```

**Important:** The config file may contain secrets. Set restrictive permissions:

```sh
mkdir -p ~/.config/secrt
chmod 700 ~/.config/secrt
touch ~/.config/secrt/config.toml
chmod 600 ~/.config/secrt/config.toml
```

If the file is group- or world-readable, secrt will warn and **skip loading secrets** (api_key, passphrase, decryption_passphrases) from it. Non-sensitive settings like base_url and default_ttl will still be loaded.

### OS keychain

When built with the `keychain` feature (the default), secrt can read `api_key`, `passphrase`, and `decryption_passphrases` from your OS credential store (macOS Keychain, Linux keyutils, Windows Credential Manager). For `decryption_passphrases`, store a JSON array string (e.g., `["p1","p2"]`).

Keychain reads are **disabled by default** to avoid OS elevation prompts (e.g., macOS Keychain) on every command. To opt in, set `use_keychain = true` in your config file.

```sh
# Install with keychain support
cargo install --path . --features keychain
```

This uses native OS APIs — no extra daemons or services required.

### Precedence

Settings are resolved in this order (first match wins):

1. **CLI flag** (`--api-key`, `--base-url`, `--passphrase-*`)
2. **Environment variable** (`SECRET_API_KEY`, `SECRET_BASE_URL`)
3. **OS keychain** (if `use_keychain = true` and built with `keychain` feature)
4. **Config file** (`~/.config/secrt/config.toml`)
5. **Built-in default**

## Cryptography

All encryption happens **client-side** before any data leaves your machine. The server never sees plaintext.

- **AES-256-GCM** — authenticated encryption
- **HKDF-SHA256** — key derivation from a random master key
- **PBKDF2-HMAC-SHA256** (600,000 iterations) — optional passphrase-based key stretching
- **CSPRNG** — all random values from the OS

Envelope format: `v1-pbkdf2-hkdf-aes256gcm` — see the [spec](https://github.com/getsecrt/secrt/tree/main/spec/v1) for full details.

## TTL format

Durations are a positive integer followed by a unit suffix:

| Unit | Meaning | Example |
| ---- | ------- | ------- |
| `s`  | Seconds | `30s`   |
| `m`  | Minutes | `5m`    |
| `h`  | Hours   | `2h`    |
| `d`  | Days    | `1d`    |
| `w`  | Weeks   | `1w`    |

No suffix defaults to seconds. Maximum TTL is 1 year.

## Development

```sh
make build     # Debug build
make release   # Optimized release build
make test      # Run tests
make check     # Clippy + fmt check
make size      # Show release binary size
```

### Build optimization

The release profile uses `opt-level = "z"` (optimize for binary size) with full LTO. This
produces the smallest binary but slows down PBKDF2 passphrase derivation by ~1.7x compared
to speed-optimized builds.

| `opt-level` | Binary size | PBKDF2 (600K iter) | Notes                                      |
| ----------- | ----------- | ------------------ | ------------------------------------------ |
| `"z"`       | ~1,484 KB   | ~111 ms            | **Current default.** Smallest binary.      |
| `"s"`       | ~1,642 KB   | ~66 ms             | Mild size optimization.                    |
| `"2"`       | ~1,642 KB   | ~65 ms             | Default Rust release level.                |
| `"3"`       | ~1,642 KB   | ~66 ms             | Max speed — no meaningful gain over `"2"`. |

_Measured on Apple M2 Max, macOS, `aarch64`. Results vary by platform._

**Why not exempt `ring` from size optimization?** The `Cargo.toml` includes
`[profile.release.package.ring] opt-level = 3`, but full LTO (`lto = true`) merges all
crates into a single compilation unit and re-optimizes globally, effectively overriding
per-package settings. This override is kept for correctness in case LTO is disabled.

**Why `"z"` is the default:** The 111 ms PBKDF2 cost is imperceptible to users (passphrase
operations take ~100 ms total either way), while the ~160 KB size savings benefits
distribution. If profiling shows the crypto overhead matters for your use case, change
`opt-level` to `"s"` in `Cargo.toml`.

**UPX compression** is not viable: on macOS arm64, UPX-packed binaries are killed by the
OS due to W^X memory protection (code signing cannot be preserved). On Linux/Windows UPX
can reduce binaries by ~40%, but triggers false positives from malware scanners, making it
unsuitable for a security-focused tool.

## License

MIT
