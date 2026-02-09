# secrt

A fast, minimal CLI for [secrt.ca](https://secrt.ca) — one-time secret sharing with zero-knowledge client-side encryption.

Built in Rust. No async runtime, no framework overhead. AES-256-GCM + HKDF-SHA256 + optional PBKDF2 passphrase protection, all powered by [ring](https://github.com/briansmith/ring).

> **Server project:** [getsecrt/secrt](https://github.com/getsecrt/secrt)

## Install

### From source

```sh
git clone https://github.com/getsecrt/secrt-rs.git
cd secrt-rs
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
secrt create

# Share with visible input and a TTL
secrt create --show --ttl 5m

# Pipe in a secret
echo "s3cret-password" | secrt create

# Share with passphrase protection
echo "s3cret-password" | secrt create -p --ttl 5m

# Claim a secret (auto-prompts for passphrase if needed)
secrt claim https://secrt.ca/s/abc123#v1.key...

# Burn a secret (requires API key)
secrt burn abc123 --api-key sk_prefix.secret
```

## Commands

### `create` — Encrypt and upload a secret

```
secrt create [options]
```

Reads the secret interactively on a TTY, or from **stdin** when piped. Use `--text` or `--file` for alternatives (exactly one input source).

| Option | Description |
|---|---|
| `--ttl <ttl>` | Time-to-live (e.g. `30s`, `5m`, `2h`, `1d`, `1w`) |
| `--text <value>` | Secret text inline (visible in shell history) |
| `--file <path>` | Read secret from a file |
| `-m`, `--multi-line` | Multi-line input (read until Ctrl+D) |
| `--trim` | Trim leading/trailing whitespace from input |
| `-s`, `--show` | Show input as you type (default: hidden) |
| `--hidden` | Hide input (default; overrides `--show`) |
| `-p`, `--passphrase-prompt` | Interactively prompt for a passphrase |
| `--passphrase-env <name>` | Read passphrase from an environment variable |
| `--passphrase-file <path>` | Read passphrase from a file |
| `--json` | Output as JSON |
| `--silent` | Suppress status output |

**Examples:**

```sh
# Interactive single-line (hidden input, like a password)
secrt create

# Interactive with visible input
secrt create --show

# Multi-line input (Ctrl+D to finish)
secrt create -m

# Pipe in a secret
echo "database-password" | secrt create

# From a file, expires in 1 hour
secrt create --file ./credentials.txt --ttl 1h

# With passphrase protection
cat key.pem | secrt create -p --ttl 30m

# JSON output for scripting
echo "token" | secrt create --json --ttl 5m
```

### `claim` — Retrieve and decrypt a secret

```
secrt claim <share-url> [options]
```

If the secret is passphrase-protected and a TTY is attached, `claim` automatically prompts for the passphrase with unlimited retries. For non-interactive use, provide the passphrase via `--passphrase-env` or `--passphrase-file`.

| Option | Description |
|---|---|
| `-p`, `--passphrase-prompt` | Prompt for the passphrase |
| `--passphrase-env <name>` | Read passphrase from an environment variable |
| `--passphrase-file <path>` | Read passphrase from a file |
| `--json` | Output as JSON |
| `--silent` | Suppress status output |

**Examples:**

```sh
# Claim a secret (auto-prompts for passphrase if needed)
secrt claim https://secrt.ca/s/abc123#v1.key...

# Explicitly prompt for passphrase
secrt claim https://secrt.ca/s/abc123#v1.key... -p

# Passphrase from env (non-interactive)
secrt claim https://secrt.ca/s/abc123#v1.key... --passphrase-env MY_PASS

# Pipe to a file
secrt claim https://secrt.ca/s/abc123#v1.key... > secret.txt
```

### `burn` — Destroy a secret

```
secrt burn <id-or-url> [options]
```

| Option | Description |
|---|---|
| `--api-key <key>` | API key (required) |
| `--json` | Output as JSON |
| `--silent` | Suppress status output |

**Examples:**

```sh
# Burn by ID
secrt burn abc123 --api-key sk_prefix.secret

# Burn by share URL
secrt burn https://secrt.ca/s/abc123#v1.key... --api-key sk_prefix.secret
```

## Global options

| Option | Description |
|---|---|
| `--base-url <url>` | Server URL (default: `https://secrt.ca`) |
| `--api-key <key>` | API key for authenticated access |
| `--json` | Output as JSON |
| `--silent` | Suppress status output |
| `-h`, `--help` | Show help |
| `-v`, `--version` | Show version |

## Environment variables

| Variable | Description |
|---|---|
| `SECRET_BASE_URL` | Override the default server URL |
| `SECRET_API_KEY` | API key (alternative to `--api-key`) |

## Configuration

Settings can be persisted in a TOML config file so you don't need to pass flags or set environment variables for every invocation.

### Config file

**Location:** `~/.config/secrt/config.toml` (or `$XDG_CONFIG_HOME/secrt/config.toml`)

```toml
# API key for authenticated access (create, burn)
api_key = "sk_live_abc123"

# Custom server URL (default: https://secrt.ca)
base_url = "https://my-secrt-server.example.com"

# Default passphrase for encryption
passphrase = "my-default-passphrase"

# Show secret input as typed (default: false)
show_input = true
```

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

If the file is group- or world-readable, secrt will warn and **skip loading secrets** (api_key, passphrase) from it. Non-sensitive settings like base_url will still be loaded.

### OS keychain

When built with the `keychain` feature, secrt can read `api_key` and `passphrase` from your OS credential store (macOS Keychain, Linux keyutils, Windows Credential Manager).

```sh
# Install with keychain support
cargo install --path . --features keychain
```

This uses native OS APIs — no extra daemons or services required.

### Precedence

Settings are resolved in this order (first match wins):

1. **CLI flag** (`--api-key`, `--base-url`, `--passphrase-*`)
2. **Environment variable** (`SECRET_API_KEY`, `SECRET_BASE_URL`)
3. **OS keychain** (if built with `keychain` feature)
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
|---|---|---|
| `s` | Seconds | `30s` |
| `m` | Minutes | `5m` |
| `h` | Hours | `2h` |
| `d` | Days | `1d` |
| `w` | Weeks | `1w` |

No suffix defaults to seconds. Maximum TTL is 1 year.

## Development

```sh
make build     # Debug build
make release   # Optimized release build
make test      # Run tests
make check     # Clippy + fmt check
make size      # Show release binary size
```

## License

MIT
