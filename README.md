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
# Share a secret (reads from stdin)
echo "s3cret-password" | secrt create

# Share with a TTL and passphrase
echo "s3cret-password" | secrt create --ttl 5m --passphrase-prompt

# Claim a secret
secrt claim https://secrt.ca/s/abc123#v1.key...

# Burn a secret (requires API key)
secrt burn abc123 --api-key sk_prefix.secret
```

## Commands

### `create` — Encrypt and upload a secret

```
secrt create [options]
```

Reads the secret from **stdin** by default. Use `--text` or `--file` for alternatives (exactly one input source).

| Option | Description |
|---|---|
| `--ttl <ttl>` | Time-to-live (e.g. `30s`, `5m`, `2h`, `1d`, `1w`) |
| `--text <value>` | Secret text inline (visible in shell history) |
| `--file <path>` | Read secret from a file |
| `--passphrase-prompt` | Interactively prompt for a passphrase |
| `--passphrase-env <name>` | Read passphrase from an environment variable |
| `--passphrase-file <path>` | Read passphrase from a file |
| `--json` | Output as JSON |

**Examples:**

```sh
# Pipe in a secret
echo "database-password" | secrt create

# From a file, expires in 1 hour
secrt create --file ./credentials.txt --ttl 1h

# With passphrase protection
cat key.pem | secrt create --passphrase-prompt --ttl 30m

# JSON output for scripting
echo "token" | secrt create --json --ttl 5m
```

### `claim` — Retrieve and decrypt a secret

```
secrt claim <share-url> [options]
```

| Option | Description |
|---|---|
| `--passphrase-prompt` | Prompt for the passphrase |
| `--passphrase-env <name>` | Read passphrase from an environment variable |
| `--passphrase-file <path>` | Read passphrase from a file |
| `--json` | Output as JSON |

**Examples:**

```sh
# Claim a secret
secrt claim https://secrt.ca/s/abc123#v1.key...

# Claim a passphrase-protected secret
secrt claim https://secrt.ca/s/abc123#v1.key... --passphrase-prompt

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
| `-h`, `--help` | Show help |
| `-v`, `--version` | Show version |

## Environment variables

| Variable | Description |
|---|---|
| `SECRET_BASE_URL` | Override the default server URL |
| `SECRET_API_KEY` | API key (alternative to `--api-key`) |

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
