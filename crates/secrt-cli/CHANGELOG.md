# Changelog

## 0.4.0 — 2026-02-11

### Changed

- **Shorter share URLs:** Dropped the `#v1.` prefix from URL fragments — the full fragment is now the base64url-encoded key directly (e.g., `#<key>` instead of `#v1.<key>`). Implicit `get` detection now matches any fragment with >= 22 base64url characters instead of looking for the literal `#v1.` prefix.

## 0.3.1 — 2026-02-10

### Fixed

- **Windows CI:** Fix `config_path_with_empty_xdg` test that failed on Windows due to backslash path separators. Now uses `Path::ends_with` for cross-platform component comparison.

### Changed

- **Rename:** Repository renamed from `secrt-rs` to `secrt-cli` across all references.

## 0.3.0 — 2026-02-10

### Changed

- **Rename CLI commands:** `create` → `send`, `claim` → `get`. Shorter, clearer verbs that map to natural usage: "send a secret" / "get the secret." This is a breaking change with no aliases for the old command names. The HTTP API endpoints and cryptographic protocol terms are unchanged.

### Added

- **`gen` command:** Built-in password generator (`secrt gen` / `secrt generate`). Defaults to 20-char passwords with lowercase, uppercase, digits, and symbols (`!@*^_+-=?`). Flags: `-L` length, `-S` no symbols, `-N` no digits, `-C` no uppercase, `-G` grouped by character type, `--count` for multiple passwords. Supports `--json` output. Uses cryptographically secure randomness with unbiased rejection sampling.
- **`use_keychain` config option:** Keychain reads are now gated behind `use_keychain = true` in the config file (default: `false`). This prevents OS elevation prompts (e.g., macOS Keychain) on every command for users who don't use keychain storage.
- **`--help` for config subcommands:** `secrt config init --help`, `secrt config path --help`, etc. now show help instead of running the subcommand.
- **Implicit get example in help:** `secrt get --help` now shows the `get` subcommand is optional (e.g., `secrt https://secrt.ca/s/abc#key`).
- **Combined `send gen` mode:** Generate a password and share it as a secret in one command. `secrt send gen` (canonical) or `secrt gen send` (alias). All gen and send flags work together (e.g., `secrt send gen -L 32 --ttl 1h -p`). Generated password is shown on stderr (TTY) or included in `--json` output as a `"password"` field.

## 0.2.0 — 2026-02-10

### Added

- **Windows code signing:** Release binaries are now Authenticode-signed via Azure Artifact Signing (FullSpec Systems).
- **Windows ARM64 build:** Release now includes `secrt-windows-arm64.exe` for Windows on ARM devices.
- **`-f` shorthand for `--file`:** `secrt send -f <path>` as alias for `--file`.
- **Local timezone display:** Secret expiry timestamps now show the local time alongside UTC.
- **README logo:** Added secrt logo to the README.

### Fixed

- Get auto-saves binary data to a file instead of dumping raw bytes to the terminal.
- Flaky test fix: avoid process-global cwd change in parallel tests.

## 0.1.1 — 2026-02-09

### Added

- **File handling:** `send --file` now stores file metadata (filename, MIME type) in the envelope `hint` field. On get, file secrets are automatically saved to disk on TTY, with raw bytes piped when stdout is not a terminal.
- **`--output` / `-o` flag for `get`:** Write retrieved secret directly to a file path, or use `-o -` to force raw bytes to stdout.
- **JSON base64 encoding:** `get --json` outputs `plaintext_base64` (standard base64) instead of lossy UTF-8 for binary files with a file hint.
- **Implicit get:** Share URLs are auto-detected as the first argument (`secrt <url>` works without `get` subcommand).

### Fixed

- `<url>` placeholder in usage text now uses ARG color (dim) instead of OPT color (yellow).

## 0.1.0 — 2026-02-09

Initial release.

- **Commands:** `send`, `get`, `burn`, `config`, `completion`
- **Crypto:** AES-256-GCM + HKDF-SHA256, optional PBKDF2 passphrases, zero-knowledge client-side encryption via `ring`
- **Config:** TOML config file (`~/.config/secrt/config.toml`) with `config init`, env vars, CLI flag precedence
- **Keychain:** Optional OS keychain integration (macOS Keychain, Linux keyutils, Windows Credential Manager) for passphrase storage
- **Get:** Auto-tries configured `decryption_passphrases`, falls back to interactive prompt on TTY
- **Input:** Stdin pipe, `--text`, `--file`, `--multi-line`, `--trim`, hidden/shown interactive input
- **Output:** Human-friendly TTY output with color, `--json` for scripting, `--silent` mode
- **Shell completions:** Bash, Zsh, Fish via `completion` command
- **No async runtime** — blocking HTTP via `ureq`, ~1.5 MB static binary
