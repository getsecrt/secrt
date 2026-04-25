# Changelog

## Unreleased

### Spec

- **New section in `spec/v1/cli.md`: "Update Check and Self-Update".** Defines the contract for the in-CLI update banner and the `secrt update` self-upgrade command:
  - **Cache-only implicit banner**: never makes a dedicated network call; refreshes opportunistically from existing `/api/v1/info` calls and from advisory response headers.
  - **Self-update fetches raw per-platform binaries** (`secrt-linux-amd64`, `secrt-darwin-arm64`, `secrt-windows-amd64.exe`, …), not archives. Archives stay published for `install.sh` / brew / human downloads.
  - **Suppression matrix**: `--silent`, `--no-update-check`, `update_check = false`, `SECRET_NO_UPDATE_CHECK=1`, `--json`, current command is `secrt update`, stdout used for binary data, **stderr is not a TTY**.
  - **Exit codes**: 0 success, 1 generic, 2 SHA-256 mismatch, 3 managed install refused, 4 permission denied, 5 lock contention.
  - **Managed-install detection** with manager-specific upgrade messages for Homebrew (Cellar), asdf, mise, Nix store, cargo (`~/.cargo/bin` → `cargo install --force secrt-cli`), and a generic-symlink fallback.
  - **Reserved**: `--channel <stable|prerelease>` flag and `update_channel` config key for future opt-in beta selection.
- **`User-Agent: secrt/<version>`** required on all CLI HTTP requests (in `spec/v1/cli.md § HTTP Client Behavior`).
- **New `update_check` config key and `--no-update-check` global flag** documented in `spec/v1/cli.md`. Default is on; opt-outs layered (flag → config → `SECRET_NO_UPDATE_CHECK=1` env).
- **Three new `/api/v1/info` body fields** documented in `spec/v1/api.md` and `spec/v1/openapi.yaml`: `latest_cli_version`, `latest_cli_version_checked_at` (advisory, server-polled from GitHub Releases), `min_supported_cli_version` (hardcoded constant in server build, always present).
- **Three new advisory response headers** on every server response: `X-Secrt-Latest-Cli-Version`, `X-Secrt-Latest-Cli-Version-Checked-At`, `X-Secrt-Min-Cli-Version`. Mirror the body fields and let CLI clients refresh their update-check cache as a side effect of any request.
- **Restructured `spec/v1/server.md` § 13** as "Background Tasks" with three subsections: § 13.1 expired-secret reaper, § 13.2 GitHub Releases version cache (60-min default, `If-None-Match`/ETag, fail-soft, **`GITHUB_POLL_INTERVAL_SECONDS=0` disables polling entirely** for air-gapped self-hosters), § 13.3 advisory response headers.
- **New test vector file `spec/v1/update.vectors.json`** covering semver comparison, GitHub release tag filtering, banner suppression matrix, and channel reservation behavior.

### Internal / Tracking

- Added `.taskmaster` task #53 (Sigstore/cosign keyless signing) as a deferred follow-up to close the supply-chain trust gap.

## 0.15.0 — 2026-04-25

### Changed

- **BREAKING — AMK wrapper AAD format change.** All call sites that wrap or unwrap an AMK (`sync`, `send` notes resolve, `auth login` AMK transfer) now parse the server-returned `user_id` UUID string into 16 raw bytes before building the AAD. Wrappers stored under the prior format will fail to unwrap and must be regenerated. See `secrt-core` 0.15.0 for the format details.

### Added

- **Sync command tightened.** `secrt sync` now MUST reject `/s/<id>` share URLs before calling claim (preventing accidental burn of unrelated secrets), MUST require the API key be linked to a user account (`/api/v1/info` returns `user_id`), and MUST verify the decrypted plaintext is exactly 32 bytes before uploading.

### Dependencies

- Bumped `toml` `0.8` → `1` (no behavioral change for our `from_str::<Config>` usage).
- Added `uuid` workspace dep for parsing the `user_id` string returned by `/api/v1/info`.

## 0.14.9 — 2026-04-22

_No CLI changes — version bump only to stay in sync with workspace._

## 0.14.8 — 2026-04-22

_No CLI changes — version bump only to stay in sync with workspace._

## 0.14.7 — 2026-02-22

_No CLI changes — version bump only to stay in sync with workspace._

## 0.14.6 — 2026-02-22

_No CLI changes — version bump only to stay in sync with workspace._

## 0.14.5 — 2026-02-22

_No CLI changes — version bump only to stay in sync with workspace._

## 0.14.4 — 2026-02-22

_No CLI changes — version bump only to stay in sync with workspace._

## 0.14.3 — 2026-02-21

_No CLI changes — version bump only to stay in sync with workspace._

## 0.14.2 — 2026-02-20

### Added

- **Auto-copy share link to clipboard:** after `secrt send`, the share link is automatically copied to the system clipboard using platform-native commands (`pbcopy` on macOS, `xclip`/`xsel` on Linux, `clip.exe` on Windows). A `→ Copied to clipboard` indicator appears on stderr. No new dependencies.
- **`--no-copy` flag:** disables clipboard auto-copy for a single invocation.
- **`auto_copy` config option:** set `auto_copy = false` in `config.toml` to disable clipboard auto-copy permanently. Copy is skipped automatically in non-TTY, `--json`, and `--silent` modes.

## 0.14.0 — 2026-02-20

_No CLI changes — version bump only to stay in sync with workspace._

## 0.13.3 — 2026-02-19

_No CLI changes — version bump only to stay in sync with workspace._

## 0.13.2 — 2026-02-19

_No CLI changes — version bump only to stay in sync with workspace._

## 0.13.1 — 2026-02-19

_No CLI changes — version bump only to stay in sync with workspace._

## 0.13.0 — 2026-02-19

### Added

- **`secrt sync <url>` command:** import a notes encryption key from a sync URL generated by the web UI. Validates the URL, claims the one-time secret, decrypts the AMK, wraps it for the local API key, and uploads the wrapper.
- **`secrt info` command:** show metadata for a single secret — ID, share URL, created/expires dates, size, passphrase indicator, and decrypted note. Accepts a full ID, prefix, or share URL. Supports `--json` output.
- **ECDH AMK transfer during `secrt login`:** when the browser has an AMK, it performs ephemeral P-256 ECDH key agreement during device authorization to securely transfer the key to the CLI.
- **`parse_secret_url` re-export:** `secrt-core`'s URL parsing is now available for sync URL handling.
- **`get_secret_metadata` on `SecretApi`:** fetch metadata for a single secret by ID.

### Changed

- **`secrt list` output:** notes column added when encrypted notes are available, showing decrypted note text for secrets with attached notes.

## 0.12.2 — 2026-02-19

### Changed

- **Release archives:** CLI downloads are now `.zip` (macOS/Windows) and `.tar.gz` (Linux) containing a properly named `secrt` (or `secrt.exe`) binary instead of bare platform-suffixed executables. macOS universal binary renamed from `secrt-darwin-universal` to `secrt-macos.zip`.

## 0.12.1 — 2026-02-18

### Added

- **`secrt list` command:** list active secrets with a formatted table showing ID, creation date, expiry countdown (`dd HH:MM:SS` with dimmed seconds), size, and passphrase indicator (⚷). Supports `--limit`, `--offset`, `--json`, and `--silent` flags.
- **Prefix-based burn:** `secrt burn` now accepts partial secret IDs — on 404, it resolves the prefix against your secret list. Ambiguous prefixes produce a clear error. Trailing ellipsis characters (`…`) from copy-pasting truncated list output are automatically stripped.

### Fixed

- **CLI `list` returns empty for web-created secrets:** API key auth now resolves the full owner key set (`user:{id}` + all `apikey:{prefix}`) when the key is linked to a user account. Secrets created via the web UI are now visible from the CLI, and vice versa. Same fix applied to `checksum` and `burn` endpoints.
- **CLI-created secrets invisible in web UI:** when creating via an API key linked to a user, the secret is now owned under `user:{id}` for consistency with session-created secrets.

## 0.12.0 — 2026-02-18

### Added

- **`secrt auth login`:** browser-based device authorization flow — generates key material locally, opens a verification URL (with QR code on TTY), polls for approval, and stores the API key in OS keychain or config file. The root key never leaves the CLI.
- **`secrt auth setup`:** interactive API key setup — paste an existing `sk2_` key, validate format, optionally verify against the server, and store securely.
- **`secrt auth status`:** show current authentication state — displays masked key, source (env/keychain/config), and server connectivity.
- **`secrt auth logout`:** clear stored credentials from both OS keychain and config file.
- **`--qr` / `-Q` flag for `send`:** display the share URL as a terminal QR code after sending a secret. Requires TTY; skipped in `--json` mode.
- **QR code rendering:** `auth login` prints a scannable QR code of the verification URL when stderr is a TTY.
- **Config write-back:** `set_config_key()` and `remove_config_key()` for programmatic config file editing that preserves comments and enforces `0600` permissions.
- **Shell completions:** `auth` command with `login`, `setup`, `status`, `logout` subcommands added to bash, zsh, and fish completions.

## 0.11.0 — 2026-02-17

### Changed

- **Envelope suite migration:** CLI now produces/consumes `v1-argon2id-hkdf-aes256gcm-sealed-payload` only.
- **Vector alignment:** CLI envelope fixtures now track Argon2id-based `spec/v1/envelope.vectors.json`.
- **Docs refresh:** CLI documentation now reflects Argon2id passphrase derivation and removes legacy passphrase-KDF references.

## 0.10.3 — 2026-02-16

No CLI behavior changes in this release. Version bump to align workspace at 0.10.3.

## 0.10.2 — 2026-02-16

No CLI behavior changes in this release. Version bump to align workspace at 0.10.2.

## 0.10.1 — 2026-02-16

No CLI behavior changes in this release. Version bump to align workspace at 0.10.1.

## 0.10.0 — 2026-02-16

No CLI behavior changes in this release. Version bump to align workspace at 0.10.0.

## 0.9.1 — 2026-02-15

No CLI behavior changes in this release. Version bump to align workspace at 0.9.1.

## 0.9.0 — 2026-02-14

No CLI behavior changes in this release. Version bump to align workspace at 0.9.0.

## 0.8.0 — 2026-02-14

No CLI behavior changes in this release. Version bump to align workspace at 0.8.0.

## 0.7.0 — 2026-02-14

No CLI behavior changes in this release. Version bump to align workspace at 0.7.0.

## 0.6.1 — 2026-02-13

No CLI behavior changes in this release. Version bump to align workspace at 0.6.1.

## 0.6.0 — 2026-02-13

### Changed

- **API key v2 compatibility:** CLI now accepts local `sk2_<prefix>.<root_b64>` keys and derives wire credentials (`ak2_<prefix>.<auth_b64>`) automatically for authenticated requests.
- **Validation behavior:** malformed `sk2_` / `ak2_` values now fail fast with clear `invalid --api-key` errors.
- **Config/help updates:** config template and help examples now document `sk2_` keys.
- **Breaking envelope hard-cut:** CLI now produces/consumes only the sealed-payload envelope format (`v1-argon2id-hkdf-aes256gcm-sealed-payload`); legacy envelope payloads are not supported.
- **Encrypted metadata handling:** file metadata is now read from decrypted payload metadata, not plaintext envelope fields.
- **Compression policy defaults:** `send` now applies zstd compression policy defaults (`threshold=2048`, `min_savings=64`, `min_savings_ratio=10%`, `level=3`) and `get` decodes framed payloads with a 100 MiB safety cap.
- **JSON output metadata source:** `get --json` file fields are now derived from decrypted payload metadata (`type=file`, `filename`, `mime`) instead of plaintext envelope hints.
- **No legacy envelope compatibility:** prior plaintext `hint` envelope behavior is intentionally removed in 0.6.0.

### Added

- **Deterministic vectors:** CLI test suite now validates key derivation against `spec/v1/apikey.vectors.json`.
- **Sealed-envelope vectors:** CLI envelope fixtures now track rewritten `spec/v1/envelope.vectors.json`, including `codec=none/zstd` and encrypted metadata cases.

## 0.5.2 — 2026-02-12

No CLI changes — version bump to unify with workspace at 0.5.2.

## 0.5.1 — 2026-02-12

No CLI changes — version bump to unify with workspace at 0.5.1.

## 0.5.0 — 2026-02-12

No CLI changes — version bump to unify with workspace at 0.5.0.

## 0.4.2 — 2026-02-11

### Changed

- **Relative expiry display:** Expiry timestamps now show relative time with the UTC timestamp in parentheses (e.g., "Expires in 3 days, 2 hours (2026-02-09 00:00 UTC)") instead of converting to local timezone.
- **Remove `chrono` dependency:** Replaced with ~35 lines of hand-rolled date math, dropping 4 crates from the dependency tree and saving ~49 KB from the release binary.

## 0.4.1 — 2026-02-11

### Changed

- **Monorepo migration:** Project moved to [getsecrt/secrt](https://github.com/getsecrt/secrt) monorepo. Shared crypto and protocol logic extracted into `secrt-core` crate. No functional changes to the CLI.

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
- **Crypto:** AES-256-GCM + HKDF-SHA256, optional Argon2id passphrases, zero-knowledge client-side encryption via `ring`
- **Config:** TOML config file (`~/.config/secrt/config.toml`) with `config init`, env vars, CLI flag precedence
- **Keychain:** Optional OS keychain integration (macOS Keychain, Linux keyutils, Windows Credential Manager) for passphrase storage
- **Get:** Auto-tries configured `decryption_passphrases`, falls back to interactive prompt on TTY
- **Input:** Stdin pipe, `--text`, `--file`, `--multi-line`, `--trim`, hidden/shown interactive input
- **Output:** Human-friendly TTY output with color, `--json` for scripting, `--silent` mode
- **Shell completions:** Bash, Zsh, Fish via `completion` command
- **No async runtime** — blocking HTTP via `ureq`, ~1.5 MB static binary
