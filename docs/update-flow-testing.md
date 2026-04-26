# Testing the self-update flow

Three ways to exercise `secrt update` end-to-end without pushing anything to
the real `getsecrt/secrt` GitHub release stream. Pick the lightest one that
covers what you need.

The **hidden `--release-base-url <url>`** flag is the linchpin: it points
the download path at any HTTP server you control, so you never need to
fight GitHub or risk shipping a placeholder release.

---

## 1. Local mock release server (preferred for E2E)

Use this for routine changes to the update logic itself. Runs on any host,
exercises the full download / SHA-256 verify / atomic-rename path.

```sh
# Build a "newer" binary with a tweaked version
sed -i.bak 's/^version = ".*"/version = "0.99.0-test"/' Cargo.toml
cargo build --release -p secrt-cli

# Stage the artifact under the asset name secrt update will look up.
# IMPORTANT: assets MUST live under cli/v<version>/, mirroring the real
# GitHub release URL layout (.../releases/download/cli/v0.16.0/<asset>).
# Asset names per spec/v1/cli.md § secrt update Subcommand:
#   linux-amd64  → secrt-linux-amd64
#   linux-arm64  → secrt-linux-arm64
#   darwin-amd64 → secrt-darwin-amd64
#   darwin-arm64 → secrt-darwin-arm64
#   windows-amd64 → secrt-windows-amd64.exe
#   windows-arm64 → secrt-windows-arm64.exe
mkdir -p /tmp/release-fixtures/cli/v0.99.0
cp target/release/secrt /tmp/release-fixtures/cli/v0.99.0/secrt-darwin-arm64   # match your host
( cd /tmp/release-fixtures/cli/v0.99.0 && shasum -a 256 secrt-* > secrt-checksums-sha256.txt )

# Restore your local Cargo.toml so the running binary stays at its real version.
mv Cargo.toml.bak Cargo.toml
# (also restore secrt-core dep pins in crates/secrt-{cli,server,app}/Cargo.toml
# if you bumped them — `cargo build --release -p secrt-cli` rebuilds at the
# original version once everything is back in place.)

# Serve it
python3 -m http.server 8000 --directory /tmp/release-fixtures &

# Run the upgrade
secrt update --version 0.99.0 --release-base-url http://localhost:8000
secrt --version       # → secrt 0.99.0
```

Note: `--version` is strict `\d+.\d+.\d+`. A `0.99.0-test` style suffix is
rejected at parse time. Use a plain triplet for the staged "newer" version.

To exercise SHA-256 mismatch: edit the staged binary by one byte after
generating the checksum file (e.g., `echo x >> /tmp/release-fixtures/cli/v0.99.0/secrt-darwin-arm64`).
`secrt update` MUST refuse, exit with code 2, and print both hashes.

To exercise managed-install detection: symlink your `secrt` under a fake
manager root before running `update`:

```sh
mkdir -p ~/Cellar/secrt/0.15.0/bin
ln -sf "$(which secrt)" ~/Cellar/secrt/0.15.0/bin/secrt
~/Cellar/secrt/0.15.0/bin/secrt update    # MUST refuse with: brew upgrade secrt
```

Repeat with `~/.asdf/installs/secrt/0.15.0/bin`, `~/.local/share/mise/installs/secrt/...`,
`/nix/store/...`, `~/.cargo/bin/secrt` to cover each manager.

---

## 2. Local-version downgrade (preferred for "is the live system OK?")

Use this once a real `cli/v0.16.0` ships, to confirm the production path
still works against real GitHub releases. Tests Apple notarization,
Windows SmartScreen, real CDN etc — stuff a mock can't simulate.

```sh
# Pretend you're behind by one version
sed -i.bak 's/^version = "0.16.0"/version = "0.15.0"/' Cargo.toml
cargo build --release -p secrt-cli

./target/release/secrt update --check     # → "0.16.0 is available"
./target/release/secrt update             # downloads + verifies + installs the REAL artifact
./target/release/secrt --version          # → "0.16.0"

mv Cargo.toml.bak Cargo.toml              # don't forget
```

Doesn't work for testing PR4 itself (no real release exists yet), but is
the right "smoke test after every release" recipe.

---

## 3. Throwaway fork + fake release tag (preferred for poller integration)

Use this once, to confirm the server-side GitHub poller actually parses
real GitHub Releases API responses correctly. After that, paths 1 and 2
cover everything.

```sh
# In a personal fork, e.g. <youruser>/secrt-test-releases:
git tag cli/v9.9.9
git push origin cli/v9.9.9
gh release create cli/v9.9.9 --notes "test"

# Point a local secrt-server at the fork
GITHUB_REPO=<youruser>/secrt-test-releases \
GITHUB_POLL_INTERVAL_SECONDS=10 \
  cargo run --release -p secrt-server

# In another shell:
curl http://localhost:8080/api/v1/info | jq '.latest_cli_version'   # → "9.9.9"
curl -I http://localhost:8080/healthz | grep -i x-secrt-latest      # → 9.9.9
```

Cleanup: delete the test release and tag from the fork when done.

---

## Banner-only smoke (no install)

Just want to see the implicit banner fire? Poison the local cache:

```sh
mkdir -p ~/.cache/secrt
cat > ~/.cache/secrt/update-check.json <<EOF
{"checked_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","latest":"99.0.0","current":"$(secrt --version | awk '{print $2}')"}
EOF

secrt --version       # banner appears on stderr
SECRET_NO_UPDATE_CHECK=1 secrt --version    # banner suppressed
secrt --version 2>/dev/null                 # stderr-not-TTY suppression
```

---

## Platform-specific notes

**macOS.** First launch of a freshly-installed `secrt` triggers an online
Gatekeeper check against Apple's notarization service. Works while online,
fails on a fully air-gapped Mac (documented limitation, matches `brew install`
behavior). Test online first.

**Linux.** Distro packages live at `/usr/bin/secrt` (not a symlink). Refusal
is the natural permission-denied error from the install attempt; the CLI
SHOULD suggest `--install-dir ~/.local/bin/secrt` rather than `sudo`.

**Windows.** Watch for these specifically:
- `secrt.exe.old` should appear next to `secrt.exe` after a successful
  `secrt update`, then disappear on the next `secrt` invocation (the
  hidden `--cleanup` startup hook).
- If antivirus / Defender holds the file, the rename-self-aside step
  fails and the CLI should fall back to
  `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`, telling the user the
  upgrade lands on next reboot.
- SmartScreen warning is expected on first launch of an unsigned local
  build. Production binaries are Azure-Trusted-Signing-signed and
  bypass it.

---

## Pre-release checklist (before tagging `cli/vX.Y.Z`)

1. **Mock-server E2E** (path 1): mismatch case still rejects with exit 2.
2. **Managed-install refuse**: at least Homebrew + asdf patterns print the
   correct upgrade command.
3. **Banner suppression matrix**: confirm `--silent`, `--no-update-check`,
   `--json`, `SECRET_NO_UPDATE_CHECK=1`, redirected stderr (`2> /tmp/x`)
   all suppress; bare TTY shows banner.
4. **Server poller** (path 3 once, then optional): `/api/v1/info` exposes
   `latest_cli_version`, `latest_cli_version_checked_at`,
   `min_supported_cli_version`. `X-Secrt-*` headers present on `/healthz`.
5. **Cross-platform**: at minimum, run path 1 on each of macOS, Linux, and
   Windows. CI matrix (if configured) covers most of this automatically;
   manual verification on Windows is still wise because of antivirus
   behavior.

After the tag is pushed and the release workflow finishes:

6. **Live-system smoke** (path 2): from a clean install of the previous
   version, run `secrt update`. Confirm the banner fires, the upgrade
   completes, `secrt --version` reflects the new release, and a second
   `secrt update --check` reports up-to-date.
