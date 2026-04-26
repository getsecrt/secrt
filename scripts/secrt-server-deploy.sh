#!/usr/bin/env bash
#
# secrt-server deploy script — pulls the latest stable server release from
# GitHub, verifies SHA-256 checksums, installs to /opt/secrt/bin, and
# restarts the systemd unit.
#
# ── Canonical copy ───────────────────────────────────────────────────
# This file in the secrt repo (scripts/secrt-server-deploy.sh) is the
# source of truth. Sync to each host after any change here.
#
# ── Intended install path (prescriptive) ─────────────────────────────
# The canonical location on any secrt server is:
#
#     /usr/local/bin/secrt-server-deploy   (root:root, mode 0755)
#
# This puts it in PATH for any user, root-owned to match the privilege
# it elevates to, and named for what it does (no "deploy.sh in someone's
# home" ambiguity).
#
# Currently deployed on: secrt.is, secrt.ca.
# New hosts SHOULD install at the canonical path.
#
# ── Install on a new server ──────────────────────────────────────────
#   scp scripts/secrt-server-deploy.sh <host>:/tmp/secrt-server-deploy
#   ssh <host> 'sudo install -m 755 -o root -g root \
#       /tmp/secrt-server-deploy /usr/local/bin/secrt-server-deploy && \
#       rm /tmp/secrt-server-deploy'
#
# Prerequisites on the target host:
#   - sudo, curl, python3, sha256sum, install (coreutils), systemctl
#   - /opt/secrt/bin exists and is writable by root
#   - /etc/systemd/system/secrt.service is installed and enabled
#   - /etc/secrt-server/env (root:root 0600) holds runtime config
#
# ── Usage ────────────────────────────────────────────────────────────
#   ssh <host> secrt-server-deploy
#   # or, after ssh:
#   secrt-server-deploy
#
# The script re-execs itself under sudo, so no manual `sudo` prefix is
# needed. It will prompt before redeploying when already on the latest
# tag (no-op safety net for accidental re-runs).
#
# ── What it does ─────────────────────────────────────────────────────
#   1. Resolves the highest stable `server/vX.Y.Z` GitHub release tag.
#   2. Downloads secrt-server and secrt-admin for the host's architecture
#      (linux-amd64 or linux-arm64, autodetected via `uname -m`).
#   3. Verifies SHA-256 against secrt-server-checksums-sha256.txt.
#   4. Installs both binaries to /opt/secrt/bin (mode 0755).
#   5. Records the deployed version in /opt/secrt/bin/.version.
#   6. Restarts the `secrt` systemd unit and prints its status.
#
# Aborts on any error: missing release, checksum mismatch, failed write,
# or systemctl failure. Safe to re-run.
#
set -euo pipefail

# Re-exec under sudo so the install/restart steps can write to root-owned
# paths (/opt/secrt/bin, /etc/systemd) without per-line sudo.
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    exec sudo --preserve-env=PATH bash "$0" "$@"
fi


REPO="getsecrt/secrt"
INSTALL_DIR="/opt/secrt/bin"
TMPDIR="$(mktemp -d)"
VERSION_FILE="${INSTALL_DIR}/.version"

# Detect architecture. The release workflow publishes linux-amd64 and
# linux-arm64; map `uname -m` onto those names. Aborts on anything else
# rather than silently picking the wrong artifact.
case "$(uname -m)" in
    x86_64|amd64)    ARCH="linux-amd64" ;;
    aarch64|arm64)   ARCH="linux-arm64" ;;
    *) printf '\033[1;31m✘ Unsupported architecture: %s\033[0m\n' "$(uname -m)" >&2
       printf '  secrt-server only ships linux-amd64 and linux-arm64.\n' >&2
       exit 1 ;;
esac

trap 'rm -rf "$TMPDIR"' EXIT

# ── Helpers ──────────────────────────────────────────────────────────
step() { printf '\n\033[1;36m▸ %s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m✔\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✘\033[0m %s\n' "$1"; }
info() { printf '  \033[2m%s\033[0m\n' "$1"; }

# ── Resolve latest server release ────────────────────────────────────
step "Checking versions"

CURRENT_VERSION="(first deploy)"
[[ -f "$VERSION_FILE" ]] && CURRENT_VERSION="$(cat "$VERSION_FILE")"

LATEST_TAG=$(
  curl -sf -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO}/releases?per_page=100" \
  | python3 -c '
import sys, json, re
releases = json.load(sys.stdin)
candidates = []
for r in releases:
    if r.get("draft") or r.get("prerelease"):
        continue
    tag = r.get("tag_name", "")
    m = re.fullmatch(r"server/v(\d+)\.(\d+)\.(\d+)", tag)
    if m:
        candidates.append((tuple(map(int, m.groups())), tag))

if not candidates:
    raise SystemExit("No stable server/vX.Y.Z release tags found")

print(max(candidates, key=lambda x: x[0])[1])
'
)

LATEST_VERSION="${LATEST_TAG#server/}"   # e.g. "v0.5.2"
BASE_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}"

printf '  Current : \033[33m%s\033[0m\n' "$CURRENT_VERSION"
printf '  Latest  : \033[32m%s\033[0m\n' "$LATEST_VERSION"

if [[ "$CURRENT_VERSION" == "$LATEST_VERSION" ]]; then
  printf '\n  \033[33mAlready on latest version.\033[0m\n'
  read -rp "  Continue anyway? [y/N] " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || exit 0
fi

# ── Download ─────────────────────────────────────────────────────────
step "Downloading binaries"

info "secrt-server"
curl -fSL --progress-bar -o "${TMPDIR}/secrt-server" "${BASE_URL}/secrt-server-${ARCH}"

info "secrt-admin"
curl -fSL --progress-bar -o "${TMPDIR}/secrt-admin" "${BASE_URL}/secrt-admin-${ARCH}"

curl -fsSL -o "${TMPDIR}/checksums.txt" "${BASE_URL}/secrt-server-checksums-sha256.txt"

# ── Verify checksums ─────────────────────────────────────────────────
step "Verifying checksums"

cd "$TMPDIR"
CHECKSUM_OK=true

for bin in secrt-server secrt-admin; do
  expected=$(grep "${bin}-${ARCH}" checksums.txt | awk '{print $1}')
  actual=$(sha256sum "$bin" | awk '{print $1}')

  if [[ "$expected" == "$actual" ]]; then
    printf '  \033[32m✔\033[0m %s  \033[2m%s…\033[0m\n' "$bin" "${actual:0:16}"
  else
    fail "$bin — checksum mismatch!"
    info "Expected: ${expected}"
    info "Got:      ${actual}"
    CHECKSUM_OK=false
  fi
done

if [[ "$CHECKSUM_OK" != "true" ]]; then
  printf '\n  \033[1;31mAborting — integrity check failed.\033[0m\n\n'
  exit 1
fi

# ── Install ──────────────────────────────────────────────────────────
step "Installing to ${INSTALL_DIR}"

install -m 755 "${TMPDIR}/secrt-server" "${INSTALL_DIR}/secrt-server"
install -m 755 "${TMPDIR}/secrt-admin"  "${INSTALL_DIR}/secrt-admin"
echo "$LATEST_VERSION" > "$VERSION_FILE"
ok "Binaries installed"

# ── Restart ──────────────────────────────────────────────────────────
step "Restarting service"

sudo systemctl restart secrt
ok "Service restarted"

echo ""
sudo systemctl status secrt --no-pager

printf '\n\033[1;32m✔ Deploy complete\033[0m  \033[2m%s → %s\033[0m\n\n' "$CURRENT_VERSION" "$LATEST_VERSION"
