#!/usr/bin/env bash
# bench.sh — Compare secrt Rust vs Go CLI performance
# Uses hyperfine for statistical benchmarking
set -euo pipefail

RUST="/Users/jdlien/code/secrt-cli/target/release/secrt"
GO="/Users/jdlien/code/secrt/secrt"

# Colors
BOLD='\033[1m'
CYAN='\033[36m'
RESET='\033[0m'

header() { echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${RESET}\n"; }

# Create temp payloads
SMALL=$(mktemp)
LARGE=$(mktemp)
dd if=/dev/urandom bs=1 count=1000 2>/dev/null | base64 > "$SMALL"
dd if=/dev/urandom bs=1024 count=100 2>/dev/null | base64 > "$LARGE"
trap 'rm -f "$SMALL" "$LARGE"' EXIT

# ── Binary size ──────────────────────────────────────────────
header "Binary Size"
echo "  Rust: $(du -h "$RUST" | cut -f1)"
echo "  Go:   $(du -h "$GO" | cut -f1)"

# ── 1. Startup: --help ───────────────────────────────────────
header "1. Startup Time (--help)"
hyperfine --warmup 50 --min-runs 500 \
  --command-name "Rust" "$RUST help" \
  --command-name "Go"   "$GO help"

# ── 2. Startup: --version ────────────────────────────────────
header "2. Startup Time (--version)"
hyperfine --warmup 50 --min-runs 500 \
  --command-name "Rust" "$RUST version" \
  --command-name "Go"   "$GO version"

# ── 3. Create + Encrypt (1 KB) ───────────────────────────────
# Uses connection-refused endpoint so crypto runs but HTTP fails
header "3. Create + Encrypt — 1 KB payload"
hyperfine --warmup 10 --min-runs 200 \
  --command-name "Rust" "$RUST create --file $SMALL --base-url http://127.0.0.1:1 2>/dev/null || true" \
  --command-name "Go"   "$GO create --file $SMALL --base-url http://127.0.0.1:1 2>/dev/null || true"

# ── 4. Create + Encrypt (100 KB) ─────────────────────────────
header "4. Create + Encrypt — 100 KB payload"
hyperfine --warmup 10 --min-runs 200 \
  --command-name "Rust" "$RUST create --file $LARGE --base-url http://127.0.0.1:1 2>/dev/null || true" \
  --command-name "Go"   "$GO create --file $LARGE --base-url http://127.0.0.1:1 2>/dev/null || true"

# ── 5. Create + Encrypt + Passphrase (PBKDF2) ────────────────
header "5. Create + Encrypt + PBKDF2 — 1 KB payload"
hyperfine --warmup 5 --min-runs 50 \
  --command-name "Rust" "BENCH_PASS=hunter2 $RUST create --file $SMALL --passphrase-env BENCH_PASS --base-url http://127.0.0.1:1 2>/dev/null || true" \
  --command-name "Go"   "BENCH_PASS=hunter2 $GO create --file $SMALL --passphrase-env BENCH_PASS --base-url http://127.0.0.1:1 2>/dev/null || true"

# ── 6. Error path: bad claim URL ──────────────────────────────
header "6. Error Handling — bad claim URL"
hyperfine --warmup 50 --min-runs 500 \
  --command-name "Rust" "$RUST claim https://secrt.ca/s/bad 2>/dev/null || true" \
  --command-name "Go"   "$GO claim https://secrt.ca/s/bad 2>/dev/null || true"

# ── 7. TTL parsing (embedded in create) ──────────────────────
header "7. Create with TTL parsing — various TTL formats"
hyperfine --warmup 10 --min-runs 200 \
  --command-name "Rust" "$RUST create --text x --ttl '2h30m' --base-url http://127.0.0.1:1 2>/dev/null || true" \
  --command-name "Go"   "$GO create --text x --ttl '2h30m' --base-url http://127.0.0.1:1 2>/dev/null || true"

header "Done!"
