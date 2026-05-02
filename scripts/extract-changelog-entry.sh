#!/usr/bin/env bash
# Extract a single version's entry from a Keep-a-Changelog-style file.
#
# Usage: extract-changelog-entry.sh <changelog.md> <version>
#
# Prints the entry body (everything between "## $version <suffix>" and the
# next "## " heading, with leading/trailing blank lines trimmed). Exits
# non-zero if the entry is missing — used by the release workflows to fail
# fast when a tag is pushed without a corresponding CHANGELOG entry.
#
# Version match is anchored: "0.17.5" matches "## 0.17.5 — 2026-05-02"
# but not "## 0.17.50 — ...". The trailing character class rejects digits
# and dots so prefix collisions don't slip through.

set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 <changelog.md> <version>" >&2
  exit 2
fi

CHANGELOG=$1
VERSION=$2

if [ ! -f "$CHANGELOG" ]; then
  echo "error: $CHANGELOG not found" >&2
  exit 2
fi

OUTPUT=$(awk -v ver="$VERSION" '
  BEGIN { capturing = 0; n = 0 }
  /^## / {
    if (capturing) { exit }
    if ($0 ~ ("^## " ver "([^0-9.]|$)")) { capturing = 1; next }
  }
  capturing {
    buf[++n] = $0
  }
  END {
    # Trim leading blank lines
    start = 1
    while (start <= n && buf[start] == "") start++
    # Trim trailing blank lines
    while (n >= start && buf[n] == "") n--
    for (i = start; i <= n; i++) print buf[i]
  }
' "$CHANGELOG")

if [ -z "$OUTPUT" ]; then
  echo "error: no changelog entry found for version '$VERSION' in $CHANGELOG" >&2
  echo "       expected a heading like: ## $VERSION — YYYY-MM-DD" >&2
  exit 1
fi

printf '%s\n' "$OUTPUT"
