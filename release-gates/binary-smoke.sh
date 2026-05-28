#!/usr/bin/env bash
set -euo pipefail

BINARY="${1:?binary path required as \$1}"

TMPDIR=""
cleanup() {
  if [[ -n "$TMPDIR" && -d "$TMPDIR" ]]; then
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

TMPDIR="$(mktemp -d)"

"$BINARY" --version
"$BINARY" --help > /dev/null
HOME="$TMPDIR" "$BINARY" doctor --json 2>/dev/null || true

echo "binary-smoke: passed"
