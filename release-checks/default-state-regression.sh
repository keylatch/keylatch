#!/usr/bin/env bash
set -euo pipefail

BINARY="${1:-./keylatch}"

TMPDIR=""
cleanup() {
  if [[ -n "$TMPDIR" && -d "$TMPDIR" ]]; then
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

TMPDIR="$(mktemp -d)"

HOME="$TMPDIR" "$BINARY" bootstrap --mode=file 2>/dev/null || true

OUTPUT="$(HOME="$TMPDIR" "$BINARY" doctor --json 2>/dev/null || echo '{}')"

if ! echo "$OUTPUT" | grep -qE '"checks"|"status"'; then
  echo "default-state-regression: FAIL — doctor output missing expected fields" >&2
  echo "Output was: $OUTPUT" >&2
  exit 1
fi

echo "default-state-regression: passed"
