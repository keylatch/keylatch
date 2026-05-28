#!/usr/bin/env bash
# verify-bundle.sh — post-build verification.
# Fails if:
#   - dist/ does not exist.
#   - dist/ contains .map files (source maps must be disabled).
#   - dist/index.html does not exist.
set -euo pipefail

DIST="$(dirname "$0")/../dist"

if [[ ! -d "$DIST" ]]; then
  echo "verify-bundle: ERROR: dist/ directory not found at $DIST" >&2
  echo "  Run 'bun run build' first." >&2
  exit 1
fi

if [[ ! -f "$DIST/index.html" ]]; then
  echo "verify-bundle: ERROR: dist/index.html not found" >&2
  exit 1
fi

MAP_COUNT=$(find "$DIST" -name "*.map" | wc -l | tr -d ' ')
if [[ "$MAP_COUNT" -gt 0 ]]; then
  echo "verify-bundle: ERROR: $MAP_COUNT .map file(s) found in dist/" >&2
  echo "  Source maps must be disabled in production builds." >&2
  find "$DIST" -name "*.map"
  exit 1
fi

echo "verify-bundle: OK — dist/ looks good (no .map files, index.html present)"
