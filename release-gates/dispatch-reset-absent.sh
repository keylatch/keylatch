#!/usr/bin/env bash
# dispatch-reset-absent.sh — T-13-08 release gate
#
# Verifies that the dispatch.Reset symbol is NOT present in the production
# keylatch binary. dispatch.Reset is gated behind //go:build test_only and
# must never be linked into release builds.
#
# S-FIND-21: `go tool nm <binary> | grep -i reset` must return empty for
# the production binary; the symbol is test-only.
#
# Usage: bash release-gates/dispatch-reset-absent.sh <binary>
# Exit:  0 if Reset symbol absent (gate passes), 1 if present (gate fails).
set -euo pipefail

BINARY="${1:?binary path required as \$1}"

if [[ ! -f "$BINARY" ]]; then
  echo "dispatch-reset-absent: binary not found: $BINARY" >&2
  exit 1
fi

echo "dispatch-reset-absent: scanning $BINARY for dispatch.Reset symbol..."

# Use go tool nm to scan the symbol table.
# Filter for Reset symbols in the dispatch package path.
# The symbol name in production binaries omits test_only symbols entirely.
if ! command -v go &>/dev/null; then
  echo "dispatch-reset-absent: 'go' not found in PATH — cannot run nm check" >&2
  exit 1
fi

RESET_SYMBOLS="$(go tool nm "$BINARY" 2>/dev/null | grep -i "dispatch.*Reset\|Reset.*dispatch" || true)"

if [[ -n "$RESET_SYMBOLS" ]]; then
  echo "FAIL: dispatch-reset-absent: dispatch.Reset symbol present in release binary!" >&2
  echo "  Found: $RESET_SYMBOLS" >&2
  echo "  Fix: ensure dispatch/dispatch_test_only.go is NOT compiled into the release build." >&2
  echo "       The Reset() function must only compile with -tags test_only." >&2
  exit 1
fi

echo "PASS: dispatch-reset-absent: dispatch.Reset symbol not found in $BINARY"
exit 0
