#!/usr/bin/env bash
# check-binary-size.sh — verifies the compiled keylatch binary stays under 30 MiB.
# Usage: check-binary-size.sh [binary-path]
set -euo pipefail

BINARY="${1:-./keylatch}"
LIMIT_BYTES=$((30 * 1024 * 1024))  # 30 MiB hard fail
WARN_BYTES=$((25 * 1024 * 1024))   # 25 MiB warning

if [[ ! -f "$BINARY" ]]; then
  echo "check-binary-size: INFO: binary not found at $BINARY — skipping size check" >&2
  exit 0
fi

SIZE=$(stat -f%z "$BINARY" 2>/dev/null || stat -c%s "$BINARY" 2>/dev/null)
SIZE_KIB=$(( SIZE / 1024 ))
LIMIT_KIB=$(( LIMIT_BYTES / 1024 ))
WARN_KIB=$(( WARN_BYTES / 1024 ))

if [[ "$SIZE" -gt "$LIMIT_BYTES" ]]; then
  echo "check-binary-size: ERROR: binary size ${SIZE_KIB} KiB exceeds ${LIMIT_KIB} KiB limit" >&2
  exit 1
fi

if [[ "$SIZE" -gt "$WARN_BYTES" ]]; then
  echo "check-binary-size: WARNING: binary size ${SIZE_KIB} KiB exceeds ${WARN_KIB} KiB warning threshold (limit: ${LIMIT_KIB} KiB)" >&2
  exit 0
fi

echo "check-binary-size: OK — binary size ${SIZE_KIB} KiB (warn: ${WARN_KIB} KiB, limit: ${LIMIT_KIB} KiB)"
