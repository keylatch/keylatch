#!/usr/bin/env bash
set -euo pipefail

BINARY="${1:-keylatch}"
TEMPLATES_DIR="templates/providers"

if [[ ! -d "$TEMPLATES_DIR" ]]; then
  echo "provider-template-validate: templates directory not found: $TEMPLATES_DIR" >&2
  exit 1
fi

FAILED=0
count=0

while IFS= read -r -d '' f; do
  count=$((count + 1))
  if ! "$BINARY" registry validate "$f" 2>&1; then
    echo "FAIL: $f" >&2
    FAILED=1
  fi
  if grep -q "KEYLATCH_CANARY_" "$f"; then
    echo "[CANARY LEAK] $f contains a canary string" >&2
    FAILED=1
  fi
done < <(find "$TEMPLATES_DIR" -name "*.yaml" -print0)

if [[ "$FAILED" -ne 0 ]]; then
  echo "provider-template-validate: FAILED ($count templates checked)" >&2
  exit 1
fi

echo "provider-template-validate: all $count provider templates valid."
