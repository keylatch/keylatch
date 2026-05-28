#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_DIR="${1:-dist/}"

if [[ ! -d "$ARTIFACT_DIR" ]]; then
  echo "artifact-scan: directory not found: $ARTIFACT_DIR" >&2
  exit 1
fi

FAILED=0

# 1. Canary strings
if grep -r "KEYLATCH_CANARY_" "$ARTIFACT_DIR" 2>/dev/null; then
  echo "[CANARY LEAK] canary strings found in $ARTIFACT_DIR" >&2
  FAILED=1
fi

# 2. Home paths (skip binary files — Go binaries embed module cache paths even with -s -w)
if grep -rIE "/Users/[^/]+|/home/[^/]+" "$ARTIFACT_DIR" 2>/dev/null; then
  echo "[PATH LEAK] home paths found in $ARTIFACT_DIR" >&2
  FAILED=1
fi

# 3. Token patterns (excluding lines with "canary")
if grep -rE "sk-[A-Za-z0-9]{32,}" "$ARTIFACT_DIR" 2>/dev/null | grep -iv "canary"; then
  echo "[TOKEN LEAK] token patterns found in $ARTIFACT_DIR" >&2
  FAILED=1
fi

# 4. Sourcemap files
if find "$ARTIFACT_DIR" -name "*.map" | grep -q .; then
  echo "[SOURCEMAP LEAK] .map files found in $ARTIFACT_DIR" >&2
  FAILED=1
fi

if [[ "$FAILED" -ne 0 ]]; then
  exit 1
fi

echo "artifact-scan: all checks passed"
