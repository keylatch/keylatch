#!/usr/bin/env bash
# lint-env-docs.sh
#
# Asserts that every KEYLATCH_* env var read in the production Go source has an
# entry in docs/cli/environment.md.
#
# Exit codes:
#   0  — all documented
#   1  — one or more undocumented KEYLATCH_* env vars found
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_DOC="${REPO_ROOT}/docs/cli/environment.md"
FAIL=0

if [[ ! -f "$ENV_DOC" ]]; then
  echo "FAIL: $ENV_DOC does not exist"
  exit 1
fi

# Extract all KEYLATCH_* names from production Go source.
# Only grep actual env-var reads (os.Getenv / env() / lookup() calls).
# Excludes _test.go files by filtering on file name before grepping.
TMP_VARS="$(mktemp)"
trap 'rm -f "$TMP_VARS"' EXIT

# Use find to list only non-test .go files, then grep for env reads.
find "${REPO_ROOT}/internal" "${REPO_ROOT}/cmd" \
  -name '*.go' ! -name '*_test.go' -print0 2>/dev/null \
| xargs -0 grep -hE \
  '(os\.Getenv|os\.LookupEnv)\("KEYLATCH_[A-Z_]+"' \
  2>/dev/null \
| grep -oE 'KEYLATCH_[A-Z_]+' \
| sort -u > "$TMP_VARS"

# Also capture env() / lookup() call patterns used in the paths package.
find "${REPO_ROOT}/internal" "${REPO_ROOT}/cmd" \
  -name '*.go' ! -name '*_test.go' -print0 2>/dev/null \
| xargs -0 grep -hE \
  'env\("KEYLATCH_[A-Z_]+"\)|lookup\("KEYLATCH_[A-Z_]+"\)' \
  2>/dev/null \
| grep -oE 'KEYLATCH_[A-Z_]+' \
| sort -u >> "$TMP_VARS"

sort -u "$TMP_VARS" -o "$TMP_VARS"

COUNT=$(wc -l < "$TMP_VARS" | tr -d ' ')
echo "Checking ${COUNT} KEYLATCH_* vars against $ENV_DOC..."

while IFS= read -r var; do
  [[ -z "$var" ]] && continue
  if ! grep -qF "$var" "$ENV_DOC"; then
    echo "FAIL  Undocumented: $var"
    FAIL=1
  fi
done < "$TMP_VARS"

if [[ $FAIL -eq 0 ]]; then
  echo "PASS  All KEYLATCH_* env vars are documented in docs/cli/environment.md"
  exit 0
else
  echo ""
  echo "FAIL  Add missing variables to docs/cli/environment.md"
  exit 1
fi
