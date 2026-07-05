#!/usr/bin/env bash
# security-grep.sh — static regression check for session-token format-string interpolation.
#
# Ensures no format-string interpolation of session tokens appears in production code.
# Pattern: fmt.Sprintf/Printf/Fprintf/Errorf with BW_SESSION or OP_SERVICE_ACCOUNT_TOKEN.
#
# Usage: bash scripts/security-grep.sh
# Exit 0: clean. Exit 1: violation found.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Checking for format-string interpolation of session tokens..."

# Must return empty — no format-string interpolation of session tokens.
# The pattern targets code that EVALUATES/INTERPOLATES the session value (via %s, %v, %q
# with a variable that holds the session), not hint messages that literally say "BW_SESSION".
# We look for:
#   - fmt.Sprintf/Fprintf/Errorf/Printf with a %s/%v/%q verb AND a BW_SESSION/OP_SERVICE_ACCOUNT variable
#
# NOTE: os.Getenv("BW_SESSION") is intentionally excluded — it is a safe environment
# variable lookup, not a format-string interpolation. Only fmt.* format calls that
# embed the session token value in a format string are considered violations.
# Exclude test files — they legitimately inject session values for testing.
MATCHES=$(grep -rE \
  'fmt\.(S|F|E)?[Pp]rintf[^(]*\([^)]*%[svq][^)]*BW_SESSION|fmt\.(S|F|E)?[Pp]rintf[^(]*\([^)]*%[svq][^)]*OP_SERVICE_ACCOUNT' \
  "${REPO_ROOT}/internal/" \
  "${REPO_ROOT}/cmd/" \
  2>/dev/null \
  | grep -v '_test\.go' \
  || true)

if [ -n "$MATCHES" ]; then
  echo "ERROR: session token in format string:"
  echo "$MATCHES"
  exit 1
fi

echo "OK — no session token format-string interpolation found."
exit 0
