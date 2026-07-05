#!/usr/bin/env bash
# lint-audit-perms.sh
#
# Asserts that the audit chain MAC salt file has mode 0600 and its containing
# directory has mode 0700.
#
# Usage:
#   scripts/lint-audit-perms.sh [salt-path]
#
# If salt-path is not given, defaults to:
#   ${KEYLATCH_CONFIG_DIR}/audit/salt   or
#   ~/.keylatch/audit/salt              (macOS/Linux default)
#
# Exit codes:
#   0  — all checks passed
#   1  — one or more checks failed
#   2  — usage error / missing arguments
set -euo pipefail

# ── Resolve the salt path ─────────────────────────────────────────────────────

SALT_PATH="${1:-}"

if [[ -z "$SALT_PATH" ]]; then
  if [[ -n "${KEYLATCH_CONFIG_DIR:-}" ]]; then
    SALT_PATH="${KEYLATCH_CONFIG_DIR}/audit/salt"
  elif [[ "$(uname -s)" == "Darwin" ]]; then
    SALT_PATH="${HOME}/.keylatch/audit/salt"
  else
    SALT_PATH="${HOME}/.keylatch/audit/salt"
  fi
fi

FAIL=0

# ── Helper ─────────────────────────────────────────────────────────────────────

check_perm() {
  local path="$1"
  local want="$2"
  local label="$3"

  if [[ ! -e "$path" ]]; then
    echo "SKIP  $label: $path does not exist (not yet initialized)"
    return 0
  fi

  local got
  if [[ "$(uname -s)" == "Darwin" ]]; then
    got="$(stat -f '%A' "$path")"   # BSD stat: octal perm, no leading zero
    got="$(printf '%04d' "$got")"   # normalise to 4 digits e.g. 0600 → 0600
  else
    got="$(stat -c '%a' "$path")"   # GNU stat: octal perm without leading zero
    got="$(printf '%04d' "$got")"
  fi

  if [[ "$got" == "$want" ]]; then
    echo "OK    $label: $path ($got)"
  else
    echo "FAIL  $label: $path — got $got, want $want"
    FAIL=1
  fi
}

# ── Checks ────────────────────────────────────────────────────────────────────

SALT_DIR="$(dirname "$SALT_PATH")"

echo "Checking audit salt permissions..."
check_perm "$SALT_PATH" "0600" "salt file mode"
check_perm "$SALT_DIR"  "0700" "salt directory mode"

# ── Result ────────────────────────────────────────────────────────────────────

if [[ $FAIL -eq 0 ]]; then
  echo "PASS  All audit salt permission checks passed."
  exit 0
else
  echo "FAIL  One or more audit salt permission checks failed."
  echo "      Fix: chmod 0600 \"$SALT_PATH\"; chmod 0700 \"$SALT_DIR\""
  exit 1
fi
