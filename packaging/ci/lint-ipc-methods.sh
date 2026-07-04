#!/usr/bin/env bash
# packaging/ci/lint-ipc-methods.sh
#
# CI lint: verify the IPC method allow-list.
#
# Checks:
#   1. internal/sidecar/ipc/handlers.go: exactly 5 handlers registered,
#      each with a name in the documented allow-list.
#   2. src-tauri/src/ipc.rs: IpcMethod enum has exactly 5 variants,
#      each matching the same allow-list.
#
# Exit 0: clean.
# Exit 1: violation found.
#
# Usage:
#   bash packaging/ci/lint-ipc-methods.sh [repo-root]

set -euo pipefail

REPO_ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
HANDLERS_GO="${REPO_ROOT}/internal/sidecar/ipc/handlers.go"
IPC_RS="${REPO_ROOT}/src-tauri/src/ipc.rs"

# The canonical 5-method allow-list.
ALLOWED_METHODS=(
  "Health"
  "MintBootstrapToken"
  "SubscribeEvents"
  "Shutdown"
  "OpenSystemBrowser"
)
EXPECTED_COUNT=${#ALLOWED_METHODS[@]}  # 5

ERRORS=0

contains() {
  local needle="$1"; shift
  local elem
  for elem in "$@"; do [[ "$elem" == "$needle" ]] && return 0; done
  return 1
}

# ── Check Go handlers.go ──────────────────────────────────────────────────────
if [[ -f "$HANDLERS_GO" ]]; then
  # Count reg.Register(Method*, ...) calls.
  go_registrations=()
  while IFS= read -r line; do
    # Match: reg.Register(MethodXxx, ...)
    method=$(echo "$line" | sed -n 's/.*reg\.Register(Method\([A-Za-z]*\),.*/\1/p')
    if [[ -n "$method" ]]; then
      go_registrations+=("$method")
    fi
  done < "$HANDLERS_GO"

  go_count=${#go_registrations[@]}
  if [[ $go_count -ne $EXPECTED_COUNT ]]; then
    echo "ERROR: handlers.go has ${go_count} registered handlers, expected ${EXPECTED_COUNT}"
    ERRORS=$((ERRORS + 1))
  fi

  for method in "${go_registrations[@]}"; do
    if ! contains "$method" "${ALLOWED_METHODS[@]}"; then
      echo "ERROR: handlers.go registers disallowed method '${method}'"
      ERRORS=$((ERRORS + 1))
    fi
  done
else
  echo "ERROR: ${HANDLERS_GO} not found — required source file is missing (N5)"
  ERRORS=$((ERRORS + 1))
fi

# ── Check Rust ipc.rs ─────────────────────────────────────────────────────────
if [[ -f "$IPC_RS" ]]; then
  # Count IpcMethod enum variants.
  rs_variants=()
  in_enum=false
  while IFS= read -r line; do
    if echo "$line" | grep -qE "^pub enum IpcMethod\b"; then
      in_enum=true
      continue
    fi
    if $in_enum && echo "$line" | grep -qE "^}"; then
      in_enum=false
      continue
    fi
    if $in_enum; then
      variant=$(echo "$line" | sed -n 's/^[[:space:]]*\([A-Z][a-zA-Z]*\),.*/\1/p')
      if [[ -n "$variant" ]]; then
        rs_variants+=("$variant")
      fi
    fi
  done < "$IPC_RS"

  rs_count=${#rs_variants[@]}
  if [[ $rs_count -ne $EXPECTED_COUNT ]]; then
    echo "ERROR: IpcMethod enum in ipc.rs has ${rs_count} variants, expected ${EXPECTED_COUNT}"
    ERRORS=$((ERRORS + 1))
  fi

  for variant in "${rs_variants[@]}"; do
    if ! contains "$variant" "${ALLOWED_METHODS[@]}"; then
      echo "ERROR: IpcMethod variant '${variant}' not in allow-list"
      ERRORS=$((ERRORS + 1))
    fi
  done
else
  echo "ERROR: ${IPC_RS} not found — required source file is missing (N5)"
  ERRORS=$((ERRORS + 1))
fi

if [[ $ERRORS -gt 0 ]]; then
  echo "FAIL: ${ERRORS} IPC allow-list violation(s). Only register/declare methods from the documented 5-method set."
  exit 1
fi

echo "OK: IPC method allow-list check passed (${EXPECTED_COUNT} methods confirmed)"
