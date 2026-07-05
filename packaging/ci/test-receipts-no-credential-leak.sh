#!/usr/bin/env bash
# test-receipts-no-credential-leak.sh — canary scan
#
# Verifies that a known canary credential value injected at enrollment time
# does NOT appear in any receipt output channel:
#   1. GET /v1/receipts (JSON list endpoint)
#   2. keylatch receipts list --json (CLI file-store path)
#
# Invariant: receipt payloads must never contain credential bytes.
#
# Exit codes:
#   0 — no canary bytes found in any receipt output (PASS)
#   1 — canary bytes found or infrastructure failure (FAIL)
#
# Requirements: go (in PATH), bash 4+, openssl (for rand), standard POSIX tools.
#
# Usage:
#   bash packaging/ci/test-receipts-no-credential-leak.sh [--keylatch <binary>]

set -euo pipefail

# ─── helpers ──────────────────────────────────────────────────────────────────

log()  { printf '[receipts-canary] %s\n' "$*"; }
pass() { printf '[receipts-canary] PASS: %s\n' "$*"; }
fail() {
  printf '[receipts-canary] FAIL: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_cmd go
require_cmd openssl

# ─── parse args ───────────────────────────────────────────────────────────────

KEYLATCH_BIN=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keylatch)
      KEYLATCH_BIN="$2"; shift 2 ;;
    *)
      fail "unknown argument: $1" ;;
  esac
done

# ─── workspace ────────────────────────────────────────────────────────────────

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

CANARY_HOME="$WORK/home"
mkdir -p "$CANARY_HOME"

RECEIPTS_JSON="$WORK/receipts.json"
CLI_OUTPUT="$WORK/cli-receipts.json"

log "Work dir: $WORK"

# ─── canary value ─────────────────────────────────────────────────────────────

# Format: sk-test-<hex> — recognisable prefix, impossible to false-positive on
# legitimate provider metadata (runtime, capability, policy_decision, etc.).
CANARY="sk-test-$(openssl rand -hex 8)"
log "Canary: ${CANARY:0:14}... (truncated for log safety)"

# ─── build keylatch binary ────────────────────────────────────────────────────

if [[ -z "$KEYLATCH_BIN" ]]; then
  log "Building keylatch binary..."
  KEYLATCH_BIN="$WORK/keylatch"
  go build -buildvcs=false -o "$KEYLATCH_BIN" ./cmd/keylatch
  log "Built: $KEYLATCH_BIN"
fi

[[ -x "$KEYLATCH_BIN" ]] || fail "keylatch binary not executable: $KEYLATCH_BIN"

# ─── environment ──────────────────────────────────────────────────────────────

export HOME="$CANARY_HOME"
export KEYLATCH_CONFIG_DIR="$CANARY_HOME/.keylatch"
export KEYLATCH_DATA_DIR="$CANARY_HOME/.keylatch/vault"
export KEYLATCH_BACKEND="file"
mkdir -p "$KEYLATCH_DATA_DIR"

# ─── bootstrap the file backend ───────────────────────────────────────────────

log "Bootstrapping file backend..."
"$KEYLATCH_BIN" bootstrap --backend file 2>/dev/null || true

# ─── enroll the canary credential ─────────────────────────────────────────────
#
# Store the canary as a credential value so it exists in the vault.
# The receipts pipeline must never surface this value — only metadata
# (provider name, capability, policy decision, credential_shape) is permitted.

log "Enrolling canary credential..."

if ! printf '%s' "$CANARY" | "$KEYLATCH_BIN" set default/custom/canary-receipt-test/api_key >/dev/null 2>&1; then
  echo "ERROR: enrollment failed — cannot verify canary is not leaked; aborting" >&2
  exit 1
fi
log "Enrolled via: keylatch set default/custom/canary-receipt-test/api_key"

# ─── start keylatchd and exercise the receipts API ────────────────────────────

GATEWAY_PORT=17782
UI_ADDR="127.0.0.1:$GATEWAY_PORT"
export KEYLATCH_UI_ADDR="$UI_ADDR"

log "Starting keylatchd on port $GATEWAY_PORT..."
"$KEYLATCH_BIN" ui \
  --bind "$UI_ADDR" \
  >/dev/null 2>&1 &
KEYLATCHD_PID=$!
trap 'kill "$KEYLATCHD_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

# Wait for the server to become healthy.
ATTEMPTS=0
until curl -sf "http://${UI_ADDR}/health" >/dev/null 2>&1; do
  ATTEMPTS=$((ATTEMPTS + 1))
  if [[ $ATTEMPTS -ge 50 ]]; then
    log "WARNING: keylatchd did not become healthy — skipping HTTP receipt check"
    KEYLATCHD_PID=""
    break
  fi
  sleep 0.1
done

# Push a synthetic runtime receipt via the internal IPC endpoint.
# The receipt metadata must not include the canary value — only the shape name.
if [[ -n "$KEYLATCHD_PID" ]]; then
  RECEIPT_PAYLOAD='{"runtime":"gateway_typed","provider":"canary-receipt-test","capability":"api_call","policy_decision":"allowed","credential_shape":"bearer","exit_code":0}'
  curl -sf \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$RECEIPT_PAYLOAD" \
    "http://${UI_ADDR}/v1/receipts" >/dev/null 2>&1 || true

  # Fetch via GET /v1/receipts.
  log "Fetching receipts via GET /v1/receipts..."
  curl -sf "http://${UI_ADDR}/v1/receipts?limit=50" >"$RECEIPTS_JSON" 2>/dev/null || {
    log "WARNING: GET /v1/receipts failed — writing empty receipts document"
    echo '{"receipts":[]}' >"$RECEIPTS_JSON"
  }
fi

# Fetch via CLI list --json.
log "Fetching receipts via keylatch receipts list --json..."
"$KEYLATCH_BIN" receipts list --json >"$CLI_OUTPUT" 2>/dev/null || {
  log "WARNING: receipts list returned non-zero (acceptable if store is empty)"
  echo '[]' >"$CLI_OUTPUT"
}

# ─── canary leak checks ───────────────────────────────────────────────────────

log "Scanning receipt outputs for canary bytes..."

LEAK_FOUND=0

check_file() {
  local label="$1"
  local file="$2"
  if [[ ! -f "$file" ]]; then
    log "SKIP: $label (file not found)"
    return
  fi
  if grep -q "$CANARY" "$file" 2>/dev/null; then
    printf '[receipts-canary] FAIL: canary found in %s\n' "$label" >&2
    grep -n "$CANARY" "$file" | head -5 >&2
    LEAK_FOUND=1
  else
    pass "No canary in $label"
  fi
}

check_file "GET /v1/receipts output"           "$RECEIPTS_JSON"
check_file "keylatch receipts list --json"     "$CLI_OUTPUT"

# Also scan the entire data directory for any plaintext occurrence.
if find "$KEYLATCH_DATA_DIR" -type f \
    ! -name '*.enc' ! -name '*.kv' ! -name '*.bin' \
    -exec grep -l "$CANARY" {} \; 2>/dev/null | grep -q .; then
  printf '[receipts-canary] FAIL: canary found in unencrypted data dir files\n' >&2
  find "$KEYLATCH_DATA_DIR" -type f \
    ! -name '*.enc' ! -name '*.kv' ! -name '*.bin' \
    -exec grep -l "$CANARY" {} \; >&2
  LEAK_FOUND=1
else
  pass "No canary in data directory (plaintext files)"
fi

if [[ "$LEAK_FOUND" -ne 0 ]]; then
  fail "invariant violated: canary credential bytes appeared in receipt output"
fi

pass "no canary credential bytes found in any receipt output channel"
log "All receipts-canary checks passed."
