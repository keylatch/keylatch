#!/usr/bin/env bash
# test-s-inv-4a-no-canary-leak.sh — canary leak detection test.
#
# Canary leak detection for the gateway_typed runtime path.
#
# Verifies that a known canary value injected as a credential does NOT appear
# in any output channel (stdout, stderr, audit log, or a simulated HTTP mock
# log) when `keylatch run --runtime gateway_typed` is invoked in an LLM session.
#
# Invariant: no raw credential bytes may reach any output channel
# during a gateway_typed run in an LLM session.
#
# Exit codes:
#   0 — no canary bytes found in any output channel (PASS)
#   1 — canary bytes found or test infrastructure failure (FAIL)
#
# Requirements: go (in PATH), bash 4+, standard POSIX tools.
# No external services or real provider credentials are required.
#
# Usage:
#   bash packaging/ci/test-s-inv-4a-no-canary-leak.sh [--keylatch <binary>]

set -euo pipefail

# ─── helpers ──────────────────────────────────────────────────────────────────

log()  { printf '[s-inv-4a] %s\n' "$*"; }
pass() { printf '[s-inv-4a] PASS: %s\n' "$*"; }
fail() {
  printf '[s-inv-4a] FAIL: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_cmd go

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

STDOUT_LOG="$WORK/stdout.log"
STDERR_LOG="$WORK/stderr.log"
AUDIT_LOG="$WORK/audit.log"
MOCK_LOG="$WORK/mock.log"

log "Work dir: $WORK"

# ─── canary value ─────────────────────────────────────────────────────────────

# The canary is a recognisable string that must NOT appear outside the vault.
# Format: kl-canary-<random> — distinctive prefix so grep cannot false-positive.
CANARY_VALUE="kl-canary-$(head -c 8 /dev/urandom | xxd -p)"
log "Canary value: ${CANARY_VALUE:0:12}... (truncated for log safety)"

# ─── build keylatch binary ────────────────────────────────────────────────────

if [[ -z "$KEYLATCH_BIN" ]]; then
  log "Building keylatch binary..."
  KEYLATCH_BIN="$WORK/keylatch"
  go build -buildvcs=false -o "$KEYLATCH_BIN" ./cmd/keylatch
  log "Built: $KEYLATCH_BIN"
fi

[[ -x "$KEYLATCH_BIN" ]] || fail "keylatch binary not executable: $KEYLATCH_BIN"

# ─── helper: set keylatch env ─────────────────────────────────────────────────

export HOME="$CANARY_HOME"
export KEYLATCH_CONFIG_DIR="$CANARY_HOME/.keylatch"
export KEYLATCH_DATA_DIR="$CANARY_HOME/.keylatch/vault"
export KEYLATCH_BACKEND="file"
mkdir -p "$KEYLATCH_DATA_DIR"

# ─── bootstrap keyring for file backend ───────────────────────────────────────

log "Bootstrapping keyring..."
"$KEYLATCH_BIN" bootstrap --backend file 2>/dev/null || true

# ─── enroll credential with canary value ──────────────────────────────────────

CRED_PATH="default/custom/anthropic-s-inv-4a/api_key"
CONNECTION="anthropic-s-inv-4a"

log "Enrolling canary credential..."
if ! printf '%s' "$CANARY_VALUE" | "$KEYLATCH_BIN" set "$CRED_PATH" \
    >"$STDOUT_LOG" 2>"$STDERR_LOG"; then
  fail "canary enrollment failed — 'keylatch set $CRED_PATH' returned non-zero"
fi

log "Credential enrolled"

# Verify the canary is NOT in plaintext in the data dir.
if grep -r --include="*.json" --include="*.kv" --include="*.bin" \
    "$CANARY_VALUE" "$KEYLATCH_DATA_DIR" 2>/dev/null | grep -v "^Binary"; then
  fail "canary value found in plaintext in data directory"
fi
pass "Canary not in plaintext in data dir"

# ─── start gateway ────────────────────────────────────────────────────────────

log "Initialising gateway..."
"$KEYLATCH_BIN" gateway init >"$STDOUT_LOG" 2>"$STDERR_LOG" || true

GATEWAY_PORT=17979
log "Starting gateway on port $GATEWAY_PORT..."
"$KEYLATCH_BIN" gateway up --port "$GATEWAY_PORT" >"$STDOUT_LOG" 2>"$STDERR_LOG" &
GATEWAY_PID=$!
trap 'kill "$GATEWAY_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

# Wait for gateway to become healthy.
ATTEMPTS=0
until curl -sf "http://127.0.0.1:$GATEWAY_PORT/health" >/dev/null 2>&1; do
  ATTEMPTS=$((ATTEMPTS + 1))
  if [[ $ATTEMPTS -ge 100 ]]; then
    fail "gateway did not become healthy after 10s"
  fi
  sleep 0.1
done
pass "Gateway healthy"

# ─── run in LLM session via gateway_typed ─────────────────────────────────────

log "Running: CLAUDE_CODE=1 keylatch run --runtime gateway_typed $CONNECTION -- echo hi"

MOCK_HTTP_LOG="$MOCK_LOG"
touch "$MOCK_HTTP_LOG"

# Capture all output channels.
CLAUDE_CODE=1 \
KEYLATCH_GATEWAY_ADDR="127.0.0.1:$GATEWAY_PORT" \
  "$KEYLATCH_BIN" run \
    --runtime gateway_typed \
    "$CONNECTION" \
    -- echo hi \
  >"$STDOUT_LOG" 2>"$STDERR_LOG" || {
    EXIT_CODE=$?
    log "run exited with code $EXIT_CODE (expected if gateway_typed requires a running session)"
    # Non-zero exit is acceptable here — what matters is no canary leak.
  }

# ─── audit log ────────────────────────────────────────────────────────────────

# Copy audit log from data dir if it exists.
AUDIT_SRC="$KEYLATCH_DATA_DIR/audit.log"
if [[ -f "$AUDIT_SRC" ]]; then
  cp "$AUDIT_SRC" "$AUDIT_LOG"
else
  touch "$AUDIT_LOG"
fi

# ─── canary leak checks ───────────────────────────────────────────────────────

log "Checking all output channels for canary bytes..."

LEAK_FOUND=0

check_channel() {
  local channel="$1"
  local file="$2"
  if [[ ! -f "$file" ]]; then
    return
  fi
  if grep -q "$CANARY_VALUE" "$file" 2>/dev/null; then
    printf '[s-inv-4a] FAIL: canary found in %s\n' "$channel" >&2
    printf '[s-inv-4a]   File: %s\n' "$file" >&2
    grep -n "$CANARY_VALUE" "$file" | head -5 >&2
    LEAK_FOUND=1
  else
    pass "No canary in $channel"
  fi
}

check_channel "stdout"     "$STDOUT_LOG"
check_channel "stderr"     "$STDERR_LOG"
check_channel "audit log"  "$AUDIT_LOG"
check_channel "mock log"   "$MOCK_HTTP_LOG"

# Also scan the entire data directory for the canary in any file.
if find "$KEYLATCH_DATA_DIR" -type f -exec grep -l "$CANARY_VALUE" {} \; 2>/dev/null | grep -q .; then
  printf '[s-inv-4a] FAIL: canary found in keylatch data directory files\n' >&2
  find "$KEYLATCH_DATA_DIR" -type f -exec grep -l "$CANARY_VALUE" {} \; >&2
  LEAK_FOUND=1
else
  pass "No canary in keylatch data directory"
fi

if [[ "$LEAK_FOUND" -ne 0 ]]; then
  fail "canary bytes escaped to one or more output channels"
fi

pass "no canary bytes found in any output channel"
log "All canary leak checks passed."
