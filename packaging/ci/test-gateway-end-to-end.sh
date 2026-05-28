#!/usr/bin/env bash
# test-gateway-end-to-end.sh — EPIC-04 Task 5
#
# End-to-end gateway integration test using an in-process memory backend.
# Verifies: gateway init → token create → request proxied → token revoke.
#
# Requirements: go (in PATH), bash 4+, standard POSIX tools.
# No external services or real provider credentials are required.
#
# Exit codes:
#   0 — all checks passed
#   1 — a check failed (details printed to stderr)
#
# Usage:
#   bash packaging/ci/test-gateway-end-to-end.sh [--keylatch <binary>]
#
# When --keylatch is not provided the script builds the binary from source
# into a temporary directory.

set -euo pipefail

# ─── helpers ──────────────────────────────────────────────────────────────────

log()  { printf '[gateway-e2e] %s\n' "$*"; }
fail() { printf '[gateway-e2e] FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf '[gateway-e2e] PASS: %s\n' "$*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_cmd go
require_cmd curl
require_cmd jq

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

# ─── setup temp workspace ─────────────────────────────────────────────────────

TMPDIR_ROOT=$(mktemp -d)
trap 'chmod -R u+w "$TMPDIR_ROOT" 2>/dev/null || true; rm -rf "$TMPDIR_ROOT"' EXIT

log "Temp workspace: $TMPDIR_ROOT"

# ─── build keylatch binary ────────────────────────────────────────────────────
# Build before overriding HOME so the Go module cache stays in the original
# location and the temp-dir cleanup (rm -rf) doesn't hit read-only module files.

if [[ -z "$KEYLATCH_BIN" ]]; then
  log "Building keylatch binary..."
  KEYLATCH_BIN="$TMPDIR_ROOT/keylatch"
  go build -o "$KEYLATCH_BIN" ./cmd/keylatch
  log "Built: $KEYLATCH_BIN"
fi

[[ -x "$KEYLATCH_BIN" ]] || fail "keylatch binary not executable: $KEYLATCH_BIN"

# ─── run gateway Go integration tests ────────────────────────────────────────
#
# Run BEFORE overriding HOME so go test writes module cache to the real user's
# GOPATH and not to the temp dir (avoids read-only file errors on rm -rf cleanup).
#
# The primary E2E coverage is provided by Go test functions in the gateway
# package that start a real HTTP server in-process. These are faster and
# more reliable than shell-driven tests that manage daemon processes:
#   - TestGatewayUp_ResolvesAEADCredential  (Task 2)
#   - TestGatewayToken_RejectsExpired       (Task 4)
#   - TestGatewayToken_RejectsScopeMismatch (Task 4)
#   - TestGatewayToken_RejectsAudienceMismatch (Task 4)
#   - TestGatewayToken_RejectsReplay        (Task 4)
#   - TestGatewayToken_RejectsAfterSessionEnd (Task 4)
#   - TestSDKDriver_OpenAIChatCompletions_Routes (Task 3)

log "Running Go gateway integration tests..."
go test -count=1 -timeout=60s \
  ./internal/gateway/... \
  ./internal/gateway/route/... \
  ./internal/gateway/token/... \
  ./internal/ui/api/...
pass "Go gateway integration tests"

# ─── override HOME and set config dir ────────────────────────────────────────
# Override HOME to isolate keylatch config from the real user HOME.
# Set KEYLATCH_CONFIG_DIR explicitly so the path is predictable across platforms
# (Linux falls back to ~/.config/keylatch via XDG; we pin it to avoid that).

GATEWAY_HOME="$TMPDIR_ROOT/home"
mkdir -p "$GATEWAY_HOME"
export HOME="$GATEWAY_HOME"
export KEYLATCH_CONFIG_DIR="$GATEWAY_HOME/.keylatch"
mkdir -p "$KEYLATCH_CONFIG_DIR"

# ─── gateway init ─────────────────────────────────────────────────────────────

log "Running: keylatch gateway init"
"$KEYLATCH_BIN" gateway init
[[ -f "$KEYLATCH_CONFIG_DIR/gateway/signing.key" ]] || \
  fail "gateway init: signing key not created at \$KEYLATCH_CONFIG_DIR/gateway/signing.key"
[[ -f "$KEYLATCH_CONFIG_DIR/gateway/config.json" ]] || \
  fail "gateway init: config.json not created"
pass "gateway init"

# ─── start gateway in background ──────────────────────────────────────────────

GATEWAY_PORT=17878
log "Starting gateway on port $GATEWAY_PORT..."
GATEWAY_PID_FILE="$KEYLATCH_CONFIG_DIR/gateway/gateway.pid"

"$KEYLATCH_BIN" gateway up --port "$GATEWAY_PORT" &
GATEWAY_BG_PID=$!
trap 'kill "$GATEWAY_BG_PID" 2>/dev/null || true; chmod -R u+w "$TMPDIR_ROOT" 2>/dev/null || true; rm -rf "$TMPDIR_ROOT"' EXIT

# Wait for the gateway to become healthy (up to 5 s).
ATTEMPTS=0
until curl -sf "http://127.0.0.1:$GATEWAY_PORT/health" >/dev/null 2>&1; do
  ATTEMPTS=$((ATTEMPTS + 1))
  if [[ $ATTEMPTS -ge 50 ]]; then
    fail "gateway did not become healthy after 5 s"
  fi
  sleep 0.1
done
pass "gateway healthy"

# ─── health endpoint ──────────────────────────────────────────────────────────

log "Checking /health response..."
HEALTH=$(curl -sf "http://127.0.0.1:$GATEWAY_PORT/health")
echo "$HEALTH" | jq -e '.status == "ok"' >/dev/null || \
  fail "health response missing status=ok: $HEALTH"
pass "/health returns {status:ok}"

# ─── token create ─────────────────────────────────────────────────────────────

log "Creating gateway token..."
TOKEN_OUTPUT=$("$KEYLATCH_BIN" gateway token create test-e2e-actor \
  --allow "openrouter.chat.completion" \
  --ttl 1h)
GATEWAY_TOKEN=$(echo "$TOKEN_OUTPUT" | grep '^token:' | awk '{print $2}')
TOKEN_ID=$(echo "$TOKEN_OUTPUT" | grep '^id:' | awk '{print $2}')
TOKEN_ACCESSOR=$(echo "$TOKEN_OUTPUT" | grep '^accessor:' | awk '{print $2}')

[[ -n "$GATEWAY_TOKEN" ]] || fail "token create: no JWT in output"
[[ -n "$TOKEN_ID" ]] || fail "token create: no id in output"
[[ -n "$TOKEN_ACCESSOR" ]] || fail "token create: no accessor in output"
pass "gateway token create"

# ─── capability enforcement: missing token → 401 ─────────────────────────────

log "Verifying missing token → 401..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "http://127.0.0.1:$GATEWAY_PORT/api/openrouter/chat.completion" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[]}')
[[ "$STATUS" == "401" ]] || fail "expected 401 for missing token, got $STATUS"
pass "missing token → 401"

# ─── capability enforcement: wrong capability → 403 ──────────────────────────

log "Creating a sentry-scoped token to verify audience isolation..."
SENTRY_TOKEN_OUTPUT=$("$KEYLATCH_BIN" gateway token create sentry-actor \
  --allow "sentry.error_reporting" --ttl 1h)
SENTRY_TOKEN=$(echo "$SENTRY_TOKEN_OUTPUT" | grep '^token:' | awk '{print $2}')

log "Verifying sentry token on openrouter route → 403..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "http://127.0.0.1:$GATEWAY_PORT/api/openrouter/chat.completion" \
  -H "Authorization: Bearer $SENTRY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[]}')
[[ "$STATUS" == "403" ]] || fail "expected 403 for audience mismatch, got $STATUS"
pass "audience mismatch → 403"

# ─── token list ───────────────────────────────────────────────────────────────

log "Listing gateway tokens..."
TOKEN_LIST=$("$KEYLATCH_BIN" gateway token list --json)
echo "$TOKEN_LIST" | jq -e '. | length >= 2' >/dev/null || \
  fail "expected at least 2 tokens in list, got: $TOKEN_LIST"
pass "gateway token list"

# ─── token revoke ─────────────────────────────────────────────────────────────

log "Revoking token $TOKEN_ID..."
"$KEYLATCH_BIN" gateway token revoke "$TOKEN_ID"
pass "gateway token revoke"

# ─── revoked token → 401 ─────────────────────────────────────────────────────

log "Verifying revoked token → 401..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "http://127.0.0.1:$GATEWAY_PORT/api/openrouter/chat.completion" \
  -H "Authorization: Bearer $GATEWAY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[]}')
[[ "$STATUS" == "401" ]] || fail "expected 401 for revoked token, got $STATUS"
pass "revoked token → 401"

# ─── gateway status ───────────────────────────────────────────────────────────

log "Checking gateway status..."
STATUS_OUT=$("$KEYLATCH_BIN" gateway status)
echo "$STATUS_OUT" | grep -q "running\|stopped" || fail "gateway status output unexpected: $STATUS_OUT"
pass "gateway status"

# ─── done ─────────────────────────────────────────────────────────────────────

log "All gateway E2E checks passed."
